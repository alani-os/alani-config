//! Configuration document loading and parsing.
//!
//! The loader accepts a small TOML-like format for host-mode tests:
//! `[section]`, `key = value`, `#` comments, quoted strings, booleans, decimal
//! or hexadecimal integers, and dotted `section.key = value` records.

use crate::error::{ConfigError, ConfigResult};
use crate::profiles::{ConfigProfile, ProfileMode};
use crate::schema::{BuiltinSchema, ConfigDomain, ConfigRecord, ConfigValue};
use crate::validation::ConfigValidator;

/// Maximum configuration document length accepted by the default loader.
pub const DEFAULT_MAX_CONFIG_LEN: usize = 32 * 1024;

/// Built-in host-mode configuration document used by smoke tests.
pub const HOST_CONFIG: &str = "\
[profile]
name = \"mvk.host\"
version = \"0.1.0\"
mode = \"host\"
target = \"x86_64-uefi\"

[environment]
name = \"host\"
mode = \"host\"
target = \"x86_64-uefi\"
log_level = \"info\"
host_mocks = true

[boot]
kernel_path = \"/boot/alani-kernel\"
init_profile = \"mvk.host\"
memory_limit_bytes = 268435456
require_measurements = false

[runtime]
max_processes = 64
max_agents = 16
default_priority = 128
enable_mock_cognition = true
supervision_tick_ms = 10

[security]
secure_boot = false
audit_required = true
policy_bundle = \"/etc/alani/policy.mvk\"
allow_unsigned = true
min_key_bits = 128

[devices]
console = \"mock\"
storage = \"memory\"
network = \"disabled\"
cognition = \"mock\"
max_device_buffers = 64
";

/// Loader strictness mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoaderMode {
    /// Unknown keys and validation errors are rejected.
    Strict,
    /// Unknown schema keys are retained for inspection.
    Permissive,
}

/// Host-mode configuration loader settings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoaderConfig {
    /// Maximum accepted document length.
    pub max_config_len: usize,
    /// Parser strictness mode.
    pub mode: LoaderMode,
}

impl LoaderConfig {
    /// Default strict loader configuration.
    pub const fn default() -> Self {
        Self {
            max_config_len: DEFAULT_MAX_CONFIG_LEN,
            mode: LoaderMode::Strict,
        }
    }
}

impl Default for LoaderConfig {
    fn default() -> Self {
        Self {
            max_config_len: DEFAULT_MAX_CONFIG_LEN,
            mode: LoaderMode::Strict,
        }
    }
}

/// Configuration document loader.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigLoader {
    /// Loader settings.
    pub config: LoaderConfig,
}

impl ConfigLoader {
    /// Creates a strict loader with default limits.
    pub const fn new() -> Self {
        Self {
            config: LoaderConfig::default(),
        }
    }

    /// Creates a loader with explicit settings.
    pub const fn with_config(config: LoaderConfig) -> Self {
        Self { config }
    }

    /// Parses a borrowed configuration document.
    pub fn parse<'a>(&self, text: &'a str) -> ConfigResult<ConfigProfile<'a>> {
        if text.trim().is_empty() || text.len() > self.config.max_config_len {
            return Err(ConfigError::InvalidDocument);
        }

        let mut profile = ConfigProfile::empty();
        let mut current_domain: Option<ConfigDomain> = None;
        let mut in_profile_section = false;

        for (index, raw_line) in text.lines().enumerate() {
            let source_line = (index + 1) as u32;
            let line = strip_comment(raw_line).trim();
            if line.is_empty() {
                continue;
            }

            if let Some(section) = parse_section_header(line)? {
                if section == "profile" {
                    current_domain = None;
                    in_profile_section = true;
                } else {
                    current_domain =
                        Some(ConfigDomain::from_label(section).ok_or(ConfigError::UnknownSection)?);
                    in_profile_section = false;
                }
                continue;
            }

            let (raw_key, raw_value) = line.split_once('=').ok_or(ConfigError::InvalidDocument)?;
            let key = raw_key.trim();
            let value = raw_value.trim();
            if key.is_empty() || value.is_empty() {
                return Err(ConfigError::InvalidDocument);
            }

            if in_profile_section
                || key.starts_with("profile.")
                || (current_domain.is_none() && is_bare_profile_key(key))
            {
                parse_profile_key(&mut profile, key, value)?;
                continue;
            }

            let (domain, key) = match key.split_once('.') {
                Some((prefix, nested)) => (
                    ConfigDomain::from_label(prefix).ok_or(ConfigError::UnknownSection)?,
                    nested.trim(),
                ),
                None => (current_domain.ok_or(ConfigError::UnknownSection)?, key),
            };

            if self.config.mode == LoaderMode::Strict && !BuiltinSchema::contains(domain, key) {
                return Err(ConfigError::UnknownKey);
            }
            let parsed = parse_value(value)?;
            let record = ConfigRecord::new(domain, key, parsed, source_line)?;
            profile.push_record(record)?;
        }

        if self.config.mode == LoaderMode::Strict {
            ConfigValidator::new().validate_strict(&profile)?;
        } else {
            profile.validate_identity()?;
        }
        Ok(profile)
    }
}

impl Default for ConfigLoader {
    fn default() -> Self {
        Self::new()
    }
}

/// Parses a configuration document using the default strict loader.
pub fn parse_config_profile(text: &str) -> ConfigResult<ConfigProfile<'_>> {
    ConfigLoader::new().parse(text)
}

/// Descriptor for the loader component itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoaderDescriptor<'a> {
    /// Component name.
    pub name: &'a str,
    /// Component version marker.
    pub version: u32,
}

impl<'a> LoaderDescriptor<'a> {
    /// Creates a loader component descriptor.
    pub const fn new(name: &'a str, version: u32) -> Self {
        Self { name, version }
    }
}

fn strip_comment(line: &str) -> &str {
    match line.as_bytes().iter().position(|byte| *byte == b'#') {
        Some(index) => &line[..index],
        None => line,
    }
}

fn parse_section_header(line: &str) -> ConfigResult<Option<&str>> {
    if !line.starts_with('[') {
        return Ok(None);
    }
    if !line.ends_with(']') || line.len() < 3 {
        return Err(ConfigError::InvalidDocument);
    }
    let section = line[1..line.len() - 1].trim();
    if section.is_empty() {
        return Err(ConfigError::InvalidDocument);
    }
    Ok(Some(section))
}

fn is_bare_profile_key(key: &str) -> bool {
    matches!(key, "name" | "version" | "mode" | "target")
}

fn parse_profile_key<'a>(
    profile: &mut ConfigProfile<'a>,
    key: &str,
    value: &'a str,
) -> ConfigResult<()> {
    let value = parse_string_like(value)?;
    match key {
        "name" | "profile.name" => profile.name = value,
        "version" | "profile.version" => profile.version = value,
        "mode" | "profile.mode" => {
            profile.mode = ProfileMode::from_label(value).ok_or(ConfigError::InvalidValue)?;
        }
        "target" | "profile.target" => profile.target = value,
        _ => return Err(ConfigError::UnknownKey),
    }
    Ok(())
}

fn parse_value(value: &str) -> ConfigResult<ConfigValue<'_>> {
    let value = value.trim();
    if value.is_empty() {
        return Err(ConfigError::InvalidValue);
    }
    if is_quoted(value) {
        return Ok(ConfigValue::String(unquote(value)?));
    }
    match value.as_bytes() {
        b"true" => return Ok(ConfigValue::Boolean(true)),
        b"false" => return Ok(ConfigValue::Boolean(false)),
        _ => {}
    }
    if is_numeric_token(value) {
        return Ok(ConfigValue::Integer(parse_u64(value)?));
    }
    Ok(ConfigValue::String(value))
}

fn parse_string_like(value: &str) -> ConfigResult<&str> {
    let value = value.trim();
    if value.is_empty() {
        return Err(ConfigError::InvalidValue);
    }
    if is_quoted(value) {
        unquote(value)
    } else {
        Ok(value)
    }
}

fn is_quoted(value: &str) -> bool {
    value.len() >= 2 && value.starts_with('"') && value.ends_with('"')
}

fn unquote(value: &str) -> ConfigResult<&str> {
    if !is_quoted(value) {
        return Err(ConfigError::InvalidValue);
    }
    let inner = &value[1..value.len() - 1];
    if inner.bytes().any(|byte| byte == b'"') {
        return Err(ConfigError::InvalidValue);
    }
    Ok(inner)
}

fn parse_u64(value: &str) -> ConfigResult<u64> {
    let value = value.trim();
    let (radix, digits) = match value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        Some(hex) => (16_u64, hex),
        None => (10_u64, value),
    };
    if digits.is_empty() {
        return Err(ConfigError::InvalidNumber);
    }

    let mut parsed = 0_u64;
    for byte in digits.bytes() {
        let digit = match byte {
            b'0'..=b'9' => (byte - b'0') as u64,
            b'a'..=b'f' => 10 + (byte - b'a') as u64,
            b'A'..=b'F' => 10 + (byte - b'A') as u64,
            _ => return Err(ConfigError::InvalidNumber),
        };
        if digit >= radix {
            return Err(ConfigError::InvalidNumber);
        }
        parsed = parsed
            .checked_mul(radix)
            .and_then(|value| value.checked_add(digit))
            .ok_or(ConfigError::InvalidNumber)?;
    }
    Ok(parsed)
}

fn is_numeric_token(token: &str) -> bool {
    token.starts_with("0x")
        || token.starts_with("0X")
        || token.bytes().all(|byte| byte.is_ascii_digit())
}
