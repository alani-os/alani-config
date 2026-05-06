//! Typed configuration schema metadata.
//!
//! `alani-config` owns configuration document schemas for boot, devices,
//! runtime, security, corpus, release, and environment profiles. This module is
//! dependency-free and mirrors future protocol schema contracts with stable Rust
//! types.

use crate::error::{ConfigError, ConfigResult};

/// Number of built-in schema fields in the MVK skeleton.
pub const BUILTIN_FIELD_COUNT: usize = 34;

/// Maximum field key length accepted by schema validation.
pub const MAX_CONFIG_KEY_LEN: usize = 64;

/// Configuration document domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ConfigDomain {
    /// Bootloader and kernel handoff settings.
    Boot,
    /// Device discovery and device policy settings.
    Devices,
    /// Userspace runtime settings.
    Runtime,
    /// Security and trust settings.
    Security,
    /// Corpus and dataset settings.
    Corpus,
    /// Release and evidence settings.
    Release,
    /// Environment profile settings.
    Environment,
}

impl ConfigDomain {
    /// Parses a domain label.
    pub const fn from_label(label: &str) -> Option<Self> {
        match label.as_bytes() {
            b"boot" => Some(Self::Boot),
            b"devices" | b"device" => Some(Self::Devices),
            b"runtime" => Some(Self::Runtime),
            b"security" => Some(Self::Security),
            b"corpus" => Some(Self::Corpus),
            b"release" => Some(Self::Release),
            b"environment" | b"env" => Some(Self::Environment),
            _ => None,
        }
    }

    /// Stable domain label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Boot => "boot",
            Self::Devices => "devices",
            Self::Runtime => "runtime",
            Self::Security => "security",
            Self::Corpus => "corpus",
            Self::Release => "release",
            Self::Environment => "environment",
        }
    }
}

/// Configuration scalar value type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigValueKind {
    /// UTF-8 string scalar.
    String,
    /// Unsigned integer scalar.
    Integer,
    /// Boolean scalar.
    Boolean,
    /// Enumerated string scalar.
    Enum,
}

/// Data classification for configuration values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataClass {
    /// Safe for public diagnostics.
    Public,
    /// Operational metadata for restricted diagnostics.
    Operational,
    /// Sensitive data requiring redaction.
    Sensitive,
    /// Secret data that should never be logged by default.
    Secret,
}

impl DataClass {
    /// Returns `true` when values with this classification require redaction.
    pub const fn requires_redaction(self) -> bool {
        matches!(self, Self::Sensitive | Self::Secret)
    }
}

/// Borrowed configuration scalar value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigValue<'a> {
    /// Empty placeholder used by fixed arrays.
    Empty,
    /// UTF-8 string scalar.
    String(&'a str),
    /// Unsigned integer scalar.
    Integer(u64),
    /// Boolean scalar.
    Boolean(bool),
}

impl<'a> ConfigValue<'a> {
    /// Returns the value kind.
    pub const fn kind(self) -> Option<ConfigValueKind> {
        match self {
            Self::Empty => None,
            Self::String(_) => Some(ConfigValueKind::String),
            Self::Integer(_) => Some(ConfigValueKind::Integer),
            Self::Boolean(_) => Some(ConfigValueKind::Boolean),
        }
    }

    /// Returns the value as a string if it is a string scalar.
    pub const fn as_str(self) -> Option<&'a str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    /// Returns the value as an integer if it is an integer scalar.
    pub const fn as_u64(self) -> Option<u64> {
        match self {
            Self::Integer(value) => Some(value),
            _ => None,
        }
    }

    /// Returns the value as a boolean if it is a boolean scalar.
    pub const fn as_bool(self) -> Option<bool> {
        match self {
            Self::Boolean(value) => Some(value),
            _ => None,
        }
    }
}

/// One configuration key-value record in a profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigRecord<'a> {
    /// Configuration domain.
    pub domain: ConfigDomain,
    /// Key within the domain.
    pub key: &'a str,
    /// Borrowed scalar value.
    pub value: ConfigValue<'a>,
    /// 1-based source line in the loaded document.
    pub source_line: u32,
}

impl<'a> ConfigRecord<'a> {
    /// Empty record for fixed-array initialization.
    pub const EMPTY: Self = Self {
        domain: ConfigDomain::Environment,
        key: "",
        value: ConfigValue::Empty,
        source_line: 0,
    };

    /// Creates a validated config record.
    pub fn new(
        domain: ConfigDomain,
        key: &'a str,
        value: ConfigValue<'a>,
        source_line: u32,
    ) -> ConfigResult<Self> {
        validate_key(key)?;
        if matches!(value, ConfigValue::Empty) {
            return Err(ConfigError::InvalidValue);
        }
        Ok(Self {
            domain,
            key,
            value,
            source_line,
        })
    }
}

/// Schema field metadata for one configuration key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigField {
    /// Configuration domain.
    pub domain: ConfigDomain,
    /// Key within the domain.
    pub key: &'static str,
    /// Expected scalar value kind.
    pub value_kind: ConfigValueKind,
    /// Whether the field must be present in a valid profile.
    pub required: bool,
    /// Data classification for diagnostics and redaction.
    pub data_class: DataClass,
    /// Minimum integer value when `value_kind` is integer.
    pub min: Option<u64>,
    /// Maximum integer value when `value_kind` is integer.
    pub max: Option<u64>,
    /// Enumerated values when `value_kind` is enum.
    pub allowed: &'static [&'static str],
}

impl ConfigField {
    /// Validates one record against this schema field.
    pub fn validate_value(&self, record: ConfigRecord<'_>) -> ConfigResult<()> {
        if record.domain != self.domain || record.key != self.key {
            return Err(ConfigError::InvalidArgument);
        }
        match (self.value_kind, record.value) {
            (ConfigValueKind::String, ConfigValue::String(value)) => {
                if value.is_empty() {
                    return Err(ConfigError::InvalidValue);
                }
            }
            (ConfigValueKind::Enum, ConfigValue::String(value)) => {
                if !self.allowed.contains(&value) {
                    return Err(ConfigError::InvalidValue);
                }
            }
            (ConfigValueKind::Integer, ConfigValue::Integer(value)) => {
                if let Some(min) = self.min {
                    if value < min {
                        return Err(ConfigError::InvalidValue);
                    }
                }
                if let Some(max) = self.max {
                    if value > max {
                        return Err(ConfigError::InvalidValue);
                    }
                }
            }
            (ConfigValueKind::Boolean, ConfigValue::Boolean(_)) => {}
            _ => return Err(ConfigError::TypeMismatch),
        }
        Ok(())
    }
}

/// Built-in MVK config schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuiltinSchema;

impl BuiltinSchema {
    /// Returns all built-in schema fields.
    pub const fn fields() -> &'static [ConfigField; BUILTIN_FIELD_COUNT] {
        &BUILTIN_FIELDS
    }

    /// Returns the schema field for a domain/key pair.
    pub fn field(domain: ConfigDomain, key: &str) -> Option<&'static ConfigField> {
        Self::fields()
            .iter()
            .find(|field| field.domain == domain && field.key == key)
    }

    /// Returns `true` when a domain/key pair is known by the built-in schema.
    pub fn contains(domain: ConfigDomain, key: &str) -> bool {
        Self::field(domain, key).is_some()
    }
}

/// Descriptor for the schema component itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemaDescriptor<'a> {
    /// Component name.
    pub name: &'a str,
    /// Component version marker.
    pub version: u32,
}

impl<'a> SchemaDescriptor<'a> {
    /// Creates a schema component descriptor.
    pub const fn new(name: &'a str, version: u32) -> Self {
        Self { name, version }
    }
}

/// Validates a key label.
pub fn validate_key(key: &str) -> ConfigResult<()> {
    if key.is_empty() || key.len() > MAX_CONFIG_KEY_LEN {
        return Err(ConfigError::MissingField);
    }
    if !key
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(ConfigError::InvalidArgument);
    }
    Ok(())
}

const HOST_MODES: &[&str] = &["host", "emulator", "hardware"];
const LOG_LEVELS: &[&str] = &["error", "warn", "info", "debug", "trace"];
const RELEASE_CHANNELS: &[&str] = &["dev", "nightly", "stable"];
const DEVICE_MODES: &[&str] = &["mock", "virtio", "native", "disabled"];
const STORAGE_MODES: &[&str] = &["memory", "disk", "disabled"];

/// Built-in schema field table.
pub const BUILTIN_FIELDS: [ConfigField; BUILTIN_FIELD_COUNT] = [
    ConfigField {
        domain: ConfigDomain::Environment,
        key: "name",
        value_kind: ConfigValueKind::String,
        required: true,
        data_class: DataClass::Public,
        min: None,
        max: None,
        allowed: &[],
    },
    ConfigField {
        domain: ConfigDomain::Environment,
        key: "mode",
        value_kind: ConfigValueKind::Enum,
        required: true,
        data_class: DataClass::Public,
        min: None,
        max: None,
        allowed: HOST_MODES,
    },
    ConfigField {
        domain: ConfigDomain::Environment,
        key: "target",
        value_kind: ConfigValueKind::String,
        required: true,
        data_class: DataClass::Operational,
        min: None,
        max: None,
        allowed: &[],
    },
    ConfigField {
        domain: ConfigDomain::Environment,
        key: "log_level",
        value_kind: ConfigValueKind::Enum,
        required: false,
        data_class: DataClass::Operational,
        min: None,
        max: None,
        allowed: LOG_LEVELS,
    },
    ConfigField {
        domain: ConfigDomain::Environment,
        key: "host_mocks",
        value_kind: ConfigValueKind::Boolean,
        required: false,
        data_class: DataClass::Operational,
        min: None,
        max: None,
        allowed: &[],
    },
    ConfigField {
        domain: ConfigDomain::Boot,
        key: "kernel_path",
        value_kind: ConfigValueKind::String,
        required: true,
        data_class: DataClass::Operational,
        min: None,
        max: None,
        allowed: &[],
    },
    ConfigField {
        domain: ConfigDomain::Boot,
        key: "init_profile",
        value_kind: ConfigValueKind::String,
        required: true,
        data_class: DataClass::Operational,
        min: None,
        max: None,
        allowed: &[],
    },
    ConfigField {
        domain: ConfigDomain::Boot,
        key: "command_line",
        value_kind: ConfigValueKind::String,
        required: false,
        data_class: DataClass::Sensitive,
        min: None,
        max: None,
        allowed: &[],
    },
    ConfigField {
        domain: ConfigDomain::Boot,
        key: "memory_limit_bytes",
        value_kind: ConfigValueKind::Integer,
        required: false,
        data_class: DataClass::Operational,
        min: Some(1024 * 1024),
        max: Some(1024 * 1024 * 1024 * 1024),
        allowed: &[],
    },
    ConfigField {
        domain: ConfigDomain::Boot,
        key: "require_measurements",
        value_kind: ConfigValueKind::Boolean,
        required: false,
        data_class: DataClass::Operational,
        min: None,
        max: None,
        allowed: &[],
    },
    ConfigField {
        domain: ConfigDomain::Runtime,
        key: "max_processes",
        value_kind: ConfigValueKind::Integer,
        required: true,
        data_class: DataClass::Operational,
        min: Some(1),
        max: Some(4096),
        allowed: &[],
    },
    ConfigField {
        domain: ConfigDomain::Runtime,
        key: "max_agents",
        value_kind: ConfigValueKind::Integer,
        required: true,
        data_class: DataClass::Operational,
        min: Some(0),
        max: Some(1024),
        allowed: &[],
    },
    ConfigField {
        domain: ConfigDomain::Runtime,
        key: "default_priority",
        value_kind: ConfigValueKind::Integer,
        required: false,
        data_class: DataClass::Operational,
        min: Some(0),
        max: Some(255),
        allowed: &[],
    },
    ConfigField {
        domain: ConfigDomain::Runtime,
        key: "enable_mock_cognition",
        value_kind: ConfigValueKind::Boolean,
        required: false,
        data_class: DataClass::Operational,
        min: None,
        max: None,
        allowed: &[],
    },
    ConfigField {
        domain: ConfigDomain::Runtime,
        key: "supervision_tick_ms",
        value_kind: ConfigValueKind::Integer,
        required: false,
        data_class: DataClass::Operational,
        min: Some(1),
        max: Some(60_000),
        allowed: &[],
    },
    ConfigField {
        domain: ConfigDomain::Security,
        key: "secure_boot",
        value_kind: ConfigValueKind::Boolean,
        required: true,
        data_class: DataClass::Operational,
        min: None,
        max: None,
        allowed: &[],
    },
    ConfigField {
        domain: ConfigDomain::Security,
        key: "audit_required",
        value_kind: ConfigValueKind::Boolean,
        required: true,
        data_class: DataClass::Operational,
        min: None,
        max: None,
        allowed: &[],
    },
    ConfigField {
        domain: ConfigDomain::Security,
        key: "policy_bundle",
        value_kind: ConfigValueKind::String,
        required: true,
        data_class: DataClass::Sensitive,
        min: None,
        max: None,
        allowed: &[],
    },
    ConfigField {
        domain: ConfigDomain::Security,
        key: "allow_unsigned",
        value_kind: ConfigValueKind::Boolean,
        required: false,
        data_class: DataClass::Sensitive,
        min: None,
        max: None,
        allowed: &[],
    },
    ConfigField {
        domain: ConfigDomain::Security,
        key: "min_key_bits",
        value_kind: ConfigValueKind::Integer,
        required: false,
        data_class: DataClass::Operational,
        min: Some(128),
        max: Some(8192),
        allowed: &[],
    },
    ConfigField {
        domain: ConfigDomain::Devices,
        key: "console",
        value_kind: ConfigValueKind::Enum,
        required: true,
        data_class: DataClass::Operational,
        min: None,
        max: None,
        allowed: DEVICE_MODES,
    },
    ConfigField {
        domain: ConfigDomain::Devices,
        key: "storage",
        value_kind: ConfigValueKind::Enum,
        required: false,
        data_class: DataClass::Operational,
        min: None,
        max: None,
        allowed: STORAGE_MODES,
    },
    ConfigField {
        domain: ConfigDomain::Devices,
        key: "network",
        value_kind: ConfigValueKind::Enum,
        required: false,
        data_class: DataClass::Operational,
        min: None,
        max: None,
        allowed: DEVICE_MODES,
    },
    ConfigField {
        domain: ConfigDomain::Devices,
        key: "cognition",
        value_kind: ConfigValueKind::Enum,
        required: false,
        data_class: DataClass::Operational,
        min: None,
        max: None,
        allowed: DEVICE_MODES,
    },
    ConfigField {
        domain: ConfigDomain::Devices,
        key: "max_device_buffers",
        value_kind: ConfigValueKind::Integer,
        required: false,
        data_class: DataClass::Operational,
        min: Some(1),
        max: Some(4096),
        allowed: &[],
    },
    ConfigField {
        domain: ConfigDomain::Corpus,
        key: "root_path",
        value_kind: ConfigValueKind::String,
        required: false,
        data_class: DataClass::Sensitive,
        min: None,
        max: None,
        allowed: &[],
    },
    ConfigField {
        domain: ConfigDomain::Corpus,
        key: "label_schema",
        value_kind: ConfigValueKind::String,
        required: false,
        data_class: DataClass::Operational,
        min: None,
        max: None,
        allowed: &[],
    },
    ConfigField {
        domain: ConfigDomain::Corpus,
        key: "max_records",
        value_kind: ConfigValueKind::Integer,
        required: false,
        data_class: DataClass::Operational,
        min: Some(1),
        max: Some(10_000_000),
        allowed: &[],
    },
    ConfigField {
        domain: ConfigDomain::Corpus,
        key: "allow_synthetic",
        value_kind: ConfigValueKind::Boolean,
        required: false,
        data_class: DataClass::Operational,
        min: None,
        max: None,
        allowed: &[],
    },
    ConfigField {
        domain: ConfigDomain::Release,
        key: "channel",
        value_kind: ConfigValueKind::Enum,
        required: false,
        data_class: DataClass::Public,
        min: None,
        max: None,
        allowed: RELEASE_CHANNELS,
    },
    ConfigField {
        domain: ConfigDomain::Release,
        key: "build_id",
        value_kind: ConfigValueKind::String,
        required: false,
        data_class: DataClass::Public,
        min: None,
        max: None,
        allowed: &[],
    },
    ConfigField {
        domain: ConfigDomain::Release,
        key: "sbom_path",
        value_kind: ConfigValueKind::String,
        required: false,
        data_class: DataClass::Operational,
        min: None,
        max: None,
        allowed: &[],
    },
    ConfigField {
        domain: ConfigDomain::Release,
        key: "evidence_required",
        value_kind: ConfigValueKind::Boolean,
        required: false,
        data_class: DataClass::Operational,
        min: None,
        max: None,
        allowed: &[],
    },
    ConfigField {
        domain: ConfigDomain::Release,
        key: "signing_required",
        value_kind: ConfigValueKind::Boolean,
        required: false,
        data_class: DataClass::Sensitive,
        min: None,
        max: None,
        allowed: &[],
    },
];
