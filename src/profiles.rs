//! Configuration profile storage and typed accessors.
//!
//! A profile is a bounded, borrowed collection of typed configuration records.
//! It can be created by the loader or by tests without heap allocation.

use crate::error::{ConfigError, ConfigResult};
use crate::schema::{ConfigDomain, ConfigRecord, ConfigValue};

/// Maximum records retained by a configuration profile.
pub const MAX_CONFIG_RECORDS: usize = 96;

/// Maximum profile name length accepted by validation.
pub const MAX_PROFILE_NAME_LEN: usize = 64;

/// Maximum profile version length accepted by validation.
pub const MAX_PROFILE_VERSION_LEN: usize = 32;

/// Profile operating mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileMode {
    /// Host-mode profile for tests and simulation.
    Host,
    /// Emulator profile.
    Emulator,
    /// Hardware target profile.
    Hardware,
}

impl ProfileMode {
    /// Parses a profile mode label.
    pub const fn from_label(label: &str) -> Option<Self> {
        match label.as_bytes() {
            b"host" | b"test" => Some(Self::Host),
            b"emulator" | b"qemu" => Some(Self::Emulator),
            b"hardware" | b"bare_metal" => Some(Self::Hardware),
            _ => None,
        }
    }

    /// Stable profile label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Emulator => "emulator",
            Self::Hardware => "hardware",
        }
    }
}

/// Configuration profile parsed from a document.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigProfile<'a> {
    /// Stable profile name.
    pub name: &'a str,
    /// Profile schema version.
    pub version: &'a str,
    /// Profile operating mode.
    pub mode: ProfileMode,
    /// Target triple or platform label.
    pub target: &'a str,
    records: [ConfigRecord<'a>; MAX_CONFIG_RECORDS],
    record_count: usize,
}

impl<'a> ConfigProfile<'a> {
    /// Empty profile with conservative defaults.
    pub const fn empty() -> Self {
        Self {
            name: "",
            version: "",
            mode: ProfileMode::Host,
            target: "",
            records: [ConfigRecord::EMPTY; MAX_CONFIG_RECORDS],
            record_count: 0,
        }
    }

    /// Creates a profile identity without records.
    pub fn new(
        name: &'a str,
        version: &'a str,
        mode: ProfileMode,
        target: &'a str,
    ) -> ConfigResult<Self> {
        let profile = Self {
            name,
            version,
            mode,
            target,
            records: [ConfigRecord::EMPTY; MAX_CONFIG_RECORDS],
            record_count: 0,
        };
        profile.validate_identity()?;
        Ok(profile)
    }

    /// Number of retained records.
    pub const fn record_count(&self) -> usize {
        self.record_count
    }

    /// Returns `true` when no records are retained.
    pub const fn is_empty(&self) -> bool {
        self.record_count == 0
    }

    /// Returns retained records.
    pub fn records(&self) -> &[ConfigRecord<'a>] {
        &self.records[..self.record_count]
    }

    /// Iterates over records in one configuration domain.
    pub fn records_for_domain(
        &self,
        domain: ConfigDomain,
    ) -> impl Iterator<Item = &ConfigRecord<'a>> {
        self.records()
            .iter()
            .filter(move |record| record.domain == domain)
    }

    /// Iterates over records whose domains should produce audit evidence on change.
    pub fn audit_relevant_records(&self) -> impl Iterator<Item = &ConfigRecord<'a>> {
        self.records()
            .iter()
            .filter(|record| record.domain.is_audit_relevant())
    }

    /// Adds a typed record, rejecting duplicate domain/key pairs.
    pub fn push_record(&mut self, record: ConfigRecord<'a>) -> ConfigResult<()> {
        if self.get(record.domain, record.key).is_some() {
            return Err(ConfigError::Duplicate);
        }
        if self.record_count == MAX_CONFIG_RECORDS {
            return Err(ConfigError::CapacityExceeded);
        }
        self.records[self.record_count] = record;
        self.record_count += 1;
        Ok(())
    }

    /// Adds a string record.
    pub fn push_string(
        &mut self,
        domain: ConfigDomain,
        key: &'a str,
        value: &'a str,
        source_line: u32,
    ) -> ConfigResult<()> {
        self.push_record(ConfigRecord::new(
            domain,
            key,
            ConfigValue::String(value),
            source_line,
        )?)
    }

    /// Adds an integer record.
    pub fn push_integer(
        &mut self,
        domain: ConfigDomain,
        key: &'a str,
        value: u64,
        source_line: u32,
    ) -> ConfigResult<()> {
        self.push_record(ConfigRecord::new(
            domain,
            key,
            ConfigValue::Integer(value),
            source_line,
        )?)
    }

    /// Adds a boolean record.
    pub fn push_bool(
        &mut self,
        domain: ConfigDomain,
        key: &'a str,
        value: bool,
        source_line: u32,
    ) -> ConfigResult<()> {
        self.push_record(ConfigRecord::new(
            domain,
            key,
            ConfigValue::Boolean(value),
            source_line,
        )?)
    }

    /// Returns a record by domain and key.
    pub fn get(&self, domain: ConfigDomain, key: &str) -> Option<ConfigRecord<'a>> {
        for record in self.records() {
            if record.domain == domain && record.key == key {
                return Some(*record);
            }
        }
        None
    }

    /// Returns a string value by domain and key.
    pub fn get_str(&self, domain: ConfigDomain, key: &str) -> ConfigResult<&'a str> {
        self.get(domain, key)
            .ok_or(ConfigError::NotFound)?
            .value
            .as_str()
            .ok_or(ConfigError::TypeMismatch)
    }

    /// Returns an integer value by domain and key.
    pub fn get_u64(&self, domain: ConfigDomain, key: &str) -> ConfigResult<u64> {
        self.get(domain, key)
            .ok_or(ConfigError::NotFound)?
            .value
            .as_u64()
            .ok_or(ConfigError::TypeMismatch)
    }

    /// Returns a boolean value by domain and key.
    pub fn get_bool(&self, domain: ConfigDomain, key: &str) -> ConfigResult<bool> {
        self.get(domain, key)
            .ok_or(ConfigError::NotFound)?
            .value
            .as_bool()
            .ok_or(ConfigError::TypeMismatch)
    }

    /// Validates profile identity fields.
    pub fn validate_identity(self) -> ConfigResult<()> {
        validate_profile_name(self.name)?;
        if self.version.is_empty() || self.version.len() > MAX_PROFILE_VERSION_LEN {
            return Err(ConfigError::MissingField);
        }
        if self.target.is_empty() {
            return Err(ConfigError::MissingField);
        }
        Ok(())
    }
}

/// Descriptor for the profiles component itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfilesDescriptor<'a> {
    /// Component name.
    pub name: &'a str,
    /// Component version marker.
    pub version: u32,
}

impl<'a> ProfilesDescriptor<'a> {
    /// Creates a profiles component descriptor.
    pub const fn new(name: &'a str, version: u32) -> Self {
        Self { name, version }
    }
}

fn validate_profile_name(name: &str) -> ConfigResult<()> {
    if name.is_empty() || name.len() > MAX_PROFILE_NAME_LEN {
        return Err(ConfigError::MissingField);
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(ConfigError::InvalidArgument);
    }
    Ok(())
}
