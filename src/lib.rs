#![cfg_attr(not(feature = "std"), no_std)]

//! Typed configuration schemas and host-mode loaders for the Alani MVK.
//!
//! This crate remains dependency-free while `alani-protocol` stabilizes. It
//! owns configuration domains, schema metadata, profile storage, TOML-like
//! parsing, validation reports, and a small configuration manager facade.

pub mod error;
pub mod loader;
pub mod profiles;
pub mod schema;
pub mod validation;

pub use error::{ConfigError, ConfigResult, ConfigStatus};
pub use loader::{
    parse_config_profile, ConfigLoader, LoaderConfig, LoaderDescriptor, LoaderMode,
    DEFAULT_MAX_CONFIG_LEN, HOST_CONFIG,
};
pub use profiles::{
    ConfigProfile, ProfileMode, ProfilesDescriptor, MAX_CONFIG_RECORDS, MAX_PROFILE_NAME_LEN,
    MAX_PROFILE_VERSION_LEN,
};
pub use schema::{
    BuiltinSchema, ConfigDomain, ConfigField, ConfigRecord, ConfigValue, ConfigValueKind,
    DataClass, SchemaDescriptor, BUILTIN_FIELDS, BUILTIN_FIELD_COUNT, CONFIG_SCHEMA_VERSION,
    MAX_CONFIG_KEY_LEN,
};
pub use validation::{
    ConfigValidator, ValidationCode, ValidationDescriptor, ValidationIssue, ValidationReport,
    ValidationSeverity, MAX_VALIDATION_ISSUES,
};

/// Repository name.
pub const REPOSITORY: &str = "alani-config";

/// Crate version.
pub const VERSION: &str = "0.1.0";

/// Public module names exposed by this skeleton.
pub const MODULES: &[&str] = &["error", "loader", "profiles", "schema", "validation"];

/// Compact root view of the config crate contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigCatalog {
    /// Repository name.
    pub repository: &'static str,
    /// Crate version.
    pub version: &'static str,
    /// Config document schema version.
    pub schema_version: &'static str,
    /// Built-in schema field count.
    pub builtin_field_count: usize,
    /// Maximum records accepted by one profile.
    pub max_records: usize,
    /// Default maximum configuration document length.
    pub default_max_config_len: usize,
}

impl ConfigCatalog {
    /// Current config catalog.
    pub const CURRENT: Self = Self {
        repository: REPOSITORY,
        version: VERSION,
        schema_version: CONFIG_SCHEMA_VERSION,
        builtin_field_count: BUILTIN_FIELD_COUNT,
        max_records: MAX_CONFIG_RECORDS,
        default_max_config_len: DEFAULT_MAX_CONFIG_LEN,
    };

    /// Returns the current catalog.
    pub const fn current() -> Self {
        Self::CURRENT
    }

    /// Validates catalog metadata.
    pub const fn validate(self) -> ConfigResult<()> {
        if self.repository.is_empty() || self.version.is_empty() || self.schema_version.is_empty() {
            return Err(ConfigError::MissingField);
        }
        if self.builtin_field_count == 0
            || self.max_records == 0
            || self.default_max_config_len == 0
        {
            return Err(ConfigError::InvalidArgument);
        }
        Ok(())
    }
}

/// Current config catalog.
pub const CONFIG_CATALOG: ConfigCatalog = ConfigCatalog::CURRENT;

/// Returns the current config catalog.
pub const fn config_catalog() -> ConfigCatalog {
    ConfigCatalog::CURRENT
}

/// Implementation maturity marker for generated repository metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentStatus {
    /// API is present as a draft skeleton.
    Draft,
    /// API is implemented enough for host-mode experimentation.
    Experimental,
    /// API is compatible and stable.
    Stable,
}

/// Stable component identity record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComponentInfo {
    /// Repository name.
    pub repository: &'static str,
    /// Crate version.
    pub version: &'static str,
    /// Current implementation status.
    pub status: ComponentStatus,
}

/// Returns stable component identity metadata.
pub const fn component_info() -> ComponentInfo {
    ComponentInfo {
        repository: REPOSITORY,
        version: VERSION,
        status: ComponentStatus::Experimental,
    }
}

/// Returns the repository name.
pub const fn repository_name() -> &'static str {
    REPOSITORY
}

/// Returns public module names.
pub fn module_names() -> &'static [&'static str] {
    MODULES
}

/// Configuration manager phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigPhase {
    /// Manager has no active profile.
    Empty,
    /// Profile has been parsed but not installed.
    Loaded,
    /// Profile is active and validated.
    Active,
    /// Last load or validation failed.
    Failed,
}

impl ConfigPhase {
    /// Stable phase label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Loaded => "loaded",
            Self::Active => "active",
            Self::Failed => "failed",
        }
    }
}

/// Configuration manager for host-mode tests and early integrations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigManager<'a> {
    /// Loader used for configuration documents.
    pub loader: ConfigLoader,
    /// Validator used for parsed profiles.
    pub validator: ConfigValidator,
    loaded: Option<ConfigProfile<'a>>,
    active: Option<ConfigProfile<'a>>,
    last_report: Option<ValidationReport>,
    phase: ConfigPhase,
}

impl<'a> ConfigManager<'a> {
    /// Creates a new configuration manager.
    pub const fn new() -> Self {
        Self {
            loader: ConfigLoader::new(),
            validator: ConfigValidator::new(),
            loaded: None,
            active: None,
            last_report: None,
            phase: ConfigPhase::Empty,
        }
    }

    /// Creates a manager with an explicit loader.
    pub const fn with_loader(loader: ConfigLoader) -> Self {
        Self {
            loader,
            validator: ConfigValidator::new(),
            loaded: None,
            active: None,
            last_report: None,
            phase: ConfigPhase::Empty,
        }
    }

    /// Returns the current manager phase.
    pub const fn phase(&self) -> ConfigPhase {
        self.phase
    }

    /// Returns the last validation report, if any.
    pub const fn last_report(&self) -> Option<&ValidationReport> {
        self.last_report.as_ref()
    }

    /// Parses and stores a profile as loaded.
    pub fn load(&mut self, text: &'a str) -> ConfigResult<ConfigProfile<'a>> {
        match self.loader.parse(text) {
            Ok(profile) => {
                let report = self.validator.validate(&profile);
                self.loaded = Some(profile);
                self.last_report = Some(report);
                self.phase = ConfigPhase::Loaded;
                Ok(profile)
            }
            Err(error) => {
                self.phase = ConfigPhase::Failed;
                Err(error)
            }
        }
    }

    /// Validates and installs a parsed profile as active.
    pub fn install(&mut self, profile: ConfigProfile<'a>) -> ConfigResult<()> {
        let report = self.validator.validate(&profile);
        if !report.is_ok() {
            let error = report
                .first_error()
                .map(|issue| issue.code.error())
                .unwrap_or(ConfigError::ValidationFailed);
            self.last_report = Some(report);
            self.phase = ConfigPhase::Failed;
            return Err(error);
        }
        self.active = Some(profile);
        self.loaded = Some(profile);
        self.last_report = Some(report);
        self.phase = ConfigPhase::Active;
        Ok(())
    }

    /// Parses, validates, and installs a profile as active.
    pub fn load_and_install(&mut self, text: &'a str) -> ConfigResult<()> {
        let profile = self.load(text)?;
        self.install(profile)
    }

    /// Returns the active profile.
    pub const fn active_profile(&self) -> Option<&ConfigProfile<'a>> {
        self.active.as_ref()
    }

    /// Returns an active record by domain and key.
    pub fn get(&self, domain: ConfigDomain, key: &str) -> ConfigResult<ConfigRecord<'a>> {
        self.active
            .as_ref()
            .ok_or(ConfigError::NotFound)?
            .get(domain, key)
            .ok_or(ConfigError::NotFound)
    }

    /// Returns an active string value by domain and key.
    pub fn get_str(&self, domain: ConfigDomain, key: &str) -> ConfigResult<&'a str> {
        self.active
            .as_ref()
            .ok_or(ConfigError::NotFound)?
            .get_str(domain, key)
    }

    /// Returns an active integer value by domain and key.
    pub fn get_u64(&self, domain: ConfigDomain, key: &str) -> ConfigResult<u64> {
        self.active
            .as_ref()
            .ok_or(ConfigError::NotFound)?
            .get_u64(domain, key)
    }

    /// Returns an active boolean value by domain and key.
    pub fn get_bool(&self, domain: ConfigDomain, key: &str) -> ConfigResult<bool> {
        self.active
            .as_ref()
            .ok_or(ConfigError::NotFound)?
            .get_bool(domain, key)
    }

    /// Loads and installs the built-in host-mode profile.
    pub fn load_host_defaults(&mut self) -> ConfigResult<()> {
        self.load_and_install(HOST_CONFIG)
    }
}

impl Default for ConfigManager<'_> {
    fn default() -> Self {
        Self::new()
    }
}
