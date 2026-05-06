//! Configuration status and typed error mapping.
//!
//! The config crate keeps rich Rust errors while preserving a compact status
//! vocabulary suitable for future protocol and release evidence contracts.

/// Stable status values exposed by configuration APIs.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigStatus {
    /// Operation completed successfully.
    Ok = 0,
    /// The caller supplied malformed or out-of-range input.
    InvalidArgument = 1,
    /// The caller is not authorized to read or apply the requested config.
    PermissionDenied = 2,
    /// The requested schema, profile, or key does not exist.
    NotFound = 3,
    /// A bounded registry or report has no free capacity.
    Busy = 4,
    /// A required value or validation deadline was not satisfied.
    DeadlineExceeded = 5,
    /// An internal invariant failed.
    Internal = 0xffff_ffff,
}

impl ConfigStatus {
    /// Converts a raw status value into a known config status.
    pub const fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            0 => Some(Self::Ok),
            1 => Some(Self::InvalidArgument),
            2 => Some(Self::PermissionDenied),
            3 => Some(Self::NotFound),
            4 => Some(Self::Busy),
            5 => Some(Self::DeadlineExceeded),
            0xffff_ffff => Some(Self::Internal),
            _ => None,
        }
    }

    /// Returns `true` when this status represents success.
    pub const fn is_ok(self) -> bool {
        matches!(self, Self::Ok)
    }
}

/// Configuration error taxonomy used by parser, schema, profile, and validator APIs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    /// A general argument validation check failed.
    InvalidArgument,
    /// A configuration document failed structural parsing.
    InvalidDocument,
    /// A required profile, schema, or key field was absent.
    MissingField,
    /// A section/domain label is not recognized.
    UnknownSection,
    /// A configuration key is not part of the active schema.
    UnknownKey,
    /// A scalar value could not be parsed.
    InvalidValue,
    /// A number could not be parsed or exceeded supported range.
    InvalidNumber,
    /// A boolean value could not be parsed.
    InvalidBoolean,
    /// A value type did not match its schema field.
    TypeMismatch,
    /// A reserved bit or schema field was set.
    ReservedBits,
    /// A fixed-capacity profile, schema, or report table is full.
    CapacityExceeded,
    /// The caller is not authorized for the requested config action.
    PermissionDenied,
    /// The requested profile, schema, section, or key was not found.
    NotFound,
    /// A schema validation rule failed.
    ValidationFailed,
    /// A security-sensitive config setting failed closed.
    SecurityViolation,
    /// A duplicate schema field, profile key, or profile name was supplied.
    Duplicate,
    /// A dependency on another schema or profile could not be satisfied.
    DependencyUnsatisfied,
    /// The operation is intentionally not available in this skeleton.
    Unsupported,
    /// An internal invariant failed.
    Internal,
}

impl ConfigError {
    /// Maps the internal error to a stable status code.
    pub const fn status(self) -> ConfigStatus {
        match self {
            Self::InvalidArgument
            | Self::InvalidDocument
            | Self::MissingField
            | Self::UnknownSection
            | Self::UnknownKey
            | Self::InvalidValue
            | Self::InvalidNumber
            | Self::InvalidBoolean
            | Self::TypeMismatch
            | Self::ReservedBits
            | Self::ValidationFailed
            | Self::Duplicate
            | Self::DependencyUnsatisfied => ConfigStatus::InvalidArgument,
            Self::PermissionDenied | Self::SecurityViolation => ConfigStatus::PermissionDenied,
            Self::NotFound => ConfigStatus::NotFound,
            Self::CapacityExceeded => ConfigStatus::Busy,
            Self::Unsupported | Self::Internal => ConfigStatus::Internal,
        }
    }

    /// Short stable reason label for diagnostics, audit, and tests.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::InvalidArgument => "invalid_argument",
            Self::InvalidDocument => "invalid_document",
            Self::MissingField => "missing_field",
            Self::UnknownSection => "unknown_section",
            Self::UnknownKey => "unknown_key",
            Self::InvalidValue => "invalid_value",
            Self::InvalidNumber => "invalid_number",
            Self::InvalidBoolean => "invalid_boolean",
            Self::TypeMismatch => "type_mismatch",
            Self::ReservedBits => "reserved_bits",
            Self::CapacityExceeded => "capacity_exceeded",
            Self::PermissionDenied => "permission_denied",
            Self::NotFound => "not_found",
            Self::ValidationFailed => "validation_failed",
            Self::SecurityViolation => "security_violation",
            Self::Duplicate => "duplicate",
            Self::DependencyUnsatisfied => "dependency_unsatisfied",
            Self::Unsupported => "unsupported",
            Self::Internal => "internal",
        }
    }
}

impl From<ConfigError> for ConfigStatus {
    fn from(error: ConfigError) -> Self {
        error.status()
    }
}

/// Result alias used by configuration APIs.
pub type ConfigResult<T> = Result<T, ConfigError>;
