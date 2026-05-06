//! Configuration validation reports and strict validation helpers.
//!
//! Validation checks schema membership, required fields, scalar types, ranges,
//! enum values, and fail-closed security rules for hardware profiles.

use crate::error::{ConfigError, ConfigResult};
use crate::profiles::{ConfigProfile, ProfileMode};
use crate::schema::{BuiltinSchema, ConfigDomain};

/// Maximum validation issues retained by a report.
pub const MAX_VALIDATION_ISSUES: usize = 64;

/// Validation issue severity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationSeverity {
    /// Informational note.
    Info,
    /// Warning that does not make the profile invalid.
    Warning,
    /// Error that makes the profile invalid.
    Error,
}

/// Validation issue code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationCode {
    /// Profile identity is incomplete.
    MissingIdentity,
    /// Required schema field is missing.
    MissingRequired,
    /// Key is unknown to the active schema.
    UnknownKey,
    /// Value type does not match the schema field.
    TypeMismatch,
    /// Value failed enum, range, or non-empty checks.
    InvalidValue,
    /// Duplicate key was supplied.
    DuplicateKey,
    /// Security-sensitive profile failed closed.
    SecurityViolation,
}

impl ValidationCode {
    /// Maps the validation code to a config error.
    pub const fn error(self) -> ConfigError {
        match self {
            Self::MissingIdentity | Self::MissingRequired => ConfigError::MissingField,
            Self::UnknownKey => ConfigError::UnknownKey,
            Self::TypeMismatch => ConfigError::TypeMismatch,
            Self::InvalidValue => ConfigError::InvalidValue,
            Self::DuplicateKey => ConfigError::Duplicate,
            Self::SecurityViolation => ConfigError::SecurityViolation,
        }
    }
}

/// One validation issue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidationIssue {
    /// Issue severity.
    pub severity: ValidationSeverity,
    /// Issue code.
    pub code: ValidationCode,
    /// Configuration domain associated with the issue.
    pub domain: Option<ConfigDomain>,
    /// Field key associated with the issue.
    pub key: &'static str,
    /// Stable reason label.
    pub reason: &'static str,
}

impl ValidationIssue {
    /// Empty issue used by fixed-array initialization.
    pub const EMPTY: Self = Self {
        severity: ValidationSeverity::Info,
        code: ValidationCode::MissingIdentity,
        domain: None,
        key: "",
        reason: "",
    };
}

/// Fixed-capacity validation report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationReport {
    issues: [ValidationIssue; MAX_VALIDATION_ISSUES],
    len: usize,
}

impl ValidationReport {
    /// Creates an empty validation report.
    pub const fn new() -> Self {
        Self {
            issues: [ValidationIssue::EMPTY; MAX_VALIDATION_ISSUES],
            len: 0,
        }
    }

    /// Number of retained issues.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` when there are no retained issues.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns `true` when no error-severity issue is present.
    pub fn is_ok(&self) -> bool {
        !self
            .issues()
            .iter()
            .any(|issue| issue.severity == ValidationSeverity::Error)
    }

    /// Returns the first error-severity issue.
    pub fn first_error(&self) -> Option<ValidationIssue> {
        self.issues()
            .iter()
            .copied()
            .find(|issue| issue.severity == ValidationSeverity::Error)
    }

    /// Returns retained issues.
    pub fn issues(&self) -> &[ValidationIssue] {
        &self.issues[..self.len]
    }

    /// Adds an issue to the report.
    pub fn push(&mut self, issue: ValidationIssue) -> ConfigResult<()> {
        if self.len == MAX_VALIDATION_ISSUES {
            return Err(ConfigError::CapacityExceeded);
        }
        self.issues[self.len] = issue;
        self.len += 1;
        Ok(())
    }
}

impl Default for ValidationReport {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration validator using the built-in schema table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigValidator;

impl ConfigValidator {
    /// Creates a validator.
    pub const fn new() -> Self {
        Self
    }

    /// Validates a profile and returns a report.
    pub fn validate(&self, profile: &ConfigProfile<'_>) -> ValidationReport {
        let mut report = ValidationReport::new();
        if profile.validate_identity().is_err() {
            push_lossy(
                &mut report,
                ValidationIssue {
                    severity: ValidationSeverity::Error,
                    code: ValidationCode::MissingIdentity,
                    domain: None,
                    key: "profile",
                    reason: "missing_profile_identity",
                },
            );
        }

        for record in profile.records() {
            match BuiltinSchema::field(record.domain, record.key) {
                Some(field) => match field.validate_value(*record) {
                    Ok(()) => {}
                    Err(ConfigError::TypeMismatch) => push_lossy(
                        &mut report,
                        ValidationIssue {
                            severity: ValidationSeverity::Error,
                            code: ValidationCode::TypeMismatch,
                            domain: Some(record.domain),
                            key: field.key,
                            reason: "type_mismatch",
                        },
                    ),
                    Err(_) => push_lossy(
                        &mut report,
                        ValidationIssue {
                            severity: ValidationSeverity::Error,
                            code: ValidationCode::InvalidValue,
                            domain: Some(record.domain),
                            key: field.key,
                            reason: "invalid_value",
                        },
                    ),
                },
                None => push_lossy(
                    &mut report,
                    ValidationIssue {
                        severity: ValidationSeverity::Error,
                        code: ValidationCode::UnknownKey,
                        domain: Some(record.domain),
                        key: "",
                        reason: "unknown_key",
                    },
                ),
            }
        }

        for field in BuiltinSchema::fields() {
            if field.required && profile.get(field.domain, field.key).is_none() {
                push_lossy(
                    &mut report,
                    ValidationIssue {
                        severity: ValidationSeverity::Error,
                        code: ValidationCode::MissingRequired,
                        domain: Some(field.domain),
                        key: field.key,
                        reason: "missing_required",
                    },
                );
            }
        }

        self.validate_security_policy(profile, &mut report);
        report
    }

    /// Validates a profile and returns the first error as a [`ConfigError`].
    pub fn validate_strict(&self, profile: &ConfigProfile<'_>) -> ConfigResult<()> {
        let report = self.validate(profile);
        if let Some(issue) = report.first_error() {
            Err(issue.code.error())
        } else {
            Ok(())
        }
    }

    fn validate_security_policy(&self, profile: &ConfigProfile<'_>, report: &mut ValidationReport) {
        if profile.mode == ProfileMode::Hardware {
            if profile
                .get_bool(ConfigDomain::Security, "secure_boot")
                .is_ok_and(|enabled| !enabled)
            {
                push_lossy(
                    report,
                    ValidationIssue {
                        severity: ValidationSeverity::Error,
                        code: ValidationCode::SecurityViolation,
                        domain: Some(ConfigDomain::Security),
                        key: "secure_boot",
                        reason: "hardware_requires_secure_boot",
                    },
                );
            }
            if profile
                .get_bool(ConfigDomain::Security, "allow_unsigned")
                .is_ok_and(|enabled| enabled)
            {
                push_lossy(
                    report,
                    ValidationIssue {
                        severity: ValidationSeverity::Error,
                        code: ValidationCode::SecurityViolation,
                        domain: Some(ConfigDomain::Security),
                        key: "allow_unsigned",
                        reason: "hardware_disallows_unsigned",
                    },
                );
            }
            if profile
                .get_bool(ConfigDomain::Release, "signing_required")
                .is_ok_and(|enabled| !enabled)
            {
                push_lossy(
                    report,
                    ValidationIssue {
                        severity: ValidationSeverity::Error,
                        code: ValidationCode::SecurityViolation,
                        domain: Some(ConfigDomain::Release),
                        key: "signing_required",
                        reason: "hardware_requires_signing",
                    },
                );
            }
        }
    }
}

impl Default for ConfigValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Descriptor for the validation component itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationDescriptor<'a> {
    /// Component name.
    pub name: &'a str,
    /// Component version marker.
    pub version: u32,
}

impl<'a> ValidationDescriptor<'a> {
    /// Creates a validation component descriptor.
    pub const fn new(name: &'a str, version: u32) -> Self {
        Self { name, version }
    }
}

fn push_lossy(report: &mut ValidationReport, issue: ValidationIssue) {
    let _ = report.push(issue);
}
