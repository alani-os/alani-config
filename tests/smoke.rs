use alani_config::{
    config_catalog, parse_config_profile, BuiltinSchema, ComponentStatus, ConfigDomain,
    ConfigError, ConfigLoader, ConfigManager, ConfigProfile, ConfigRecord, ConfigValue,
    ConfigValueKind, DataClass, LoaderConfig, LoaderMode, ProfileMode, ValidationCode,
    CONFIG_SCHEMA_VERSION, HOST_CONFIG,
};

const VALID_CONFIG: &str = r#"
[profile]
name = "mvk.test"
version = "0.1.0"
mode = "host"
target = "x86_64-uefi"

[environment]
name = "test"
mode = "host"
target = "x86_64-uefi"
log_level = "debug"
host_mocks = true

[boot]
kernel_path = "/boot/alani-kernel"
init_profile = "mvk.test"
command_line = "console=ttyS0"
memory_limit_bytes = 268435456
require_measurements = false

[runtime]
max_processes = 64
max_agents = 8
default_priority = 128
enable_mock_cognition = true
supervision_tick_ms = 5

[security]
secure_boot = false
audit_required = true
policy_bundle = "/etc/alani/policy.mvk"
allow_unsigned = true
min_key_bits = 128

[devices]
console = "mock"
storage = "memory"
network = "disabled"
cognition = "mock"
max_device_buffers = 32

[release]
channel = "dev"
build_id = "test"
evidence_required = false
signing_required = false
"#;

#[test]
fn repository_identity_is_stable() {
    assert_eq!(alani_config::repository_name(), "alani-config");
    assert_eq!(
        alani_config::component_info().status,
        ComponentStatus::Experimental
    );
    assert_eq!(
        alani_config::module_names(),
        &["error", "loader", "profiles", "schema", "validation"]
    );

    let catalog = config_catalog();
    assert_eq!(catalog.schema_version, CONFIG_SCHEMA_VERSION);
    assert_eq!(
        catalog.builtin_field_count,
        alani_config::BUILTIN_FIELD_COUNT
    );
    assert_eq!(catalog.validate(), Ok(()));
}

#[test]
fn builtin_schema_declares_domains_types_and_redaction() {
    let field = BuiltinSchema::field(ConfigDomain::Runtime, "max_processes").unwrap();
    assert_eq!(field.value_kind, ConfigValueKind::Integer);
    assert!(field.required);
    assert_eq!(field.min, Some(1));

    let policy_bundle = BuiltinSchema::field(ConfigDomain::Security, "policy_bundle").unwrap();
    assert_eq!(policy_bundle.data_class, DataClass::Sensitive);
    assert!(policy_bundle.requires_redaction());

    assert!(ConfigDomain::from_label("environment").is_some());
    assert_eq!(ConfigDomain::Release.label(), "release");
    assert!(ConfigDomain::Security.is_audit_relevant());
    assert!(!ConfigDomain::Environment.is_audit_relevant());
}

#[test]
fn loader_parses_toml_like_profile_and_typed_values() {
    let profile = parse_config_profile(VALID_CONFIG).unwrap();

    assert_eq!(profile.name, "mvk.test");
    assert_eq!(profile.mode, ProfileMode::Host);
    assert_eq!(profile.target, "x86_64-uefi");
    assert_eq!(
        profile.get_str(ConfigDomain::Environment, "name").unwrap(),
        "test"
    );
    assert_eq!(
        profile
            .get_u64(ConfigDomain::Runtime, "max_processes")
            .unwrap(),
        64
    );
    assert!(profile
        .get_bool(ConfigDomain::Runtime, "enable_mock_cognition")
        .unwrap());
    assert_eq!(
        profile
            .get(ConfigDomain::Boot, "command_line")
            .unwrap()
            .source_line,
        18
    );

    let runtime_keys: Vec<&str> = profile
        .records_for_domain(ConfigDomain::Runtime)
        .map(|record| record.key)
        .collect();
    assert!(runtime_keys.contains(&"max_processes"));
    assert_eq!(
        profile
            .audit_relevant_records()
            .filter(|record| record.domain == ConfigDomain::Security)
            .count(),
        5
    );
}

#[test]
fn loader_rejects_unknown_sections_keys_types_and_missing_required() {
    let unknown_section = "[profile]\nname=\"x\"\nversion=\"1\"\nmode=\"host\"\ntarget=\"t\"\n[unknown]\nkey = true\n";
    assert_eq!(
        parse_config_profile(unknown_section).unwrap_err(),
        ConfigError::UnknownSection
    );

    let unknown_key = VALID_CONFIG.replace("max_agents = 8", "unknown_key = 8");
    assert_eq!(
        parse_config_profile(&unknown_key).unwrap_err(),
        ConfigError::UnknownKey
    );

    let type_mismatch = VALID_CONFIG.replace("max_processes = 64", "max_processes = true");
    assert_eq!(
        parse_config_profile(&type_mismatch).unwrap_err(),
        ConfigError::TypeMismatch
    );

    let missing_required = VALID_CONFIG.replace("kernel_path = \"/boot/alani-kernel\"\n", "");
    assert_eq!(
        parse_config_profile(&missing_required).unwrap_err(),
        ConfigError::MissingField
    );
}

#[test]
fn permissive_loader_retains_unknown_records_for_validation_reports() {
    let text = r#"
[profile]
name = "mvk.permissive"
version = "0.1.0"
mode = "host"
target = "x86_64-uefi"
[environment]
name = "host"
mode = "host"
target = "x86_64-uefi"
[boot]
kernel_path = "/boot/alani-kernel"
init_profile = "mvk.permissive"
[runtime]
max_processes = 16
max_agents = 2
mystery = "kept"
[security]
secure_boot = false
audit_required = true
policy_bundle = "/policy"
[devices]
console = "mock"
"#;
    let loader = ConfigLoader::with_config(LoaderConfig {
        max_config_len: 4096,
        mode: LoaderMode::Permissive,
    });
    let profile = loader.parse(text).unwrap();
    assert_eq!(
        profile.get(ConfigDomain::Runtime, "mystery").unwrap().value,
        ConfigValue::String("kept")
    );
    let report = alani_config::ConfigValidator::new().validate(&profile);
    assert!(!report.is_ok());
    assert_eq!(
        report.first_error().unwrap().code,
        ValidationCode::UnknownKey
    );
}

#[test]
fn profile_rejects_duplicate_records_and_supports_manual_records() {
    let mut profile =
        ConfigProfile::new("manual", "0.1.0", ProfileMode::Host, "x86_64-uefi").unwrap();
    profile
        .push_record(
            ConfigRecord::new(
                ConfigDomain::Runtime,
                "max_processes",
                ConfigValue::Integer(8),
                1,
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(
        profile
            .push_integer(ConfigDomain::Runtime, "max_processes", 16, 2)
            .unwrap_err(),
        ConfigError::Duplicate
    );
    assert_eq!(
        profile
            .get_u64(ConfigDomain::Runtime, "max_processes")
            .unwrap(),
        8
    );
}

#[test]
fn validator_enforces_hardware_fail_closed_rules() {
    let hardware = VALID_CONFIG
        .replace("mode = \"host\"", "mode = \"hardware\"")
        .replace("secure_boot = false", "secure_boot = true")
        .replace("allow_unsigned = true", "allow_unsigned = false")
        .replace("signing_required = false", "signing_required = true");
    let profile = parse_config_profile(&hardware).unwrap();
    assert!(alani_config::ConfigValidator::new()
        .validate(&profile)
        .is_ok());

    let insecure = hardware.replace("allow_unsigned = false", "allow_unsigned = true");
    assert_eq!(
        parse_config_profile(&insecure).unwrap_err(),
        ConfigError::SecurityViolation
    );
}

#[test]
fn manager_loads_installs_and_serves_active_values() {
    let mut manager = ConfigManager::new();
    manager.load_and_install(VALID_CONFIG).unwrap();

    assert_eq!(manager.phase().label(), "active");
    assert_eq!(
        manager
            .get_str(ConfigDomain::Security, "policy_bundle")
            .unwrap(),
        "/etc/alani/policy.mvk"
    );
    assert_eq!(
        manager
            .get_u64(ConfigDomain::Devices, "max_device_buffers")
            .unwrap(),
        32
    );
    assert!(!manager
        .get_bool(ConfigDomain::Boot, "require_measurements")
        .unwrap());

    let mut defaults = ConfigManager::new();
    defaults.load_host_defaults().unwrap();
    assert_eq!(
        defaults
            .active_profile()
            .unwrap()
            .get_str(ConfigDomain::Environment, "name")
            .unwrap(),
        "host"
    );
    assert!(HOST_CONFIG.contains("[runtime]"));
}
