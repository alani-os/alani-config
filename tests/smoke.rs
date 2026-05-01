#[test]
fn repository_identity_is_stable() {
    assert_eq!(alani_config::repository_name(), "alani-config");
    assert!(!alani_config::module_names().is_empty());
}
