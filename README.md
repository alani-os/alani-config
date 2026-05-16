# alani-config

Typed configuration schema skeleton for the Alani MVK. This crate owns configuration document schemas for boot, devices, runtime, security, corpus, release, and environment profiles.

| Field | Value |
|---|---|
| Status | Experimental MVK skeleton |
| Tier | MVK required |
| Owner | Platform and runtime teams |
| Aliases | None |
| Architectural dependencies | `alani-protocol` |

The Cargo manifest intentionally keeps sibling crates out of `[dependencies]`. `alani-protocol` remains recorded as package metadata until its schema contracts are stable enough to consume directly.

The public schema version is `alani.config.v1`. Checked examples live under `examples/`, and machine-readable field metadata lives under `schemas/`.

## Quick Start

```bash
cargo fmt -- --check
cargo test --all-features
cargo test --no-default-features
python3 tools/validate_config_examples.py
cargo clippy --all-features -- -D warnings
```

## Repository Layout

```text
src/
  error.rs       Config status and typed error mapping
  schema.rs      Domains, scalar values, data classes, built-in schema fields
  profiles.rs    Borrowed fixed-capacity config profiles and accessors
  loader.rs      TOML-like host-mode config parser
  validation.rs  Validation reports and strict security checks
  lib.rs         ConfigManager facade and public re-exports
tests/
  smoke.rs       Host-mode coverage for public config contracts
examples/
  host.toml      Valid host-mode profile fixture
schemas/
  config-profile.schema.json
tools/
  validate_config_examples.py
```

## Profile Format

The host-mode loader accepts a compact TOML-like format with `#` comments, `[section]` headers, and scalar `key = value` entries.

```toml
[profile]
name = "mvk.host"
version = "0.1.0"
mode = "host"
target = "x86_64-uefi"

[environment]
name = "host"
mode = "host"
target = "x86_64-uefi"
host_mocks = true

[runtime]
max_processes = 64
max_agents = 16
```

Strict loading rejects unknown sections, unknown keys, type mismatches, missing required fields, and hardware profiles that disable required security controls.

## Feature Flags

- `std` is enabled by default for ordinary host builds.
- `--no-default-features` builds the library as `no_std` for bare-metal-facing integration work.

## Compatibility Notes

This is not a production configuration system. It is a dependency-free public API skeleton aligned with the Alani specification bundle, especially `docs/repositories/alani-config.md`, Doc 42, Doc 43, and Doc 63. Real protocol schemas should be wired only after `alani-protocol` exposes stable public contracts.
