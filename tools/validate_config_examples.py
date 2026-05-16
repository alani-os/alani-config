#!/usr/bin/env python3
"""Validate checked-in config TOML examples against the local schema metadata."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "config-profile.schema.json"
EXAMPLE_DIR = ROOT / "examples"
MAX_PROFILE_NAME_LEN = 64
MAX_PROFILE_VERSION_LEN = 32


def strip_comment(line: str) -> str:
    quoted = False
    for index, char in enumerate(line):
        if char == '"':
            quoted = not quoted
        if char == "#" and not quoted:
            return line[:index]
    return line


def parse_value(raw: str) -> Any:
    value = raw.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        inner = value[1:-1]
        if '"' in inner:
            raise ValueError("invalid quote in string")
        return inner
    if value == "true":
        return True
    if value == "false":
        return False
    if value.lower().startswith("0x"):
        return int(value[2:], 16)
    if value.isdecimal():
        return int(value, 10)
    if not value:
        raise ValueError("empty scalar")
    return value


def parse_profile(path: Path) -> tuple[dict[str, str], dict[tuple[str, str], Any]]:
    profile: dict[str, str] = {}
    records: dict[tuple[str, str], Any] = {}
    section: str | None = None

    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = strip_comment(raw_line).strip()
        if not line:
            continue
        if line.startswith("["):
            if not line.endswith("]") or len(line) < 3:
                raise ValueError(f"{path.name}:{line_number}: invalid section")
            section = line[1:-1].strip()
            if not section:
                raise ValueError(f"{path.name}:{line_number}: empty section")
            continue
        if "=" not in line:
            raise ValueError(f"{path.name}:{line_number}: expected key = value")
        if section is None:
            raise ValueError(f"{path.name}:{line_number}: key outside a section")
        key, raw_value = (part.strip() for part in line.split("=", 1))
        if not key:
            raise ValueError(f"{path.name}:{line_number}: empty key")
        value = parse_value(raw_value)
        if section == "profile":
            if key not in {"name", "version", "mode", "target"}:
                raise ValueError(f"{path.name}:{line_number}: unknown profile key {key!r}")
            profile[key] = str(value)
            continue
        record_key = (section, key)
        if record_key in records:
            raise ValueError(f"{path.name}:{line_number}: duplicate {section}.{key}")
        records[record_key] = value

    return profile, records


def validate_profile_identity(
    profile: dict[str, str], modes: set[str], path: Path, errors: list[str]
) -> None:
    for key in ("name", "version", "mode", "target"):
        if not profile.get(key):
            errors.append(f"{path.name}: missing profile.{key}")
    name = profile.get("name", "")
    if len(name) > MAX_PROFILE_NAME_LEN or not all(
        char.isalnum() or char in ".-_" for char in name
    ):
        errors.append(f"{path.name}: invalid profile.name")
    version = profile.get("version", "")
    if len(version) > MAX_PROFILE_VERSION_LEN:
        errors.append(f"{path.name}: invalid profile.version")
    mode = profile.get("mode")
    if mode and mode not in modes:
        errors.append(f"{path.name}: unsupported profile.mode {mode!r}")


def validate_record(
    path: Path,
    field: dict[str, Any],
    value: Any,
    errors: list[str],
) -> None:
    label = f"{path.name}:{field['domain']}.{field['key']}"
    kind = field["kind"]
    if kind in {"string", "enum"}:
        if not isinstance(value, str) or not value:
            errors.append(f"{label}: expected non-empty string")
            return
        allowed = field.get("allowed")
        if allowed and value not in allowed:
            errors.append(f"{label}: unsupported value {value!r}")
    elif kind == "integer":
        if not isinstance(value, int) or isinstance(value, bool):
            errors.append(f"{label}: expected integer")
            return
        if "min" in field and value < field["min"]:
            errors.append(f"{label}: value below {field['min']}")
        if "max" in field and value > field["max"]:
            errors.append(f"{label}: value above {field['max']}")
    elif kind == "boolean":
        if not isinstance(value, bool):
            errors.append(f"{label}: expected boolean")
    else:
        errors.append(f"{label}: unknown kind {kind!r}")


def validate_hardware_rules(
    profile: dict[str, str], records: dict[tuple[str, str], Any], path: Path, errors: list[str]
) -> None:
    if profile.get("mode") != "hardware":
        return
    if records.get(("security", "secure_boot")) is not True:
        errors.append(f"{path.name}: hardware profile requires security.secure_boot = true")
    if records.get(("security", "allow_unsigned")) is True:
        errors.append(f"{path.name}: hardware profile disallows security.allow_unsigned = true")
    if records.get(("release", "signing_required")) is False:
        errors.append(f"{path.name}: hardware profile requires release.signing_required = true")


def main() -> int:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    fields = {
        (field["domain"], field["key"]): field for field in schema.get("x-alani-fields", [])
    }
    modes = set(schema.get("x-alani-profile-modes", []))
    if schema.get("x-alani-schema-version") != "alani.config.v1" or not fields:
        print("invalid config schema metadata", file=sys.stderr)
        return 1

    examples = sorted(EXAMPLE_DIR.glob("*.toml"))
    if not examples:
        print("no config TOML examples found", file=sys.stderr)
        return 1

    errors: list[str] = []
    for example in examples:
        try:
            profile, records = parse_profile(example)
        except ValueError as error:
            errors.append(str(error))
            continue

        validate_profile_identity(profile, modes, example, errors)
        for key in records:
            if key not in fields:
                errors.append(f"{example.name}:{key[0]}.{key[1]}: unknown key")
        for key, field in fields.items():
            if field.get("required") and key not in records:
                errors.append(f"{example.name}:{key[0]}.{key[1]}: missing required field")
            if key in records:
                validate_record(example, field, records[key], errors)
        validate_hardware_rules(profile, records, example, errors)

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    print(f"validated {len(examples)} config example(s) against {SCHEMA_PATH.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
