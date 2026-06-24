#!/usr/bin/env python3
"""Validate the small RCP data perimeter policy pack."""

from __future__ import annotations

import datetime as dt
import json
import re
import sys
from pathlib import Path
from typing import Any


Policy = dict[str, Any]
Statement = dict[str, Any]

# Repository contract
POLICY_DIR = "policies"
RCP_DIR = "resource-control-policies"
SCP_DIR = "service-control-policies"
EXCEPTION_REGISTER = "exceptions/exception-register.example.json"

# AWS Organizations limits reviewed on 2026-06-24.
RCP_SIZE_LIMIT = 5120
SCP_SIZE_LIMIT = 10240
CUSTOM_RCP_ATTACHMENTS_PER_TARGET = 4
POLICY_VERSION = "2012-10-17"

# Lightweight repository hygiene checks.
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
ACCOUNT_ID_RE = re.compile(r"(?<!\d)(\d{12})(?!\d)")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
SECRET_PATTERNS = {
    "AWS access key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "AWS secret key label": re.compile("aws" + r"_secret_access_key", re.IGNORECASE),
    "private key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
}
ALLOWED_ACCOUNT_IDS = {"123456789012"}
ALLOWED_EMAIL_DOMAINS = {"example.com", "example.org", "example.net"}
EXCEPTION_STATUSES = {"proposed", "approved", "expired", "rejected"}
EXCEPTION_TYPES = {"vendor-principal", "aws-service-integration", "break-glass"}

# RCP-supported prefixes used by this starter, reviewed against AWS Organizations
# RCP-supported services on 2026-06-24. Re-check before publication or use.
RCP_SUPPORTED_PREFIXES = {
    "dynamodb",
    "kms",
    "logs",
    "s3",
    "secretsmanager",
    "signin",
    "sqs",
}
EXPECTED_POLICY_FILES = {
    f"{POLICY_DIR}/{RCP_DIR}/01-trusted-identity-perimeter.json",
    f"{POLICY_DIR}/{RCP_DIR}/02-kms-cryptographic-boundary.json",
    f"{POLICY_DIR}/{RCP_DIR}/03-aws-service-confused-deputy-boundary.json",
    f"{POLICY_DIR}/{RCP_DIR}/04-s3-transport-boundary.json",
    f"{POLICY_DIR}/{RCP_DIR}/05-console-signin-network-boundary.json",
    f"{POLICY_DIR}/{SCP_DIR}/kms-grant-administration-boundary.json",
}


def _load_json(path: Path, errors: list[str]) -> Any | None:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except json.JSONDecodeError as exc:
        errors.append(f"{path}: invalid JSON: {exc}")
    except OSError as exc:
        errors.append(f"{path}: cannot read file: {exc}")
    return None


def _statements(path: Path, policy: Policy, errors: list[str]) -> list[Statement]:
    statement = policy.get("Statement")
    if isinstance(statement, dict):
        return [statement]
    if isinstance(statement, list):
        statements: list[Statement] = []
        for index, item in enumerate(statement, start=1):
            if isinstance(item, dict):
                statements.append(item)
            else:
                errors.append(f"{path}: Statement[{index}] must be an object")
        return statements
    return []


def _contains_key(value: Any, key: str) -> bool:
    if isinstance(value, dict):
        return key in value or any(_contains_key(child, key) for child in value.values())
    if isinstance(value, list):
        return any(_contains_key(item, key) for item in value)
    return False


def _is_bare_global_action(action: Any) -> bool:
    if action == "*":
        return True
    if isinstance(action, list):
        return any(item == "*" for item in action)
    return False


def _action_values(path: Path, sid: Any, action: Any, errors: list[str], allow_global: bool = False) -> list[str]:
    if isinstance(action, str):
        values = [action]
    elif isinstance(action, list) and action and all(isinstance(item, str) for item in action):
        values = action
    else:
        errors.append(f"{path}: {sid}: Action must be a string or non-empty list of strings")
        return []

    malformed = []
    for value in values:
        if value == "*" and allow_global:
            continue
        if ":" not in value or value.startswith(":") or value.endswith(":"):
            malformed.append(value)
    if malformed:
        errors.append(f"{path}: {sid}: malformed Action value(s): {', '.join(malformed)}")
    return [value for value in values if value not in malformed]


def _unsupported_action_prefixes(action_values: list[str]) -> list[str]:
    prefixes: set[str] = set()
    for value in action_values:
        if value == "*":
            continue
        prefix, _ = value.split(":", 1)
        if prefix not in RCP_SUPPORTED_PREFIXES:
            prefixes.add(prefix)
    return sorted(prefixes)


def _minified_size(policy: Any) -> int:
    return len(json.dumps(policy, separators=(",", ":"), ensure_ascii=False))


def _is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_non_empty_string_list(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(_is_non_empty_string(item) for item in value)


def _validate_action_shape(
    path: Path,
    sid: Any,
    statement: Statement,
    errors: list[str],
    *,
    allow_global: bool,
) -> list[str]:
    if "Action" not in statement:
        errors.append(f"{path}: {sid}: missing Action")
        return []
    if not allow_global and _is_bare_global_action(statement["Action"]):
        errors.append(f"{path}: {sid}: RCP statement must not use bare global Action \"*\"")
        return []
    return _action_values(path, sid, statement["Action"], errors, allow_global=allow_global)


def _validate_resource_shape(path: Path, sid: Any, statement: Statement, errors: list[str]) -> None:
    has_resource = "Resource" in statement
    has_not_resource = "NotResource" in statement
    if not has_resource and not has_not_resource:
        errors.append(f"{path}: {sid}: missing Resource or NotResource")
    if has_resource and has_not_resource:
        errors.append(f"{path}: {sid}: use Resource or NotResource, not both")


def _validate_sids(path: Path, statements: list[Statement], errors: list[str]) -> None:
    seen: dict[str, int] = {}
    for index, statement in enumerate(statements, start=1):
        sid = statement.get("Sid")
        if not _is_non_empty_string(sid):
            errors.append(f"{path}: statement {index}: Sid must be a non-empty string")
            continue
        if sid in seen:
            errors.append(f"{path}: duplicate Sid \"{sid}\" in statements {seen[sid]} and {index}")
        seen[sid] = index


def _policy_kind(path: Path, root: Path) -> str:
    relative = path.relative_to(root)
    if relative.parts[:2] == (POLICY_DIR, RCP_DIR):
        return "rcp"
    if relative.parts[:2] == (POLICY_DIR, SCP_DIR):
        return "scp"
    return "other"


def _validate_policy_document(path: Path, root: Path, errors: list[str]) -> tuple[str, Policy, list[Statement]] | None:
    policy = _load_json(path, errors)
    if policy is None:
        return None
    if not isinstance(policy, dict):
        errors.append(f"{path}: policy must be a JSON object")
        return None

    if "Version" not in policy:
        errors.append(f"{path}: missing Version")
    if "Statement" not in policy:
        errors.append(f"{path}: missing Statement")

    kind = _policy_kind(path, root)
    statements = _statements(path, policy, errors)

    if "Statement" in policy and not statements:
        errors.append(f"{path}: Statement must be an object or a non-empty array of objects")

    if kind == "other":
        return None

    if policy.get("Version") != POLICY_VERSION:
        errors.append(f"{path}: Version must be \"{POLICY_VERSION}\"")

    _validate_sids(path, statements, errors)
    return kind, policy, statements


def _validate_rcp_policy(path: Path, policy: Policy, statements: list[Statement], errors: list[str]) -> None:
    size = _minified_size(policy)
    if size > RCP_SIZE_LIMIT:
        errors.append(f"{path}: minified RCP size {size} exceeds {RCP_SIZE_LIMIT} characters")

    for blocked_key in ("NotAction", "NotPrincipal"):
        if _contains_key(policy, blocked_key):
            errors.append(f"{path}: RCPs must not use {blocked_key}")

    for index, statement in enumerate(statements, start=1):
        sid = statement.get("Sid", f"statement {index}")
        if statement.get("Effect") != "Deny":
            errors.append(f"{path}: {sid}: every RCP statement must use Effect Deny")
        if statement.get("Principal") != "*":
            errors.append(f"{path}: {sid}: every RCP statement must use Principal \"*\"")
        action_values = _validate_action_shape(path, sid, statement, errors, allow_global=False)
        unsupported = _unsupported_action_prefixes(action_values)
        if unsupported:
            errors.append(f"{path}: {sid}: unsupported RCP action prefix(es): {', '.join(unsupported)}")
        _validate_resource_shape(path, sid, statement, errors)


def _validate_scp_policy(path: Path, policy: Policy, statements: list[Statement], errors: list[str]) -> None:
    size = _minified_size(policy)
    if size > SCP_SIZE_LIMIT:
        errors.append(f"{path}: minified SCP size {size} exceeds {SCP_SIZE_LIMIT} characters")

    for blocked_key in ("Principal", "NotPrincipal"):
        if _contains_key(policy, blocked_key):
            errors.append(f"{path}: SCPs must not use {blocked_key}")

    for index, statement in enumerate(statements, start=1):
        sid = statement.get("Sid", f"statement {index}")
        if statement.get("Effect") not in {"Allow", "Deny"}:
            errors.append(f"{path}: {sid}: SCP Effect must be Allow or Deny")
        _validate_action_shape(path, sid, statement, errors, allow_global=True)
        _validate_resource_shape(path, sid, statement, errors)


def _validate_policy_file(path: Path, root: Path, errors: list[str]) -> None:
    document = _validate_policy_document(path, root, errors)
    if document is None:
        return
    kind, policy, statements = document
    if kind == "rcp":
        _validate_rcp_policy(path, policy, statements, errors)
    elif kind == "scp":
        _validate_scp_policy(path, policy, statements, errors)


def _validate_exceptions(path: Path, errors: list[str]) -> None:
    data = _load_json(path, errors)
    if data is None:
        return
    if not isinstance(data, dict):
        errors.append(f"{path}: exception register must be a JSON object")
        return

    records = data.get("exceptions")
    if not isinstance(records, list) or not records:
        errors.append(f"{path}: exceptions must be a non-empty array")
        return

    required = {
        "id",
        "status",
        "type",
        "owner",
        "business_reason",
        "scope",
        "related_policy_sids",
        "review_by",
        "evidence",
        "rollback_plan",
    }

    for index, record in enumerate(records, start=1):
        if not isinstance(record, dict):
            errors.append(f"{path}: exception {index}: record must be an object")
            continue
        label = record.get("id", f"exception {index}")
        missing = sorted(required - record.keys())
        if missing:
            errors.append(f"{path}: {label}: missing required fields: {', '.join(missing)}")
            continue

        if record.get("status") not in EXCEPTION_STATUSES:
            errors.append(f"{path}: {label}: status must be one of {', '.join(sorted(EXCEPTION_STATUSES))}")
        if record.get("type") not in EXCEPTION_TYPES:
            errors.append(f"{path}: {label}: type must be one of {', '.join(sorted(EXCEPTION_TYPES))}")

        for field in ("owner", "business_reason", "rollback_plan"):
            if not _is_non_empty_string(record.get(field)):
                errors.append(f"{path}: {label}: {field} must be non-empty")

        if not _is_non_empty_string_list(record.get("related_policy_sids")):
            errors.append(f"{path}: {label}: related_policy_sids must be a non-empty array")
        if not _is_non_empty_string_list(record.get("evidence")):
            errors.append(f"{path}: {label}: evidence must be a non-empty array")
        scope = record.get("scope")
        if not isinstance(scope, dict) or not scope:
            errors.append(f"{path}: {label}: scope must be a non-empty object")

        review_by = record.get("review_by")
        if not isinstance(review_by, str) or not DATE_RE.match(review_by):
            errors.append(f"{path}: {label}: review_by must look like YYYY-MM-DD")
        else:
            try:
                dt.date.fromisoformat(review_by)
            except ValueError:
                errors.append(f"{path}: {label}: review_by is not a valid calendar date")


def _validate_expected_paths(root: Path, errors: list[str]) -> None:
    found = {path.relative_to(root).as_posix() for path in (root / "policies").glob("**/*.json")}
    missing = sorted(EXPECTED_POLICY_FILES - found)
    unexpected = sorted(found - EXPECTED_POLICY_FILES)
    for path in missing:
        errors.append(f"{path}: expected policy file is missing")
    for path in unexpected:
        errors.append(f"{path}: unexpected policy file")


def _validate_repo_hygiene(root: Path, errors: list[str]) -> None:
    for path in sorted(root.glob("**/*")):
        if not path.is_file() or ".git" in path.parts:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for label, pattern in SECRET_PATTERNS.items():
            if pattern.search(text):
                errors.append(f"{path}: possible {label} found")
        for account_id in ACCOUNT_ID_RE.findall(text):
            if account_id not in ALLOWED_ACCOUNT_IDS:
                errors.append(f"{path}: real-looking AWS account ID {account_id} is not an approved placeholder")
        for domain in EMAIL_RE.findall(text):
            if domain.lower() not in ALLOWED_EMAIL_DOMAINS:
                errors.append(f"{path}: email domain {domain} is not an approved placeholder domain")


def validate_repo(root: Path) -> list[str]:
    """Return validation errors for the repository rooted at root."""
    root = root.resolve()
    errors: list[str] = []

    for path in sorted(root.glob("**/*.json")):
        relative = path.relative_to(root)
        if relative.parts[:1] != (POLICY_DIR,) and relative.as_posix() != EXCEPTION_REGISTER:
            _load_json(path, errors)

    _validate_repo_hygiene(root, errors)
    _validate_expected_paths(root, errors)

    policy_files = sorted((root / POLICY_DIR).glob("**/*.json"))
    if not policy_files:
        errors.append(f"{root / 'policies'}: no JSON policy files found")
    for path in policy_files:
        _validate_policy_file(path, root, errors)

    _validate_exceptions(root / EXCEPTION_REGISTER, errors)
    return errors


def _print_size_report(root: Path) -> None:
    rcp_paths = sorted((root / POLICY_DIR / RCP_DIR).glob("*.json"))
    if not rcp_paths:
        return
    print("RCP minified sizes:")
    for path in rcp_paths:
        policy = json.loads(path.read_text(encoding="utf-8"))
        relative = path.relative_to(root).as_posix()
        print(f"- {relative}: {_minified_size(policy)}/{RCP_SIZE_LIMIT} characters")
    print(
        "Attachment note: RCPFullAWSAccess counts toward the direct attachment quota; "
        f"plan for at most {CUSTOM_RCP_ATTACHMENTS_PER_TARGET} customer-managed RCPs per root, OU, or account."
    )


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    root = Path(args[0]) if args else Path(__file__).resolve().parents[1]
    errors = validate_repo(root)
    if errors:
        print("FAIL policy pack validation")
        for error in errors:
            print(f"- {error}")
        return 1
    print("PASS policy pack validation")
    _print_size_report(root.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
