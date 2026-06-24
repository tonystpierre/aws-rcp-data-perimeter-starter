import json
import tempfile
import unittest
from pathlib import Path

from tools.validate_policy_pack import validate_repo


REPO_ROOT = Path(__file__).resolve().parents[1]


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def valid_exception_register() -> dict:
    return {
        "version": "2026-06-24",
        "exceptions": [
            {
                "id": "EX-TEST",
                "status": "approved",
                "type": "break-glass",
                "owner": "security@example.com",
                "business_reason": "Test exception record.",
                "scope": {"accounts": ["123456789012"]},
                "related_policy_sids": ["TestSid"],
                "review_by": "2026-12-31",
                "evidence": ["ticket:TEST-1"],
                "rollback_plan": "Remove the test exception.",
            }
        ],
    }


def valid_rcp(effect: str = "Deny", extra: dict | None = None) -> dict:
    statement = {
        "Sid": "TestSid",
        "Effect": effect,
        "Principal": "*",
        "Action": "s3:GetObject",
        "Resource": "*",
    }
    if extra:
        statement.update(extra)
    return {"Version": "2012-10-17", "Statement": [statement]}


def valid_scp(extra: dict | None = None) -> dict:
    statement = {
        "Sid": "TestScpSid",
        "Effect": "Deny",
        "Action": "kms:DisableKey",
        "Resource": "*",
    }
    if extra:
        statement.update(extra)
    return {"Version": "2012-10-17", "Statement": [statement]}


class ValidatePolicyPackTests(unittest.TestCase):
    def test_valid_policy_pack_passes(self) -> None:
        self.assertEqual(validate_repo(REPO_ROOT), [])

    def test_bad_rcp_with_allow_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            write_json(root / "policies/resource-control-policies/bad.json", valid_rcp(effect="Allow"))
            write_json(root / "exceptions/exception-register.example.json", valid_exception_register())

            errors = validate_repo(root)

        self.assertTrue(any("Effect Deny" in error for error in errors))

    def test_bad_rcp_with_not_action_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            write_json(
                root / "policies/resource-control-policies/bad.json",
                valid_rcp(extra={"NotAction": "s3:DeleteObject"}),
            )
            write_json(root / "exceptions/exception-register.example.json", valid_exception_register())

            errors = validate_repo(root)

        self.assertTrue(any("NotAction" in error for error in errors))

    def test_bad_rcp_with_not_principal_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            write_json(
                root / "policies/resource-control-policies/bad.json",
                valid_rcp(extra={"NotPrincipal": {"AWS": "arn:aws:iam::123456789012:root"}}),
            )
            write_json(root / "exceptions/exception-register.example.json", valid_exception_register())

            errors = validate_repo(root)

        self.assertTrue(any("NotPrincipal" in error for error in errors))

    def test_bad_rcp_with_bare_global_action_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            write_json(
                root / "policies/resource-control-policies/bad.json",
                valid_rcp(extra={"Action": "*"}),
            )
            write_json(root / "exceptions/exception-register.example.json", valid_exception_register())

            errors = validate_repo(root)

        self.assertTrue(any("bare global Action" in error for error in errors))

    def test_bad_rcp_with_malformed_action_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            write_json(
                root / "policies/resource-control-policies/bad.json",
                valid_rcp(extra={"Action": "s3"}),
            )
            write_json(root / "exceptions/exception-register.example.json", valid_exception_register())

            errors = validate_repo(root)

        self.assertTrue(any("malformed Action" in error for error in errors))

    def test_bad_rcp_with_unsupported_action_prefix_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            write_json(
                root / "policies/resource-control-policies/bad.json",
                valid_rcp(extra={"Action": "iam:PassRole"}),
            )
            write_json(root / "exceptions/exception-register.example.json", valid_exception_register())

            errors = validate_repo(root)

        self.assertTrue(any("unsupported RCP action prefix" in error for error in errors))

    def test_bad_rcp_with_non_object_statement_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            write_json(
                root / "policies/resource-control-policies/bad.json",
                {"Version": "2012-10-17", "Statement": ["not-an-object"]},
            )
            write_json(root / "exceptions/exception-register.example.json", valid_exception_register())

            errors = validate_repo(root)

        self.assertTrue(any("Statement[1] must be an object" in error for error in errors))

    def test_bad_policy_with_duplicate_sid_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            policy = valid_rcp()
            policy["Statement"].append(dict(policy["Statement"][0]))
            write_json(root / "policies/resource-control-policies/bad.json", policy)
            write_json(root / "exceptions/exception-register.example.json", valid_exception_register())

            errors = validate_repo(root)

        self.assertTrue(any("duplicate Sid" in error for error in errors))

    def test_bad_exception_record_missing_owner_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            register = valid_exception_register()
            del register["exceptions"][0]["owner"]
            write_json(root / "policies/resource-control-policies/ok.json", valid_rcp())
            write_json(root / "exceptions/exception-register.example.json", register)

            errors = validate_repo(root)

        self.assertTrue(any("missing required fields: owner" in error for error in errors))

    def test_bad_exception_empty_related_policy_sids_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            register = valid_exception_register()
            register["exceptions"][0]["related_policy_sids"] = []
            write_json(root / "policies/resource-control-policies/ok.json", valid_rcp())
            write_json(root / "exceptions/exception-register.example.json", register)

            errors = validate_repo(root)

        self.assertTrue(any("related_policy_sids must be a non-empty array" in error for error in errors))

    def test_bad_exception_invalid_review_by_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            register = valid_exception_register()
            register["exceptions"][0]["review_by"] = "2026-99-99"
            write_json(root / "policies/resource-control-policies/ok.json", valid_rcp())
            write_json(root / "exceptions/exception-register.example.json", register)

            errors = validate_repo(root)

        self.assertTrue(any("review_by is not a valid calendar date" in error for error in errors))

    def test_bad_scp_missing_action_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            scp = valid_scp()
            del scp["Statement"][0]["Action"]
            write_json(root / "policies/service-control-policies/bad.json", scp)
            write_json(root / "exceptions/exception-register.example.json", valid_exception_register())

            errors = validate_repo(root)

        self.assertTrue(any("missing Action" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
