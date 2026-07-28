from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from agent_safe.adapters.exec_adapter import exec_risky
from agent_safe.adapters.fs import SafetyError
from agent_safe.core.journal import Journal
from agent_safe.core.verification import compare_assertions, parse_expected_state


def command_text(*args: str) -> str:
    return subprocess.list2cmdline(args) if os.name == "nt" else shlex.join(args)


class VerificationTests(unittest.TestCase):
    def make_script(self, root: Path, name: str, body: str) -> str:
        path = root / name
        path.write_text(body, encoding="utf-8")
        return command_text(sys.executable, str(path))

    def run_risky(self, root: Path, actual_stdout: str, *, verify_exit: int = 0, receipt: Path | None = None):
        verify = self.make_script(root, "verify.py", f"import sys\nprint({actual_stdout!r})\nsys.exit({verify_exit})\n")
        receipt_command = None
        if receipt is not None:
            receipt_command = self.make_script(root, "receipt.py", f"from pathlib import Path\nPath({str(receipt)!r}).write_text('receipt', encoding='utf-8')\n")
        journal = Journal(root)
        record = exec_risky(
            [sys.executable, "-c", "print('changed')"],
            journal=journal,
            channel="local",
            domain="unknown",
            target="test-target",
            reason="проверка структурной верификации",
            expected_state_json=json.dumps({
                "assertions": {"resource": {"active": True, "count": 2}},
                "declarations": {"operation": "test"},
            }),
            rollback_command="manual rollback",
            verify_command=verify,
            receipt_command=receipt_command,
            approved=True,
        )
        return journal, record

    def test_full_match_is_done_and_journaled(self):
        with tempfile.TemporaryDirectory() as td:
            journal, record = self.run_risky(Path(td), json.dumps({"resource": {"active": True, "count": 2}}))
            self.assertEqual(record.status.value, "done")
            self.assertTrue(record.verification_complete)
            self.assertEqual(record.verified_assertions, {"resource.active": True, "resource.count": 2})
            self.assertEqual(record.missing_assertions, {})
            self.assertEqual(record.mismatched_assertions, {})
            stored = journal.records()[-1]
            self.assertTrue(stored["verification_complete"])
            self.assertEqual(stored["actual_state"]["resource"]["count"], 2)

    def test_missing_field_is_unexpected_and_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            journal, record = self.run_risky(Path(td), json.dumps({"resource": {"active": True}}))
            self.assertEqual(record.status.value, "unexpected")
            self.assertIn("resource.count", record.missing_assertions)
            self.assertTrue(journal.is_blocked())

    def test_value_mismatch_is_unexpected(self):
        with tempfile.TemporaryDirectory() as td:
            _, record = self.run_risky(Path(td), json.dumps({"resource": {"active": False, "count": 2}}))
            self.assertEqual(record.status.value, "unexpected")
            self.assertEqual(record.mismatched_assertions["resource.active"]["reason"], "value_mismatch")

    def test_type_mismatch_is_unexpected(self):
        with tempfile.TemporaryDirectory() as td:
            _, record = self.run_risky(Path(td), json.dumps({"resource": {"active": 1, "count": 2}}))
            self.assertEqual(record.status.value, "unexpected")
            self.assertEqual(record.mismatched_assertions["resource.active"]["reason"], "type_mismatch")

    def test_invalid_json_is_unexpected(self):
        with tempfile.TemporaryDirectory() as td:
            _, record = self.run_risky(Path(td), "not-json")
            self.assertEqual(record.status.value, "unexpected")
            self.assertEqual(record.verify_result["verification_error_code"], "actual_state_invalid_json")
            self.assertFalse(record.verification_complete)

    def test_nonzero_verify_is_unexpected(self):
        with tempfile.TemporaryDirectory() as td:
            _, record = self.run_risky(Path(td), "{}", verify_exit=7)
            self.assertEqual(record.status.value, "unexpected")
            self.assertEqual(record.verify_result["verification_error_code"], "verify_failed")

    def test_extra_actual_fields_are_allowed(self):
        with tempfile.TemporaryDirectory() as td:
            _, record = self.run_risky(Path(td), json.dumps({"resource": {"active": True, "count": 2, "extra": "ok"}, "diagnostics": {}}))
            self.assertEqual(record.status.value, "done")

    def test_receipt_does_not_run_after_mismatch(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            receipt = root / "receipt.txt"
            _, record = self.run_risky(root, json.dumps({"resource": {"active": False, "count": 2}}), receipt=receipt)
            self.assertEqual(record.status.value, "unexpected")
            self.assertFalse(receipt.exists())
            self.assertIsNone(record.metadata["receipt_exec"])

    def test_declarations_are_not_marked_verified(self):
        with tempfile.TemporaryDirectory() as td:
            _, record = self.run_risky(Path(td), json.dumps({"resource": {"active": True, "count": 2}, "operation": "different"}))
            self.assertEqual(record.status.value, "done")
            self.assertNotIn("operation", record.verified_assertions)
            self.assertEqual(record.expected_state["declarations"], {"operation": "test"})

    def test_assertions_require_verify_before_action(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            marker = root / "changed.txt"
            journal = Journal(root)
            with self.assertRaises(SafetyError):
                exec_risky(
                    [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).write_text('changed')"],
                    journal=journal,
                    channel="local",
                    domain="unknown",
                    target="test-target",
                    reason="test",
                    expected_state_json=json.dumps({"assertions": {"ok": True}, "declarations": {}}),
                    rollback_command="manual rollback",
                    approved=True,
                )
            self.assertFalse(marker.exists())
            self.assertEqual(journal.records(), [])

    def test_declarations_only_do_not_require_verify(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            journal = Journal(root)
            record = exec_risky(
                [sys.executable, "-c", "print('changed')"],
                journal=journal,
                channel="local",
                domain="unknown",
                target="test-target",
                reason="test",
                expected_state_json=json.dumps({"assertions": {}, "declarations": {"operation": "test"}}),
                rollback_command="manual rollback",
                approved=True,
            )
            self.assertEqual(record.status.value, "done")
            self.assertTrue(record.verification_complete)
            self.assertEqual(record.verified_assertions, {})

    def test_old_journal_entries_remain_readable(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            journal = Journal(root)
            old = {"txn_id": "old-1", "status": "done", "kind": "legacy", "expected_state": {"ok": True}}
            journal.journal_path.write_text(json.dumps(old) + "\n", encoding="utf-8")
            self.assertEqual(journal.records(), [old])

    def test_expected_state_rejects_legacy_flat_shape(self):
        with self.assertRaisesRegex(ValueError, "assertions и declarations"):
            parse_expected_state('{"ok": true}')

    def test_comparison_is_recursive_and_type_exact(self):
        outcome = compare_assertions({"values": [1, True]}, {"values": [1, 1]})
        self.assertEqual(outcome.mismatched_assertions["values[1]"]["reason"], "type_mismatch")


if __name__ == "__main__":
    unittest.main()
