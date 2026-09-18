import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from agent_safe.adapters.exec_adapter import exec_risky
from agent_safe.adapters.fs import SafetyError, redo_record, undo_record
from agent_safe.cli import main
from agent_safe.core.journal import Journal
from agent_safe.core.models import Status


class RecoveryContractTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.journal = Journal(self.root)
        now = datetime.now(timezone.utc)
        self.evidence = {
            "schema_version": 1, "target": "vm:test", "checkpoint_id": "backup-001",
            "recovery_source": "backup:test-001",
            "conditions": {"backup_available": True, "access_verified": True},
            "observed_at": (now - timedelta(minutes=1)).isoformat(),
            "valid_until": (now + timedelta(minutes=30)).isoformat(),
            "private_detail": "DO_NOT_COPY_TO_JOURNAL",
        }
        self.contract = {
            "schema_version": 1, "kind": "checkpoint", "target": "vm:test",
            "checkpoint_id": "backup-001", "recovery_source": "backup:test-001",
            "evidence_path": "evidence.json", "evidence_sha256": "",
            "conditions": {"backup_available": True, "access_verified": True},
            "recovery_steps": ["Stop changes; inspect target; restore checkpoint after approval."],
        }
        self.save_evidence()
        self.kwargs = dict(
            journal=self.journal, channel="local", domain="test", target="vm:test",
            reason="test recovery", expected_state_json='{"assertions":{"ready":true},"declarations":{}}',
            verify_command="inspect-state", approved=True,
        )

    def save_evidence(self, raw=None):
        raw = raw if raw is not None else json.dumps(self.evidence).encode("utf-8")
        (self.root / "evidence.json").write_bytes(raw)
        self.contract["evidence_sha256"] = hashlib.sha256(raw).hexdigest()

    def run_checkpoint(self, responses=None, **overrides):
        kwargs = dict(self.kwargs, recovery_contract_json=json.dumps(self.contract))
        kwargs.update(overrides)
        if responses is None:
            responses = [{"returncode": 0}, {"returncode": 0, "stdout": '{"ready":true}'}]
        with patch("agent_safe.adapters.exec_adapter._run", side_effect=responses) as run:
            record = exec_risky(["apply-update"], **kwargs)
        return record, run

    def assert_rejected(self, **overrides):
        with patch("agent_safe.adapters.exec_adapter._run") as run:
            kwargs = dict(self.kwargs, recovery_contract_json=json.dumps(self.contract))
            kwargs.update(overrides)
            with self.assertRaises(SafetyError):
                exec_risky(["apply-update"], **kwargs)
            run.assert_not_called()

    def test_plan_and_barrier_exist_before_execution(self):
        calls = []

        def execute(args, cwd, timeout):
            planned = self.journal.records()[0]
            self.assertEqual(planned["status"], "planned")
            self.assertEqual(planned["command"]["args"], ["apply-update"])
            self.assertEqual(planned["metadata"]["recovery"]["contract"], self.contract)
            self.assertTrue(self.journal.is_blocked())
            calls.append(args)
            return {"returncode": 0, "stdout": '{"ready":true}'}

        record, _ = self.run_checkpoint(responses=execute)
        self.assertEqual(len(calls), 2)
        self.assertEqual(record.status, Status.DONE)
        self.assertFalse(self.journal.is_blocked())
        self.assertEqual([r["status"] for r in self.journal.records()], ["planned", "done"])
        self.assertEqual(self.journal.find(record.txn_id)["status"], "done")
        self.assertEqual(record.undo["op"], "manual-recovery")
        self.assertNotIn("DO_NOT_COPY_TO_JOURNAL", self.journal.journal_path.read_text(encoding="utf-8"))

    def test_existing_rollback_path_keeps_single_record(self):
        record, _ = self.run_checkpoint(recovery_contract_json=None, rollback_command="restore")
        self.assertEqual(record.status, Status.DONE)
        self.assertEqual(record.metadata["recovery"]["mode"], "rollback-command")
        self.assertEqual(len(self.journal.records()), 1)

    def test_no_implicit_bypass_or_ambiguous_mode(self):
        self.assert_rejected(recovery_contract_json=None)
        self.assert_rejected(rollback_command="restore")
        for value in ("", "opaque", "{}", "[]", '{"a":1,"a":2}', '{"a":NaN}'):
            with self.subTest(value=value):
                self.assert_rejected(recovery_contract_json=value)

    def test_strict_contract_fields(self):
        original = dict(self.contract)
        for key, value in (("extra", True), ("kind", "opaque"), ("schema_version", True),
                           ("target", "vm:other"), ("conditions", {}), ("conditions", {"ready": 1}),
                           ("recovery_steps", []), ("recovery_steps", [""]),
                           ("evidence_sha256", "z" * 64), ("evidence_path", "../evidence.json")):
            with self.subTest(key=key, value=value):
                self.contract = dict(original, **{key: value})
                self.assert_rejected()

    def test_evidence_must_match_target_checkpoint_and_source(self):
        for key in ("target", "checkpoint_id", "recovery_source", "schema_version"):
            with self.subTest(key=key):
                original = self.evidence[key]
                self.evidence[key] = "wrong"
                self.save_evidence()
                self.assert_rejected()
                self.evidence[key] = original

    def test_missing_corrupted_or_non_regular_evidence_rejected(self):
        (self.root / "evidence.json").unlink()
        self.assert_rejected()
        self.save_evidence()
        self.contract["evidence_sha256"] = "0" * 64
        self.assert_rejected()
        self.contract["evidence_path"] = str(self.root)
        self.assert_rejected()

    def test_evidence_json_encoding_and_size(self):
        for raw in (b"\xff", b"{}", b"[]", b"not-json", b" " * (1024 * 1024 + 1)):
            with self.subTest(size=len(raw)):
                self.save_evidence(raw)
                self.assert_rejected()

    def test_conditions_require_boolean_true(self):
        for value in (False, 1, "true", None):
            with self.subTest(value=value):
                self.evidence["conditions"]["backup_available"] = value
                self.save_evidence()
                self.assert_rejected()

    def test_evidence_freshness_and_timezone(self):
        original = dict(self.evidence)
        now = datetime.now(timezone.utc)
        for key, value in (("valid_until", (now - timedelta(minutes=1)).isoformat()),
                           ("observed_at", (now + timedelta(minutes=1)).isoformat()),
                           ("observed_at", "2020-01-01T00:00:00"), ("valid_until", "not-a-date")):
            with self.subTest(key=key, value=value):
                self.evidence = dict(original, **{key: value})
                self.save_evidence()
                self.assert_rejected()

    def test_approval_assertions_and_verification_remain_required(self):
        self.assert_rejected(approved=False)
        self.assert_rejected(verify_command=None)
        self.assert_rejected(expected_state_json='{"assertions":{},"declarations":{"note":"reviewed"}}')
        self.assert_rejected(reason=" ")

    def test_critical_guard_remains(self):
        with patch("agent_safe.adapters.exec_adapter._run") as run:
            with self.assertRaises(SafetyError):
                exec_risky(["rm", "-rf", "exact-test-target"],
                           recovery_contract_json=json.dumps(self.contract), **self.kwargs)
            run.assert_not_called()

    def test_failures_unknown_and_partial_do_not_retry(self):
        for code in (1, 12, 13, 127):
            with self.subTest(code=code):
                record, run = self.run_checkpoint(responses=[{"returncode": code}])
                self.assertEqual(record.status, Status.UNEXPECTED)
                self.assertEqual(run.call_count, 1)
                self.assertTrue(self.journal.is_blocked())
                self.assert_rejected()
                self.journal.clear_block("isolated test fixture reset")

    def test_verify_mismatch_skips_receipt_and_blocks(self):
        record, run = self.run_checkpoint(
            responses=[{"returncode": 0}, {"returncode": 0, "stdout": '{"ready":false}'}],
            receipt_command="receipt",
        )
        self.assertEqual(record.status, Status.UNEXPECTED)
        self.assertEqual(run.call_count, 2)
        self.assertTrue(self.journal.is_blocked())

    def test_receipt_failure_blocks(self):
        record, run = self.run_checkpoint(
            responses=[{"returncode": 0}, {"returncode": 0, "stdout": '{"ready":true}'}, {"returncode": 1}],
            receipt_command="receipt",
        )
        self.assertEqual(record.status, Status.UNEXPECTED)
        self.assertEqual(run.call_count, 3)
        self.assertTrue(self.journal.is_blocked())

    def test_interrupt_has_unknown_result(self):
        record, run = self.run_checkpoint(responses=KeyboardInterrupt)
        self.assertEqual(record.status, Status.UNEXPECTED)
        self.assertEqual(run.call_count, 1)
        self.assertTrue(self.journal.is_blocked())

    def test_process_exit_leaves_preexecution_barrier(self):
        with self.assertRaises(SystemExit):
            self.run_checkpoint(responses=SystemExit)
        self.assertTrue(self.journal.is_blocked())
        self.assertEqual(self.journal.records()[-1]["status"], "planned")
        self.assert_rejected()

    def test_journal_failure_prevents_execution(self):
        with patch.object(self.journal, "append", side_effect=OSError("disk unavailable")):
            self.assert_rejected()

    def test_pending_barrier_failure_prevents_execution(self):
        with patch.object(self.journal, "begin_pending", side_effect=OSError("disk unavailable")):
            self.assert_rejected()

    def test_final_journal_failure_keeps_block(self):
        original = self.journal.append

        def append(record, **kwargs):
            if record.status != Status.PLANNED:
                raise OSError("disk unavailable")
            original(record, **kwargs)

        with patch.object(self.journal, "append", side_effect=append), self.assertRaises(OSError):
            self.run_checkpoint()
        self.assertTrue(self.journal.is_blocked())
        self.assert_rejected()

    def test_pending_barrier_prevents_nested_execution(self):
        def execute(args, cwd, timeout):
            self.assert_rejected()
            return {"returncode": 0, "stdout": '{"ready":true}'}
        record, _ = self.run_checkpoint(responses=execute)
        self.assertEqual(record.status, Status.DONE)

    def test_recovery_plan_selects_pending_or_failed_transaction(self):
        for responses in (SystemExit, [{"returncode": 1}]):
            with self.subTest(responses=responses):
                try:
                    self.run_checkpoint(responses=responses)
                except SystemExit:
                    pass
                with patch("agent_safe.cli.print_json") as output:
                    result = main(["--root", str(self.root), "recovery-plan"])
                plan = output.call_args.args[0]
                self.assertEqual(result, 0)
                self.assertEqual(plan["transaction"]["txn_id"], self.journal.records()[-1]["txn_id"])
                self.assertEqual(plan["recovery_contract"], self.contract)
                self.journal.clear_block("изолированный тест завершён")

    def test_cannot_clear_another_incident(self):
        def execute(args, cwd, timeout):
            self.journal.block("another incident", "another-transaction")
            return {"returncode": 0, "stdout": '{"ready":true}'}
        record, _ = self.run_checkpoint(responses=execute)
        self.assertEqual(record.status, Status.UNEXPECTED)
        self.assertTrue(self.journal.is_blocked())

    def test_undo_and_redo_never_execute_recovery_steps(self):
        record, _ = self.run_checkpoint()
        with self.assertRaises(SafetyError):
            undo_record(record.to_dict(), self.journal)
        with self.assertRaises(SafetyError):
            redo_record(record.to_dict(), self.journal)

    def test_evidence_symlink_rejected(self):
        link = self.root / "evidence-link.json"
        try:
            link.symlink_to(self.root / "evidence.json")
        except OSError:
            self.skipTest("symlinks unavailable")
        self.contract["evidence_path"] = str(link)
        self.assert_rejected()

    def test_find_returns_latest_full_record_not_event(self):
        record, _ = self.run_checkpoint()
        self.journal.append_raw({"event": "test", "txn_id": record.txn_id})
        self.assertEqual(self.journal.find(record.txn_id)["status"], "done")

    def test_cli_accepts_explicit_contract_file(self):
        contract_path = self.root / "recovery.json"
        contract_path.write_text(json.dumps(self.contract), encoding="utf-8")
        with patch("agent_safe.adapters.exec_adapter._run", side_effect=[
            {"returncode": 0}, {"returncode": 0, "stdout": '{"ready":true}'},
        ]), patch("builtins.print"):
            result = main([
                "--root", str(self.root), "exec-risky", "--target", "vm:test", "--reason", "test",
                "--expected-state", self.kwargs["expected_state_json"],
                "--recovery-contract-file", str(contract_path), "--verify-command", "inspect-state",
                "--approved", "--", "apply-update",
            ])
        self.assertEqual(result, 0)


if __name__ == "__main__":
    unittest.main()
