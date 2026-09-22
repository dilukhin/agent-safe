"""Managed recovery with a simulated trusted owner, not an OpenCode host proof."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from agent_safe.adapters.exec_adapter import exec_risky
from agent_safe.adapters.fs import SafetyError
from agent_safe.adapters.recover import _recover_managed, recover
from agent_safe.core.journal import Journal
from agent_safe.core.managed_process import ManagedAuthorizationError
from agent_safe.core.models import Status
from agent_safe.core.rollback import prepare_process


class SimulatedAuthorizationError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class SimulatedBinding:
    session_id: str
    call_id: str
    source_txn_id: str
    attempt_txn_id: str
    role: str
    transport: str = "local-inprocess/v1"


@dataclass(frozen=True)
class SimulatedProjection:
    prepared: object


@dataclass(frozen=True)
class SimulatedPending:
    decision: str
    projection: object
    continuation: object | None


class SimulatedTrustedOwner:
    """Test-only owner with separate host events and atomic one-use consume."""

    authorization_error_type = SimulatedAuthorizationError

    def __init__(self, acquire, *, approve=("process", "verify"), deny=(), admit=True,
                 binding_change=None, approval_action=None, bind_error=None,
                 projection_mismatch=False, consume_base_error=None):
        self.execution_port = self
        self.acquire = acquire
        self.approve = set(approve)
        self.deny = set(deny)
        self.admit = admit
        self.binding_change = binding_change
        self.approval_action = approval_action
        self.bind_error = bind_error
        self.projection_mismatch = projection_mismatch
        self.consume_base_error = consume_base_error
        self.originals = {}
        self.entries = {}
        self.calls = []
        self.admissions = []
        self.closed = False
        self.lock = threading.Lock()

    def admit_recovery(self, admission):
        self.admissions.append(admission)
        if self.admit == "error":
            raise SimulatedAuthorizationError("ADMISSION_DENIED")
        return admission if self.admit else None

    def bind(self, prepared, *, call_id):
        if self.bind_error:
            raise SimulatedAuthorizationError(self.bind_error)
        binding = SimulatedBinding("test-session", call_id, prepared.source_txn_id,
                                   prepared.attempt_txn_id, prepared.role)
        self.originals[binding] = prepared
        if self.binding_change:
            binding = replace(binding, **self.binding_change)
        return binding

    def _observe(self, binding):
        original = self.originals.get(binding)
        if original is None:
            raise SimulatedAuthorizationError("CALL_BINDING_MISMATCH")
        fresh = self.acquire(binding)
        if fresh != original:
            raise SimulatedAuthorizationError("PREPARED_DRIFT")
        return SimulatedProjection(original)

    def request(self, binding):
        projection = self._observe(binding)
        self.calls.append(binding)
        if binding.role in self.deny:
            return SimulatedPending("DENY", projection, None)
        ticket = object()
        self.entries[ticket] = [binding, projection, "PENDING"]
        return SimulatedPending("ASK_USER", projection, ticket)

    def approval_event(self, pending, binding):
        if self.approval_action:
            self.approval_action(binding)
        if binding.role in self.approve:
            self.entries[pending.continuation][2] = "APPROVED_ONCE"

    def consume(self, continuation, binding):
        with self.lock:
            entry = self.entries.get(continuation)
            if entry is None:
                raise SimulatedAuthorizationError("CONTINUATION_UNKNOWN")
            if entry[0] != binding:
                entry[2] = "REVOKED"
                raise SimulatedAuthorizationError("CALL_BINDING_MISMATCH")
            if entry[2] != "APPROVED_ONCE":
                code = "CONTINUATION_CONSUMED" if entry[2] == "CONSUMED" else "CONTINUATION_NOT_APPROVED"
                raise SimulatedAuthorizationError(code)
            if self.consume_base_error is not None:
                raise self.consume_base_error
            projection = self._observe(binding)
            entry[2] = "CONSUMED"
            return SimulatedProjection("wrong") if self.projection_mismatch else projection

    def cancel(self, pending):
        entry = self.entries.get(pending.continuation)
        if entry is not None and entry[2] != "CONSUMED":
            entry[2] = "REVOKED"

    def close(self):
        self.closed = True


class ManagedRecoveryTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.journal = Journal(self.root)
        self.target = self.root / "target.txt"
        self.target.write_bytes(b"modified")
        self.backup = self.root / "backup.bin"
        self.backup.write_bytes(b"original")
        self.script = self.root / "restore.py"
        self.script.write_text("restore fixture\n", encoding="utf-8")
        self.verify = self.root / "verify.py"
        self.verify.write_text("verify fixture\n", encoding="utf-8")
        spec = {"schema_version": 1, "program": str(Path(sys.executable).resolve()),
                "argv": [], "cwd": str(self.root), "shell": False, "timeout_seconds": 5}
        self.process_stdin = "line1\r\nline2\nРусский\n"
        self.plan = {
            "schema_version": 1, "target": str(self.target),
            "artifacts": [{"id": name, "path": str(path), "non_secret": True}
                          for name, path in (("restore", self.script), ("backup", self.backup), ("verify", self.verify))],
            "process": dict(spec, argv=["-I", {"artifact": "restore"}, {"artifact": "backup"}, str(self.target)],
                            stdin_utf8=self.process_stdin),
            "verify": dict(spec, argv=["-I", {"artifact": "verify"}, str(self.target)], stdin_utf8=""),
            "expected_state": {"assertions": {"restored": True}},
        }
        with patch("agent_safe.adapters.exec_adapter._run", side_effect=[
            {"outcome": "exited", "returncode": 0},
            {"outcome": "exited", "returncode": 0, "stdout": '{"ready":true}'},
        ]):
            self.source = exec_risky(
                ["apply-update"], journal=self.journal, channel="local", domain="test",
                target=str(self.target), reason="fixture", expected_state_json='{"assertions":{"ready":true}}',
                rollback_plan_json=json.dumps(self.plan), verify_command="inspect-state", approved=True,
            )
        self.context = dict(
            journal=self.journal, txn_id=self.source.txn_id,
            recovery=self.source.metadata["recovery"], plan_raw=json.dumps(self.plan),
        )

    def acquire(self, binding):
        return prepare_process(attempt_txn_id=binding.attempt_txn_id, role=binding.role, **self.context)

    def restore(self, owner, **overrides):
        options = dict(journal=self.journal, source_id=self.source.txn_id,
                       plan_raw=json.dumps(self.plan), reason="managed test", authority=owner)
        options.update(overrides)
        return _recover_managed(**options)

    def test_separate_process_and_verify_permissions_preserve_exact_stdin(self):
        owner = SimulatedTrustedOwner(self.acquire)
        responses = [
            {"outcome": "exited", "returncode": 0},
            {"outcome": "exited", "returncode": 0, "stdout": '{"restored":true}'},
        ]
        with patch("agent_safe.adapters.recover._run", side_effect=responses) as run:
            result = self.restore(owner)
        self.assertEqual(result.status, Status.DONE)
        self.assertEqual([call.role for call in owner.calls], ["process", "verify"])
        self.assertNotEqual(owner.calls[0].call_id, owner.calls[1].call_id)
        self.assertEqual(run.call_args_list[0].kwargs["stdin_utf8"], self.process_stdin)
        self.assertEqual(run.call_args_list[1].kwargs["stdin_utf8"], "")
        self.assertEqual([entry[2] for entry in owner.entries.values()], ["CONSUMED", "CONSUMED"])
        self.assertTrue(owner.closed)

    def test_ask_without_trusted_host_event_never_spawns(self):
        owner = SimulatedTrustedOwner(self.acquire, approve=())
        with patch("agent_safe.adapters.recover._run") as run:
            result = self.restore(owner)
        run.assert_not_called()
        self.assertEqual(result.status, Status.FAILED)
        self.assertEqual(result.verify_result["error_code"], "recovery_process_authorization_failed")
        self.assertTrue(self.journal.is_blocked())

    def test_native_deny_never_spawns_and_is_recorded(self):
        owner = SimulatedTrustedOwner(self.acquire, deny=("process",))
        before = len(self.journal.records())
        with patch("agent_safe.adapters.recover._run") as run:
            result = self.restore(owner)
        run.assert_not_called()
        self.assertEqual(result.status, Status.FAILED)
        self.assertEqual(len(self.journal.records()), before + 2)
        self.assertTrue(owner.closed)

    def test_managed_entry_rejects_missing_admission_and_execution_port(self):
        before = self.journal.journal_path.read_bytes()
        owner = SimulatedTrustedOwner(self.acquire, admit=False)
        with self.assertRaises(ManagedAuthorizationError):
            self.restore(owner)
        self.assertEqual(self.journal.journal_path.read_bytes(), before)
        self.assertFalse(self.journal.block_path.exists())
        self.assertFalse((self.journal.safety_dir / "recovery" / "ACTIVE.json").exists())
        owner = SimulatedTrustedOwner(self.acquire)
        owner.execution_port = None
        with self.assertRaises(ManagedAuthorizationError):
            self.restore(owner)

    def test_public_approved_flag_cannot_authorize_managed_path(self):
        owner = SimulatedTrustedOwner(self.acquire)
        with self.assertRaises(SafetyError):
            recover(journal=self.journal, source_id=self.source.txn_id,
                    plan_raw=json.dumps(self.plan), approved=True, reason="not authority", _managed=owner)
        with self.assertRaises(TypeError):
            self.restore(owner, approved=True)

    def test_prepared_drift_after_approval_blocks_spawn(self):
        changed = {"active": False}
        def acquire(binding):
            prepared = self.acquire(binding)
            return replace(prepared, stdin_utf8="changed") if changed["active"] else prepared
        owner = SimulatedTrustedOwner(acquire, approval_action=lambda binding: changed.update(active=True))
        with patch("agent_safe.adapters.recover._run") as run:
            result = self.restore(owner)
        run.assert_not_called()
        self.assertEqual(result.status, Status.FAILED)

    def test_same_bytes_artifact_replacement_cancels_before_consume(self):
        def replace_artifact(binding):
            if binding.role == "process":
                artifact = Path(self.source.metadata["recovery"]["bundle"]) / "artifacts" / "backup"
                replacement = self.root / "replacement"
                replacement.write_bytes(artifact.read_bytes())
                replacement.replace(artifact)
        owner = SimulatedTrustedOwner(self.acquire, approval_action=replace_artifact)
        with patch("agent_safe.adapters.recover._run") as run:
            result = self.restore(owner)
        run.assert_not_called()
        self.assertEqual(result.status, Status.FAILED)
        self.assertEqual(next(iter(owner.entries.values()))[2], "REVOKED")

    def test_binding_fields_are_checked_before_spawn(self):
        changes = (
            {"call_id": "other"}, {"source_txn_id": "other"},
            {"attempt_txn_id": "other"}, {"role": "verify"},
        )
        for change in changes:
            with self.subTest(change=change):
                self.setUp()
                owner = SimulatedTrustedOwner(self.acquire, binding_change=change)
                with patch("agent_safe.adapters.recover._run") as run:
                    result = self.restore(owner)
                run.assert_not_called()
                self.assertEqual(result.status, Status.FAILED)

    def test_verify_deny_preserves_process_result_and_prevents_repeat(self):
        owner = SimulatedTrustedOwner(self.acquire, deny=("verify",))
        with patch("agent_safe.adapters.recover._run", return_value={"outcome": "exited", "returncode": 0}) as run:
            result = self.restore(owner)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(result.status, Status.UNEXPECTED)
        self.assertEqual(result.metadata["result"]["outcome"], "exited")
        self.assertEqual(result.verify_result["error_code"], "recovery_verify_authorization_failed")
        self.assertTrue(self.journal.is_blocked())
        with patch("agent_safe.adapters.recover._run") as second, self.assertRaises(SafetyError):
            self.restore(SimulatedTrustedOwner(self.acquire))
        second.assert_not_called()
        with patch("agent_safe.adapters.recover._run") as second, self.assertRaises(SafetyError):
            self.restore(SimulatedTrustedOwner(self.acquire), retry_after=result.txn_id)
        second.assert_not_called()

    def test_verify_exception_preserves_process_and_cannot_retry(self):
        owner = SimulatedTrustedOwner(self.acquire)
        with patch("agent_safe.adapters.recover._run", side_effect=[
                {"outcome": "exited", "returncode": 0}, RuntimeError("test")]) as run:
            result = self.restore(owner)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(result.metadata["result"]["outcome"], "exited")
        self.assertEqual(result.verify_result["error_code"], "recovery_verify_unknown")
        with patch("agent_safe.adapters.recover._run") as second, self.assertRaises(SafetyError):
            self.restore(SimulatedTrustedOwner(self.acquire), retry_after=result.txn_id)
        second.assert_not_called()

    def test_uncaught_base_exception_cancels_pending_and_closes(self):
        owner = SimulatedTrustedOwner(self.acquire, consume_base_error=SystemExit("test"))
        with self.assertRaises(SystemExit):
            self.restore(owner)
        self.assertEqual(next(iter(owner.entries.values()))[2], "REVOKED")
        self.assertTrue(owner.closed)

    def test_manual_recovery_keeps_legacy_metadata_shape(self):
        with patch("agent_safe.adapters.recover._run", side_effect=[
            {"outcome": "exited", "returncode": 0},
            {"outcome": "exited", "returncode": 0, "stdout": '{"restored":true}'},
        ]):
            result = recover(
                journal=self.journal, source_id=self.source.txn_id,
                plan_raw=json.dumps(self.plan), approved=True, reason="manual test",
            )
        self.assertEqual(set(result.metadata), {
            "parent_txn_id", "manifest_sha256", "retry_after", "approved",
            "result", "verify_exec", "target_after",
        })
        self.assertTrue(result.metadata["approved"])

    def test_authority_errors_are_normalized_and_projection_mismatch_stays_consumed(self):
        owner = SimulatedTrustedOwner(self.acquire, admit="error")
        with self.assertRaises(ManagedAuthorizationError) as cm:
            self.restore(owner)
        self.assertEqual(cm.exception.code, "ADMISSION_DENIED")
        self.setUp()
        owner = SimulatedTrustedOwner(self.acquire, bind_error="BINDING_DENIED")
        with patch("agent_safe.adapters.recover._run") as run:
            result = self.restore(owner)
        run.assert_not_called()
        self.assertIn("BINDING_DENIED", result.verify_result["error_message"])
        self.setUp()
        owner = SimulatedTrustedOwner(self.acquire, projection_mismatch=True)
        with patch("agent_safe.adapters.recover._run") as run:
            result = self.restore(owner)
        run.assert_not_called()
        self.assertEqual(result.status, Status.FAILED)
        self.assertEqual(next(iter(owner.entries.values()))[2], "CONSUMED")

    def test_process_permission_stays_consumed_for_all_spawn_outcomes(self):
        for outcome in (
            {"outcome": "not_started", "returncode": 127},
            {"outcome": "exited", "returncode": 1},
            {"outcome": "unknown", "returncode": 127},
        ):
            with self.subTest(outcome=outcome):
                self.setUp()
                owner = SimulatedTrustedOwner(self.acquire)
                with patch("agent_safe.adapters.recover._run", return_value=outcome):
                    self.restore(owner)
                process = next(entry for entry in owner.entries.values() if entry[0].role == "process")
                self.assertEqual(process[2], "CONSUMED")

    def test_simulated_owner_allows_only_one_concurrent_consume(self):
        owner = SimulatedTrustedOwner(self.acquire)
        prepared = self.acquire(SimulatedBinding("test-session", "seed", self.source.txn_id,
                                                 "20260922-120000-1234abcd", "process"))
        binding = owner.bind(prepared, call_id="concurrent")
        pending = owner.request(binding)
        owner.approval_event(pending, binding)
        def consume(_):
            try:
                owner.consume(pending.continuation, binding)
                return "consumed"
            except SimulatedAuthorizationError as exc:
                return exc.code
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(consume, range(8)))
        self.assertEqual(results.count("consumed"), 1)
        self.assertEqual(results.count("CONTINUATION_CONSUMED"), 7)


if __name__ == "__main__":
    unittest.main()
