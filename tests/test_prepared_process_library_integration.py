"""Opt-in check against the exact opencode_permissions PR #37 library.

The test class is defined only when those uninstalled modules are supplied by a
pinned test environment. They are deliberately not an agent-safe dependency.
"""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from agent_safe.adapters.exec_adapter import exec_risky
from agent_safe.adapters.recover import _recover_managed
from agent_safe.core.journal import Journal
from agent_safe.core.models import Status
from agent_safe.core.rollback import prepare_process

try:
    from prepared_process_adapter import PROFILE, project_prepared
    from prepared_process_authorization import (
        AuthorizationError, CallBinding, create_local_session,
    )
except ImportError:
    PROFILE = None


if PROFILE is not None:
    class RealLibraryOwner:
        """Test composition owner; not a native OpenCode continuation."""

        authorization_error_type = AuthorizationError

        def __init__(self, acquire, *, approve=True, native="ask"):
            self._acquire_fresh = acquire
            self._prepared = {}
            self._approve = approve
            self._native = native
            self.host, self.execution_port = create_local_session(
                session_id="agent-safe-integration-test", platform=("windows" if os.name == "nt" else "linux"),
                acquire=self._acquire, native_check=lambda binding, projection: self._native,
            )

        def admit_recovery(self, admission):
            return admission

        def bind(self, prepared, *, call_id):
            binding = CallBinding(
                "agent-safe-integration-test", call_id, prepared.source_txn_id,
                prepared.attempt_txn_id, prepared.role,
            )
            self._prepared[binding] = prepared
            return binding

        def _acquire(self, binding):
            fresh = self._acquire_fresh(binding)
            if fresh != self._prepared[binding]:
                return replace(fresh, role="verify" if fresh.role == "process" else "process")
            return fresh

        def approval_event(self, pending, binding):
            if self._approve:
                self.host.approve_once(
                    pending.continuation, binding,
                    snapshot_identity=pending.projection.snapshot_identity,
                )

        def cancel(self, pending):
            self.host.cancel(pending.continuation)

        def close(self):
            self.host.close()


    class PreparedProcessLibraryIntegrationTests(unittest.TestCase):
        def setUp(self):
            temp = tempfile.TemporaryDirectory()
            self.addCleanup(temp.cleanup)
            self.root = Path(temp.name).resolve()
            self.journal = Journal(self.root)
            self.target = self.root / "target.txt"
            self.target.write_bytes(b"modified")
            files = {}
            for name, raw in (("restore", b"restore fixture\n"),
                              ("backup", b"original"), ("verify", b"verify fixture\n")):
                path = self.root / name
                path.write_bytes(raw)
                files[name] = path
            spec = {"schema_version": 1, "program": str(Path(sys.executable).resolve()),
                    "argv": [], "cwd": str(self.root), "shell": False, "timeout_seconds": 5}
            self.stdin = "line1\r\nline2\nРусский\n"
            self.plan = {
                "schema_version": 1, "target": str(self.target),
                "artifacts": [{"id": name, "path": str(path), "non_secret": True}
                              for name, path in files.items()],
                "process": dict(spec, argv=["-I", {"artifact": "restore"},
                                              {"artifact": "backup"}, str(self.target)], stdin_utf8=self.stdin),
                "verify": dict(spec, argv=["-I", {"artifact": "verify"}, str(self.target)]),
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
            return prepare_process(attempt_txn_id=binding.attempt_txn_id,
                                   role=binding.role, **self.context)

        def test_real_projection_preserves_prepared_facts(self):
            binding = CallBinding("agent-safe-integration-test", "projection",
                                  self.source.txn_id, "20260922-120000-1234abcd", "process")
            prepared = self.acquire(binding)
            projection = project_prepared(prepared, platform=("windows" if os.name == "nt" else "linux"))
            operation = projection.operation()
            self.assertEqual(operation["execution"]["argv"], [prepared.program, *prepared.argv])
            raw = self.stdin.encode("utf-8")
            self.assertEqual(operation["execution"]["stdin"], {
                "mode": "pipe", "encoding": "utf-8", "size_bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            })
            self.assertEqual(len(operation["context_dependencies"]), 3)

        def test_real_execution_port_gates_both_spawns(self):
            owner = RealLibraryOwner(self.acquire)
            with patch("agent_safe.adapters.recover._run", side_effect=[
                {"outcome": "exited", "returncode": 0},
                {"outcome": "exited", "returncode": 0, "stdout": '{"restored":true}'},
            ]) as run:
                result = _recover_managed(
                    journal=self.journal, source_id=self.source.txn_id,
                    plan_raw=json.dumps(self.plan), reason="real library test", authority=owner,
                )
            self.assertEqual(result.status, Status.DONE)
            self.assertEqual(run.call_count, 2)

        def test_real_ask_without_host_event_blocks_spawn(self):
            owner = RealLibraryOwner(self.acquire, approve=False)
            with patch("agent_safe.adapters.recover._run") as run:
                result = _recover_managed(
                    journal=self.journal, source_id=self.source.txn_id,
                    plan_raw=json.dumps(self.plan), reason="real library test", authority=owner,
                )
            run.assert_not_called()
            self.assertEqual(result.status, Status.FAILED)


if __name__ == "__main__":
    unittest.main()
