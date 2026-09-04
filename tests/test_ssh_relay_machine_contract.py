import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from agent_safe.adapters import ssh_relay
from agent_safe.adapters.fs import SafetyError
from agent_safe.core.journal import Journal


_RECEIPT_HASH = "a" * 64
_EXIT_BY_STATUS = {
    "succeeded": 0,
    "not_started": 10,
    "command_failed": 11,
    "partial_success": 12,
    "unknown": 13,
}


def risky_payload(
    status: str,
    transaction_id: str,
    *,
    mode: str = "exec",
    command_exit_code: int | None = 0,
    receipt_status: str = "succeeded",
    partial_success: bool = False,
    stdout: str = "MAIN_SECRET_STDOUT",
    stderr: str = "MAIN_SECRET_STDERR",
) -> dict:
    command_status = {
        "succeeded": "succeeded",
        "not_started": "not_started",
        "command_failed": "failed",
        "partial_success": "succeeded",
        "unknown": "unknown",
    }[status]
    if status in {"not_started", "unknown"}:
        command_exit_code = None
    return {
        "schema_version": 1,
        "tool": "ssh_relay",
        "tool_version": "0.9.1",
        "action": mode,
        "operation_status": status,
        "session": "prod",
        "remote_host": "198.51.100.10",
        "remote_port": 22,
        "remote_user": "operator",
        "sudo": mode == "sudo-exec",
        "risky": True,
        "command_status": command_status,
        "command_exit_code": command_exit_code,
        "receipt_status": receipt_status,
        "partial_success": partial_success,
        "stdout": stdout,
        "stderr": stderr,
        "error_code": None,
        "error_stage": None,
        "transaction_id": transaction_id,
        "receipt_id": str(uuid4()),
        "receipt_hash": _RECEIPT_HASH if receipt_status == "succeeded" else None,
        "receipt_path": "/var/lib/agent-safe/changes.jsonl",
    }


def verify_payload(*, mode: str = "exec", stdout: str = '{"service":"active"}') -> dict:
    return {
        "schema_version": 1,
        "tool": "ssh_relay",
        "tool_version": "0.9.1",
        "action": mode,
        "operation_status": "succeeded",
        "session": "prod",
        "remote_host": "198.51.100.10",
        "remote_port": 22,
        "remote_user": "operator",
        "sudo": mode == "sudo-exec",
        "risky": False,
        "command_status": "succeeded",
        "command_exit_code": 0,
        "receipt_status": "not_requested",
        "partial_success": False,
        "stdout": stdout,
        "stderr": "",
        "error_code": None,
        "error_stage": None,
    }


class SshRelayMachineContractTests(unittest.TestCase):
    def _run_case(
        self,
        main_builder,
        *,
        mode: str = "exec",
        receipt_path: str | None = None,
        verify_stdout: str = '{"service":"active"}',
    ):
        with tempfile.TemporaryDirectory() as td:
            journal = Journal(Path(td))
            calls: list[list[str]] = []

            def runner(args, _cwd, timeout=120):
                self.assertEqual(120, timeout)
                calls.append(list(args))
                if "--risky" in args:
                    transaction_id = args[args.index("--transaction-id") + 1]
                    payload = main_builder(transaction_id)
                    return {
                        "launched": True,
                        "returncode": _EXIT_BY_STATUS[payload["operation_status"]],
                        "stdout": json.dumps(payload),
                        "stderr": "LOCAL_SECRET_STDERR",
                    }
                payload = verify_payload(mode=mode, stdout=verify_stdout)
                return {
                    "launched": True,
                    "returncode": 0,
                    "stdout": json.dumps(payload),
                    "stderr": "",
                }

            with patch.object(ssh_relay, "_run_machine", side_effect=runner):
                record = ssh_relay.ssh_relay_risky(
                    "ssh_relay",
                    "systemctl restart app; printf COMMAND_SECRET >/dev/null",
                    journal=journal,
                    host_label="prod",
                    reason="проверка машинного контракта",
                    relay_name="prod",
                    relay_mode=mode,
                    receipt_path=receipt_path,
                    expected_state_json=json.dumps(
                        {
                            "assertions": {"service": "active"},
                            "declarations": {"operation": "restart"},
                        }
                    ),
                    rollback_command="systemctl restart app-old; printf ROLLBACK_SECRET >/dev/null",
                    verify_remote_command="cat /run/app-state.json",
                    approved=True,
                    allow_critical=False,
                )
            return record, journal, calls

    def test_success_requires_receipt_and_verify(self):
        record, journal, calls = self._run_case(lambda tx: risky_payload("succeeded", tx))
        self.assertEqual("done", record.status.value)
        self.assertFalse(journal.is_blocked())
        self.assertEqual(record.txn_id, calls[0][calls[0].index("--transaction-id") + 1])
        self.assertEqual(record.txn_id, record.metadata["relay"]["remote_receipt"]["transaction_id"])
        self.assertEqual(_RECEIPT_HASH, record.metadata["relay"]["remote_receipt"]["receipt_hash"])
        self.assertEqual(0, record.metadata["relay"]["local_process"]["returncode"])
        self.assertEqual(0, record.metadata["relay"]["remote_command"]["exit_code"])
        self.assertTrue(record.verification_complete)
        self.assertEqual(1, sum("--risky" in call for call in calls))

    def test_partial_success_enters_recovery_without_retry(self):
        record, journal, calls = self._run_case(
            lambda tx: risky_payload(
                "partial_success",
                tx,
                receipt_status="failed",
                partial_success=True,
            )
        )
        self.assertEqual("unexpected", record.status.value)
        self.assertTrue(journal.is_blocked())
        self.assertEqual("partial_success", record.metadata["relay"]["operation_status"])
        self.assertEqual("failed", record.metadata["relay"]["remote_receipt"]["status"])
        self.assertEqual(1, sum("--risky" in call for call in calls))

    def test_unknown_enters_recovery_without_retry(self):
        record, journal, calls = self._run_case(
            lambda tx: risky_payload(
                "unknown",
                tx,
                receipt_status="unknown",
                command_exit_code=None,
            )
        )
        self.assertEqual("unexpected", record.status.value)
        self.assertTrue(journal.is_blocked())
        self.assertEqual("unknown", record.metadata["relay"]["operation_status"])
        self.assertEqual(1, sum("--risky" in call for call in calls))

    def test_command_failure_keeps_remote_exit_separate(self):
        record, journal, calls = self._run_case(
            lambda tx: risky_payload(
                "command_failed",
                tx,
                command_exit_code=7,
                receipt_status="not_attempted",
            )
        )
        self.assertEqual("unexpected", record.status.value)
        self.assertTrue(journal.is_blocked())
        self.assertEqual(11, record.metadata["relay"]["local_process"]["returncode"])
        self.assertEqual(7, record.metadata["relay"]["remote_command"]["exit_code"])
        self.assertEqual(1, sum("--risky" in call for call in calls))

    def test_not_started_is_failed_without_recovery_or_verify(self):
        record, journal, calls = self._run_case(
            lambda tx: risky_payload(
                "not_started",
                tx,
                command_exit_code=None,
                receipt_status="not_attempted",
            )
        )
        self.assertEqual("failed", record.status.value)
        self.assertFalse(journal.is_blocked())
        self.assertEqual(1, len(calls))
        self.assertEqual(10, record.metadata["relay"]["local_process"]["returncode"])

    def test_sudo_exec_uses_same_mode_for_verify(self):
        record, journal, calls = self._run_case(
            lambda tx: risky_payload("succeeded", tx, mode="sudo-exec"),
            mode="sudo-exec",
            receipt_path="/var/lib/agent-safe/changes.jsonl",
        )
        self.assertEqual("done", record.status.value)
        self.assertFalse(journal.is_blocked())
        self.assertEqual("sudo-exec", calls[0][1])
        self.assertEqual("sudo-exec", calls[1][1])
        self.assertNotIn("--risky", calls[1])
        self.assertEqual("sudo-exec", record.expected_state["declarations"]["ssh_relay_mode"])
        self.assertTrue(record.expected_state["declarations"]["ssh_relay_sudo"])

    def test_sudo_exec_requires_absolute_system_receipt_path(self):
        with tempfile.TemporaryDirectory() as td:
            journal = Journal(Path(td))
            for receipt_path in (None, "~/.local/state/changes.jsonl"):
                with self.subTest(receipt_path=receipt_path), self.assertRaises(SafetyError):
                    ssh_relay.ssh_relay_risky(
                        "ssh_relay",
                        "systemctl restart app",
                        journal=journal,
                        host_label="prod",
                        reason="sudo",
                        relay_mode="sudo-exec",
                        receipt_path=receipt_path,
                        expected_state_json='{"assertions":{"service":"active"}}',
                        rollback_command="systemctl restart app-old",
                        verify_remote_command="cat /run/app-state.json",
                        approved=True,
                        allow_critical=False,
                    )

    def test_receipt_remote_command_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            journal = Journal(Path(td))
            with self.assertRaises(SafetyError):
                ssh_relay.ssh_relay_risky(
                    "ssh_relay",
                    "systemctl restart app",
                    journal=journal,
                    host_label="prod",
                    reason="legacy receipt",
                    expected_state_json='{"assertions":{"service":"active"}}',
                    rollback_command="systemctl restart app-old",
                    verify_remote_command="cat /run/app-state.json",
                    receipt_remote_command="echo receipt",
                    approved=True,
                    allow_critical=False,
                )

    def test_transaction_mismatch_is_incident(self):
        record, journal, calls = self._run_case(lambda _tx: risky_payload("succeeded", "other-transaction"))
        self.assertEqual("unexpected", record.status.value)
        self.assertTrue(journal.is_blocked())
        self.assertEqual("relay_machine_transaction_mismatch", record.metadata["relay"]["contract_error"])
        self.assertEqual(1, sum("--risky" in call for call in calls))

    def test_launcher_success_is_not_final_success(self):
        record, journal, _calls = self._run_case(
            lambda tx: risky_payload("succeeded", tx),
            verify_stdout='{"service":"inactive"}',
        )
        self.assertEqual("unexpected", record.status.value)
        self.assertTrue(journal.is_blocked())
        self.assertFalse(record.verification_complete)

    def test_commands_and_stream_contents_are_not_written_to_record(self):
        record, _journal, _calls = self._run_case(lambda tx: risky_payload("succeeded", tx))
        serialized = json.dumps(record.to_dict(), ensure_ascii=False)
        for secret in (
            "COMMAND_SECRET",
            "ROLLBACK_SECRET",
            "MAIN_SECRET_STDOUT",
            "MAIN_SECRET_STDERR",
            "LOCAL_SECRET_STDERR",
        ):
            self.assertNotIn(secret, serialized)

    def test_rollback_is_recorded_as_nonautomatic_hash_and_never_executed(self):
        record, journal, calls = self._run_case(
            lambda tx: risky_payload(
                "partial_success",
                tx,
                receipt_status="failed",
                partial_success=True,
            )
        )
        self.assertTrue(journal.is_blocked())
        self.assertEqual("manual-command", record.undo["op"])
        self.assertFalse(record.undo["automatic"])
        self.assertFalse(record.undo["command_stored"])
        self.assertEqual(64, len(record.undo["command_sha256"]))
        self.assertEqual(1, sum("--risky" in call for call in calls))
        self.assertFalse(any("app-old" in " ".join(call) for call in calls))

    def test_named_sessions_keep_receipts_and_targets_separate(self):
        records = []
        for relay_name, host_label, remote_host in (
            ("one", "server-one", "198.51.100.11"),
            ("two", "server-two", "198.51.100.12"),
        ):
            with tempfile.TemporaryDirectory() as td:
                journal = Journal(Path(td))
                calls = []

                def runner(args, _cwd, timeout=120):
                    calls.append(list(args))
                    if "--risky" in args:
                        tx = args[args.index("--transaction-id") + 1]
                        payload = risky_payload("succeeded", tx)
                        payload["session"] = relay_name
                        payload["remote_host"] = remote_host
                        return {"launched": True, "returncode": 0, "stdout": json.dumps(payload), "stderr": ""}
                    payload = verify_payload()
                    payload["session"] = relay_name
                    payload["remote_host"] = remote_host
                    return {"launched": True, "returncode": 0, "stdout": json.dumps(payload), "stderr": ""}

                with patch.object(ssh_relay, "_run_machine", side_effect=runner):
                    record = ssh_relay.ssh_relay_risky(
                        "ssh_relay",
                        "systemctl restart app",
                        journal=journal,
                        host_label=host_label,
                        reason="разделение сессий",
                        relay_name=relay_name,
                        expected_state_json='{"assertions":{"service":"active"}}',
                        rollback_command="systemctl restart app-old",
                        verify_remote_command="cat /run/app-state.json",
                        approved=True,
                        allow_critical=False,
                    )
                records.append(record)

        first, second = records
        self.assertEqual("one", first.metadata["relay"]["session"])
        self.assertEqual("two", second.metadata["relay"]["session"])
        self.assertEqual("198.51.100.11", first.metadata["relay"]["remote_host"])
        self.assertEqual("198.51.100.12", second.metadata["relay"]["remote_host"])
        self.assertEqual(["host:server-one"], first.target_paths)
        self.assertEqual(["host:server-two"], second.target_paths)
        self.assertNotEqual(first.txn_id, second.txn_id)
        self.assertNotEqual(
            first.metadata["relay"]["remote_receipt"]["receipt_id"],
            second.metadata["relay"]["remote_receipt"]["receipt_id"],
        )

    def test_timeout_after_launcher_start_is_not_not_started(self):
        with patch.object(subprocess, "run", side_effect=subprocess.TimeoutExpired(["ssh_relay"], 1)):
            result = ssh_relay._run_machine(["ssh_relay", "exec", "true"], Path.cwd(), timeout=1)
        self.assertTrue(result["launched"])
        self.assertEqual("TimeoutExpired", result["error_type"])

    def test_entrypoint_exposes_explicit_relay_mode(self):
        from agent_safe.entrypoint import build_parser

        args = build_parser().parse_args(
            [
                "ssh-relay-risky",
                "--relay",
                "ssh_relay",
                "--host-label",
                "prod",
                "--remote-command",
                "systemctl restart app",
                "--reason",
                "test",
                "--relay-mode",
                "sudo-exec",
            ]
        )
        self.assertEqual("sudo-exec", args.relay_mode)
        self.assertEqual(120, args.timeout)

    def test_build_risky_command_requires_transaction_id(self):
        with self.assertRaises(SafetyError):
            ssh_relay.build_relay_command("ssh_relay", "true", risky=True, machine_json=True)
        command = ssh_relay.build_relay_command(
            "ssh_relay",
            "true",
            relay_mode="sudo-exec",
            relay_name="prod",
            risky=True,
            machine_json=True,
            transaction_id="tx-1",
            receipt_path="/var/lib/agent-safe/changes.jsonl",
        )
        self.assertEqual(
            [
                "ssh_relay",
                "sudo-exec",
                "--name",
                "prod",
                "--json",
                "--risky",
                "--transaction-id",
                "tx-1",
                "--receipt-path",
                "/var/lib/agent-safe/changes.jsonl",
                "true",
            ],
            command,
        )


if __name__ == "__main__":
    unittest.main()
