import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_safe.adapters import ssh_relay_sudo_job as sudo_job
from agent_safe.adapters.fs import SafetyError
from agent_safe.core.journal import Journal


JOB = "11111111-1111-4111-8111-111111111111"
TX = "22222222-2222-4222-8222-222222222222"
COMMAND = "apt-get install -y hello"
COMMAND_HASH = hashlib.sha256(COMMAND.encode("utf-8")).hexdigest()
VERIFY = "printf '{\"installed\":true}'"
TARGET = {
    "remote_host": "198.51.100.42",
    "remote_port": 22,
    "remote_user": "donpedro",
    "host_key_algorithm": "ssh-ed25519",
    "remote_host_key_sha256": "SHA256:" + "A" * 43,
}
IDENTITY = {
    "schema_version": 1,
    **TARGET,
    "trusted_known_hosts": True,
    "daemon_instance_id": "44444444-4444-4444-8444-444444444444",
    "connection_generation": 1,
    "daemon_source_sha": "a" * 40,
}


def witness(phase, *, exit_code=None):
    value = {
        "schema_version": 1,
        "job_id": JOB,
        "transaction_id": TX,
        "command_sha256": COMMAND_HASH,
        "target": TARGET,
        "boot_id": "55555555-5555-4555-8555-555555555555",
        "unit": "ssh-relay-sudo-" + JOB.replace("-", "") + ".service",
        "phase": phase,
        "invocation_id": "a" * 32,
    }
    if exit_code is not None:
        value["exit_code"] = exit_code
    canonical = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {**value, "witness_sha256": hashlib.sha256(canonical).hexdigest()}


def payload(operation, state, **updates):
    value = {
        "schema_version": 1,
        "tool": "ssh_relay",
        "tool_version": "0.12.0",
        "result_type": "sudo_job",
        "operation": operation,
        "job_id": JOB,
        "transaction_id": TX,
        "command_sha256": COMMAND_HASH,
        "state": state,
        "verified_identity": IDENTITY,
        "process_exit_code": 0,
    }
    if state == "running":
        value["start_witness"] = witness("start")
    elif state == "succeeded":
        value.update(exit_code=0, accounting_status="recorded",
                     start_witness=witness("start"), completion_witness=witness("completion", exit_code=0))
    elif state == "failed":
        value.update(exit_code=7, accounting_status="recorded", process_exit_code=7,
                     start_witness=witness("start"), completion_witness=witness("completion", exit_code=7))
    elif state == "unknown":
        value["process_exit_code"] = 3
    elif state == "not_started":
        value.pop("verified_identity")
        value["process_exit_code"] = 2
    value.update(updates)
    return value


class SudoJobLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.journal = Journal(self.root)
        self.identity = self.root / "identity.json"
        self.identity.write_text(json.dumps(IDENTITY), encoding="utf-8")

    @staticmethod
    def run_for(value):
        return {
            "launched": True,
            "returncode": value["process_exit_code"],
            "stdout": json.dumps(value),
            "stderr": "SECRET_LOCAL_STDERR",
        }

    def start(self, value):
        with patch.object(sudo_job, "_run", return_value=self.run_for(value)):
            return sudo_job.start(
                "ssh_relay", COMMAND, journal=self.journal, host_label="prod", relay_name="prod",
                job_id=JOB, transaction_id=TX, expected_identity_file=str(self.identity),
                expected_state_json='{"assertions":{"installed":true}}',
                verify_remote_command=VERIFY, recovery_plan="проверить dpkg и восстановить вручную",
                reason="установка пакета", approved=True,
            )

    def test_running_creates_durable_barrier_and_does_not_claim_success(self):
        record = self.start(payload("start", "running"))
        self.assertEqual("blocked", record.status.value)
        self.assertTrue(self.journal.is_blocked())
        text = self.journal.journal_path.read_text(encoding="utf-8")
        self.assertNotIn(COMMAND, text)
        self.assertNotIn("SECRET_LOCAL_STDERR", text)
        self.assertIn(COMMAND_HASH, text)

    def test_proven_not_started_clears_barrier(self):
        record = self.start(payload("start", "not_started"))
        self.assertEqual("failed", record.status.value)
        self.assertFalse(self.journal.is_blocked())

    def test_unknown_keeps_barrier_without_retry(self):
        record = self.start(payload("start", "unknown"))
        self.assertEqual("unexpected", record.status.value)
        self.assertTrue(self.journal.is_blocked())
        self.assertEqual(1, len(self.journal.records()))

    def test_succeeded_observation_verifies_and_clears_barrier(self):
        self.start(payload("start", "running"))
        verify_payload = {
            "schema_version": 1, "tool": "ssh_relay", "tool_version": "0.12.0",
            "action": "exec", "operation_status": "succeeded", "session": "prod",
            "remote_host": TARGET["remote_host"], "remote_port": 22, "remote_user": "donpedro",
            "sudo": False, "risky": False, "command_status": "succeeded", "command_exit_code": 0,
            "receipt_status": "not_requested", "partial_success": False,
            "stdout": '{"installed":true}', "stderr": "", "error_code": None, "error_stage": None,
        }
        control = self.run_for(payload("status", "succeeded"))
        verify_run = {"launched": True, "returncode": 0, "stdout": json.dumps(verify_payload), "stderr": ""}
        with patch.object(sudo_job, "_run", return_value=control), patch.object(
            sudo_job, "_run_machine", return_value=verify_run
        ):
            record = sudo_job.observe(
                "ssh_relay", journal=self.journal, operation="status", relay_name="prod",
                job_id=JOB, transaction_id=TX, command_hash=COMMAND_HASH,
                expected_identity_file=str(self.identity), verify_remote_command=VERIFY,
                reason="проверка завершения",
            )
        self.assertEqual("done", record.status.value)
        self.assertFalse(self.journal.is_blocked())
        self.assertTrue(record.verification_complete)

    def test_accounting_failure_never_becomes_done(self):
        self.start(payload("start", "running"))
        value = payload("status", "succeeded", accounting_status="failed", completion_witness=None)
        with patch.object(sudo_job, "_run", return_value=self.run_for(value)):
            record = sudo_job.observe(
                "ssh_relay", journal=self.journal, operation="status", relay_name="prod",
                job_id=JOB, transaction_id=TX, command_hash=COMMAND_HASH,
                expected_identity_file=str(self.identity), verify_remote_command=VERIFY,
                reason="проверка учёта",
            )
        self.assertEqual("unexpected", record.status.value)
        self.assertTrue(self.journal.is_blocked())

    def test_changed_target_is_rejected_before_control_call(self):
        self.start(payload("start", "running"))
        changed = {**IDENTITY, "remote_host_key_sha256": "SHA256:" + "B" * 43, "connection_generation": 2}
        self.identity.write_text(json.dumps(changed), encoding="utf-8")
        with patch.object(sudo_job, "_run") as run:
            with self.assertRaises(SafetyError):
                sudo_job.observe(
                    "ssh_relay", journal=self.journal, operation="status", relay_name="prod",
                    job_id=JOB, transaction_id=TX, command_hash=COMMAND_HASH,
                    expected_identity_file=str(self.identity), verify_remote_command=VERIFY,
                    reason="проверка другой цели",
                )
        run.assert_not_called()

    def test_stop_is_separate_mutation_and_keeps_barrier(self):
        self.start(payload("start", "running"))
        value = payload("stop", "running", stop_requested=True)
        with patch.object(sudo_job, "_run", return_value=self.run_for(value)):
            record = sudo_job.stop(
                "ssh_relay", journal=self.journal, relay_name="prod", job_id=JOB,
                transaction_id=TX, command_hash=COMMAND_HASH,
                expected_identity_file=str(self.identity), reason="мягкая остановка", approved=True,
            )
        self.assertEqual("blocked", record.status.value)
        self.assertTrue(self.journal.is_blocked())

    def test_tail_does_not_persist_sensitive_log(self):
        self.start(payload("start", "running"))
        before = len(self.journal.records())
        value = payload("tail", "running", log="TAIL_SECRET", stream="stdout")
        with patch.object(sudo_job, "_run", return_value=self.run_for(value)):
            result = sudo_job.tail(
                "ssh_relay", journal=self.journal, relay_name="prod", job_id=JOB,
                transaction_id=TX, command_hash=COMMAND_HASH, expected_identity_file=str(self.identity),
            )
        self.assertEqual("TAIL_SECRET", result["log"])
        self.assertEqual(before, len(self.journal.records()))
        self.assertNotIn("TAIL_SECRET", self.journal.journal_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
