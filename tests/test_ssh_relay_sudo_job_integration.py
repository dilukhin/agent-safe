from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SSH_RELAY = ROOT / "_deps" / "ssh_relay"
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(SSH_RELAY))

import paramiko
import ssh_relay
from agent_safe.adapters import ssh_relay_sudo_job as sudo_job
from agent_safe.core.journal import Journal

PASSWORD = "relay-ci-artificial-password-52"
SOURCE_SHA = "d997b377bf9703db890f3d0f8a4535d19f27997d"


@unittest.skipUnless(
    os.environ.get("GITHUB_ACTIONS") == "true" and sys.platform == "linux",
    "Требуется одноразовый GitHub Actions Ubuntu",
)
class SudoJobCrossRepoIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="agent-safe-sudo-job-")
        cls.root = Path(cls.tmp.name)
        cls.state = cls.root / "relay-state"
        cls.state.mkdir()

        key = cls.root / "host-key"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
            check=True,
        )
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            cls.port = sock.getsockname()[1]

        config = cls.root / "sshd_config"
        config.write_text(
            f"Port {cls.port}\n"
            "ListenAddress 127.0.0.1\n"
            f"HostKey {key}\n"
            "PasswordAuthentication yes\n"
            "KbdInteractiveAuthentication no\n"
            "UsePAM no\n"
            "PermitRootLogin no\n"
            "AllowUsers relayci\n"
            "LogLevel ERROR\n"
            f"PidFile {cls.root / 'sshd.pid'}\n",
            encoding="utf-8",
        )
        cls.sshd_log = (cls.root / "sshd.log").open("wb")
        cls.sshd = subprocess.Popen(
            ["sudo", "-n", "/usr/sbin/sshd", "-D", "-e", "-f", str(config)],
            stdout=cls.sshd_log,
            stderr=cls.sshd_log,
        )

        cls.known = cls.root / "known_hosts"
        public = key.with_suffix(".pub").read_text(encoding="utf-8").split()
        cls.known.write_text(
            f"[127.0.0.1]:{cls.port} {public[0]} {public[1]}\n",
            encoding="utf-8",
        )
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", cls.port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise AssertionError("Испытательный sshd не запустился")

        cls.env = {
            **os.environ,
            "GITHUB_ACTIONS": "true",
            "SSH_RELAY_SOURCE_SHA": SOURCE_SHA,
            "XDG_STATE_HOME": str(cls.state),
            "LOCALAPPDATA": str(cls.state),
            "SSH_RELAY_SUDO_JOB_TEST_PASSWORD": PASSWORD,
            "SSH_RELAY_SUDO_JOB_TEST_PORT": str(cls.port),
            "SSH_RELAY_SUDO_JOB_TEST_KNOWN_HOSTS": str(cls.known),
            "PYTHONIOENCODING": "utf-8",
        }
        os.environ.update({
            "SSH_RELAY_SOURCE_SHA": SOURCE_SHA,
            "XDG_STATE_HOME": str(cls.state),
            "LOCALAPPDATA": str(cls.state),
            "PYTHONIOENCODING": "utf-8",
        })

        cls.daemon_stdout = (cls.root / "daemon.stdout.log").open("wb")
        cls.daemon_stderr = (cls.root / "daemon.stderr.log").open("wb")
        cls.daemon = subprocess.Popen(
            [sys.executable, "-u", str(SSH_RELAY / "tests" / "daemon_sudo_job_runner.py")],
            cwd=SSH_RELAY,
            env=cls.env,
            stdout=cls.daemon_stdout,
            stderr=cls.daemon_stderr,
        )

        cls.session_path = cls.state / "ssh_relay" / "sessions" / "ci-sudo-job.json"
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if cls.daemon.poll() is not None:
                raise AssertionError("Испытательный relay daemon завершился раньше времени")
            try:
                cls.session = json.loads(cls.session_path.read_text(encoding="utf-8"))
                status = ssh_relay._core.request_daemon(cls.session, "status", response_timeout=2)
                identity = status.get("verified_identity")
                if status.get("sudo_jobs_enabled") and isinstance(identity, dict):
                    cls.identity = identity
                    break
            except (OSError, ValueError, ssh_relay.RelayError):
                pass
            time.sleep(0.05)
        else:
            raise AssertionError("Не дождались ssh_relay daemon")

        self_client = paramiko.SSHClient()
        self_client.load_host_keys(str(cls.known))
        self_client.connect(
            "127.0.0.1",
            port=cls.port,
            username="relayci",
            password=PASSWORD,
            allow_agent=False,
            look_for_keys=False,
        )
        _stdin, stdout, _stderr = self_client.exec_command("sudo -k -n true")
        if stdout.channel.recv_exit_status() == 0:
            raise AssertionError("Испытательный пользователь обязан требовать sudo-пароль")
        self_client.close()

        cls.identity_file = cls.root / "identity.json"
        cls.identity_file.write_text(json.dumps(cls.identity), encoding="utf-8")
        cls.relay = f"{sys.executable} {SSH_RELAY / 'ssh_relay.py'}"

    @classmethod
    def tearDownClass(cls):
        try:
            if getattr(cls, "daemon", None) is not None and cls.daemon.poll() is None:
                try:
                    ssh_relay._core.request_daemon(cls.session, "stop", response_timeout=3)
                except Exception:
                    cls.daemon.terminate()
                cls.daemon.wait(timeout=10)
            if getattr(cls, "sshd", None) is not None:
                cls.sshd.terminate()
                try:
                    cls.sshd.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    cls.sshd.kill()
            for stream_name in ("daemon_stdout", "daemon_stderr", "sshd_log"):
                stream = getattr(cls, stream_name, None)
                if stream:
                    stream.close()
            for path in (cls.root / "daemon.stdout.log", cls.root / "daemon.stderr.log"):
                if path.exists() and PASSWORD.encode("utf-8") in path.read_bytes():
                    raise AssertionError("Испытательный пароль попал в журнал daemon")
        finally:
            cls.tmp.cleanup()

    def test_agent_safe_waits_for_completion_and_verifies_package(self):
        journal = Journal(self.root / "agent-state")
        job_id = str(uuid.uuid4())
        transaction_id = str(uuid.uuid4())
        command = "DEBIAN_FRONTEND=noninteractive apt-get -y install hello"
        command_hash = hashlib.sha256(command.encode("utf-8")).hexdigest()
        verify = "dpkg-query -W -f='{\"installed\":true}' hello"

        first = sudo_job.start(
            self.relay,
            command,
            journal=journal,
            host_label="ci-ubuntu",
            relay_name="ci-sudo-job",
            job_id=job_id,
            transaction_id=transaction_id,
            expected_identity_file=str(self.identity_file),
            expected_state_json='{"assertions":{"installed":true}}',
            verify_remote_command=verify,
            recovery_plan="Проверить dpkg --audit и при необходимости восстановить пакетный менеджер вручную.",
            reason="Сквозная проверка длительной установки пакета",
            approved=True,
            timeout=120,
        )

        if first.status.value == "done":
            final = first
        else:
            self.assertIn(first.status.value, {"blocked"}, first.to_dict())
            final = sudo_job.observe(
                self.relay,
                journal=journal,
                operation="wait",
                relay_name="ci-sudo-job",
                job_id=job_id,
                transaction_id=transaction_id,
                command_hash=command_hash,
                expected_identity_file=str(self.identity_file),
                verify_remote_command=verify,
                reason="Дождаться завершения и проверить установленный пакет",
                timeout=120,
                wait_timeout=300,
                poll_interval=1,
            )

        self.assertEqual("done", final.status.value, final.to_dict())
        self.assertTrue(final.verification_complete, final.to_dict())
        self.assertFalse(journal.is_blocked())
        self.assertEqual(True, final.actual_state.get("installed"))
        record_text = journal.journal_path.read_text(encoding="utf-8")
        self.assertNotIn(command, record_text)
        self.assertNotIn(PASSWORD, record_text)
        self.assertIn(command_hash, record_text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
