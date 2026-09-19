"""Проверки восстановления на собственных временных файлах без внешних систем."""

import copy
import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_safe.adapters.exec_adapter import _run, exec_risky
from agent_safe.adapters.fs import SafetyError, undo_record, redo_record
from agent_safe.adapters.recover import recover
from agent_safe.cli import main
from agent_safe.core.journal import Journal
from agent_safe.core.models import Status
from agent_safe.core.process_spec import read_regular, strict_object
from agent_safe.core.rollback import local_journal


class SavedRollbackTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.journal = Journal(self.root)
        self.target = self.root / "цель с пробелом.txt"
        self.target.write_bytes(b"modified")
        self.backup = self.root / "backup.bin"
        self.backup.write_bytes(b"original")
        self.script = self.root / "restore.py"
        self.script.write_text("from pathlib import Path\nimport sys\nPath(sys.argv[2]).write_bytes(Path(sys.argv[1]).read_bytes())\n", encoding="utf-8")
        self.verify = self.root / "check.py"
        self.verify.write_text("from pathlib import Path\nimport sys,json\nprint(json.dumps({'restored':Path(sys.argv[1]).read_bytes()==b'original'}))\n", encoding="utf-8")
        program = str(Path(sys.executable).resolve())
        spec = {"schema_version": 1, "program": program, "argv": [], "cwd": str(self.root),
                "shell": False, "timeout_seconds": 5}
        self.plan = {
            "schema_version": 1, "target": str(self.target),
            "artifacts": [{"id": name, "path": str(path), "non_secret": True}
                          for name, path in (("restore", self.script), ("backup", self.backup), ("check", self.verify))],
            "process": dict(spec, argv=["-I", {"artifact": "restore"}, {"artifact": "backup"}, str(self.target)]),
            "verify": dict(spec, argv=["-I", {"artifact": "check"}, str(self.target)]),
            "expected_state": {"assertions": {"restored": True}},
        }
        self.kwargs = dict(journal=self.journal, channel="local", domain="test", target=str(self.target),
                           reason="изолированная проверка", expected_state_json='{"assertions":{"ready":true}}',
                           verify_command="inspect-state", approved=True)

    def source(self, responses=None, **kwargs):
        with patch("agent_safe.adapters.exec_adapter._run", side_effect=responses or [
            {"outcome": "exited", "returncode": 0}, {"outcome": "exited", "returncode": 0, "stdout": '{"ready":true}'},
        ]):
            return exec_risky(["apply-update"], rollback_plan_json=json.dumps(self.plan), **dict(self.kwargs, **kwargs))

    def restore(self, source, **overrides):
        args = dict(journal=self.journal, source_id=source.txn_id, plan_raw=json.dumps(self.plan),
                    approved=True, reason="отдельное восстановление тестовой цели")
        args.update(overrides)
        return recover(**args)

    def bundle(self, source):
        return Path(source.metadata["recovery"]["bundle"])

    def assert_no_restore(self, source, **overrides):
        with patch("agent_safe.adapters.recover._run") as run, self.assertRaises(SafetyError):
            self.restore(source, **overrides)
        run.assert_not_called()

    def test_actual_cli_round_trip_uses_saved_files(self):
        update = self.root / "apply.py"
        update.write_text("from pathlib import Path\nimport sys\nPath(sys.argv[1]).write_bytes(b'modified')\n", encoding="utf-8")
        check = self.root / "main_check.py"
        check.write_text("from pathlib import Path\nimport sys,json\nprint(json.dumps({'ready':Path(sys.argv[1]).read_bytes()==b'modified'}))\n", encoding="utf-8")
        self.target.write_bytes(b"original")
        plan = self.root / "plan.json"
        plan.write_text(json.dumps(self.plan), encoding="utf-8")
        verify_args = [sys.executable, str(check), str(self.target)]
        verify_command = subprocess.list2cmdline(verify_args) if os.name == "nt" else shlex.join(verify_args)
        with patch("agent_safe.cli.print_json") as output:
            result = main(["--root", str(self.root), "exec-risky", "--channel", "local", "--target", str(self.target),
                           "--reason", "тест", "--expected-state", self.kwargs["expected_state_json"],
                           "--rollback-plan-file", str(plan), "--verify-command", verify_command,
                           "--approved", "--", sys.executable, str(update), str(self.target)])
        self.assertEqual(result, 0)
        source = output.call_args.args[0]
        self.assertEqual(self.target.read_bytes(), b"modified")
        self.script.unlink()
        self.backup.unlink()
        self.verify.unlink()
        plan.unlink()
        saved_plan = Path(source["metadata"]["recovery"]["bundle"]) / "plan.json"
        with patch("agent_safe.cli.print_json") as output:
            result = main(["--root", str(self.root), "recover", "--txn-id", source["txn_id"],
                           "--plan-file", str(saved_plan), "--approved", "--reason", "отдельное согласование"])
        self.assertEqual(result, 0)
        restored = output.call_args.args[0]
        self.assertEqual(restored["status"], "done")
        self.assertTrue(restored["verification_complete"])
        self.assertEqual(restored["metadata"]["parent_txn_id"], source["txn_id"])
        self.assertNotEqual(restored["txn_id"], source["txn_id"])
        self.assertEqual(self.target.read_bytes(), b"original")
        self.assertTrue(self.journal.is_blocked())

    def test_failed_source_block_is_preserved_byte_for_byte(self):
        source = self.source([{"outcome": "exited", "returncode": 1}])
        before = self.journal.block_path.read_bytes()
        result = self.restore(source)
        self.assertEqual(result.status, Status.DONE)
        self.assertEqual(self.journal.block_path.read_bytes(), before)
        self.assert_no_restore(source)

    def test_approval_and_exact_transaction_required(self):
        source = self.source()
        for options in ({"approved": False}, {"reason": " "}, {"source_id": "last"},
                        {"source_id": "../outside"}, {"retry_after": "unknown"}):
            with self.subTest(options=options):
                self.assert_no_restore(source, **options)

    def test_tampered_and_missing_artifacts_rejected(self):
        source = self.source()
        artifact = self.bundle(source) / "artifacts" / "backup"
        artifact.write_bytes(b"tampered")
        self.assert_no_restore(source)
        artifact.unlink()
        self.assert_no_restore(source)

    def test_manifest_and_supplied_plan_drift_rejected(self):
        source = self.source()
        changed = copy.deepcopy(self.plan)
        changed["process"]["argv"].append("extra")
        self.assert_no_restore(source, plan_raw=json.dumps(changed))
        manifest = self.bundle(source) / "manifest.json"
        manifest.write_bytes(manifest.read_bytes() + b" ")
        self.assert_no_restore(source)

    def test_target_content_and_identity_drift_rejected(self):
        source = self.source()
        self.target.write_bytes(b"external change")
        self.assert_no_restore(source)
        self.target.unlink()
        self.target.write_bytes(b"modified")
        self.assert_no_restore(source)

    def test_target_parent_replacement_rejected(self):
        parent = self.root / "parent"
        parent.mkdir()
        self.target = parent / "item"
        self.target.write_bytes(b"modified")
        self.plan["target"] = self.kwargs["target"] = str(self.target)
        self.plan["process"]["argv"][-1] = self.plan["verify"]["argv"][-1] = str(self.target)
        source = self.source()
        parent.rename(self.root / "old-parent")
        parent.mkdir()
        self.target.write_bytes(b"modified")
        self.assert_no_restore(source)

    def test_unrelated_and_malformed_block_rejected(self):
        source = self.source()
        for raw in ('{"txn_id":"other"}', '[]', '{"txn_id":"'+source.txn_id+'","pending_txn_id":"other"}', 'broken'):
            self.journal.block_path.write_text(raw, encoding="utf-8")
            self.assert_no_restore(source)
            self.assertEqual(self.journal.block_path.read_text(encoding="utf-8"), raw)

    def test_preparation_is_complete_before_mutation(self):
        def execute(*args, **kwargs):
            record = self.journal.records()[-1]
            self.assertEqual(record["status"], "planned")
            self.assertTrue(self.journal.is_blocked())
            root = Path(record["metadata"]["recovery"]["bundle"])
            self.assertEqual((root / "artifacts" / "backup").read_bytes(), b"original")
            self.assertTrue((root / "manifest.json").is_file())
            return {"outcome": "exited", "returncode": 0, "stdout": '{"ready":true}'}
        self.assertEqual(self.source(execute).status, Status.DONE)

    def test_invalid_plans_never_launch_main(self):
        cases = []
        for key, value in (("schema_version", True), ("target", "relative"), ("extra", 1), ("artifacts", [])):
            cases.append(dict(self.plan, **{key: value}))
        for key, value in (("shell", True), ("timeout_seconds", True), ("cwd", "relative"), ("program", "cmd.exe"),
                           ("argv", ["-c", "code"]), ("env_dependencies", ["TOKEN"]), ("argv", ["-I", {"artifact":"missing"}])):
            plan = copy.deepcopy(self.plan)
            plan["process"][key] = value
            cases.append(plan)
        for plan in cases:
            with self.subTest(plan=plan), patch("agent_safe.adapters.exec_adapter._run") as run:
                with self.assertRaises(SafetyError):
                    exec_risky(["apply-update"], rollback_plan_json=json.dumps(plan), **self.kwargs)
                run.assert_not_called()

    def test_strict_json_unicode_duplicates_and_constants(self):
        for raw in ('{"a":1,"a":2}', '{"a":NaN}', '{"a":1e999}', '{"a":"\\u0000"}', '{"a":"\\ud800"}', '[]'):
            with self.subTest(raw=raw), self.assertRaises(SafetyError):
                strict_object(raw)

    def test_artifact_limits_and_secret_declaration(self):
        self.plan["artifacts"][0]["non_secret"] = False
        with self.assertRaises(SafetyError):
            self.source()
        self.plan["artifacts"][0]["non_secret"] = True
        with self.backup.open("wb") as stream:
            stream.truncate(8 * 1024 * 1024 + 1)
        with patch("agent_safe.adapters.exec_adapter._run") as run, self.assertRaises(SafetyError):
            exec_risky(["apply-update"], rollback_plan_json=json.dumps(self.plan), **self.kwargs)
        run.assert_not_called()

    def test_remote_and_ambiguous_modes_rejected(self):
        for options in ({"channel": "ssh"}, {"rollback_command": "restore"}, {"recovery_contract_json": "{}"}):
            with self.subTest(options=options), self.assertRaises(SafetyError):
                self.source(**options)

    def test_main_not_started_is_distinct_and_not_recoverable(self):
        source = self.source([{"outcome": "not_started", "returncode": 127}])
        self.assertEqual(source.status, Status.FAILED)
        self.assertFalse(self.journal.is_blocked())
        self.assert_no_restore(source)

    def test_not_started_with_unobservable_target_keeps_block(self):
        def execute(*args, **kwargs):
            self.target.unlink()
            self.target.mkdir()
            return {"outcome": "not_started", "returncode": 127}
        source = self.source(execute)
        self.assertEqual(source.status, Status.UNEXPECTED)
        self.assertEqual(source.verify_result["verification_error_code"], "target_observation_failed")
        self.assertTrue(self.journal.is_blocked())

    def test_path_and_descriptor_metadata_agree_for_supported_files(self):
        for name in ("ordinary.bin", "script.py", "executable.exe"):
            with self.subTest(name=name):
                path = self.root / name
                path.write_bytes(b"known bytes")
                self.assertEqual(read_regular(path), b"known bytes")

    def test_legacy_undo_redo_do_not_execute_plan(self):
        source = self.source()
        for operation in (undo_record, redo_record):
            with self.assertRaises(SafetyError):
                operation(source.to_dict(), self.journal)

    def test_verify_failure_keeps_block_and_does_not_retry(self):
        self.verify.write_text("print('{\"restored\":false}')\n", encoding="utf-8")
        source = self.source()
        result = self.restore(source)
        self.assertEqual(result.status, Status.UNEXPECTED)
        self.assertFalse(result.verification_complete)
        self.assertTrue(self.journal.is_blocked())
        self.assert_no_restore(source)

    def test_completed_failure_can_retry_only_with_explicit_reference(self):
        source = self.source()
        with patch("agent_safe.adapters.recover._run", return_value={"outcome": "not_started", "returncode": 127}) as run:
            first = self.restore(source)
        self.assertEqual(run.call_count, 1)
        self.assert_no_restore(source)
        result = self.restore(source, retry_after=first.txn_id)
        self.assertEqual(result.status, Status.DONE)

    def test_unknown_process_or_verify_cannot_retry(self):
        source = self.source()
        with patch("agent_safe.adapters.recover._run", return_value={"outcome": "unknown", "returncode": 127}) as run:
            first = self.restore(source)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(first.status, Status.UNEXPECTED)
        self.assert_no_restore(source, retry_after=first.txn_id)

    def test_truncated_verify_and_duplicate_keys_are_not_success(self):
        source = self.source()
        with patch("agent_safe.adapters.recover._run", side_effect=[
            {"outcome":"exited", "returncode":0},
            {"outcome":"exited", "returncode":0, "stdout":'{"restored":true}', "stdout_truncated":True},
        ]):
            first = self.restore(source)
        self.assertEqual(first.status, Status.UNEXPECTED)
        with patch("agent_safe.adapters.recover._run", side_effect=[
            {"outcome":"exited", "returncode":0},
            {"outcome":"exited", "returncode":0, "stdout":'{"restored":false,"restored":true}'},
        ]):
            second = self.restore(source, retry_after=first.txn_id)
        self.assertEqual(second.status, Status.UNEXPECTED)

    def test_planned_journal_failure_prevents_recovery(self):
        source = self.source()
        with patch.object(self.journal, "append", side_effect=OSError("test")):
            self.assert_no_restore(source)
        self.assertTrue(self.journal.is_blocked())
        self.assert_no_restore(source)
        with self.assertRaises(SafetyError):
            self.journal.clear_block("нельзя снимать незавершённый барьер")

    def test_final_journal_failure_preserves_active_attempt(self):
        source = self.source()
        append = self.journal.append
        def fail_final(record, **kwargs):
            if record.status != Status.PLANNED:
                raise OSError("test")
            append(record, **kwargs)
        with patch.object(self.journal, "append", side_effect=fail_final), self.assertRaises(SafetyError):
            self.restore(source)
        self.assertTrue((self.journal.safety_dir / "recovery" / "ACTIVE.json").exists())
        self.assert_no_restore(source)

    def test_exit_before_result_preserves_active_attempt(self):
        source = self.source()
        with patch("agent_safe.adapters.recover._run", side_effect=SystemExit), self.assertRaises(SystemExit):
            self.restore(source)
        self.assert_no_restore(source)
        self.assertTrue(self.journal.is_blocked())

    def test_reentrant_recovery_refused(self):
        source = self.source()
        def execute(*args, **kwargs):
            self.assert_no_restore(source)
            return {"outcome":"exited", "returncode":0, "stdout":'{"restored":true}'}
        with patch("agent_safe.adapters.recover._run", side_effect=execute):
            self.assertEqual(self.restore(source).status, Status.DONE)

    def test_context_change_and_symlink_rejected(self):
        source = self.source()
        artifact = self.bundle(source) / "artifacts" / "backup"
        artifact.unlink()
        try:
            artifact.symlink_to(self.backup)
        except OSError:
            self.skipTest("ссылки недоступны")
        self.assert_no_restore(source)

    def test_storage_symlink_rejected_before_creating_children(self):
        other = self.root / "other"
        other.mkdir()
        root = self.root / "fresh"
        root.mkdir()
        try:
            (root / ".agent-safety").symlink_to(other, target_is_directory=True)
        except OSError:
            self.skipTest("ссылки недоступны")
        with self.assertRaises(SafetyError):
            local_journal(root)
        self.assertEqual(list(other.iterdir()), [])

    def test_actual_argument_bytes_stdin_and_not_started(self):
        helper = self.root / "arguments.py"
        helper.write_text("import sys,json\nprint(json.dumps({'argv':sys.argv[1:],'stdin':sys.stdin.buffer.read().decode('utf-8')}))\n", encoding="utf-8")
        args = ["", "a b", 'a"b', "$HOME", "{\"a\":1}", "Русский"]
        result = _run([sys.executable, "-I", str(helper), *args], self.root, structured=True, stdin_utf8="ввод")
        self.assertEqual(result["outcome"], "exited")
        self.assertEqual(json.loads(result["stdout"]), {"argv": args, "stdin": "ввод"})
        absent = _run([str(self.root / "absent.exe")], self.root, structured=True)
        self.assertEqual(absent["outcome"], "not_started")

    def test_actual_timeout_is_unknown(self):
        helper = self.root / "wait.py"
        helper.write_text("import time\ntime.sleep(10)\n", encoding="utf-8")
        result = _run([sys.executable, "-I", str(helper)], self.root, timeout=1, structured=True)
        self.assertEqual(result["outcome"], "unknown")

    def test_storage_permissions_on_posix(self):
        if os.name == "nt":
            self.skipTest("POSIX-права")
        source = self.source()
        bundle = self.bundle(source)
        self.assertEqual(bundle.stat().st_mode & 0o777, 0o700)
        self.assertEqual((bundle / "artifacts" / "backup").stat().st_mode & 0o777, 0o600)

    def test_main_preparation_and_final_journal_failures(self):
        with patch.object(self.journal, "append", side_effect=OSError("test")), self.assertRaises(SafetyError):
            self.source()
        self.assertFalse(self.journal.is_blocked())
        append = self.journal.append
        def fail_final(record, **kwargs):
            if record.status != Status.PLANNED:
                raise OSError("test")
            append(record, **kwargs)
        with patch.object(self.journal, "append", side_effect=fail_final), self.assertRaises(OSError):
            self.source()
        self.assertTrue(self.journal.is_blocked())

    def test_target_drift_after_planned_record_stops_main(self):
        append = self.journal.append
        def change_target(record, **kwargs):
            append(record, **kwargs)
            self.target.write_bytes(b"changed after approval")
        with patch.object(self.journal, "append", side_effect=change_target), patch("agent_safe.adapters.exec_adapter._run") as run:
            with self.assertRaises(SafetyError):
                exec_risky(["apply-update"], rollback_plan_json=json.dumps(self.plan), **self.kwargs)
        run.assert_not_called()
        self.assertTrue(self.journal.is_blocked())

    def test_changed_verify_artifact_prevents_its_execution(self):
        source = self.source()
        def execute(*args, **kwargs):
            (self.bundle(source) / "artifacts" / "check").write_bytes(b"changed")
            return {"outcome":"exited", "returncode":0}
        with patch("agent_safe.adapters.recover._run", side_effect=execute) as run:
            result = self.restore(source)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(result.status, Status.UNEXPECTED)
        self.assertTrue(self.journal.is_blocked())

    def test_unknown_verify_blocks_retry(self):
        source = self.source()
        with patch("agent_safe.adapters.recover._run", side_effect=[
            {"outcome":"exited", "returncode":0}, {"outcome":"unknown", "returncode":127},
        ]):
            result = self.restore(source)
        self.assert_no_restore(source, retry_after=result.txn_id)

    def test_foreign_block_appearing_during_recovery_is_preserved(self):
        source = self.source()
        def execute(*args, **kwargs):
            self.journal.block("другой инцидент", "other")
            return {"outcome":"exited", "returncode":0}
        with patch("agent_safe.adapters.recover._run", side_effect=execute) as run:
            result = self.restore(source)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(result.status, Status.UNEXPECTED)
        self.assertEqual(json.loads(self.journal.block_path.read_text())["txn_id"], "other")

    @unittest.skipUnless(os.name == "nt", "проверка junction на Windows")
    def test_windows_bundle_junction_is_rejected(self):
        source = self.source()
        artifacts = self.bundle(source) / "artifacts"
        moved = self.bundle(source) / "artifacts-original"
        artifacts.rename(moved)
        result = subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(artifacts), str(moved)], capture_output=True)
        self.assertEqual(result.returncode, 0)
        self.addCleanup(lambda: artifacts.rmdir())
        self.assert_no_restore(source)


if __name__ == "__main__":
    unittest.main()
