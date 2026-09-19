import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_safe.adapters import fs
from agent_safe.core.journal import Journal


class ReversalSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.parent = self.root / "original"
        self.parent.mkdir()
        self.source = self.parent / "item.txt"
        self.source.write_text("исходные данные", encoding="utf-8")
        self.dest = self.root / "moved.txt"
        self.journal = Journal(self.root)
        self.record = fs.fs_move(self.source, self.dest, "проверка восстановления", self.journal).to_dict()

    def symlink(self, path, target, directory=False):
        try:
            path.symlink_to(target, target_is_directory=directory)
        except OSError as exc:
            self.skipTest(f"создание symlink недоступно: {exc}")

    def test_repeated_cycles_record_verified_identity(self):
        for _ in range(2):
            fs.undo_record(self.record, self.journal)
            self.assertEqual("исходные данные", self.source.read_text(encoding="utf-8"))
            fs.redo_record(self.record, self.journal)
            self.assertFalse(self.source.exists())
        events = [r for r in self.journal.records() if r.get("event") in {"undo", "redo"}]
        self.assertEqual(4, len(events))
        self.assertTrue(all(r["verification_complete"] and r["verify_result"]["sha256"] for r in events))
        self.assertFalse(self.journal.is_blocked())

    def test_directory_round_trip(self):
        source = self.parent / "directory"
        source.mkdir()
        (source / "child.txt").write_text("содержимое", encoding="utf-8")
        dest = self.root / "moved-directory"
        record = fs.fs_move(source, dest, "каталог", self.journal).to_dict()
        fs.undo_record(record, self.journal)
        self.assertTrue((source / "child.txt").is_file())
        fs.redo_record(record, self.journal)
        self.assertTrue((dest / "child.txt").is_file())

    def test_redo_rejects_changed_source(self):
        fs.undo_record(self.record, self.journal)
        self.source.rename(self.parent / "preserved.txt")
        self.source.write_text("замена", encoding="utf-8")
        with self.assertRaises(fs.SafetyError):
            fs.redo_record(self.record, self.journal)
        self.assertFalse(self.dest.exists())

    def test_preflight_conflict_does_not_append_success(self):
        self.source.write_text("конфликт", encoding="utf-8")
        before = self.journal.journal_path.read_bytes()
        with self.assertRaises(fs.SafetyError):
            fs.undo_record(self.record, self.journal)
        self.assertEqual(before, self.journal.journal_path.read_bytes())
        self.assertFalse(self.journal.is_blocked())

    def test_parent_symlink_is_rejected_before_move(self):
        other = self.root / "other"
        other.mkdir()
        self.parent.rename(self.root / "preserved")
        self.symlink(self.parent, other, True)
        with self.assertRaises(fs.SafetyError):
            fs.undo_record(self.record, self.journal)
        self.assertTrue(self.dest.exists())
        self.assertFalse((other / self.source.name).exists())
        self.assertEqual(1, len(self.journal.records()))

    def test_replaced_plain_parent_is_rejected(self):
        self.parent.rename(self.root / "preserved")
        self.parent.mkdir()
        with self.assertRaises(fs.SafetyError):
            fs.undo_record(self.record, self.journal)
        self.assertTrue(self.dest.exists())

    def test_replaced_source_object_is_rejected(self):
        self.dest.rename(self.root / "preserved.txt")
        self.dest.write_text("посторонний объект", encoding="utf-8")
        with self.assertRaises(fs.SafetyError):
            fs.undo_record(self.record, self.journal)
        self.assertFalse(self.source.exists())

    def test_source_symlink_is_rejected(self):
        preserved = self.root / "preserved.txt"
        self.dest.rename(preserved)
        self.symlink(self.dest, preserved)
        with self.assertRaises(fs.SafetyError):
            fs.undo_record(self.record, self.journal)
        self.assertTrue(preserved.exists())

    def test_dangling_destination_is_rejected(self):
        self.symlink(self.source, self.root / "missing")
        with self.assertRaises(fs.SafetyError):
            fs.undo_record(self.record, self.journal)
        self.assertTrue(self.dest.exists())
        self.assertTrue(self.source.is_symlink())

    def test_existing_destination_is_rejected(self):
        self.source.write_text("конфликт", encoding="utf-8")
        with self.assertRaises(fs.SafetyError):
            fs.undo_record(self.record, self.journal)
        self.assertEqual("конфликт", self.source.read_text(encoding="utf-8"))

    def test_redo_and_undo_do_not_bypass_block(self):
        fs.undo_record(self.record, self.journal)
        self.journal.block("другой инцидент", "other-txn")
        before = self.journal.block_path.read_bytes()
        for callback in (fs.undo_record, fs.redo_record):
            with self.assertRaises(fs.SafetyError):
                callback(self.record, self.journal)
        self.assertEqual(before, self.journal.block_path.read_bytes())
        self.assertTrue(self.source.exists())
        self.assertFalse(self.dest.exists())

    def test_cli_redo_does_not_bypass_block(self):
        fs.undo_record(self.record, self.journal)
        self.journal.block("проверка", "other-txn")
        result = subprocess.run([sys.executable, "-m", "agent_safe", "--root", str(self.root), "redo", self.record["txn_id"]], capture_output=True, encoding="utf-8")
        self.assertNotEqual(0, result.returncode)
        self.assertEqual("SafetyError", json.loads(result.stdout)["type"])
        self.assertTrue(self.source.exists())

    def test_repeated_undo_and_premature_redo_are_rejected(self):
        with self.assertRaises(fs.SafetyError):
            fs.redo_record(self.record, self.journal)
        fs.undo_record(self.record, self.journal)
        with self.assertRaises(fs.SafetyError):
            fs.undo_record(self.record, self.journal)
        fs.redo_record(self.record, self.journal)
        with self.assertRaises(fs.SafetyError):
            fs.redo_record(self.record, self.journal)

    def test_legacy_evidence_remains_readable_but_cannot_execute(self):
        legacy = dict(self.record)
        legacy["verify_result"] = {}
        self.journal.append_raw(legacy)
        self.assertEqual(legacy, self.journal.find(legacy["txn_id"]))
        with self.assertRaises(fs.SafetyError):
            fs.undo_record(legacy, self.journal)
        self.assertTrue(self.dest.exists())

    def test_partial_failure_blocks_and_records_evidence(self):
        move = fs.shutil.move
        def move_then_fail(source, dest):
            move(source, dest)
            raise OSError("сбой после перемещения")
        with patch.object(fs.shutil, "move", side_effect=move_then_fail):
            with self.assertRaises(fs.SafetyError):
                fs.undo_record(self.record, self.journal)
        self.assertTrue(self.journal.is_blocked())
        last = self.journal.records()[-1]
        self.assertEqual("unexpected", last["status"])
        self.assertFalse(last["verification_complete"])
        self.assertTrue(self.source.exists())

    def test_missing_effect_is_not_reported_as_success(self):
        with patch.object(fs.shutil, "move", return_value=None):
            with self.assertRaises(fs.SafetyError):
                fs.undo_record(self.record, self.journal)
        self.assertEqual("unexpected", self.journal.records()[-1]["status"])
        self.assertTrue(self.journal.is_blocked())
        self.assertTrue(self.dest.exists())

    def test_content_mismatch_after_move_blocks(self):
        move = fs.shutil.move
        def wrong_content(source, dest):
            move(source, dest)
            Path(dest).write_text("неверный результат", encoding="utf-8")
        with patch.object(fs.shutil, "move", side_effect=wrong_content):
            with self.assertRaises(fs.SafetyError):
                fs.undo_record(self.record, self.journal)
        self.assertTrue(self.journal.is_blocked())
        self.assertEqual("unexpected", self.journal.records()[-1]["status"])

    def test_planned_write_failure_prevents_mutation(self):
        with patch.object(self.journal, "append_raw", side_effect=OSError("запись недоступна")):
            with self.assertRaises(fs.SafetyError):
                fs.undo_record(self.record, self.journal)
        self.assertTrue(self.dest.exists())
        self.assertFalse(self.source.exists())
        self.assertTrue(self.journal.is_blocked())

    def test_result_write_failure_keeps_pending_barrier(self):
        append = self.journal.append_raw
        def fail_result(payload, **kwargs):
            if payload.get("event") == "undo":
                raise OSError("результат не записан")
            return append(payload, **kwargs)
        with patch.object(self.journal, "append_raw", side_effect=fail_result):
            with self.assertRaises(OSError):
                fs.undo_record(self.record, self.journal)
        self.assertTrue(self.source.exists())
        self.assertTrue(self.journal.is_blocked())

    def test_changed_path_at_last_check_prevents_mutation(self):
        recheck = fs._recheck_existing
        def replace_then_recheck(*args, **kwargs):
            self.dest.rename(self.root / "preserved.txt")
            self.dest.write_text("замена", encoding="utf-8")
            return recheck(*args, **kwargs)
        with patch.object(fs, "_recheck_existing", side_effect=replace_then_recheck):
            with self.assertRaises(fs.SafetyError):
                fs.undo_record(self.record, self.journal)
        self.assertFalse(self.source.exists())
        self.assertTrue(self.journal.is_blocked())

    def test_barrier_finalize_failure_is_not_success(self):
        with patch.object(self.journal, "finish_pending", return_value=False):
            with self.assertRaises(fs.SafetyError):
                fs.undo_record(self.record, self.journal)
        self.assertTrue(self.journal.is_blocked())
        self.assertEqual("unexpected", self.journal.records()[-1]["status"])

    @unittest.skipUnless(os.name == "nt", "проверка Windows reparse point")
    def test_windows_junction_parent_is_rejected(self):
        other = self.root / "other"
        other.mkdir()
        self.parent.rename(self.root / "preserved")
        result = subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(self.parent), str(other)], capture_output=True)
        if result.returncode:
            self.skipTest("создание junction недоступно")
        self.addCleanup(lambda: self.parent.rmdir() if self.parent.exists() else None)
        with self.assertRaises(fs.SafetyError):
            fs.undo_record(self.record, self.journal)
        self.assertTrue(self.dest.exists())
        self.assertFalse((other / self.source.name).exists())
