import os
import tempfile
import unittest
from pathlib import Path

from agent_safe.adapters.fs import SafetyError, fs_trash
from agent_safe.adapters.fs_lifecycle import fs_cleanup, fs_mark, fs_status, resource_class
from agent_safe.core.journal import Journal


class FsLifecycleTests(unittest.TestCase):
    def test_normal_is_default_and_cleanup_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path = root / "data.txt"
            path.write_text("important", encoding="utf-8")
            journal = Journal(root)
            self.assertEqual(resource_class(path, journal), "normal")
            with self.assertRaises(SafetyError):
                fs_cleanup(path, "не должно удалиться", journal)
            self.assertTrue(path.exists())

    def test_temporary_cleanup_is_irreversible_but_audited(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path = root / "tmp.txt"
            path.write_text("temporary", encoding="utf-8")
            journal = Journal(root)
            fs_mark(path, "temporary", "временный результат проверки", journal)
            record = fs_cleanup(path, "проверка завершена", journal)
            self.assertEqual(record.status.value, "done")
            self.assertFalse(path.exists())
            self.assertEqual(record.metadata["reversibility"], "irreversible")
            self.assertTrue(record.metadata["tombstone"])
            records = journal.records()
            self.assertTrue(any(item.get("event") == "fs.cleanup.intent" for item in records))
            self.assertTrue(any(item.get("kind") == "fs.cleanup" and item.get("status") == "done" for item in records))
            status = fs_status(path, journal)
            self.assertEqual(status["resource_class"], "temporary")
            self.assertEqual(status["state"], "deleted")
            self.assertFalse(status["exists"])

    def test_class_follows_reversible_trash_move(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path = root / "probe"
            path.mkdir()
            (path / "result.txt").write_text("x", encoding="utf-8")
            journal = Journal(root)
            fs_mark(path, "temporary", "временный probe", journal)
            trash_record = fs_trash(path, "сначала обратимо убрать", journal)
            trash_path = Path(trash_record.command["dest"])
            self.assertEqual(resource_class(trash_path, journal), "temporary")
            cleanup_record = fs_cleanup(trash_path, "окончательная очистка временного probe", journal)
            self.assertEqual(cleanup_record.status.value, "done")
            self.assertFalse(trash_path.exists())

    def test_existing_trash_object_can_be_marked_temporary_afterwards(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path = root / "old.tmp"
            path.write_text("old", encoding="utf-8")
            journal = Journal(root)
            trash_record = fs_trash(path, "старое безопасное удаление", journal)
            trash_path = Path(trash_record.command["dest"])
            self.assertEqual(resource_class(trash_path, journal), "normal")
            fs_mark(trash_path, "temporary", "подтверждено как временное", journal)
            record = fs_cleanup(trash_path, "окончательно удалить", journal)
            self.assertEqual(record.status.value, "done")
            self.assertFalse(trash_path.exists())

    def test_protected_cannot_be_cleaned(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path = root / "keep.txt"
            path.write_text("keep", encoding="utf-8")
            journal = Journal(root)
            fs_mark(path, "protected", "важные данные", journal)
            with self.assertRaises(SafetyError):
                fs_cleanup(path, "ошибка", journal)
            self.assertTrue(path.exists())

    def test_safety_metadata_cannot_be_cleaned(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            journal = Journal(root)
            with self.assertRaises(SafetyError):
                fs_mark(journal.journal_path, "temporary", "нельзя", journal)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink недоступен")
    def test_cleanup_does_not_follow_symlink_outside_temporary_directory(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            outside = root / "outside.txt"
            outside.write_text("keep", encoding="utf-8")
            temp_dir = root / "temp"
            temp_dir.mkdir()
            link = temp_dir / "link.txt"
            try:
                link.symlink_to(outside)
            except OSError:
                self.skipTest("создание symlink не разрешено в этой среде")
            journal = Journal(root)
            fs_mark(temp_dir, "temporary", "временный каталог", journal)
            record = fs_cleanup(temp_dir, "удалить временный каталог", journal)
            self.assertEqual(record.status.value, "done")
            self.assertTrue(outside.exists())
            self.assertEqual(outside.read_text(encoding="utf-8"), "keep")


if __name__ == "__main__":
    unittest.main()
