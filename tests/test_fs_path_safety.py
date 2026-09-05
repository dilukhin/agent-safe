import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_safe.adapters.fs import SafetyError, fs_move, fs_trash
from agent_safe.adapters.fs_lifecycle import fs_cleanup, fs_mark
from agent_safe.core.journal import Journal


class FsPathSafetyTests(unittest.TestCase):
    def test_move_regular_file_preserves_requested_path_and_preflight_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / "source.txt"
            dst = root / "dest.txt"
            src.write_text("data", encoding="utf-8")
            journal = Journal(root)

            record = fs_move(src, dst, "обычное перемещение", journal)

            self.assertEqual(record.status.value, "done")
            self.assertFalse(src.exists())
            self.assertEqual(dst.read_text(encoding="utf-8"), "data")
            self.assertEqual(record.command["requested_source"], str(src))
            self.assertEqual(record.command["requested_dest"], str(dst))
            self.assertEqual(record.metadata["preflight"]["source_final"]["leaf"]["kind"], "file")
            self.assertFalse(record.metadata["preflight"]["source_final"]["leaf"]["is_symlink"])

    def test_trash_regular_directory(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / "directory"
            src.mkdir()
            (src / "data.txt").write_text("data", encoding="utf-8")
            journal = Journal(root)

            record = fs_trash(src, "обратимо убрать каталог", journal)
            dest = Path(record.command["dest"])

            self.assertEqual(record.status.value, "done")
            self.assertFalse(src.exists())
            self.assertEqual((dest / "data.txt").read_text(encoding="utf-8"), "data")

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink недоступен")
    def test_move_refuses_symlink_source_and_preserves_target(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "target.txt"
            target.write_text("keep", encoding="utf-8")
            link = root / "link.txt"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("создание symlink не разрешено в этой среде")
            journal = Journal(root)

            with self.assertRaises(SafetyError):
                fs_move(link, root / "moved.txt", "symlink должен быть отклонён", journal)

            self.assertTrue(os.path.lexists(link))
            self.assertEqual(target.read_text(encoding="utf-8"), "keep")
            self.assertFalse((root / "moved.txt").exists())
            self.assertEqual(journal.records(), [])

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink недоступен")
    def test_trash_refuses_symlink_source_and_preserves_target(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "target.txt"
            target.write_text("keep", encoding="utf-8")
            link = root / "link.txt"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("создание symlink не разрешено в этой среде")
            journal = Journal(root)

            with self.assertRaises(SafetyError):
                fs_trash(link, "symlink должен быть отклонён", journal)

            self.assertTrue(os.path.lexists(link))
            self.assertEqual(target.read_text(encoding="utf-8"), "keep")
            self.assertEqual(journal.records(), [])

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink недоступен")
    def test_trash_refuses_path_through_symlink_parent(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            real_dir = root / "real"
            real_dir.mkdir()
            target = real_dir / "target.txt"
            target.write_text("keep", encoding="utf-8")
            link_dir = root / "link-dir"
            try:
                link_dir.symlink_to(real_dir, target_is_directory=True)
            except OSError:
                self.skipTest("создание symlink каталога не разрешено в этой среде")
            journal = Journal(root)

            with self.assertRaises(SafetyError):
                fs_trash(link_dir / "target.txt", "путь через symlink должен быть отклонён", journal)

            self.assertEqual(target.read_text(encoding="utf-8"), "keep")
            self.assertTrue(os.path.lexists(link_dir))
            self.assertEqual(journal.records(), [])

    def test_move_refuses_source_destination_overlap(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / "source"
            src.mkdir()
            journal = Journal(root)

            with self.assertRaises(SafetyError):
                fs_move(src, src / "nested", "вложенное перемещение запрещено", journal)

            self.assertTrue(src.exists())
            self.assertFalse((src / "nested").exists())
            self.assertEqual(journal.records(), [])

    def test_trash_refuses_dotdot_path(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "target.txt"
            target.write_text("keep", encoding="utf-8")
            requested = root / "child" / ".." / "target.txt"
            journal = Journal(root)

            with self.assertRaises(SafetyError):
                fs_trash(requested, "неоднозначный путь запрещён", journal)

            self.assertEqual(target.read_text(encoding="utf-8"), "keep")
            self.assertEqual(journal.records(), [])

    def test_move_mutation_failure_enters_recovery_mode(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / "source.txt"
            dst = root / "dest.txt"
            src.write_text("data", encoding="utf-8")
            journal = Journal(root)

            with patch("agent_safe.adapters.fs.shutil.move", side_effect=OSError("сбой теста")):
                record = fs_move(src, dst, "проверка Recovery Mode", journal)

            self.assertEqual(record.status.value, "unexpected")
            self.assertTrue(journal.is_blocked())
            self.assertTrue(src.exists())
            self.assertFalse(dst.exists())
            self.assertIn("error", record.verify_result)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink недоступен")
    def test_cleanup_removes_symlink_leaf_without_touching_target(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "target.txt"
            target.write_text("keep", encoding="utf-8")
            link = root / "temporary-link"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("создание symlink не разрешено в этой среде")
            journal = Journal(root)
            fs_mark(link, "temporary", "временная ссылка", journal)

            record = fs_cleanup(link, "удалить только symlink leaf", journal)

            self.assertEqual(record.status.value, "done")
            self.assertFalse(os.path.lexists(link))
            self.assertEqual(target.read_text(encoding="utf-8"), "keep")

    @unittest.skipUnless(os.name == "nt", "junction проверяется только на Windows")
    def test_windows_junction_is_refused_and_target_is_preserved(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target_dir = root / "target-dir"
            target_dir.mkdir()
            target_file = target_dir / "keep.txt"
            target_file.write_text("keep", encoding="utf-8")
            junction = root / "junction"

            result = subprocess.run(
                ["cmd.exe", "/d", "/c", "mklink", "/J", str(junction), str(target_dir)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                self.skipTest(f"не удалось создать junction: {result.stderr.strip() or result.stdout.strip()}")

            try:
                journal = Journal(root)
                with self.assertRaises(SafetyError):
                    fs_trash(junction, "junction должен быть отклонён", journal)

                self.assertTrue(os.path.lexists(junction))
                self.assertEqual(target_file.read_text(encoding="utf-8"), "keep")
                self.assertEqual(journal.records(), [])
            finally:
                if os.path.lexists(junction):
                    os.rmdir(junction)


if __name__ == "__main__":
    unittest.main()
