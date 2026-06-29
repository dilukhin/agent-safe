import tempfile
import unittest
from pathlib import Path

from agent_safe.adapters.fs import SafetyError, fs_move, fs_trash, undo_record, redo_record
from agent_safe.core.journal import Journal


class FsTests(unittest.TestCase):
    def test_move_refuses_existing_dest(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / "src"
            dst = root / "dst"
            src.mkdir()
            dst.mkdir()
            journal = Journal(root)
            with self.assertRaises(SafetyError):
                fs_move(src, dst, "test", journal)

    def test_trash_undo_redo(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            p = root / "a.txt"
            p.write_text("hello", encoding="utf-8")
            journal = Journal(root)
            rec = fs_trash(p, "test trash", journal)
            self.assertFalse(p.exists())
            self.assertEqual(rec.status.value, "done")
            undo_record(rec.to_dict(), journal)
            self.assertTrue(p.exists())
            redo_record(rec.to_dict(), journal)
            self.assertFalse(p.exists())


if __name__ == "__main__":
    unittest.main()
