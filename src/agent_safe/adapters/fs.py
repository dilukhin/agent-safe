from __future__ import annotations

import hashlib
import os
import shutil
from pathlib import Path
from typing import Any

from agent_safe.core.journal import Journal
from agent_safe.core.models import ActionRecord, Risk, Status


class SafetyError(RuntimeError):
    pass


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def describe_path(path: Path) -> dict[str, Any]:
    path = path.resolve()
    if not path.exists():
        return {"path": str(path), "exists": False}
    info: dict[str, Any] = {
        "path": str(path),
        "exists": True,
        "is_dir": path.is_dir(),
        "is_file": path.is_file(),
        "name": path.name,
    }
    if path.is_file():
        st = path.stat()
        info.update({"size": st.st_size, "sha256": _hash_file(path)})
    if path.is_dir():
        info["children"] = sorted(p.name for p in path.iterdir())[:200]
        info["contains_git"] = (path / ".git").exists()
    return info


def require_not_blocked(journal: Journal) -> None:
    if journal.is_blocked():
        raise SafetyError("INCIDENT_BLOCKED exists; high-risk operations are disabled. Run diagnose/recovery-plan first.")


def fs_move(source: Path, dest: Path, reason: str, journal: Journal) -> ActionRecord:
    require_not_blocked(journal)
    source = source.resolve()
    dest = dest.resolve()
    if not source.exists():
        raise SafetyError(f"source does not exist: {source}")
    if dest.exists():
        raise SafetyError(f"destination already exists; refusing ambiguous move/nesting: {dest}")
    if not dest.parent.exists():
        raise SafetyError(f"destination parent does not exist: {dest.parent}")

    before = {"source": describe_path(source), "dest": describe_path(dest), "dest_parent": describe_path(dest.parent)}
    txn_id = ActionRecord.new_id()
    shutil.move(str(source), str(dest))

    verify = {
        "source_exists": source.exists(),
        "dest_exists": dest.exists(),
        "dest_contains_git": (dest / ".git").exists() if dest.is_dir() else False,
    }
    expected = {"source_exists": False, "dest_exists": True}
    status = Status.DONE if verify["source_exists"] is False and verify["dest_exists"] is True else Status.UNEXPECTED
    record = ActionRecord(
        txn_id=txn_id,
        status=status,
        kind="fs.move",
        risk=Risk.HIGH,
        reason=reason,
        cwd=str(Path.cwd().resolve()),
        target_paths=[str(source), str(dest)],
        command={"op": "move", "source": str(source), "dest": str(dest)},
        undo={"op": "move", "source": str(dest), "dest": str(source)},
        redo={"op": "move", "source": str(source), "dest": str(dest)},
        expected_state=expected,
        verify_result=verify,
        metadata={"before": before},
    )
    journal.append(record)
    if status == Status.UNEXPECTED:
        journal.block("unexpected result after fs.move", txn_id)
    return record


def fs_trash(path: Path, reason: str, journal: Journal) -> ActionRecord:
    require_not_blocked(journal)
    path = path.resolve()
    if not path.exists():
        raise SafetyError(f"path does not exist: {path}")
    txn_id = ActionRecord.new_id()
    trash_dir = journal.safety_dir / "trash" / txn_id
    trash_dir.mkdir(parents=True, exist_ok=False)
    dest = trash_dir / path.name
    before = describe_path(path)
    shutil.move(str(path), str(dest))
    verify = {"source_exists": path.exists(), "trash_exists": dest.exists()}
    status = Status.DONE if verify == {"source_exists": False, "trash_exists": True} else Status.UNEXPECTED
    record = ActionRecord(
        txn_id=txn_id,
        status=status,
        kind="fs.trash",
        risk=Risk.HIGH,
        reason=reason,
        cwd=str(Path.cwd().resolve()),
        target_paths=[str(path), str(dest)],
        command={"op": "trash", "source": str(path), "dest": str(dest)},
        undo={"op": "move", "source": str(dest), "dest": str(path)},
        redo={"op": "move", "source": str(path), "dest": str(dest)},
        expected_state={"source_exists": False, "trash_exists": True},
        verify_result=verify,
        metadata={"before": before},
    )
    journal.append(record)
    if status == Status.UNEXPECTED:
        journal.block("unexpected result after fs.trash", txn_id)
    return record


def _do_move(source: Path, dest: Path) -> None:
    if not source.exists():
        raise SafetyError(f"rollback source does not exist: {source}")
    if dest.exists():
        raise SafetyError(f"rollback destination already exists: {dest}")
    if not dest.parent.exists():
        raise SafetyError(f"rollback destination parent does not exist: {dest.parent}")
    shutil.move(str(source), str(dest))


def undo_record(record: dict[str, Any], journal: Journal) -> dict[str, Any]:
    undo = record.get("undo") or {}
    if undo.get("op") != "move":
        raise SafetyError(f"unsupported undo operation: {undo}")
    _do_move(Path(undo["source"]), Path(undo["dest"]))
    journal.append_raw({"event": "undo", "txn_id": record.get("txn_id"), "status": Status.UNDONE.value})
    return {"undone": record.get("txn_id")}


def redo_record(record: dict[str, Any], journal: Journal) -> dict[str, Any]:
    redo = record.get("redo") or {}
    if redo.get("op") != "move":
        raise SafetyError(f"unsupported redo operation: {redo}")
    _do_move(Path(redo["source"]), Path(redo["dest"]))
    journal.append_raw({"event": "redo", "txn_id": record.get("txn_id"), "status": Status.DONE.value})
    return {"redone": record.get("txn_id")}
