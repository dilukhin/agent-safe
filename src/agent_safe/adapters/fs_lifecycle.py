from __future__ import annotations

import hashlib
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent_safe.core.journal import Journal
from agent_safe.core.models import ActionRecord, Risk, Status
from .fs import SafetyError, require_not_blocked


RESOURCE_CLASSES = ("normal", "temporary", "protected")


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.path.expanduser(str(path))))


def _lexists(path: Path) -> bool:
    return os.path.lexists(str(path))


def _identity_path(path: Path | str) -> Path:
    absolute = _absolute(Path(path))
    if _lexists(absolute) and not absolute.is_symlink():
        try:
            return absolute.resolve()
        except OSError:
            pass
    return absolute


def _key(path: Path | str) -> str:
    return os.path.normcase(str(_identity_path(path)))


def _inside(path: Path, parent: Path) -> bool:
    path_key = _key(path)
    parent_key = _key(parent)
    try:
        return os.path.commonpath([path_key, parent_key]) == parent_key
    except ValueError:
        return False


def _guard_safety_path(path: Path, journal: Journal) -> None:
    if not _inside(path, journal.safety_dir):
        return
    trash_root = journal.safety_dir / "trash"
    if not _inside(path, trash_root) or _key(path) == _key(trash_root):
        raise SafetyError("служебные данные .agent-safety нельзя переклассифицировать или окончательно удалять; исключение — конкретные объекты внутри trash")


def _guard_cleanup_scope(path: Path, journal: Journal) -> None:
    _guard_safety_path(path, journal)
    if path.parent == path:
        raise SafetyError("корень файловой системы нельзя окончательно удалять через fs-cleanup")
    root_key = _key(journal.root)
    path_key = _key(path)
    if path_key == root_key:
        raise SafetyError("корень safety-проекта нельзя окончательно удалять через fs-cleanup")
    try:
        if os.path.commonpath([root_key, path_key]) == path_key:
            raise SafetyError("родитель корня safety-проекта нельзя окончательно удалять через fs-cleanup")
    except ValueError:
        pass


def _transition_for_dest(record: dict[str, Any], current_key: str) -> str | None:
    if record.get("status") != Status.DONE.value:
        return None
    if record.get("kind") not in {"fs.move", "fs.trash"}:
        return None
    command = record.get("command") or {}
    source = command.get("source")
    dest = command.get("dest")
    if not source or not dest:
        return None
    if _key(dest) == current_key:
        return _key(source)
    return None


def resource_class(path: Path, journal: Journal) -> str:
    current_key = _key(path)
    for record in reversed(journal.records()):
        if record.get("kind") == "fs.mark":
            command = record.get("command") or {}
            marked_path = command.get("path")
            marked_class = command.get("resource_class")
            if marked_path and _key(marked_path) == current_key and marked_class in RESOURCE_CLASSES:
                return str(marked_class)
        previous_key = _transition_for_dest(record, current_key)
        if previous_key is not None:
            current_key = previous_key
    return "normal"


def _hash_regular_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def describe_resource(path: Path, *, max_entries: int = 10000) -> dict[str, Any]:
    path = _absolute(path)
    if not _lexists(path):
        return {"path": str(path), "exists": False}
    stat = path.lstat()
    info: dict[str, Any] = {
        "path": str(path),
        "exists": True,
        "is_symlink": path.is_symlink(),
        "is_dir": path.is_dir() if not path.is_symlink() else False,
        "is_file": path.is_file() if not path.is_symlink() else False,
        "size": stat.st_size,
    }
    if path.is_symlink():
        try:
            info["link_target"] = os.readlink(path)
        except OSError:
            info["link_target"] = None
        return info
    if path.is_file():
        info["sha256"] = _hash_regular_file(path)
        return info
    if path.is_dir():
        files = 0
        dirs = 0
        bytes_total = 0
        scanned = 0
        truncated = False
        for root, dirnames, filenames in os.walk(path, followlinks=False):
            dirs += len(dirnames)
            for filename in filenames:
                scanned += 1
                if scanned > max_entries:
                    truncated = True
                    break
                child = Path(root) / filename
                files += 1
                try:
                    bytes_total += child.lstat().st_size
                except OSError:
                    pass
            if truncated:
                break
            scanned += len(dirnames)
            if scanned > max_entries:
                truncated = True
                break
        info.update({
            "files": files,
            "directories": dirs,
            "bytes_scanned": bytes_total,
            "scan_truncated": truncated,
            "scan_limit": max_entries,
        })
    return info


def fs_mark(path: Path, resource_class_name: str, reason: str, journal: Journal) -> ActionRecord:
    require_not_blocked(journal)
    if resource_class_name not in RESOURCE_CLASSES:
        raise SafetyError(f"неподдерживаемый класс ресурса: {resource_class_name}")
    path = _absolute(path)
    if not _lexists(path):
        raise SafetyError(f"путь не существует: {path}")
    path = _identity_path(path)
    _guard_safety_path(path, journal)
    before_class = resource_class(path, journal)
    txn_id = ActionRecord.new_id()
    record = ActionRecord(
        txn_id=txn_id,
        status=Status.DONE,
        kind="fs.mark",
        risk=Risk.HIGH if resource_class_name == "temporary" else Risk.CAUTIOUS,
        reason=reason,
        cwd=str(Path.cwd().resolve()),
        target_paths=[str(path)],
        command={"op": "mark", "path": str(path), "resource_class": resource_class_name},
        expected_state={"resource_class": resource_class_name},
        verify_result={"resource_class": resource_class_name},
        verification_complete=True,
        verified_assertions={"resource_class": resource_class_name},
        actual_state={"resource_class": resource_class_name},
        metadata={
            "before_class": before_class,
            "changed": before_class != resource_class_name,
            "path_snapshot": describe_resource(path),
        },
    )
    journal.append(record)
    return record


def _history_for(path: Path, journal: Journal) -> list[dict[str, Any]]:
    target_key = _key(path)
    relevant: list[dict[str, Any]] = []
    lineage_key = target_key
    for record in reversed(journal.records()):
        command = record.get("command") or {}
        keys: set[str] = set()
        for field in ("path", "source", "dest"):
            value = command.get(field)
            if value:
                keys.add(_key(value))
        for value in record.get("target_paths") or []:
            keys.add(_key(value))
        if target_key in keys or lineage_key in keys:
            relevant.append(record)
        previous_key = _transition_for_dest(record, lineage_key)
        if previous_key is not None:
            lineage_key = previous_key
    relevant.reverse()
    return relevant


def _lifecycle_state(path: Path, journal: Journal) -> str:
    path = _absolute(path)
    if _lexists(path):
        return "present"
    path_key = _key(path)
    for record in reversed(journal.records()):
        if record.get("kind") == "fs.cleanup" and record.get("status") == Status.DONE.value:
            command = record.get("command") or {}
            if command.get("path") and _key(command["path"]) == path_key:
                return "deleted"
        if record.get("kind") == "fs.trash" and record.get("status") == Status.DONE.value:
            command = record.get("command") or {}
            source = command.get("source")
            dest = command.get("dest")
            if source and dest and _key(source) == path_key and _lexists(_absolute(Path(dest))):
                return "trashed"
    return "missing"


def fs_status(path: Path, journal: Journal) -> dict[str, Any]:
    path = _absolute(path)
    klass = resource_class(path, journal)
    state = _lifecycle_state(path, journal)
    return {
        "path": str(path),
        "resource_class": klass,
        "state": state,
        "exists": _lexists(path),
        "cleanup_allowed": klass == "temporary" and state == "present" and not journal.is_blocked(),
        "blocked": journal.is_blocked(),
        "history": _history_for(path, journal),
    }


def fs_cleanup(path: Path, reason: str, journal: Journal) -> ActionRecord:
    require_not_blocked(journal)
    path = _absolute(path)
    if not _lexists(path):
        raise SafetyError(f"путь не существует: {path}")
    path = _identity_path(path)
    _guard_cleanup_scope(path, journal)
    klass = resource_class(path, journal)
    if klass != "temporary":
        raise SafetyError(
            f"fs-cleanup разрешён только для resource_class=temporary; текущий класс: {klass}. "
            "Сначала явно классифицируйте объект через fs-mark."
        )

    txn_id = ActionRecord.new_id()
    before = describe_resource(path)
    expected = {"path_exists": False, "resource_class": "temporary"}
    intent = {
        "event": "fs.cleanup.intent",
        "txn_id": txn_id,
        "status": Status.PLANNED.value,
        "kind": "fs.cleanup",
        "risk": Risk.HIGH.value,
        "reason": reason,
        "target_paths": [str(path)],
        "command": {"op": "cleanup", "path": str(path)},
        "expected_state": expected,
        "metadata": {
            "resource_class": klass,
            "reversibility": "irreversible",
            "before": before,
        },
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    journal.append_raw(intent)

    error: str | None = None
    try:
        if path.is_symlink() or path.is_file():
            path.unlink()
        elif path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
    except Exception as exc:  # noqa: BLE001 - ошибка удаления должна попасть в журнал инцидента
        error = f"{type(exc).__name__}: {exc}"

    exists_after = _lexists(path)
    verify: dict[str, Any] = {
        "path_exists": exists_after,
        "resource_class": klass,
    }
    if error is not None:
        verify["error"] = error
    status = Status.DONE if not exists_after and error is None else Status.UNEXPECTED
    record = ActionRecord(
        txn_id=txn_id,
        status=status,
        kind="fs.cleanup",
        risk=Risk.HIGH,
        reason=reason,
        cwd=str(Path.cwd().resolve()),
        target_paths=[str(path)],
        command={"op": "cleanup", "path": str(path)},
        expected_state=expected,
        verify_result=verify,
        verification_complete=True,
        verified_assertions={"path_exists": False} if status == Status.DONE else {},
        mismatched_assertions={} if status == Status.DONE else {"path_exists": {"expected": False, "actual": exists_after}},
        actual_state=verify,
        metadata={
            "resource_class": klass,
            "reversibility": "irreversible",
            "tombstone": True,
            "before": before,
        },
    )
    journal.append(record)
    if status == Status.UNEXPECTED:
        journal.block("неожиданный результат после fs.cleanup", txn_id)
    return record
