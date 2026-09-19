from __future__ import annotations

import hashlib
import os
import shutil
import stat
from pathlib import Path
from typing import Any

from agent_safe.core.journal import Journal
from agent_safe.core.models import ActionRecord, Risk, Status


class SafetyError(RuntimeError):
    pass


def _absolute_path(path: Path) -> Path:
    return Path(os.path.abspath(os.path.expanduser(str(path))))


def _requested_path(path: Path, role: str) -> tuple[str, Path]:
    requested = str(path)
    expanded = Path(os.path.expanduser(requested))
    if ".." in expanded.parts:
        raise SafetyError(f"{role}: компоненты '..' запрещены для изменяющих файловых операций: {requested}")
    return requested, _absolute_path(expanded)


def _lexists(path: Path) -> bool:
    return os.path.lexists(str(path))


def _path_key(path: Path) -> str:
    return os.path.normcase(os.path.normpath(str(path)))


def _lstat_evidence(path: Path) -> dict[str, Any]:
    st = path.lstat()
    attributes = getattr(st, "st_file_attributes", None)
    reparse_mask = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    is_reparse_point = bool(attributes is not None and attributes & reparse_mask)
    if stat.S_ISLNK(st.st_mode):
        kind = "symlink"
    elif stat.S_ISDIR(st.st_mode):
        kind = "directory"
    elif stat.S_ISREG(st.st_mode):
        kind = "file"
    else:
        kind = "other"
    return {
        "path": str(path),
        "kind": kind,
        "mode": st.st_mode,
        "device": st.st_dev,
        "inode": st.st_ino,
        "size": st.st_size,
        "mtime_ns": st.st_mtime_ns,
        "ctime_ns": st.st_ctime_ns,
        "is_symlink": stat.S_ISLNK(st.st_mode),
        "is_reparse_point": is_reparse_point,
        "file_attributes": attributes,
        "reparse_tag": getattr(st, "st_reparse_tag", None) if is_reparse_point else None,
    }


def _path_components(path: Path) -> list[Path]:
    if not path.is_absolute() or not path.anchor:
        raise SafetyError(f"внутренняя ошибка предварительной проверки: ожидался абсолютный путь: {path}")
    anchor = Path(path.anchor)
    if path == anchor:
        return [path]
    current = anchor
    result: list[Path] = []
    for part in path.parts[1:]:
        current = current / part
        result.append(current)
    return result


def _preflight_existing_path(
    path: Path,
    *,
    requested: str,
    role: str,
    require_directory: bool = False,
) -> dict[str, Any]:
    chain: list[dict[str, Any]] = []
    components = _path_components(path)
    for current in components:
        try:
            evidence = _lstat_evidence(current)
        except FileNotFoundError as exc:
            if current == path:
                raise SafetyError(f"{role} не существует: {path}") from exc
            raise SafetyError(f"{role}: родительский компонент не существует: {current}") from exc
        except OSError as exc:
            raise SafetyError(f"{role}: не удалось выполнить lstat для {current}: {exc}") from exc

        if evidence["is_symlink"]:
            raise SafetyError(f"{role}: symlink запрещён для изменяющей операции: {current}")
        if evidence["is_reparse_point"]:
            tag = evidence.get("reparse_tag")
            suffix = f", reparse_tag={tag}" if tag is not None else ", тип reparse point не определён"
            raise SafetyError(f"{role}: Windows reparse point запрещён для изменяющей операции: {current}{suffix}")
        if current != path and evidence["kind"] != "directory":
            raise SafetyError(f"{role}: родительский компонент не является каталогом: {current}")
        chain.append(evidence)

    leaf = chain[-1]
    if require_directory and leaf["kind"] != "directory":
        raise SafetyError(f"{role} должен быть каталогом: {path}")
    return {
        "requested_path": requested,
        "path": str(path),
        "path_key": _path_key(path),
        "leaf": leaf,
        "chain": chain,
    }


def _preflight_destination(path: Path, *, requested: str, role: str) -> dict[str, Any]:
    parent = _preflight_existing_path(
        path.parent,
        requested=str(path.parent),
        role=f"{role}: родитель",
        require_directory=True,
    )
    if _lexists(path):
        try:
            leaf = _lstat_evidence(path)
        except OSError:
            leaf = {"path": str(path)}
        raise SafetyError(f"{role} уже существует; неоднозначное перемещение запрещено: {leaf}")
    return {
        "requested_path": requested,
        "path": str(path),
        "path_key": _path_key(path),
        "exists": False,
        "parent": parent,
    }


def _guard_no_overlap(source: Path, dest: Path) -> None:
    source_key = _path_key(source)
    dest_key = _path_key(dest)
    if source_key == dest_key:
        raise SafetyError(f"источник и назначение совпадают: {source}")
    try:
        common = os.path.commonpath([source_key, dest_key])
    except ValueError:
        return
    if common in {source_key, dest_key}:
        raise SafetyError(
            "источник и назначение неоднозначно пересекаются; "
            f"вложенное перемещение запрещено: источник={source}, назначение={dest}"
        )


_IDENTITY_FIELDS = (
    "mode",
    "device",
    "inode",
    "size",
    "mtime_ns",
    "ctime_ns",
    "file_attributes",
    "reparse_tag",
)


def _same_leaf_identity(first: dict[str, Any], second: dict[str, Any]) -> bool:
    first_leaf = first["leaf"]
    second_leaf = second["leaf"]
    return all(first_leaf.get(field) == second_leaf.get(field) for field in _IDENTITY_FIELDS)


def _recheck_existing(
    initial: dict[str, Any],
    path: Path,
    *,
    requested: str,
    role: str,
    require_directory: bool = False,
) -> dict[str, Any]:
    current = _preflight_existing_path(
        path,
        requested=requested,
        role=role,
        require_directory=require_directory,
    )
    if not _same_leaf_identity(initial, current):
        raise SafetyError(f"{role}: объект изменился между предварительной проверкой и изменяющей операцией: {path}")
    return current


def _recheck_destination(
    initial: dict[str, Any],
    path: Path,
    *,
    requested: str,
    role: str,
) -> dict[str, Any]:
    current = _preflight_destination(path, requested=requested, role=role)
    if not _same_leaf_identity(initial["parent"], current["parent"]):
        raise SafetyError(
            f"{role}: родитель назначения изменился между предварительной проверкой и изменяющей операцией: {path.parent}"
        )
    return current


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def describe_path(path: Path) -> dict[str, Any]:
    path = _absolute_path(path)
    if not _lexists(path):
        return {"path": str(path), "exists": False}
    try:
        evidence = _lstat_evidence(path)
    except OSError as exc:
        return {"path": str(path), "exists": True, "inspect_error": f"{type(exc).__name__}: {exc}"}

    info: dict[str, Any] = {
        "path": str(path),
        "exists": True,
        "is_dir": evidence["kind"] == "directory",
        "is_file": evidence["kind"] == "file",
        "is_symlink": evidence["is_symlink"],
        "is_reparse_point": evidence["is_reparse_point"],
        "reparse_tag": evidence["reparse_tag"],
        "name": path.name,
    }
    if evidence["is_symlink"] or evidence["is_reparse_point"]:
        return info
    if evidence["kind"] == "file":
        info.update({"size": evidence["size"], "sha256": _hash_file(path)})
    if evidence["kind"] == "directory":
        info["children"] = sorted(p.name for p in path.iterdir())[:200]
        info["contains_git"] = _lexists(path / ".git")
    return info


def require_not_blocked(journal: Journal) -> None:
    if journal.is_blocked():
        raise SafetyError("INCIDENT_BLOCKED exists; high-risk operations are disabled. Run diagnose/recovery-plan first.")


def _verify_move_result(source: Path, dest: Path, mutation_error: str | None) -> tuple[dict[str, Any], Status]:
    source_exists = _lexists(source)
    dest_exists = _lexists(dest)
    verify: dict[str, Any] = {
        "source_exists": source_exists,
        "dest_exists": dest_exists,
    }
    dest_safe = False
    if dest_exists:
        try:
            dest_postflight = _preflight_existing_path(
                dest,
                requested=str(dest),
                role="результат перемещения",
            )
            verify["dest_identity"] = dest_postflight["leaf"]
            dest_safe = True
            if dest_postflight["leaf"]["kind"] == "directory":
                verify["dest_contains_git"] = _lexists(dest / ".git")
        except SafetyError as exc:
            verify["dest_preflight_error"] = str(exc)
    if mutation_error is not None:
        verify["error"] = mutation_error
    verify["dest_safe"] = dest_safe
    status = (
        Status.DONE
        if mutation_error is None and source_exists is False and dest_exists is True and dest_safe
        else Status.UNEXPECTED
    )
    return verify, status


def fs_move(source: Path, dest: Path, reason: str, journal: Journal) -> ActionRecord:
    require_not_blocked(journal)
    requested_source, source = _requested_path(source, "источник")
    requested_dest, dest = _requested_path(dest, "назначение")
    _guard_no_overlap(source, dest)

    source_initial = _preflight_existing_path(
        source,
        requested=requested_source,
        role="источник",
    )
    dest_initial = _preflight_destination(
        dest,
        requested=requested_dest,
        role="назначение",
    )

    before = {
        "source": describe_path(source),
        "dest": describe_path(dest),
        "dest_parent": describe_path(dest.parent),
    }

    source_final = _recheck_existing(
        source_initial,
        source,
        requested=requested_source,
        role="источник",
    )
    dest_final = _recheck_destination(
        dest_initial,
        dest,
        requested=requested_dest,
        role="назначение",
    )

    txn_id = ActionRecord.new_id()
    mutation_error: str | None = None
    try:
        shutil.move(str(source), str(dest))
    except Exception as exc:  # noqa: BLE001 - после попытки изменяющей операции нужен Recovery Mode
        mutation_error = f"{type(exc).__name__}: {exc}"

    verify, status = _verify_move_result(source, dest, mutation_error)
    expected = {"source_exists": False, "dest_exists": True}
    record = ActionRecord(
        txn_id=txn_id,
        status=status,
        kind="fs.move",
        risk=Risk.HIGH,
        reason=reason,
        cwd=str(Path.cwd().resolve()),
        target_paths=[str(source), str(dest)],
        command={
            "op": "move",
            "source": str(source),
            "dest": str(dest),
            "requested_source": requested_source,
            "requested_dest": requested_dest,
        },
        undo={"op": "move", "source": str(dest), "dest": str(source)},
        redo={"op": "move", "source": str(source), "dest": str(dest)},
        expected_state=expected,
        verify_result=verify,
        verification_complete=True,
        verified_assertions=expected if status == Status.DONE else {},
        mismatched_assertions={} if status == Status.DONE else {"move_result": {"expected": expected, "actual": verify}},
        actual_state=verify,
        metadata={
            "before": before,
            "preflight": {
                "source_initial": source_initial,
                "source_final": source_final,
                "dest_initial": dest_initial,
                "dest_final": dest_final,
            },
        },
    )
    journal.append(record)
    if status == Status.UNEXPECTED:
        journal.block("неожиданный результат после fs.move", txn_id)
    return record


def fs_trash(path: Path, reason: str, journal: Journal) -> ActionRecord:
    require_not_blocked(journal)
    requested_path, path = _requested_path(path, "путь")
    source_initial = _preflight_existing_path(
        path,
        requested=requested_path,
        role="путь",
    )
    before = describe_path(path)

    txn_id = ActionRecord.new_id()
    trash_root = _absolute_path(journal.safety_dir / "trash")
    trash_root_preflight = _preflight_existing_path(
        trash_root,
        requested=str(trash_root),
        role="корень safety-trash",
        require_directory=True,
    )
    trash_dir = trash_root / txn_id
    dest = trash_dir / path.name
    _guard_no_overlap(path, dest)

    trash_dir.mkdir(parents=False, exist_ok=False)
    dest_initial = _preflight_destination(
        dest,
        requested=str(dest),
        role="назначение safety-trash",
    )

    source_final = _recheck_existing(
        source_initial,
        path,
        requested=requested_path,
        role="путь",
    )
    dest_final = _recheck_destination(
        dest_initial,
        dest,
        requested=str(dest),
        role="назначение safety-trash",
    )
    _preflight_existing_path(
        trash_root,
        requested=str(trash_root),
        role="корень safety-trash",
        require_directory=True,
    )

    mutation_error: str | None = None
    try:
        shutil.move(str(path), str(dest))
    except Exception as exc:  # noqa: BLE001 - после попытки изменяющей операции нужен Recovery Mode
        mutation_error = f"{type(exc).__name__}: {exc}"

    verify, status = _verify_move_result(path, dest, mutation_error)
    expected = {"source_exists": False, "trash_exists": True}
    verify["trash_exists"] = verify.pop("dest_exists")
    record = ActionRecord(
        txn_id=txn_id,
        status=status,
        kind="fs.trash",
        risk=Risk.HIGH,
        reason=reason,
        cwd=str(Path.cwd().resolve()),
        target_paths=[str(path), str(dest)],
        command={
            "op": "trash",
            "source": str(path),
            "dest": str(dest),
            "requested_path": requested_path,
        },
        undo={"op": "move", "source": str(dest), "dest": str(path)},
        redo={"op": "move", "source": str(path), "dest": str(dest)},
        expected_state=expected,
        verify_result=verify,
        verification_complete=True,
        verified_assertions=expected if status == Status.DONE else {},
        mismatched_assertions={} if status == Status.DONE else {"trash_result": {"expected": expected, "actual": verify}},
        actual_state=verify,
        metadata={
            "before": before,
            "preflight": {
                "source_initial": source_initial,
                "source_final": source_final,
                "trash_root": trash_root_preflight,
                "dest_initial": dest_initial,
                "dest_final": dest_final,
            },
        },
    )
    journal.append(record)
    if status == Status.UNEXPECTED:
        journal.block("неожиданный результат после fs.trash", txn_id)
    return record


def _reversal_context(record: dict[str, Any], journal: Journal, event: str):
    """Берёт состояние из журнала, включая уже выполненные обратные шаги."""
    txn_id = record.get("txn_id")
    original = journal.find(txn_id) if isinstance(txn_id, str) else None
    if not original or original.get("kind") not in {"fs.move", "fs.trash"}:
        raise SafetyError("undo/redo поддерживают только записанные файловые перемещения")
    state = original.get("status")
    evidence = (original.get("verify_result") or {}).get("dest_identity")
    before = (original.get("metadata") or {}).get("before") or {}
    digest = (before.get("source", before)).get("sha256")
    for item in journal.records():
        if item.get("txn_id") == txn_id and item.get("event") in {"undo", "redo"}:
            state = item.get("status")
            verification = item.get("verify_result") or {}
            evidence = verification.get("dest_identity")
            digest = verification.get("sha256")
    required = Status.DONE.value if event == "undo" else Status.UNDONE.value
    if state != required:
        raise SafetyError(f"недопустимый переход {event}: состояние транзакции {state}")
    if not isinstance(evidence, dict) or any(key not in evidence for key in _IDENTITY_FIELDS):
        raise SafetyError("в журнале недостаточно сведений об объекте; нужно ручное восстановление")
    return original, evidence, digest


def _reversal_parent(original: dict[str, Any], event: str) -> dict[str, Any]:
    preflight = (original.get("metadata") or {}).get("preflight") or {}
    if event == "undo":
        chain = (preflight.get("source_initial") or {}).get("chain") or []
        parent = chain[-2] if len(chain) >= 2 else None
    else:
        parent = ((preflight.get("dest_initial") or {}).get("parent") or {}).get("leaf")
    if not isinstance(parent, dict):
        raise SafetyError("не записана идентичность родителя назначения; нужно ручное восстановление")
    return parent


def _reverse_move(record: dict[str, Any], journal: Journal, event: str) -> dict[str, Any]:
    # Восстановление при инциденте не должно быть скрытым обходом общего барьера.
    require_not_blocked(journal)
    original, expected_identity, expected_digest = _reversal_context(record, journal, event)
    operation = original.get(event) or {}
    if operation.get("op") != "move":
        raise SafetyError("undo/redo не исполняют произвольные команды")
    if any(not isinstance(operation.get(key), str) or not operation[key] for key in ("source", "dest")):
        raise SafetyError("неполные пути файлового восстановления")
    requested_source, source = _requested_path(Path(operation["source"]), "источник восстановления")
    requested_dest, dest = _requested_path(Path(operation["dest"]), "назначение восстановления")
    _guard_no_overlap(source, dest)
    source_initial = _preflight_existing_path(source, requested=requested_source, role="источник восстановления")
    dest_initial = _preflight_destination(dest, requested=requested_dest, role="назначение восстановления")
    if not _same_leaf_identity({"leaf": expected_identity}, source_initial):
        raise SafetyError("объект восстановления изменился после записанного перемещения")
    expected_parent = _reversal_parent(original, event)
    actual_parent = dest_initial["parent"]["leaf"]
    # Время и размер каталога меняются при штатном перемещении его ребёнка.
    parent_fields = ("device", "inode", "kind", "mode", "file_attributes", "reparse_tag")
    if any(key not in expected_parent or expected_parent[key] != actual_parent.get(key) for key in parent_fields):
        raise SafetyError("родитель назначения заменён после исходного перемещения")
    kind = source_initial["leaf"]["kind"]
    if kind not in {"file", "directory"}:
        raise SafetyError("восстановление поддерживает только обычные файлы и каталоги")
    if kind == "file":
        if not isinstance(expected_digest, str) or _hash_file(source) != expected_digest:
            raise SafetyError("содержимое файла восстановления не совпадает с журналом")

    txn_id = original["txn_id"]
    operation_id = ActionRecord.new_id()
    # Барьер создаётся до повторной проверки и остаётся при аварии процесса.
    try:
        journal.begin_pending(txn_id)
    except OSError as exc:
        raise SafetyError("не удалось установить барьер восстановления; действие не запущено") from exc
    try:
        _recheck_existing(source_initial, source, requested=requested_source, role="источник восстановления")
        _recheck_destination(dest_initial, dest, requested=requested_dest, role="назначение восстановления")
        journal.append_raw({
            "event": f"{event}.planned", "txn_id": txn_id, "operation_id": operation_id,
            "source": str(source), "dest": str(dest),
            "expected_state": {"source_exists": False, "dest_exists": True},
            "source_identity": source_initial["leaf"],
        }, durable=True)
    except (Exception, KeyboardInterrupt) as exc:
        # Изменение цели ещё не начиналось. Незавершённый барьер сохраняется
        # для явной диагностики, если подготовка оборвалась после его создания.
        raise SafetyError("подготовка восстановления прервана; действие не запущено, требуется диагностика") from exc

    mutation_error = None
    try:
        shutil.move(str(source), str(dest))
    except (Exception, KeyboardInterrupt) as exc:
        mutation_error = f"{type(exc).__name__}: {exc}"
    try:
        verify, status = _verify_move_result(source, dest, mutation_error)
        if status == Status.DONE:
            if verify["dest_identity"]["kind"] != kind:
                status = Status.UNEXPECTED
                verify["error"] = "тип результата восстановления изменился"
            elif kind == "file":
                verify["sha256"] = _hash_file(dest)
                if verify["sha256"] != expected_digest:
                    status = Status.UNEXPECTED
                    verify["error"] = "содержимое результата восстановления не совпало"
    except (Exception, KeyboardInterrupt) as exc:
        verify = {"error": f"{type(exc).__name__}: {exc}"}
        status = Status.UNEXPECTED
    success_status = Status.UNDONE.value if event == "undo" else Status.DONE.value
    result = {
        "event": event, "txn_id": txn_id, "operation_id": operation_id,
        "source": str(source), "dest": str(dest),
        "status": success_status if status == Status.DONE else Status.UNEXPECTED.value,
        "verification_complete": status == Status.DONE, "verify_result": verify,
    }
    if status == Status.UNEXPECTED:
        journal.block(f"неожиданный результат файлового {event}", txn_id)
    # Если запись результата не удаётся, ранее установленный барьер остаётся.
    journal.append_raw(result, durable=True)
    if status == Status.UNEXPECTED:
        raise SafetyError("восстановление не подтверждено; включён Recovery Mode")
    if not journal.finish_pending(txn_id):
        result.update(status=Status.UNEXPECTED.value, verification_complete=False)
        result["verify_result"]["barrier_error"] = True
        journal.block("не удалось завершить барьер файлового восстановления", txn_id)
        journal.append_raw(result, durable=True)
        raise SafetyError("барьер восстановления не завершён; включён Recovery Mode")
    return {"undone" if event == "undo" else "redone": txn_id}


def undo_record(record: dict[str, Any], journal: Journal) -> dict[str, Any]:
    return _reverse_move(record, journal, "undo")


def redo_record(record: dict[str, Any], journal: Journal) -> dict[str, Any]:
    return _reverse_move(record, journal, "redo")
