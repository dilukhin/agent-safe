"""Сохранённый комплект локального восстановления обычного файла."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

from agent_safe.adapters.fs import SafetyError
from agent_safe.core.journal import Journal
from agent_safe.core.process_spec import (
    FILE_LIMIT, absolute_path, checked_path, directory_identity, identity,
    read_json_file, read_regular, strict_object, text_value, validate_spec,
)
from agent_safe.core.verification import VerificationError, parse_expected_state


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def encoded(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def target_state(target: str, journal: Journal) -> dict[str, Any]:
    path = absolute_path(target)
    if path == journal.safety_dir or journal.safety_dir in path.parents:
        raise SafetyError("цель восстановления не должна находиться в служебном каталоге")
    parent = directory_identity(path.parent)
    info = checked_path(path, missing=True)
    if info is None:
        return {"parent": parent, "file": None}
    if not stat.S_ISREG(info.st_mode):
        raise SafetyError("первый профиль восстановления поддерживает только обычный файл или его отсутствие")
    raw = read_regular(path)
    return {"parent": parent, "file": {"identity": identity(info), "sha256": digest(raw)}}


def check_storage(journal: Journal) -> None:
    directory_identity(journal.safety_dir)
    directory_identity(journal.safety_dir / "recovery")
    for path in (journal.journal_path, journal.block_path):
        info = checked_path(path, missing=True)
        if info is not None and not stat.S_ISREG(info.st_mode):
            raise SafetyError("журнал и блокировка должны быть обычными файлами")


def local_journal(root: Path | None) -> Journal:
    """Проверяет существующие служебные пути до создания каталогов Journal."""
    root = Path(root or Path.cwd()).resolve()
    safety = root / ".agent-safety"
    info = checked_path(safety, missing=True)
    if info is not None:
        directory_identity(safety)
        for name in ("trash", "snapshots", "patches", "evidence", "recovery", "command-output"):
            child = safety / name
            if checked_path(child, missing=True) is not None:
                directory_identity(child)
    journal = Journal(root)
    check_storage(journal)
    return journal


def bundle_path(journal: Journal, txn_id: str) -> Path:
    if not isinstance(txn_id, str) or not re.fullmatch(r"\d{8}-\d{6}-[0-9a-f]{8}", txn_id):
        raise SafetyError("нужен точный идентификатор исходной транзакции")
    return journal.safety_dir / "recovery" / txn_id


def sync_directory(path: Path) -> None:
    if os.name != "nt":
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def write_new(path: Path, raw: bytes) -> None:
    directory_identity(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    if read_regular(path, max(len(raw), 1)) != raw:
        raise SafetyError("записанный комплект не прошёл проверку")
    sync_directory(path.parent)


def python_profile(spec: dict[str, Any]) -> None:
    # Системный интерпретатор — доверенная часть установки; скрипт сохраняется отдельно.
    program = absolute_path(spec["program"])
    trusted = Path(sys.executable).resolve()
    if program != trusted:
        raise SafetyError("первый профиль требует абсолютный путь текущего Python без ссылок")
    info = checked_path(program)
    if info is None or not stat.S_ISREG(info.st_mode):
        raise SafetyError("исполняемый файл Python недоступен")
    argv = spec["argv"]
    if len(argv) < 2 or argv[0] != "-I" or not isinstance(argv[1], dict):
        raise SafetyError("поддерживается Python -I и отдельный сохранённый скрипт; inline-код запрещён")


def validate_plan(raw: str, *, target: str) -> dict[str, Any]:
    plan = strict_object(raw)
    if set(plan) != {"schema_version", "target", "artifacts", "process", "verify", "expected_state"}:
        raise SafetyError("неизвестные или отсутствующие поля RollbackPlan")
    if type(plan["schema_version"]) is not int or plan["schema_version"] != 1 or plan["target"] != target:
        raise SafetyError("версия или точная цель плана восстановления не совпадает")
    absolute_path(target)
    artifacts = plan["artifacts"]
    if not isinstance(artifacts, list) or not 1 <= len(artifacts) <= 32:
        raise SafetyError("план требует от 1 до 32 файлов")
    ids = set()
    for item in artifacts:
        if not isinstance(item, dict) or set(item) != {"id", "path", "non_secret"}:
            raise SafetyError("артефакт требует id, path и non_secret")
        name = text_value(item["id"])
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", name) or name in ids:
            raise SafetyError("некорректный или повторный id артефакта")
        ids.add(name)
        path = absolute_path(item["path"])
        if item["non_secret"] is not True or re.search(r"(^\.env($|\.)|token|secret|cookie|session|\.(pem|key|p12|pfx)$)", path.name, re.I):
            raise SafetyError("секретные файлы не поддерживаются этим профилем")
    for role in ("process", "verify"):
        validate_spec(plan[role], ids)
        python_profile(plan[role])
    try:
        parse_expected_state(json.dumps(plan["expected_state"], ensure_ascii=False))
    except VerificationError as exc:
        raise SafetyError(str(exc)) from exc
    return plan


def prepare_bundle(raw: str, *, target: str, txn_id: str, journal: Journal) -> dict[str, Any]:
    check_storage(journal)
    plan = validate_plan(raw, target=target)
    state = target_state(target, journal)
    files = {}
    total = 0
    for item in plan["artifacts"]:
        data = read_regular(absolute_path(item["path"]))
        total += len(data)
        if total > 32 * 1024 * 1024:
            raise SafetyError("комплект восстановления превышает 32 МиБ")
        files[item["id"]] = data
    root = bundle_path(journal, txn_id)
    manifest = {
        "schema_version": 1, "source_txn_id": txn_id, "plan": plan,
        "target_before": state,
        "context": {role: {"cwd": directory_identity(absolute_path(plan[role]["cwd"])),
                           "program": identity(checked_path(absolute_path(plan[role]["program"])))}
                    for role in ("process", "verify")},
        "artifacts": {name: {"type": "regular-file", "size_bytes": len(data), "sha256": digest(data)}
                      for name, data in files.items()},
    }
    try:
        root.mkdir(mode=0o700)
        (root / "artifacts").mkdir(mode=0o700)
        for name, data in files.items():
            write_new(root / "artifacts" / name, data)
        write_new(root / "plan.json", encoded(plan))
        raw_manifest = encoded(manifest)
        write_new(root / "manifest.json", raw_manifest)
        sync_directory(root.parent)
    except OSError as exc:
        raise SafetyError("не удалось сохранить комплект; основное действие не запущено, частичные файлы сохранены") from exc
    return {"mode": "saved-rollback", "automatic": False, "manifest_sha256": digest(raw_manifest),
            "plan_sha256": digest(encoded(plan)), "bundle": str(root), "target_state": state}


def load_bundle(*, journal: Journal, txn_id: str, recovery: dict[str, Any], plan_raw: str | None = None) -> dict[str, Any]:
    check_storage(journal)
    root = bundle_path(journal, txn_id)
    raw = read_regular(root / "manifest.json", 1024 * 1024)
    if digest(raw) != recovery.get("manifest_sha256"):
        raise SafetyError("контрольная сумма комплекта восстановления изменилась")
    try:
        manifest = strict_object(raw.decode("utf-8"))
    except UnicodeError as exc:
        raise SafetyError("комплект восстановления содержит некорректный UTF-8") from exc
    if manifest.get("source_txn_id") != txn_id:
        raise SafetyError("комплект относится к другой транзакции")
    plan = manifest["plan"]
    supplied = read_json_file(root / "plan.json") if plan_raw is None else plan_raw
    supplied_plan = validate_plan(supplied, target=plan["target"])
    if supplied_plan != plan or digest(encoded(supplied_plan)) != recovery.get("plan_sha256"):
        raise SafetyError("план изменён; требуется отдельное рассмотрение")
    for name, expected in manifest["artifacts"].items():
        data = read_regular(root / "artifacts" / name)
        if len(data) != expected["size_bytes"] or digest(data) != expected["sha256"]:
            raise SafetyError("сохранённый артефакт отсутствует или изменён")
    for role in ("process", "verify"):
        spec = plan[role]
        python_profile(spec)
        context = manifest["context"][role]
        if (directory_identity(absolute_path(spec["cwd"])) != context["cwd"]
                or identity(checked_path(absolute_path(spec["program"]))) != context["program"]):
            raise SafetyError("каталог или интерпретатор восстановления изменился")
    return manifest


def resolved_spec(manifest: dict[str, Any], role: str, journal: Journal) -> dict[str, Any]:
    spec = dict(manifest["plan"][role])
    root = bundle_path(journal, manifest["source_txn_id"]) / "artifacts"
    spec["argv"] = [str(root / arg["artifact"]) if isinstance(arg, dict) else arg for arg in spec["argv"]]
    return spec
