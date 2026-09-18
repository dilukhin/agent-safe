"""Проверка явного плана восстановления без автоматического исполнения."""

from __future__ import annotations

import hashlib
import json
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent_safe.adapters.fs import SafetyError


_LIMIT = 1024 * 1024
_FIELDS = {
    "schema_version", "kind", "target", "checkpoint_id", "recovery_source",
    "evidence_path", "evidence_sha256", "conditions", "recovery_steps",
}


def _text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _object(text: str) -> dict[str, Any]:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("повтор поля")
            result[key] = value
        return result

    def reject_constant(_value):
        raise ValueError("неконечное число")

    try:
        value = json.loads(text, object_pairs_hook=unique, parse_constant=reject_constant)
    except (ValueError, RecursionError) as exc:
        raise SafetyError("план восстановления или свидетельство содержит некорректный JSON") from exc
    if not isinstance(value, dict):
        raise SafetyError("план восстановления и свидетельство должны быть JSON-объектами")
    return value


def _timestamp(value: object) -> datetime:
    if not _text(value):
        raise SafetyError("свидетельство требует время с часовым поясом")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SafetyError("некорректное время в свидетельстве восстановления") from exc
    if result.tzinfo is None:
        raise SafetyError("время свидетельства должно включать часовой пояс")
    return result


def _read_evidence(path: Path) -> bytes:
    try:
        # Не принимаем ссылки, junction и неопределённые типы объектов.
        for part in (path, *path.parents):
            info = part.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise SafetyError("путь свидетельства не должен проходить через ссылки или reparse point")
        if not stat.S_ISREG(path.stat().st_mode):
            raise SafetyError("свидетельство должно быть обычным файлом")
        with path.open("rb") as stream:
            data = stream.read(_LIMIT + 1)
    except (OSError, ValueError) as exc:
        raise SafetyError("свидетельство восстановления отсутствует или недоступно") from exc
    if len(data) > _LIMIT:
        raise SafetyError("свидетельство восстановления превышает 1 МиБ")
    return data


def validate_recovery_contract(text: str, *, target: str, cwd: Path) -> dict[str, Any]:
    if len(text.encode("utf-8")) > _LIMIT:
        raise SafetyError("план восстановления превышает 1 МиБ")
    contract = _object(text)
    if set(contract) != _FIELDS:
        raise SafetyError("план восстановления имеет неизвестные или отсутствующие поля")
    if type(contract["schema_version"]) is not int or contract["schema_version"] != 1:
        raise SafetyError("поддерживается только schema_version=1 плана восстановления")
    if contract["kind"] != "checkpoint":
        raise SafetyError("поддерживается только явно выбранный вид восстановления checkpoint")
    if contract["target"] != target:
        raise SafetyError("цель плана восстановления не совпадает с --target")
    for key in ("checkpoint_id", "recovery_source", "evidence_path", "evidence_sha256"):
        if not _text(contract[key]):
            raise SafetyError("план восстановления содержит пустое обязательное поле")
    digest = contract["evidence_sha256"]
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise SafetyError("evidence_sha256 должен быть SHA-256 из 64 строчных hex-символов")
    conditions = contract["conditions"]
    if not isinstance(conditions, dict) or not conditions:
        raise SafetyError("нужны непустые проверяемые условия доступности восстановления")
    if any(not _text(key) or value is not True for key, value in conditions.items()):
        raise SafetyError("все условия доступности восстановления должны требовать true")
    steps = contract["recovery_steps"]
    if not isinstance(steps, list) or not steps or any(not _text(step) for step in steps):
        raise SafetyError("нужны непустые шаги ручного или специализированного восстановления")

    path = Path(contract["evidence_path"])
    if ".." in path.parts:
        raise SafetyError("путь свидетельства не должен содержать ..")
    if not path.is_absolute():
        path = cwd / path
    raw = _read_evidence(path)
    if hashlib.sha256(raw).hexdigest() != digest:
        raise SafetyError("SHA-256 свидетельства восстановления не совпадает")
    try:
        evidence = _object(raw.decode("utf-8"))
    except UnicodeError as exc:
        raise SafetyError("свидетельство восстановления должно быть UTF-8 JSON") from exc
    if type(evidence.get("schema_version")) is not int or evidence.get("schema_version") != 1:
        raise SafetyError("неподдерживаемая схема свидетельства восстановления")
    for key in ("target", "checkpoint_id", "recovery_source"):
        if evidence.get(key) != contract[key]:
            raise SafetyError("свидетельство относится к другой цели или контрольной точке")
    actual = evidence.get("conditions")
    if not isinstance(actual, dict) or any(actual.get(key) is not True for key in conditions):
        raise SafetyError("свидетельство не подтверждает все условия восстановления")
    observed = _timestamp(evidence.get("observed_at"))
    expires = _timestamp(evidence.get("valid_until"))
    now = datetime.now(timezone.utc)
    if not observed <= now < expires:
        raise SafetyError("свидетельство восстановления просрочено или датировано будущим")

    # Сохраняем лишь согласованные поля, не копируя произвольное содержимое evidence.
    return {
        "mode": "checkpoint",
        "automatic": False,
        "contract": contract,
        "evidence": {
            "sha256": digest,
            "size_bytes": len(raw),
            "observed_at": observed.isoformat(),
            "valid_until": expires.isoformat(),
            "validated_at": now.isoformat(),
            "conditions": conditions,
        },
    }
