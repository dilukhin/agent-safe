"""Строгий внутренний вход процесса; разрешения остаются вне спецификации."""

from __future__ import annotations

import json
import math
import os
import stat
from pathlib import Path
from typing import Any

from agent_safe.adapters.fs import SafetyError


JSON_LIMIT = 1024 * 1024
FILE_LIMIT = 8 * 1024 * 1024


def text_value(value: object, *, empty: bool = False, limit: int = 32768) -> str:
    if not isinstance(value, str) or (not empty and not value.strip()) or "\0" in value:
        raise SafetyError("нужна строка без NUL и пустого обязательного значения")
    try:
        if len(value.encode("utf-8")) > limit:
            raise SafetyError("строка превышает допустимый размер")
    except UnicodeError as exc:
        raise SafetyError("строка содержит некорректный Unicode") from exc
    return value


def strict_object(raw: str) -> dict[str, Any]:
    text_value(raw, limit=JSON_LIMIT)

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("повтор ключа")
            result[key] = value
        return result

    def reject_constant(_value):
        raise ValueError("неконечное число")

    try:
        value = json.loads(raw, object_pairs_hook=unique, parse_constant=reject_constant)
        # Проверяем также Unicode/NUL внутри экранированных JSON-строк.
        def check(item):
            if isinstance(item, str):
                text_value(item, empty=True, limit=JSON_LIMIT)
            elif isinstance(item, dict):
                for key, child in item.items():
                    check(key)
                    check(child)
            elif isinstance(item, list):
                for child in item:
                    check(child)
            elif isinstance(item, float) and not math.isfinite(item):
                raise ValueError("неконечное число")
        check(value)
    except (ValueError, RecursionError) as exc:
        raise SafetyError("нужен строгий UTF-8 JSON без повторов ключей и неконечных чисел") from exc
    if not isinstance(value, dict):
        raise SafetyError("ожидается JSON-объект")
    return value


def absolute_path(value: object) -> Path:
    path = Path(text_value(value))
    if not path.is_absolute() or ".." in path.parts:
        raise SafetyError("нужен абсолютный путь без ..")
    if os.name == "nt" and (str(path).startswith("\\\\") or ":" in str(path)[2:]):
        raise SafetyError("сетевые пути, устройства и альтернативные потоки не поддерживаются")
    return path


def checked_path(path: Path, *, missing: bool = False) -> os.stat_result | None:
    """Проверяет всю цепочку, не разрешая ссылки и точки повторной обработки."""
    try:
        leaf = None
        for part in reversed((path, *path.parents)):
            try:
                info = part.lstat()
            except FileNotFoundError:
                if missing and part == path:
                    return None
                raise
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise SafetyError("ссылки и reparse point в пути восстановления запрещены")
            if part != path and not stat.S_ISDIR(info.st_mode):
                raise SafetyError("родитель пути должен быть каталогом")
            leaf = info
        return leaf
    except (OSError, ValueError) as exc:
        raise SafetyError("путь восстановления недоступен") from exc


def identity(info: os.stat_result) -> list[int]:
    return [info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns,
            getattr(info, "st_file_attributes", 0), getattr(info, "st_reparse_tag", 0)]


def directory_identity(path: Path) -> list[int]:
    info = checked_path(path)
    if info is None or not stat.S_ISDIR(info.st_mode):
        raise SafetyError("ожидается существующий каталог")
    return [info.st_dev, info.st_ino, info.st_mode,
            getattr(info, "st_file_attributes", 0), getattr(info, "st_reparse_tag", 0)]


def read_regular(path: Path, limit: int = FILE_LIMIT) -> bytes:
    before = checked_path(path)
    if before is None or not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        raise SafetyError("ожидается обычный файл в пределах допустимого размера")
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
        with os.fdopen(os.open(path, flags), "rb") as stream:
            if identity(os.fstat(stream.fileno())) != identity(before):
                raise SafetyError("файл подменён при открытии")
            raw = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
        current = checked_path(path)
        if (len(raw) > limit or identity(after) != identity(before)
                or current is None or identity(current) != identity(before)):
            raise SafetyError("файл изменился во время чтения")
        return raw
    except OSError as exc:
        raise SafetyError("не удалось прочитать файл восстановления") from exc


def read_json_file(path: Path) -> str:
    try:
        return read_regular(absolute_path(str(path)), JSON_LIMIT).decode("utf-8")
    except UnicodeError as exc:
        raise SafetyError("файл должен содержать UTF-8 JSON") from exc


def validate_spec(value: object, artifact_ids: set[str]) -> dict[str, Any]:
    required = {"schema_version", "program", "argv", "cwd", "shell", "timeout_seconds"}
    if (not isinstance(value, dict) or not required <= value.keys()
            or value.keys() - required - {"stdin_utf8", "env_dependencies"}):
        raise SafetyError("неизвестные или отсутствующие поля ProcessSpec")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1 or value["shell"] is not False:
        raise SafetyError("ProcessSpec требует schema_version=1 и shell=false")
    absolute_path(value["program"])
    directory_identity(absolute_path(value["cwd"]))
    timeout = value["timeout_seconds"]
    if type(timeout) is not int or not 1 <= timeout <= 3600:
        raise SafetyError("тайм-аут должен быть целым числом от 1 до 3600")
    if value.get("env_dependencies", []) != []:
        raise SafetyError("этот профиль пока не поддерживает зависимости окружения")
    if "stdin_utf8" in value:
        text_value(value["stdin_utf8"], empty=True, limit=65536)
    argv = value["argv"]
    if not isinstance(argv, list) or len(argv) > 1024:
        raise SafetyError("argv должен быть массивом не более 1024 аргументов")
    for arg in argv:
        if isinstance(arg, dict):
            if set(arg) != {"artifact"} or not isinstance(arg["artifact"], str) or arg["artifact"] not in artifact_ids:
                raise SafetyError("неизвестная ссылка на артефакт")
        else:
            text_value(arg, empty=True)
    return value
