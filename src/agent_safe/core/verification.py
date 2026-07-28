from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


_ALLOWED_EXPECTED_STATE_KEYS = {"assertions", "declarations"}


class VerificationError(ValueError):
    """Ошибка структуры expected state или результата verify без вывода исходных данных."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ExpectedStateSpec:
    assertions: dict[str, Any] = field(default_factory=dict)
    declarations: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "assertions": self.assertions,
            "declarations": self.declarations,
        }


@dataclass(frozen=True)
class VerificationOutcome:
    verification_complete: bool
    actual_state: dict[str, Any] = field(default_factory=dict)
    verified_assertions: dict[str, Any] = field(default_factory=dict)
    missing_assertions: dict[str, Any] = field(default_factory=dict)
    mismatched_assertions: dict[str, Any] = field(default_factory=dict)
    error_code: str | None = None
    error_message: str | None = None

    @property
    def successful(self) -> bool:
        return (
            self.verification_complete
            and not self.missing_assertions
            and not self.mismatched_assertions
            and self.error_code is None
        )


def parse_expected_state(text: str | None) -> ExpectedStateSpec:
    if not text:
        raise VerificationError("expected_state_empty", "expected state не должен быть пустым")
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise VerificationError(
            "expected_state_invalid_json",
            f"expected state должен быть корректным JSON-объектом: строка {exc.lineno}, столбец {exc.colno}",
        ) from exc
    if not isinstance(value, dict):
        raise VerificationError("expected_state_not_object", "expected state должен быть JSON-объектом")

    unknown = sorted(set(value) - _ALLOWED_EXPECTED_STATE_KEYS)
    if unknown:
        raise VerificationError(
            "expected_state_unknown_fields",
            "expected state допускает только поля assertions и declarations; неизвестные поля: "
            + ", ".join(unknown),
        )

    assertions = value.get("assertions", {})
    declarations = value.get("declarations", {})
    if not isinstance(assertions, dict):
        raise VerificationError("assertions_not_object", "поле assertions должно быть JSON-объектом")
    if not isinstance(declarations, dict):
        raise VerificationError("declarations_not_object", "поле declarations должно быть JSON-объектом")
    if not assertions and not declarations:
        raise VerificationError(
            "expected_state_empty_sections",
            "expected state должен содержать непустые assertions или declarations",
        )
    return ExpectedStateSpec(assertions=assertions, declarations=declarations)


def parse_actual_state(stdout: str | None) -> dict[str, Any]:
    if stdout is None or not stdout.strip():
        raise VerificationError("actual_state_empty", "verify-команда не вернула JSON фактического состояния")
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise VerificationError(
            "actual_state_invalid_json",
            f"verify-команда вернула некорректный JSON: строка {exc.lineno}, столбец {exc.colno}",
        ) from exc
    if not isinstance(value, dict):
        raise VerificationError("actual_state_not_object", "verify-команда должна вернуть JSON-объект")
    return value


def _join_path(path: str, key: str) -> str:
    return key if not path else f"{path}.{key}"


def _index_path(path: str, index: int) -> str:
    return f"{path}[{index}]" if path else f"[{index}]"


def _flatten_expected(value: Any, path: str = "") -> dict[str, Any]:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        if not value and path:
            out[path] = value
        for key, child in value.items():
            out.update(_flatten_expected(child, _join_path(path, str(key))))
        return out
    if isinstance(value, list):
        out = {}
        if not value and path:
            out[path] = value
        for index, child in enumerate(value):
            out.update(_flatten_expected(child, _index_path(path, index)))
        return out
    return {path: value}


def compare_assertions(assertions: dict[str, Any], actual_state: dict[str, Any]) -> VerificationOutcome:
    verified: dict[str, Any] = {}
    missing: dict[str, Any] = {}
    mismatched: dict[str, Any] = {}

    def compare(expected: Any, actual: Any, path: str) -> None:
        if type(actual) is not type(expected):
            mismatched[path] = {
                "expected": expected,
                "actual": actual,
                "reason": "type_mismatch",
            }
            return

        if isinstance(expected, dict):
            if not expected:
                verified[path] = actual
                return
            for key, expected_value in expected.items():
                child_path = _join_path(path, str(key))
                if key not in actual:
                    missing[child_path] = {"expected": expected_value}
                    continue
                compare(expected_value, actual[key], child_path)
            return

        if isinstance(expected, list):
            if len(actual) != len(expected):
                mismatched[path] = {
                    "expected": expected,
                    "actual": actual,
                    "reason": "length_mismatch",
                }
                return
            if not expected:
                verified[path] = actual
                return
            for index, expected_value in enumerate(expected):
                compare(expected_value, actual[index], _index_path(path, index))
            return

        if actual == expected:
            verified[path] = actual
        else:
            mismatched[path] = {
                "expected": expected,
                "actual": actual,
                "reason": "value_mismatch",
            }

    for key, expected_value in assertions.items():
        path = str(key)
        if key not in actual_state:
            missing[path] = {"expected": expected_value}
            continue
        compare(expected_value, actual_state[key], path)

    return VerificationOutcome(
        verification_complete=not missing and not mismatched,
        actual_state=actual_state,
        verified_assertions=verified,
        missing_assertions=missing,
        mismatched_assertions=mismatched,
    )


def verify_stdout(assertions: dict[str, Any], stdout: str | None) -> VerificationOutcome:
    try:
        actual_state = parse_actual_state(stdout)
    except VerificationError as exc:
        return VerificationOutcome(
            verification_complete=False,
            missing_assertions={path: {"expected": value} for path, value in _flatten_expected(assertions).items()},
            error_code=exc.code,
            error_message=str(exc),
        )
    return compare_assertions(assertions, actual_state)


def failed_verification(assertions: dict[str, Any], code: str, message: str) -> VerificationOutcome:
    return VerificationOutcome(
        verification_complete=False,
        missing_assertions={path: {"expected": value} for path, value in _flatten_expected(assertions).items()},
        error_code=code,
        error_message=message,
    )
