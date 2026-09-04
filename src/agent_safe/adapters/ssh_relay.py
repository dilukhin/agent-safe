from __future__ import annotations

import hashlib
import json
import shlex
import subprocess
from pathlib import Path
from typing import Any
from uuid import UUID

from agent_safe.adapters.exec_adapter import exec_readonly
from agent_safe.adapters.fs import SafetyError
from agent_safe.core.journal import Journal
from agent_safe.core.models import ActionRecord, Risk, Status
from agent_safe.core.risk import assess_command
from agent_safe.core.verification import (
    VerificationError,
    VerificationOutcome,
    failed_verification,
    parse_expected_state,
    verify_stdout,
)


_RELAY_MODES = {"exec", "sudo-exec"}
_MACHINE_EXIT_CODES = {
    "succeeded": 0,
    "not_started": 10,
    "command_failed": 11,
    "partial_success": 12,
    "unknown": 13,
}
_HIGH_ATTENTION_RISKS = {Risk.CAUTIOUS, Risk.HIGH, Risk.UNKNOWN, Risk.CRITICAL}


def _split_relay(relay: str) -> list[str]:
    try:
        base = shlex.split(relay, posix=("\\" not in relay))
    except ValueError as exc:
        raise SafetyError(f"не удалось разобрать команду relay: {relay}: {exc}") from exc
    if not base:
        raise SafetyError("команда relay не должна быть пустой")
    return base


def _validate_relay_mode(relay_mode: str) -> str:
    if relay_mode not in _RELAY_MODES:
        raise SafetyError(f"неподдерживаемый режим ssh_relay: {relay_mode}")
    return relay_mode


def build_relay_command(
    relay: str,
    remote_command: str,
    *,
    relay_name: str | None = None,
    relay_mode: str = "exec",
    risky: bool = False,
    receipt_path: str | None = None,
    machine_json: bool = False,
    transaction_id: str | None = None,
) -> list[str]:
    relay_mode = _validate_relay_mode(relay_mode)
    command = [*_split_relay(relay), relay_mode]
    if relay_name:
        command.extend(["--name", relay_name])
    if machine_json:
        command.append("--json")
    if risky:
        command.append("--risky")
        if transaction_id:
            command.extend(["--transaction-id", transaction_id])
        elif machine_json:
            raise SafetyError("risky machine-команда ssh_relay требует заранее созданный transaction ID")
    if receipt_path:
        command.extend(["--receipt-path", receipt_path])
    command.append(remote_command)
    return command


def _run_machine(args: list[str], cwd: Path, timeout: int = 120) -> dict[str, Any]:
    try:
        proc = subprocess.run(args, cwd=str(cwd), text=True, capture_output=True, timeout=timeout)
    except (FileNotFoundError, PermissionError) as exc:
        return {
            "launched": False,
            "returncode": None,
            "error_type": type(exc).__name__,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "launched": True,
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "error_type": type(exc).__name__,
        }
    except KeyboardInterrupt as exc:
        return {
            "launched": True,
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "error_type": type(exc).__name__,
        }
    except Exception as exc:  # noqa: BLE001 - после запуска процесса исход удалённой команды может быть неизвестен
        return {
            "launched": True,
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "error_type": type(exc).__name__,
        }
    return {
        "launched": True,
        "returncode": int(proc.returncode),
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def _byte_len(value: object) -> int:
    return len(str(value or "").encode("utf-8", errors="replace"))


def _is_sha256(value: object) -> bool:
    text = str(value or "")
    return len(text) == 64 and all(char in "0123456789abcdefABCDEF" for char in text)


def _is_uuid(value: object) -> bool:
    try:
        UUID(str(value))
    except (ValueError, TypeError, AttributeError):
        return False
    return True


def _parse_machine_payload(
    run: dict[str, Any],
    *,
    relay_mode: str,
    risky: bool,
    transaction_id: str | None,
    relay_name: str | None,
) -> tuple[dict[str, Any] | None, str | None]:
    if not run.get("launched"):
        return None, "relay_launcher_not_started"
    try:
        payload = json.loads(str(run.get("stdout", "")))
    except json.JSONDecodeError:
        return None, "relay_machine_invalid_json"
    if not isinstance(payload, dict):
        return None, "relay_machine_not_object"

    if type(payload.get("schema_version")) is not int or payload.get("schema_version") != 1 or payload.get("tool") != "ssh_relay":
        return payload, "relay_machine_schema_mismatch"
    if payload.get("action") != relay_mode:
        return payload, "relay_machine_action_mismatch"
    if type(payload.get("sudo")) is not bool or payload.get("sudo") != (relay_mode == "sudo-exec"):
        return payload, "relay_machine_sudo_mismatch"
    if type(payload.get("risky")) is not bool or payload.get("risky") != risky:
        return payload, "relay_machine_risky_mismatch"
    if relay_name and payload.get("session") != relay_name:
        return payload, "relay_machine_session_mismatch"

    operation_status = payload.get("operation_status")
    if operation_status not in _MACHINE_EXIT_CODES:
        return payload, "relay_machine_unknown_operation_status"
    if run.get("returncode") != _MACHINE_EXIT_CODES[operation_status]:
        return payload, "relay_machine_process_code_mismatch"

    command_status = payload.get("command_status")
    command_exit_code = payload.get("command_exit_code")
    receipt_status = payload.get("receipt_status")
    if type(payload.get("partial_success")) is not bool:
        return payload, "relay_machine_partial_flag_type"
    partial_success = payload.get("partial_success")

    if risky:
        if transaction_id is None or payload.get("transaction_id") != transaction_id:
            return payload, "relay_machine_transaction_mismatch"
        if operation_status != "not_started" and not _is_uuid(payload.get("receipt_id")):
            return payload, "relay_machine_receipt_id_missing"

    if operation_status == "succeeded":
        if command_status != "succeeded" or command_exit_code != 0:
            return payload, "relay_machine_success_command_mismatch"
        if risky:
            if receipt_status != "succeeded" or partial_success:
                return payload, "relay_machine_success_receipt_mismatch"
            if not _is_uuid(payload.get("receipt_id")) or not _is_sha256(payload.get("receipt_hash")):
                return payload, "relay_machine_success_receipt_identity_missing"
        elif receipt_status != "not_requested" or partial_success:
            return payload, "relay_machine_readonly_receipt_mismatch"
    elif operation_status == "not_started":
        if command_status != "not_started" or command_exit_code is not None or partial_success:
            return payload, "relay_machine_not_started_mismatch"
        if risky and receipt_status != "not_attempted":
            return payload, "relay_machine_not_started_receipt_mismatch"
    elif operation_status == "command_failed":
        if command_status != "failed" or type(command_exit_code) is not int or command_exit_code == 0:
            return payload, "relay_machine_command_failed_mismatch"
        if risky and receipt_status != "not_attempted":
            return payload, "relay_machine_command_failed_receipt_mismatch"
        if partial_success:
            return payload, "relay_machine_command_failed_partial_flag"
    elif operation_status == "partial_success":
        if not risky or command_status != "succeeded" or command_exit_code != 0:
            return payload, "relay_machine_partial_command_mismatch"
        if receipt_status not in {"failed", "unknown"} or not partial_success:
            return payload, "relay_machine_partial_receipt_mismatch"
    elif operation_status == "unknown":
        if command_status != "unknown" or command_exit_code is not None or partial_success:
            return payload, "relay_machine_unknown_mismatch"
        if risky and receipt_status != "unknown":
            return payload, "relay_machine_unknown_receipt_mismatch"

    return payload, None


def _relay_summary(run: dict[str, Any], payload: dict[str, Any] | None, contract_error: str | None) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "local_process": {
            "launched": bool(run.get("launched")),
            "returncode": run.get("returncode"),
            "stdout_bytes": _byte_len(run.get("stdout")),
            "stderr_bytes": _byte_len(run.get("stderr")),
            "error_type": run.get("error_type"),
        },
        "contract_error": contract_error,
    }
    if not isinstance(payload, dict):
        return summary
    summary.update(
        {
            "tool_version": payload.get("tool_version"),
            "action": payload.get("action"),
            "operation_status": payload.get("operation_status"),
            "session": payload.get("session"),
            "remote_host": payload.get("remote_host"),
            "remote_port": payload.get("remote_port"),
            "remote_user": payload.get("remote_user"),
            "sudo": payload.get("sudo"),
            "remote_command": {
                "status": payload.get("command_status"),
                "exit_code": payload.get("command_exit_code"),
                "stdout_bytes": _byte_len(payload.get("stdout")),
                "stderr_bytes": _byte_len(payload.get("stderr")),
            },
            "remote_receipt": {
                "status": payload.get("receipt_status"),
                "transaction_id": payload.get("transaction_id"),
                "receipt_id": payload.get("receipt_id"),
                "receipt_hash": payload.get("receipt_hash"),
                "receipt_path": payload.get("receipt_path"),
            },
            "error_code": payload.get("error_code"),
            "error_stage": payload.get("error_stage"),
        }
    )
    return summary


def _risk_for_record(remote_command: str) -> tuple[Any, Risk]:
    assessment = assess_command(remote_command, channel="ssh_relay")
    risk = assessment.risk if assessment.risk in _HIGH_ATTENTION_RISKS else Risk.HIGH
    return assessment, risk


def _assessment_summary(assessment: Any) -> dict[str, Any]:
    return {
        "channel": assessment.channel,
        "domain": assessment.domain,
        "operation": assessment.operation,
        "risk": assessment.risk.value,
        "knowledge": assessment.knowledge.value,
        "predictability": assessment.predictability.value,
        "reversibility": assessment.reversibility.value,
        "state_changing": assessment.state_changing,
        "reasons": list(assessment.reasons),
        "required_next_step": assessment.required_next_step,
    }


def _expected_with_mode(expected_state_json: str, relay_mode: str):
    try:
        expected = parse_expected_state(expected_state_json)
    except VerificationError as exc:
        raise SafetyError(str(exc)) from exc
    declarations = dict(expected.declarations)
    declared_mode = declarations.get("ssh_relay_mode")
    if declared_mode is not None and declared_mode != relay_mode:
        raise SafetyError("expected state: ssh_relay_mode противоречит --relay-mode")
    declared_sudo = declarations.get("ssh_relay_sudo")
    sudo = relay_mode == "sudo-exec"
    if declared_sudo is not None and declared_sudo is not sudo:
        raise SafetyError("expected state: ssh_relay_sudo противоречит --relay-mode")
    declarations["ssh_relay_mode"] = relay_mode
    declarations["ssh_relay_sudo"] = sudo
    return expected, {"assertions": expected.assertions, "declarations": declarations}


def _validate_verify_command(verify_remote_command: str) -> None:
    verification_assessment = assess_command(verify_remote_command, channel="ssh_relay")
    if verification_assessment.state_changing or verification_assessment.risk != Risk.SAFE:
        raise SafetyError(
            "verify-команда ssh_relay должна быть read-only; "
            f"risk={verification_assessment.risk.value}; reasons={verification_assessment.reasons}"
        )


def ssh_relay_readonly(
    relay: str,
    remote_command: str,
    *,
    journal: Journal,
    host_label: str,
    reason: str,
    relay_name: str | None = None,
    cwd: Path | None = None,
):
    remote_assessment = assess_command(remote_command, channel="ssh_relay")
    if remote_assessment.state_changing or remote_assessment.risk.value != "safe":
        raise SafetyError(f"удалённая команда не является read-only: risk={remote_assessment.risk.value}; reasons={remote_assessment.reasons}")
    command = build_relay_command(relay, remote_command, relay_name=relay_name)
    return exec_readonly(command, journal=journal, channel="ssh_relay", domain="ssh_relay", reason=reason or f"read-only проверка на {host_label}", cwd=cwd)


def ssh_relay_risky(
    relay: str,
    remote_command: str,
    *,
    journal: Journal,
    host_label: str,
    reason: str,
    relay_name: str | None = None,
    relay_mode: str = "exec",
    receipt_path: str | None = None,
    expected_state_json: str,
    rollback_command: str,
    verify_remote_command: str | None,
    receipt_remote_command: str | None = None,
    approved: bool,
    allow_critical: bool,
    cwd: Path | None = None,
    timeout: int = 120,
):
    from agent_safe.adapters.exec_adapter import require_not_blocked

    require_not_blocked(journal)
    relay_mode = _validate_relay_mode(relay_mode)
    cwd = Path(cwd or journal.root).resolve()
    if not host_label.strip():
        raise SafetyError("ssh-relay-risky требует точный --host-label")
    if not approved:
        raise SafetyError("ssh-relay-risky требует --approved после проверки пользователем")
    if not rollback_command.strip():
        raise SafetyError("ssh-relay-risky требует --rollback-command")
    if receipt_remote_command:
        raise SafetyError("--receipt-remote-command несовместим с машинным receipt-контрактом ssh_relay")
    if relay_mode == "sudo-exec":
        if not receipt_path:
            raise SafetyError("sudo-exec требует явный системный --receipt-path")
        if not receipt_path.startswith("/"):
            raise SafetyError("для sudo-exec --receipt-path должен быть абсолютным системным POSIX-путём")
    if verify_remote_command is None or not verify_remote_command.strip():
        raise SafetyError("ssh-relay-risky требует --verify-remote-command")
    _validate_verify_command(verify_remote_command)

    assessment, record_risk = _risk_for_record(remote_command)
    if assessment.risk == Risk.CRITICAL and not allow_critical:
        raise SafetyError("критическая удалённая команда требует --allow-critical и явного плана восстановления")
    if assessment.risk == Risk.SAFE and not assessment.state_changing:
        raise SafetyError("удалённая команда выглядит read-only; используйте ssh-relay-readonly")

    expected, expected_state = _expected_with_mode(expected_state_json, relay_mode)
    txn_id = ActionRecord.new_id()
    command_hash = hashlib.sha256(remote_command.encode("utf-8")).hexdigest()
    risky_command = build_relay_command(
        relay,
        remote_command,
        relay_name=relay_name,
        relay_mode=relay_mode,
        risky=True,
        receipt_path=receipt_path,
        machine_json=True,
        transaction_id=txn_id,
    )
    run = _run_machine(risky_command, cwd, timeout=timeout)
    payload, contract_error = _parse_machine_payload(
        run,
        relay_mode=relay_mode,
        risky=True,
        transaction_id=txn_id,
        relay_name=relay_name,
    )
    operation_status = payload.get("operation_status") if payload and not contract_error else None

    verification: VerificationOutcome
    verify_run: dict[str, Any] | None = None
    verify_payload: dict[str, Any] | None = None
    verify_contract_error: str | None = None

    should_verify = bool(run.get("launched")) and operation_status != "not_started"
    if should_verify:
        verify_command = build_relay_command(
            relay,
            verify_remote_command,
            relay_name=relay_name,
            relay_mode=relay_mode,
            machine_json=True,
        )
        verify_run = _run_machine(verify_command, cwd, timeout=timeout)
        verify_payload, verify_contract_error = _parse_machine_payload(
            verify_run,
            relay_mode=relay_mode,
            risky=False,
            transaction_id=None,
            relay_name=relay_name,
        )
        if verify_contract_error:
            verification = failed_verification(
                expected.assertions,
                "verify_relay_contract_error",
                "verify через ssh_relay не дал согласованный машинный результат",
            )
        elif verify_payload.get("operation_status") != "succeeded":
            verification = failed_verification(
                expected.assertions,
                f"verify_relay_{verify_payload.get('operation_status')}",
                "verify-команда через ssh_relay не завершилась подтверждённо успешно",
            )
        else:
            verification = verify_stdout(expected.assertions, str(verify_payload.get("stdout", "")))
    elif not run.get("launched"):
        verification = failed_verification(
            expected.assertions,
            "relay_launcher_not_started",
            "локальный процесс ssh_relay не был запущен; удалённая команда не стартовала",
        )
    else:
        verification = failed_verification(
            expected.assertions,
            "relay_command_not_started",
            "ssh_relay подтвердил, что удалённая команда не стартовала",
        )

    fully_succeeded = (
        contract_error is None
        and operation_status == "succeeded"
        and verification.successful
    )
    if fully_succeeded:
        status = Status.DONE
    elif not run.get("launched") or (contract_error is None and operation_status == "not_started"):
        status = Status.FAILED
    else:
        status = Status.UNEXPECTED

    verify_result: dict[str, Any] = {
        "relay_operation_status": operation_status,
        "verification_error_code": verification.error_code,
        "verification_error_message": verification.error_message,
    }
    if verify_payload:
        verify_result["verify_operation_status"] = verify_payload.get("operation_status")
        verify_result["verify_command_exit_code"] = verify_payload.get("command_exit_code")
    if verify_contract_error:
        verify_result["verify_contract_error"] = verify_contract_error

    record = ActionRecord(
        txn_id=txn_id,
        status=status,
        kind="ssh_relay.risky-exec",
        risk=record_risk,
        reason=reason,
        cwd=str(cwd),
        target_paths=[f"host:{host_label}"],
        command={
            "channel": "ssh_relay",
            "domain": "ssh_relay",
            "target": f"host:{host_label}",
            "relay_mode": relay_mode,
            "relay_name": relay_name,
            "remote_command_sha256": command_hash,
        },
        undo={
            "op": "manual-command",
            "command_sha256": hashlib.sha256(rollback_command.encode("utf-8")).hexdigest(),
            "relay_mode": relay_mode,
            "automatic": False,
            "command_stored": False,
        },
        redo={
            "op": "manual-review-required",
            "remote_command_sha256": command_hash,
            "automatic": False,
            "reason": "risky-выполнение ssh_relay никогда не повторяется автоматически",
        },
        expected_state=expected_state,
        verify_result=verify_result,
        verification_complete=verification.verification_complete,
        verified_assertions=verification.verified_assertions,
        missing_assertions=verification.missing_assertions,
        mismatched_assertions=verification.mismatched_assertions,
        actual_state=verification.actual_state,
        metadata={
            "assessment": _assessment_summary(assessment),
            "relay": _relay_summary(run, payload, contract_error),
            "verify_relay": _relay_summary(verify_run, verify_payload, verify_contract_error) if verify_run else None,
        },
    )
    journal.append(record)
    if status == Status.UNEXPECTED:
        journal.block(f"неожиданный результат ssh_relay: {operation_status or 'contract-error'}", txn_id)
    return record
