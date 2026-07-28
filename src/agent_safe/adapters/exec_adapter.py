from __future__ import annotations

import shlex
import subprocess
from pathlib import Path
from typing import Any

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


SAFE_RISKS = {Risk.SAFE}
HIGH_ATTENTION_RISKS = {Risk.CAUTIOUS, Risk.HIGH, Risk.UNKNOWN, Risk.CRITICAL}


def _display_command(args: list[str]) -> str:
    return " ".join(shlex.quote(str(a)) for a in args)


def _run(args: list[str], cwd: Path, timeout: int = 120) -> dict[str, Any]:
    try:
        proc = subprocess.run(args, cwd=str(cwd), text=True, capture_output=True, timeout=timeout)
        return {
            "args": args,
            "display": _display_command(args),
            "returncode": proc.returncode,
            "stdout": proc.stdout[-50000:],
            "stderr": proc.stderr[-50000:],
        }
    except Exception as exc:  # noqa: BLE001 - safety wrapper must report failures as data
        return {"args": args, "display": _display_command(args), "error": repr(exc), "returncode": 127}


def _unquote_windows_token(token: str) -> str:
    if len(token) >= 2 and token[0] == token[-1] and token[0] in {'"', "'"}:
        return token[1:-1]
    return token


def _looks_windows_command(text: str) -> bool:
    return "\\" in text or ".exe" in text.lower() or ".cmd" in text.lower() or ".bat" in text.lower()


def _split_shell_command(text: str | None) -> list[str] | None:
    if not text:
        return None
    try:
        args = shlex.split(text, posix=(not _looks_windows_command(text)))
    except ValueError as exc:
        raise SafetyError(f"cannot parse command: {text}: {exc}") from exc
    if _looks_windows_command(text):
        return [_unquote_windows_token(arg) for arg in args]
    return args


def require_not_blocked(journal: Journal, allow_recovery: bool = False) -> None:
    if journal.is_blocked() and not allow_recovery:
        raise SafetyError("INCIDENT_BLOCKED exists; high-risk operations are disabled. Run diagnose/recovery-plan first.")


def exec_readonly(
    command: list[str],
    *,
    journal: Journal,
    channel: str,
    domain: str,
    reason: str,
    cwd: Path | None = None,
    timeout: int = 120,
) -> ActionRecord:
    require_not_blocked(journal, allow_recovery=True)
    cwd = Path(cwd or journal.root).resolve()
    command_text = _display_command(command)
    assessment = assess_command(command_text, channel=channel)
    if assessment.risk not in SAFE_RISKS or assessment.state_changing:
        raise SafetyError(
            "exec-readonly refuses non-read-only command; use assess/inspect first or exec-risky with rollback. "
            f"risk={assessment.risk.value}; reasons={assessment.reasons}"
        )
    result = _run(command, cwd, timeout=timeout)
    txn_id = ActionRecord.new_id()
    status = Status.DONE if result.get("returncode") == 0 else Status.FAILED
    record = ActionRecord(
        txn_id=txn_id,
        status=status,
        kind=f"{domain}.readonly-exec",
        risk=Risk.SAFE,
        reason=reason,
        cwd=str(cwd),
        command={"channel": channel, "domain": domain, "args": command, "display": command_text},
        verify_result={"returncode": result.get("returncode")},
        metadata={"assessment": assessment.to_dict(), "result": result},
    )
    journal.append(record)
    return record


def exec_risky(
    command: list[str],
    *,
    journal: Journal,
    channel: str,
    domain: str,
    target: str,
    reason: str,
    expected_state_json: str,
    rollback_command: str,
    verify_command: str | None = None,
    receipt_command: str | None = None,
    approved: bool = False,
    allow_critical: bool = False,
    cwd: Path | None = None,
    timeout: int = 120,
) -> ActionRecord:
    require_not_blocked(journal)
    cwd = Path(cwd or journal.root).resolve()
    command_text = _display_command(command)
    assessment = assess_command(command_text, channel=channel)
    try:
        expected_state = parse_expected_state(expected_state_json)
    except VerificationError as exc:
        raise SafetyError(str(exc)) from exc

    if not target.strip():
        raise SafetyError("exec-risky requires explicit --target")
    if not approved:
        raise SafetyError("exec-risky requires --approved after user review")
    if not rollback_command.strip():
        raise SafetyError("exec-risky requires --rollback-command")
    if assessment.risk == Risk.CRITICAL and not allow_critical:
        raise SafetyError("critical command requires --allow-critical plus explicit recovery plan")
    if assessment.risk == Risk.SAFE and not assessment.state_changing:
        raise SafetyError("command appears read-only; use exec-readonly instead")

    verify_args = _split_shell_command(verify_command)
    receipt_args = _split_shell_command(receipt_command)
    if expected_state.assertions and not verify_args:
        raise SafetyError("непустые assertions требуют --verify-command или --verify-command-file")

    txn_id = ActionRecord.new_id()
    result = _run(command, cwd, timeout=timeout)
    verify_result: dict[str, Any] = {"command_returncode": result.get("returncode")}
    verify_exec: dict[str, Any] | None = None

    verification: VerificationOutcome
    if result.get("returncode") != 0:
        verification = failed_verification(
            expected_state.assertions,
            "command_failed",
            "основная команда завершилась с ненулевым кодом",
        )
    elif verify_args:
        verify_exec = _run(verify_args, cwd, timeout=timeout)
        verify_result["verify_returncode"] = verify_exec.get("returncode")
        verify_result["verify_display"] = verify_exec.get("display")
        if verify_exec.get("returncode") != 0:
            verification = failed_verification(
                expected_state.assertions,
                "verify_failed",
                "verify-команда завершилась с ненулевым кодом",
            )
        else:
            verification = verify_stdout(expected_state.assertions, str(verify_exec.get("stdout", "")))
    else:
        verification = VerificationOutcome(verification_complete=True)

    if verification.error_code:
        verify_result["verification_error_code"] = verification.error_code
        verify_result["verification_error_message"] = verification.error_message

    receipt_exec: dict[str, Any] | None = None
    if result.get("returncode") == 0 and verification.successful and receipt_args:
        receipt_exec = _run(receipt_args, cwd, timeout=timeout)
        verify_result["receipt_returncode"] = receipt_exec.get("returncode")
        verify_result["receipt_display"] = receipt_exec.get("display")

    ok = (
        result.get("returncode") == 0
        and verification.successful
        and (receipt_exec is None or receipt_exec.get("returncode") == 0)
    )
    status = Status.DONE if ok else Status.UNEXPECTED
    record = ActionRecord(
        txn_id=txn_id,
        status=status,
        kind=f"{domain}.risky-exec",
        risk=assessment.risk if assessment.risk in HIGH_ATTENTION_RISKS else Risk.HIGH,
        reason=reason,
        cwd=str(cwd),
        target_paths=[target],
        command={"channel": channel, "domain": domain, "target": target, "args": command, "display": command_text},
        undo={"op": "manual-command", "command": rollback_command},
        redo={"op": "manual-command", "command": command_text},
        expected_state=expected_state.to_dict(),
        verify_result=verify_result,
        verification_complete=verification.verification_complete,
        verified_assertions=verification.verified_assertions,
        missing_assertions=verification.missing_assertions,
        mismatched_assertions=verification.mismatched_assertions,
        actual_state=verification.actual_state,
        metadata={"assessment": assessment.to_dict(), "result": result, "verify_exec": verify_exec, "receipt_exec": receipt_exec},
    )
    journal.append(record)
    if status == Status.UNEXPECTED:
        journal.block(f"unexpected result after {domain}.risky-exec", txn_id)
    return record
