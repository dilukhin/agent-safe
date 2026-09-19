from __future__ import annotations

import shlex
import subprocess
from pathlib import Path
from typing import Any

from agent_safe.adapters.fs import SafetyError
from agent_safe.core.journal import Journal
from agent_safe.core.models import ActionRecord, Risk, Status
from agent_safe.core.risk import assess_command
from agent_safe.core.recovery import validate_recovery_contract
from agent_safe.core.rollback import load_bundle, prepare_bundle, target_state
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


def _run(args: list[str], cwd: Path, timeout: int = 120, *, structured: bool = False,
         stdin_utf8: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"args": args, "display": _display_command(args)}
    options: dict[str, Any] = {}
    if structured:
        options.update(encoding="utf-8", errors="strict",
                       stdin=subprocess.PIPE if stdin_utf8 is not None else subprocess.DEVNULL)
    try:
        proc = subprocess.Popen(args, cwd=str(cwd), text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, shell=False, **options)
    except (OSError, ValueError) as exc:
        return dict(result, outcome="not_started", error=type(exc).__name__, returncode=127)
    except (Exception, KeyboardInterrupt) as exc:
        return dict(result, outcome="unknown", error=type(exc).__name__, returncode=127)
    try:
        stdout, stderr = proc.communicate(input=stdin_utf8, timeout=timeout)
        return dict(result, outcome="exited", returncode=proc.returncode,
                    stdout=stdout[-50000:], stderr=stderr[-50000:],
                    stdout_truncated=len(stdout) > 50000, stderr_truncated=len(stderr) > 50000)
    except (Exception, KeyboardInterrupt) as exc:
        # Завершение родителя не доказывает остановку потомков или внешних действий.
        try:
            proc.kill()
            proc.wait(timeout=1)
        except (OSError, subprocess.TimeoutExpired):
            pass
        return dict(result, outcome="unknown", error=type(exc).__name__, returncode=127)
    finally:
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass


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
    rollback_command: str | None = None,
    recovery_contract_json: str | None = None,
    rollback_plan_json: str | None = None,
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
    if not reason.strip():
        raise SafetyError("exec-risky требует непустое обоснование")
    has_rollback = bool(rollback_command and rollback_command.strip())
    if sum((has_rollback, recovery_contract_json is not None, rollback_plan_json is not None)) != 1:
        raise SafetyError("нужно выбрать один источник: rollback-команда, checkpoint или сохранённый план отката")
    if rollback_plan_json is not None and channel != "local":
        raise SafetyError("сохранённый план отката поддерживает только --channel local")
    if assessment.risk == Risk.CRITICAL and not allow_critical:
        raise SafetyError("critical command requires --allow-critical plus explicit recovery plan")
    if assessment.risk == Risk.SAFE and not assessment.state_changing:
        raise SafetyError("command appears read-only; use exec-readonly instead")

    verify_args = _split_shell_command(verify_command)
    receipt_args = _split_shell_command(receipt_command)
    if expected_state.assertions and not verify_args:
        raise SafetyError("непустые assertions требуют --verify-command или --verify-command-file")
    if recovery_contract_json is not None and (not expected_state.assertions or not verify_args):
        raise SafetyError("checkpoint требует непустые assertions и обязательную verify-команду")

    recovery = (
        validate_recovery_contract(recovery_contract_json, target=target, cwd=cwd)
        if recovery_contract_json is not None
        else {"mode": "rollback-command", "automatic": False}
    )
    txn_id = ActionRecord.new_id()
    saved_rollback = rollback_plan_json is not None
    durable = recovery_contract_json is not None or saved_rollback
    if saved_rollback:
        recovery = prepare_bundle(rollback_plan_json, target=target, txn_id=txn_id, journal=journal)
    if durable:
        planned = ActionRecord(
            txn_id=txn_id, status=Status.PLANNED, kind=f"{domain}.risky-exec",
            risk=assessment.risk, reason=reason, cwd=str(cwd), target_paths=[target],
            command={"channel": channel, "domain": domain, "target": target, "args": command, "display": command_text},
            expected_state=expected_state.to_dict(),
            metadata={"recovery": recovery, "verify_args": verify_args, "receipt_args": receipt_args, "approved": True},
        )
        try:
            journal.append(planned, durable=True)
            journal.begin_pending(txn_id)
        except OSError as exc:
            raise SafetyError("не удалось зафиксировать план восстановления; действие не запущено") from exc
    if saved_rollback:
        load_bundle(journal=journal, txn_id=txn_id, recovery=recovery)
        if target_state(target, journal) != recovery["target_state"]:
            raise SafetyError("цель изменилась после подготовки; действие не запущено, барьер сохранён")

    def execute_once(args: list[str]) -> dict[str, Any]:
        try:
            return _run(args, cwd, timeout=timeout)
        except KeyboardInterrupt:
            return {"returncode": 130, "error": "выполнение прервано; результат неизвестен"}

    result = execute_once(command)
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
        verify_exec = execute_once(verify_args)
        verify_result["verify_returncode"] = verify_exec.get("returncode")
        verify_result["verify_display"] = verify_exec.get("display")
        if verify_exec.get("returncode") != 0:
            verification = failed_verification(
                expected_state.assertions,
                "verify_failed",
                "verify-команда завершилась с ненулевым кодом",
            )
        elif saved_rollback and verify_exec.get("stdout_truncated"):
            verification = failed_verification(expected_state.assertions, "verify_truncated", "вывод проверки усечён")
        else:
            verification = verify_stdout(expected_state.assertions, str(verify_exec.get("stdout", "")))
    else:
        verification = VerificationOutcome(verification_complete=True)

    if verification.error_code:
        verify_result["verification_error_code"] = verification.error_code
        verify_result["verification_error_message"] = verification.error_message

    receipt_exec: dict[str, Any] | None = None
    if result.get("returncode") == 0 and verification.successful and receipt_args:
        receipt_exec = execute_once(receipt_args)
        verify_result["receipt_returncode"] = receipt_exec.get("returncode")
        verify_result["receipt_display"] = receipt_exec.get("display")

    ok = (
        result.get("returncode") == 0
        and verification.successful
        and (receipt_exec is None or receipt_exec.get("returncode") == 0)
    )
    status = Status.DONE if ok else Status.UNEXPECTED
    if saved_rollback:
        try:
            recovery["target_state"] = target_state(target, journal)
        except SafetyError:
            recovery["target_state"] = None
            status = Status.UNEXPECTED
            verification = failed_verification(expected_state.assertions, "target_observation_failed", "цель после действия недоступна для безопасного наблюдения")
            verify_result["verification_error_code"] = verification.error_code
            verify_result["verification_error_message"] = verification.error_message
        if result.get("outcome") == "not_started" and recovery["target_state"] is not None:
            status = Status.FAILED
    record = ActionRecord(
        txn_id=txn_id,
        status=status,
        kind=f"{domain}.risky-exec",
        risk=assessment.risk if assessment.risk in HIGH_ATTENTION_RISKS else Risk.HIGH,
        reason=reason,
        cwd=str(cwd),
        target_paths=[target],
        command={"channel": channel, "domain": domain, "target": target, "args": command, "display": command_text},
        undo=(
            {"op": "manual-command", "command": rollback_command}
            if has_rollback else {"op": "manual-recovery", "automatic": False}
        ),
        redo=(
            {"op": "manual-command", "command": command_text}
            if has_rollback else {"op": "manual-review-required", "automatic": False}
        ),
        expected_state=expected_state.to_dict(),
        verify_result=verify_result,
        verification_complete=verification.verification_complete,
        verified_assertions=verification.verified_assertions,
        missing_assertions=verification.missing_assertions,
        mismatched_assertions=verification.mismatched_assertions,
        actual_state=verification.actual_state,
        metadata={"assessment": assessment.to_dict(), "result": result, "verify_exec": verify_exec, "receipt_exec": receipt_exec, "recovery": recovery},
    )
    if status == Status.UNEXPECTED:
        journal.block(f"unexpected result after {domain}.risky-exec", txn_id)
    journal.append(record, durable=durable)
    if status in {Status.DONE, Status.FAILED} and durable and not journal.finish_pending(txn_id):
        record.status = Status.UNEXPECTED
        record.verify_result["recovery_barrier_error"] = True
        journal.block("не удалось завершить барьер проверки восстановления", txn_id)
        journal.append(record)
    return record
