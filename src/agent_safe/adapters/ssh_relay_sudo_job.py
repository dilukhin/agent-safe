from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any
from uuid import UUID

from agent_safe.adapters.fs import SafetyError
from agent_safe.adapters.ssh_relay import (
    _endpoint,
    _parse_machine_payload,
    _run_machine,
    _split_relay,
    build_relay_command,
)
from agent_safe.core.journal import Journal
from agent_safe.core.models import ActionRecord, Risk, Status
from agent_safe.core.risk import assess_command
from agent_safe.core.verification import (
    VerificationOutcome,
    failed_verification,
    parse_expected_state,
    verify_stdout,
)

_SCHEMA = 1
_STATES = {"not_started", "running", "succeeded", "failed", "unknown"}
_TARGET_FIELDS = (
    "remote_host",
    "remote_port",
    "remote_user",
    "host_key_algorithm",
    "remote_host_key_sha256",
)
_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _uuid(value: str, field: str) -> str:
    try:
        parsed = str(UUID(value))
    except (ValueError, TypeError, AttributeError) as exc:
        raise SafetyError(f"{field} должен быть каноническим UUID") from exc
    if parsed != value:
        raise SafetyError(f"{field} должен быть каноническим UUID")
    return parsed


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _read_identity(path: str | Path) -> dict[str, Any]:
    source = Path(path).expanduser()
    try:
        if source.stat().st_size > 8192:
            raise SafetyError("файл verified identity слишком велик")
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SafetyError("не удалось прочитать verified identity") from exc
    if not isinstance(value, dict):
        raise SafetyError("verified identity должна быть JSON-объектом")
    if (
        set(value) != {"schema_version", "trusted_known_hosts", "daemon_instance_id", "connection_generation", "daemon_source_sha", *_TARGET_FIELDS}
        or type(value.get("schema_version")) is not int
        or value["schema_version"] != _SCHEMA
        or value.get("trusted_known_hosts") is not True
        or not isinstance(value.get("remote_host"), str)
        or not value["remote_host"]
        or type(value.get("remote_port")) is not int
        or not 1 <= value["remote_port"] <= 65535
        or not isinstance(value.get("remote_user"), str)
        or not value["remote_user"]
        or not isinstance(value.get("host_key_algorithm"), str)
        or not value["host_key_algorithm"]
        or not isinstance(value.get("remote_host_key_sha256"), str)
        or _FINGERPRINT.fullmatch(value["remote_host_key_sha256"]) is None
        or not isinstance(value.get("daemon_instance_id"), str)
        or _uuid(value["daemon_instance_id"], "daemon_instance_id") != value["daemon_instance_id"]
        or type(value.get("connection_generation")) is not int
        or value["connection_generation"] < 1
        or not isinstance(value.get("daemon_source_sha"), str)
        or re.fullmatch(r"[0-9a-f]{40}", value["daemon_source_sha"]) is None
    ):
        raise SafetyError("verified identity неполна или некорректна")
    return value


def _target(identity: dict[str, Any]) -> dict[str, Any]:
    return {name: identity[name] for name in _TARGET_FIELDS}


def _same_target(identity: dict[str, Any], expected: dict[str, Any]) -> bool:
    try:
        return _target(identity) == expected
    except KeyError:
        return False


def _witness_valid(
    witness: object,
    *,
    phase: str,
    job_id: str,
    transaction_id: str,
    command_hash: str,
    target: dict[str, Any],
    exit_code: int | None = None,
) -> bool:
    if not isinstance(witness, dict):
        return False
    saved = witness.get("witness_sha256")
    original = {key: value for key, value in witness.items() if key != "witness_sha256"}
    canonical = json.dumps(original, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if saved != hashlib.sha256(canonical).hexdigest():
        return False
    if (
        witness.get("phase") != phase
        or witness.get("job_id") != job_id
        or witness.get("transaction_id") != transaction_id
        or witness.get("command_sha256") != command_hash
        or witness.get("target") != target
        or not isinstance(witness.get("boot_id"), str)
        or witness.get("unit") != "ssh-relay-sudo-" + UUID(job_id).hex + ".service"
        or not isinstance(witness.get("invocation_id"), str)
        or re.fullmatch(r"[0-9a-f]{32}", witness["invocation_id"]) is None
    ):
        return False
    try:
        if str(UUID(witness["boot_id"])) != witness["boot_id"]:
            return False
    except (ValueError, TypeError, AttributeError):
        return False
    if phase == "completion" and witness.get("exit_code") != exit_code:
        return False
    return True


def _build(
    relay: str,
    operation: str,
    *,
    relay_name: str,
    job_id: str,
    transaction_id: str,
    identity_file: str,
    command_hash: str,
    remote_command: str | None = None,
    wait_timeout: int = 300,
    poll_interval: int = 2,
    stream: str = "stdout",
    max_bytes: int = 16384,
) -> list[str]:
    args = [
        *_split_relay(relay),
        "sudo-job",
        operation,
        "--name",
        relay_name,
        "--job-id",
        job_id,
        "--transaction-id",
        transaction_id,
        "--expected-identity-file",
        identity_file,
    ]
    if operation == "start":
        if remote_command is None:
            raise SafetyError("для sudo-job start нужна удалённая команда")
        args.append(remote_command)
    else:
        args.extend(["--command-sha256", command_hash])
    if operation == "wait":
        args.extend(["--timeout", str(wait_timeout), "--poll-interval", str(poll_interval)])
    if operation == "tail":
        args.extend(["--stream", stream, "--bytes", str(max_bytes)])
    return args


def _run(args: list[str], cwd: Path, timeout: int) -> dict[str, Any]:
    try:
        proc = subprocess.run(args, cwd=str(cwd), encoding="utf-8", capture_output=True, timeout=timeout)
    except (FileNotFoundError, PermissionError) as exc:
        return {"launched": False, "returncode": None, "stdout": "", "stderr": "", "error_type": type(exc).__name__}
    except subprocess.TimeoutExpired as exc:
        return {"launched": True, "returncode": None, "stdout": "", "stderr": "", "error_type": type(exc).__name__}
    except KeyboardInterrupt as exc:
        return {"launched": True, "returncode": None, "stdout": "", "stderr": "", "error_type": type(exc).__name__}
    except Exception as exc:
        return {"launched": True, "returncode": None, "stdout": "", "stderr": "", "error_type": type(exc).__name__}
    return {"launched": True, "returncode": int(proc.returncode), "stdout": proc.stdout, "stderr": proc.stderr}


def _parse(
    run: dict[str, Any],
    *,
    operation: str,
    job_id: str,
    transaction_id: str,
    command_hash: str,
    current_target: dict[str, Any],
    expected_identity: dict[str, Any],
) -> tuple[dict[str, Any] | None, str | None]:
    if not run.get("launched"):
        return None, "sudo_job_launcher_not_started"
    try:
        payload = json.loads(str(run.get("stdout", "")))
    except json.JSONDecodeError:
        return None, "sudo_job_invalid_json"
    if not isinstance(payload, dict):
        return None, "sudo_job_not_object"
    if (
        payload.get("schema_version") != _SCHEMA
        or payload.get("tool") != "ssh_relay"
        or payload.get("result_type") != "sudo_job"
        or payload.get("operation") != operation
        or payload.get("job_id") != job_id
        or payload.get("transaction_id") != transaction_id
        or payload.get("command_sha256") != command_hash
        or payload.get("state") not in _STATES
    ):
        return payload, "sudo_job_contract_mismatch"
    if type(payload.get("process_exit_code")) is not int or payload["process_exit_code"] != run.get("returncode"):
        return payload, "sudo_job_process_code_mismatch"
    state = payload["state"]
    if state != "not_started":
        identity = payload.get("verified_identity")
        if identity != expected_identity or not _same_target(identity, current_target):
            return payload, "sudo_job_target_mismatch"
    start = payload.get("start_witness")
    completion = payload.get("completion_witness")
    if start is not None and not _witness_valid(
        start, phase="start", job_id=job_id, transaction_id=transaction_id,
        command_hash=command_hash, target=current_target,
    ):
        return payload, "sudo_job_start_witness_invalid"
    if state == "running" and start is None:
        return payload, "sudo_job_start_witness_missing"
    if state in {"succeeded", "failed"}:
        if start is None:
            return payload, "sudo_job_start_witness_missing"
        code = payload.get("exit_code")
        if type(code) is not int or not 0 <= code <= 255 or (state == "succeeded") != (code == 0):
            return payload, "sudo_job_exit_invalid"
        if completion is not None:
            if not isinstance(completion, dict):
                return payload, "sudo_job_completion_witness_invalid"
            if any(completion.get(field) != start.get(field) for field in ("boot_id", "unit", "invocation_id")):
                return payload, "sudo_job_completion_launch_mismatch"
            if not _witness_valid(
                completion, phase="completion", job_id=job_id, transaction_id=transaction_id,
                command_hash=command_hash, target=current_target, exit_code=code,
            ):
                return payload, "sudo_job_completion_witness_invalid"
        elif not (state == "succeeded" and payload.get("accounting_status") == "failed" and start is not None):
            return payload, "sudo_job_completion_witness_missing"
    return payload, None


def _summary(run: dict[str, Any], payload: dict[str, Any] | None, error: str | None) -> dict[str, Any]:
    value: dict[str, Any] = {
        "launched": bool(run.get("launched")),
        "returncode": run.get("returncode"),
        "contract_error": error,
    }
    if payload:
        for key in (
            "operation", "state", "job_id", "transaction_id", "command_sha256",
            "exit_code", "accounting_status", "error_code", "wait_timed_out", "stop_requested",
        ):
            if key in payload:
                value[key] = payload[key]
        for key in ("start_witness", "completion_witness"):
            witness = payload.get(key)
            if isinstance(witness, dict):
                value[key] = {
                    field: witness.get(field)
                    for field in (
                        "phase", "job_id", "transaction_id", "command_sha256", "target",
                        "boot_id", "unit", "invocation_id", "exit_code", "witness_sha256",
                    )
                    if field in witness
                }
    return value


def _verify(
    relay: str,
    relay_name: str,
    command: str,
    *,
    cwd: Path,
    expected_target: dict[str, Any],
    expected_identity: dict[str, Any],
    assertions: dict[str, Any],
    timeout: int,
) -> tuple[VerificationOutcome, dict[str, Any]]:
    assessment = assess_command(command, channel="ssh_relay")
    if assessment.state_changing or assessment.risk != Risk.SAFE:
        raise SafetyError("verify-команда sudo-job должна быть read-only")
    args = build_relay_command(relay, command, relay_name=relay_name, relay_mode="exec", machine_json=True)
    flags = ["--require-verified-identity"]
    for key, flag in (
        ("remote_host", "--expected-remote-host"), ("remote_port", "--expected-remote-port"),
        ("remote_user", "--expected-remote-user"), ("host_key_algorithm", "--expected-host-key-algorithm"),
        ("remote_host_key_sha256", "--expected-host-key-sha256"),
        ("daemon_instance_id", "--expected-daemon-instance-id"),
        ("connection_generation", "--expected-connection-generation"), ("daemon_source_sha", "--expected-daemon-source-sha"),
    ):
        flags.extend([flag, str(expected_identity[key])])
    args[-1:-1] = flags
    run = _run_machine(args, cwd, timeout=timeout)
    payload, error = _parse_machine_payload(
        run, relay_mode="exec", risky=False, transaction_id=None, relay_name=relay_name,
    )
    if error is not None:
        return failed_verification(assertions, error, "verify через ssh_relay не дал согласованный результат"), {"contract_error": error}
    if payload.get("verified_identity") != expected_identity or payload.get("operation_status") != "succeeded" or _endpoint(payload) != (
        expected_target["remote_host"], expected_target["remote_port"], expected_target["remote_user"]
    ):
        return failed_verification(assertions, "verify_relay_target_or_status", "verify не подтвердил ту же SSH-цель"), {
            "operation_status": payload.get("operation_status"),
            "contract_error": "verify_relay_target_or_status",
        }
    return verify_stdout(assertions, str(payload.get("stdout", ""))), {
        "operation_status": payload.get("operation_status"),
        "command_exit_code": payload.get("command_exit_code"),
    }


def _new_record(
    *,
    transaction_id: str,
    status: Status,
    risk: Risk,
    reason: str,
    cwd: Path,
    host_label: str,
    relay_name: str,
    job_id: str,
    command_hash: str,
    verify_hash: str,
    recovery_hash: str,
    target: dict[str, Any],
    expected_state: dict[str, Any],
    run: dict[str, Any],
    payload: dict[str, Any] | None,
    contract_error: str | None,
    verification: VerificationOutcome | None = None,
    verify_meta: dict[str, Any] | None = None,
) -> ActionRecord:
    verification = verification or VerificationOutcome(verification_complete=False)
    return ActionRecord(
        txn_id=transaction_id,
        status=status,
        kind="ssh_relay.sudo-job",
        risk=risk,
        reason=reason,
        cwd=str(cwd),
        target_paths=[f"host:{host_label}", f"sudo-job:{job_id}"],
        command={
            "channel": "ssh_relay",
            "domain": "ssh_relay",
            "relay_name": relay_name,
            "job_id": job_id,
            "transaction_id": transaction_id,
            "remote_command_sha256": command_hash,
            "verify_command_sha256": verify_hash,
        },
        undo={
            "op": "manual-recovery",
            "recovery_plan_sha256": recovery_hash,
            "automatic": False,
            "command_stored": False,
        },
        redo={
            "op": "manual-review-required",
            "automatic": False,
            "reason": "длительная root-операция не повторяется автоматически",
        },
        expected_state=expected_state,
        verify_result=verify_meta or {},
        verification_complete=verification.verification_complete,
        verified_assertions=verification.verified_assertions,
        missing_assertions=verification.missing_assertions,
        mismatched_assertions=verification.mismatched_assertions,
        actual_state=verification.actual_state,
        metadata={
            "sudo_job": _summary(run, payload, contract_error),
            "original_target": target,
        },
    )


def _previous(journal: Journal, transaction_id: str, job_id: str, command_hash: str) -> dict[str, Any]:
    previous = journal.find(transaction_id)
    if not isinstance(previous, dict) or previous.get("kind") != "ssh_relay.sudo-job":
        raise SafetyError("не найдена локальная запись sudo-job для этой транзакции")
    command = previous.get("command", {})
    if command.get("job_id") != job_id or command.get("remote_command_sha256") != command_hash:
        raise SafetyError("job_id или command hash не совпадает с локальной транзакцией")
    return previous


def _save_result(journal: Journal, record: ActionRecord, *, terminal: bool) -> ActionRecord:
    # Сначала сохраняется полный результат; сбой записи не снимает барьер.
    journal.append(record, durable=True)
    if terminal and not journal.finish_pending(record.txn_id):
        record.status = Status.UNEXPECTED
        journal.append(record, durable=True)
    return record


def start(
    relay: str,
    remote_command: str,
    *,
    journal: Journal,
    host_label: str,
    relay_name: str,
    job_id: str,
    transaction_id: str,
    expected_identity_file: str,
    expected_state_json: str,
    verify_remote_command: str,
    recovery_plan: str,
    reason: str,
    approved: bool,
    allow_critical: bool = False,
    cwd: Path | None = None,
    timeout: int = 120,
) -> ActionRecord:
    from agent_safe.adapters.exec_adapter import require_not_blocked

    require_not_blocked(journal)
    if not approved:
        raise SafetyError("запуск sudo-job требует подтверждённого разрешения")
    job_id = _uuid(job_id, "job_id")
    transaction_id = _uuid(transaction_id, "transaction_id")
    if not host_label.strip() or not recovery_plan.strip():
        raise SafetyError("нужны точный host-label и план восстановления")
    assessment = assess_command(remote_command, channel="ssh_relay")
    if assessment.risk == Risk.CRITICAL and not allow_critical:
        raise SafetyError("критическая root-команда требует отдельного разрешения")
    if assessment.risk == Risk.SAFE and not assessment.state_changing:
        raise SafetyError("read-only команда не должна запускаться как sudo-job")
    expected = parse_expected_state(expected_state_json)
    verify_assessment = assess_command(verify_remote_command, channel="ssh_relay")
    if verify_assessment.state_changing or verify_assessment.risk != Risk.SAFE:
        raise SafetyError("verify-команда sudo-job должна быть read-only")
    identity = _read_identity(expected_identity_file)
    target = _target(identity)
    command_hash = _hash_text(remote_command)
    verify_hash = _hash_text(verify_remote_command)
    recovery_hash = _hash_text(recovery_plan)
    cwd = Path(cwd or journal.root).resolve()
    try:
        journal.begin_pending(transaction_id)
    except FileExistsError as exc:
        raise SafetyError("журнал уже заблокирован другой незавершённой операцией") from exc

    args = _build(
        relay, "start", relay_name=relay_name, job_id=job_id, transaction_id=transaction_id,
        identity_file=expected_identity_file, command_hash=command_hash, remote_command=remote_command,
    )
    # Эти данные доступны для status даже после аварии клиента до ответа start.
    pending = _new_record(
        transaction_id=transaction_id, status=Status.BLOCKED, risk=assessment.risk,
        reason=reason, cwd=cwd, host_label=host_label, relay_name=relay_name,
        job_id=job_id, command_hash=command_hash, verify_hash=verify_hash,
        recovery_hash=recovery_hash, target=target, expected_state=expected.to_dict(),
        run={"launched": False}, payload=None, contract_error="pending_start",
    )
    journal.append(pending, durable=True)
    run = _run(args, cwd, timeout)
    payload, error = _parse(
        run, operation="start", job_id=job_id, transaction_id=transaction_id,
        command_hash=command_hash, current_target=target, expected_identity=identity,
    )
    state = payload.get("state") if payload and error is None else "unknown"
    verification = None
    verify_meta = None
    status = Status.BLOCKED if state == "running" else Status.UNEXPECTED

    if state == "not_started" and error is None:
        status = Status.FAILED
    elif state == "succeeded" and error is None and payload.get("accounting_status") == "recorded":
        verification, verify_meta = _verify(
            relay, relay_name, verify_remote_command, cwd=cwd, expected_target=target,
            assertions=expected.assertions, timeout=timeout, expected_identity=identity,
        )
        if verification.successful:
            status = Status.DONE

    record = _new_record(
        transaction_id=transaction_id, status=status, risk=assessment.risk, reason=reason, cwd=cwd,
        host_label=host_label, relay_name=relay_name, job_id=job_id, command_hash=command_hash,
        verify_hash=verify_hash, recovery_hash=recovery_hash, target=target,
        expected_state=expected.to_dict(), run=run, payload=payload, contract_error=error,
        verification=verification, verify_meta=verify_meta,
    )
    return _save_result(journal, record, terminal=status in {Status.DONE, Status.FAILED})


def observe(
    relay: str,
    *,
    journal: Journal,
    operation: str,
    relay_name: str,
    job_id: str,
    transaction_id: str,
    command_hash: str,
    expected_identity_file: str,
    verify_remote_command: str,
    reason: str,
    cwd: Path | None = None,
    timeout: int = 120,
    wait_timeout: int = 300,
    poll_interval: int = 2,
) -> ActionRecord:
    if operation not in {"status", "wait"}:
        raise SafetyError("observe поддерживает только status или wait")
    job_id = _uuid(job_id, "job_id")
    transaction_id = _uuid(transaction_id, "transaction_id")
    if _SHA256.fullmatch(command_hash) is None:
        raise SafetyError("command_sha256 должен быть SHA-256")
    previous = _previous(journal, transaction_id, job_id, command_hash)
    if not journal.is_blocked():
        raise SafetyError("локальный safety-барьер отсутствует; требуется ручной разбор")
    command = previous["command"]
    if _hash_text(verify_remote_command) != command.get("verify_command_sha256"):
        raise SafetyError("verify-команда не совпадает с исходной транзакцией")
    identity = _read_identity(expected_identity_file)
    target = previous.get("metadata", {}).get("original_target")
    if not isinstance(target, dict) or not _same_target(identity, target):
        raise SafetyError("текущая SSH identity относится к другой цели")
    cwd = Path(cwd or journal.root).resolve()
    args = _build(
        relay, operation, relay_name=relay_name, job_id=job_id, transaction_id=transaction_id,
        identity_file=expected_identity_file, command_hash=command_hash,
        wait_timeout=wait_timeout, poll_interval=poll_interval,
    )
    local_timeout = max(timeout, wait_timeout + 30 if operation == "wait" else timeout)
    run = _run(args, cwd, local_timeout)
    payload, error = _parse(
        run, operation=operation, job_id=job_id, transaction_id=transaction_id,
        command_hash=command_hash, current_target=target, expected_identity=identity,
    )
    state = payload.get("state") if payload and error is None else "unknown"
    verification = None
    verify_meta = None
    status = Status.BLOCKED if state == "running" else Status.UNEXPECTED
    if state == "succeeded" and error is None and payload.get("accounting_status") == "recorded":
        expected_state = previous.get("expected_state", {})
        assertions = expected_state.get("assertions", {}) if isinstance(expected_state, dict) else {}
        verification, verify_meta = _verify(
            relay, relay_name, verify_remote_command, cwd=cwd, expected_target=target,
            assertions=assertions, timeout=timeout, expected_identity=identity,
        )
        if verification.successful:
            status = Status.DONE
    record = _new_record(
        transaction_id=transaction_id, status=status, risk=Risk(previous["risk"]), reason=reason, cwd=cwd,
        host_label=previous["target_paths"][0].removeprefix("host:"), relay_name=relay_name,
        job_id=job_id, command_hash=command_hash,
        verify_hash=command["verify_command_sha256"],
        recovery_hash=previous.get("undo", {}).get("recovery_plan_sha256", ""),
        target=target, expected_state=previous.get("expected_state", {}),
        run=run, payload=payload, contract_error=error,
        verification=verification, verify_meta=verify_meta,
    )
    return _save_result(journal, record, terminal=status == Status.DONE)


def tail(
    relay: str,
    *,
    journal: Journal,
    relay_name: str,
    job_id: str,
    transaction_id: str,
    command_hash: str,
    expected_identity_file: str,
    stream: str = "stdout",
    max_bytes: int = 16384,
    cwd: Path | None = None,
    timeout: int = 120,
) -> dict[str, Any]:
    job_id = _uuid(job_id, "job_id")
    transaction_id = _uuid(transaction_id, "transaction_id")
    if _SHA256.fullmatch(command_hash) is None or stream not in {"stdout", "stderr"} or not 1 <= max_bytes <= 65536:
        raise SafetyError("некорректные параметры tail")
    previous = _previous(journal, transaction_id, job_id, command_hash)
    identity = _read_identity(expected_identity_file)
    target = previous.get("metadata", {}).get("original_target")
    if not isinstance(target, dict) or not _same_target(identity, target):
        raise SafetyError("текущая SSH identity относится к другой цели")
    cwd = Path(cwd or journal.root).resolve()
    args = _build(
        relay, "tail", relay_name=relay_name, job_id=job_id, transaction_id=transaction_id,
        identity_file=expected_identity_file, command_hash=command_hash, stream=stream, max_bytes=max_bytes,
    )
    run = _run(args, cwd, timeout)
    payload, error = _parse(
        run, operation="tail", job_id=job_id, transaction_id=transaction_id,
        command_hash=command_hash, current_target=target, expected_identity=identity,
    )
    if error is not None or payload is None:
        raise SafetyError(f"tail не дал подтверждённый результат: {error or 'unknown'}")
    return payload


def stop(
    relay: str,
    *,
    journal: Journal,
    relay_name: str,
    job_id: str,
    transaction_id: str,
    command_hash: str,
    expected_identity_file: str,
    reason: str,
    approved: bool,
    cwd: Path | None = None,
    timeout: int = 120,
) -> ActionRecord:
    if not approved:
        raise SafetyError("остановка sudo-job требует отдельного разрешения")
    job_id = _uuid(job_id, "job_id")
    transaction_id = _uuid(transaction_id, "transaction_id")
    if _SHA256.fullmatch(command_hash) is None:
        raise SafetyError("command_sha256 должен быть SHA-256")
    previous = _previous(journal, transaction_id, job_id, command_hash)
    if not journal.is_blocked():
        raise SafetyError("локальный safety-барьер отсутствует; требуется ручной разбор")
    identity = _read_identity(expected_identity_file)
    target = previous.get("metadata", {}).get("original_target")
    if not isinstance(target, dict) or not _same_target(identity, target):
        raise SafetyError("текущая SSH identity относится к другой цели")
    cwd = Path(cwd or journal.root).resolve()
    args = _build(
        relay, "stop", relay_name=relay_name, job_id=job_id, transaction_id=transaction_id,
        identity_file=expected_identity_file, command_hash=command_hash,
    )
    run = _run(args, cwd, timeout)
    payload, error = _parse(
        run, operation="stop", job_id=job_id, transaction_id=transaction_id,
        command_hash=command_hash, current_target=target, expected_identity=identity,
    )
    status = Status.BLOCKED if payload and error is None and payload.get("stop_requested") is True else Status.UNEXPECTED
    record = _new_record(
        transaction_id=transaction_id, status=status, risk=Risk(previous["risk"]), reason=reason, cwd=cwd,
        host_label=previous["target_paths"][0].removeprefix("host:"), relay_name=relay_name,
        job_id=job_id, command_hash=command_hash,
        verify_hash=previous["command"]["verify_command_sha256"],
        recovery_hash=previous.get("undo", {}).get("recovery_plan_sha256", ""),
        target=target, expected_state=previous.get("expected_state", {}),
        run=run, payload=payload, contract_error=error,
    )
    journal.append(record, durable=True)
    return record
