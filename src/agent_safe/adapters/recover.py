"""Явное восстановление, связанное с одной исходной локальной транзакцией."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agent_safe.adapters.exec_adapter import _display_command, _run
from agent_safe.adapters.fs import SafetyError
from agent_safe.core.journal import Journal
from agent_safe.core.managed_process import (
    ManagedAuthorizationError, ManagedCall, ManagedRecoveryAuthority,
    admission_for, cancel_unconsumed, consume_call, request_call,
    require_admission,
)
from agent_safe.core.models import ActionRecord, Risk, Status
from agent_safe.core.process_spec import read_json_file, strict_object
from agent_safe.core.risk import assess_command
from agent_safe.core.rollback import (
    check_storage, encoded, load_bundle, prepare_process, revalidate_process,
    sync_directory, target_state, write_new,
)
from agent_safe.core.verification import failed_verification, verify_stdout


def _matching_block(journal: Journal, source_id: str) -> None:
    check_storage(journal)
    if not journal.block_path.exists():
        raise SafetyError("барьер восстановления отсутствует")
    block = strict_object(read_json_file(journal.block_path))
    links = [block[key] for key in ("txn_id", "pending_txn_id") if key in block]
    if not links or any(link != source_id for link in links):
        raise SafetyError("блокировка относится к другому или неизвестному инциденту")


def recover(*, journal: Journal, source_id: str, plan_raw: str, approved: bool,
            reason: str, allow_critical: bool = False, retry_after: str | None = None,
            _managed: ManagedRecoveryAuthority | None = None) -> ActionRecord:
    if _managed is None and (not approved or not reason.strip()):
        raise SafetyError("восстановление требует отдельного --approved и непустого --reason")
    if _managed is not None and (approved or not reason.strip()):
        raise SafetyError("управляемое восстановление не принимает --approved и требует непустое обоснование")
    check_storage(journal)
    try:
        source = journal.find(source_id)
        records = journal.records()
    except (OSError, ValueError) as exc:
        raise SafetyError("журнал недоступен или повреждён; восстановление не запущено") from exc
    if (source is None or source.get("command", {}).get("channel") != "local"
            or not source.get("kind", "").endswith(".risky-exec")
            or source.get("status") not in {"done", "unexpected", "planned"}):
        raise SafetyError("нужна исходная локальная транзакция с сохранённым откатом")
    recovery = source.get("metadata", {}).get("recovery", {})
    if recovery.get("mode") != "saved-rollback":
        raise SafetyError("эта транзакция не содержит сохранённого плана отката")
    manifest = load_bundle(journal=journal, txn_id=source_id, recovery=recovery, plan_raw=plan_raw)
    target = manifest["plan"]["target"]
    if source.get("target_paths") != [target] or source["command"].get("target") != target:
        raise SafetyError("цель исходной транзакции не совпадает с комплектом")
    attempts = [r for r in records if r.get("kind") == "local.recovery"
                and r.get("metadata", {}).get("parent_txn_id") == source_id]
    expected_target = recovery.get("target_state")
    if attempts:
        previous = attempts[-1]
        if (retry_after != previous["txn_id"] or previous["status"] not in {"failed", "unexpected"}
                or previous.get("metadata", {}).get("result", {}).get("outcome") == "unknown"
                or (previous.get("metadata", {}).get("verify_exec") or {}).get("outcome") == "unknown"
                or previous.get("verify_result", {}).get("error_code") in {
                    "recovery_verify_authorization_failed", "recovery_verify_unknown",
                }):
            raise SafetyError("повтор требует завершённой неуспешной попытки и её явного --retry-after; неизвестный исход требует ручного разбора")
        expected_target = previous.get("metadata", {}).get("target_after")
    elif retry_after is not None:
        raise SafetyError("нет попытки, соответствующей --retry-after")
    if expected_target is None or target_state(target, journal) != expected_target:
        raise SafetyError("цель или её родитель изменились; требуется отдельный разбор восстановления")
    txn_id = ActionRecord.new_id()
    context = dict(journal=journal, txn_id=source_id, recovery=recovery,
                   plan_raw=plan_raw, attempt_txn_id=txn_id)
    process = prepare_process(role="process", **context)
    verify = prepare_process(role="verify", **context)
    args = [process.program, *process.argv]
    assessment = assess_command(_display_command(args), channel="local")
    if (assessment.risk == Risk.CRITICAL or source.get("risk") == "critical") and not allow_critical:
        raise SafetyError("критическое восстановление требует отдельного --allow-critical")
    process_call: ManagedCall | None = None
    verify_call: ManagedCall | None = None
    if _managed is not None:
        active = journal.safety_dir / "recovery" / "ACTIVE.json"
        require_admission(_managed, admission_for(
            journal_path=journal.journal_path, block_path=journal.block_path,
            active_path=active, source_txn_id=source_id, attempt_txn_id=txn_id,
            manifest_sha256=recovery["manifest_sha256"],
        ))
    if journal.is_blocked():
        _matching_block(journal, source_id)
    else:
        try:
            journal.begin_pending(source_id)
        except OSError as exc:
            raise SafetyError("не удалось установить барьер восстановления") from exc
    lock = journal.safety_dir / "recovery" / "ACTIVE.json"
    metadata = {"parent_txn_id": source_id, "manifest_sha256": recovery["manifest_sha256"],
                "retry_after": retry_after, "approved": _managed is None}
    if _managed is not None:
        metadata.update(authorization="managed", process_call_id=f"{txn_id}:process")
    record = ActionRecord(
        txn_id=txn_id, status=Status.PLANNED, kind="local.recovery", risk=assessment.risk,
        reason=reason, cwd=process.cwd, target_paths=[target],
        command={"channel": "local", "operation": "saved-rollback"},
        expected_state=manifest["plan"]["expected_state"],
        metadata=metadata,
    )
    try:
        write_new(lock, encoded({"txn_id": txn_id, "parent_txn_id": source_id}))
        journal.append(record, durable=True)
    except (OSError, SafetyError) as exc:
        raise SafetyError("не удалось зафиксировать попытку либо уже есть незавершённое восстановление; запуск запрещён") from exc
    assertions = manifest["plan"]["expected_state"]["assertions"]
    result: dict[str, Any] = {"outcome": "not_started", "returncode": 127}
    verification = failed_verification(assertions, "recovery_not_started", "восстановление не запущено")
    verify_result = None
    try:
        if _managed is not None:
            process_call = request_call(_managed, process, call_id=f"{txn_id}:process")
        _matching_block(journal, source_id)
        if target_state(target, journal) != expected_target:
            raise SafetyError("цель изменилась перед запуском восстановления")
        revalidate_process(process, role="process", **context)
        if _managed is not None:
            consume_call(_managed, process_call)
        result = _run([process.program, *process.argv], Path(process.cwd), timeout=process.timeout_seconds,
                      structured=True, stdin_utf8=process.stdin_utf8)
        if result.get("returncode") == 0 and result.get("outcome") == "exited":
            if _managed is not None:
                verify_call = request_call(_managed, verify, call_id=f"{txn_id}:verify")
                if verify_call.call_id == process_call.call_id:
                    raise ManagedAuthorizationError("CALL_BINDING_MISMATCH")
                record.metadata["verify_call_id"] = verify_call.call_id
            _matching_block(journal, source_id)
            revalidate_process(verify, role="verify", **context)
            if _managed is not None:
                consume_call(_managed, verify_call)
            verify_result = _run([verify.program, *verify.argv], Path(verify.cwd),
                                 timeout=verify.timeout_seconds, structured=True,
                                 stdin_utf8=verify.stdin_utf8)
            if (verify_result.get("returncode") == 0 and verify_result.get("outcome") == "exited"
                    and not verify_result.get("stdout_truncated")):
                strict_object(verify_result.get("stdout", ""))
                verification = verify_stdout(assertions, verify_result["stdout"])
            else:
                verification = failed_verification(assertions, "recovery_verify_failed", "проверка восстановления не завершена или её вывод усечён")
        else:
            verification = failed_verification(assertions, "recovery_process_failed", "восстановление не завершилось успешно")
        _matching_block(journal, source_id)
    except ManagedAuthorizationError as exc:
        cancel_unconsumed(_managed, verify_call or process_call)
        if result.get("returncode") == 0 and result.get("outcome") == "exited":
            verification = failed_verification(
                assertions, "recovery_verify_authorization_failed",
                f"восстановление выполнено, но разрешение проверки не получено ({exc.code})",
            )
        else:
            verification = failed_verification(
                assertions, "recovery_process_authorization_failed",
                f"разрешение процесса восстановления не получено ({exc.code})",
            )
    except (SafetyError, OSError) as exc:
        if _managed is not None:
            cancel_unconsumed(_managed, verify_call or process_call)
        verification = failed_verification(assertions, "recovery_precondition_failed", str(exc))
    except (Exception, KeyboardInterrupt) as exc:
        if _managed is not None:
            cancel_unconsumed(_managed, verify_call or process_call)
        if result.get("returncode") == 0 and result.get("outcome") == "exited":
            verification = failed_verification(
                assertions, "recovery_verify_unknown",
                "восстановление выполнено, но исход проверки неизвестен",
            )
        else:
            result = {"outcome": "unknown", "returncode": 127, "error": type(exc).__name__}
            verification = failed_verification(assertions, "recovery_unknown", "исход восстановления неизвестен")
    except BaseException:
        if _managed is not None:
            cancel_unconsumed(_managed, verify_call or process_call)
        raise
    record.status = (Status.DONE if verification.successful else
                     Status.FAILED if result.get("outcome") == "not_started" else Status.UNEXPECTED)
    record.verification_complete = verification.verification_complete
    record.verified_assertions = verification.verified_assertions
    record.missing_assertions = verification.missing_assertions
    record.mismatched_assertions = verification.mismatched_assertions
    record.actual_state = verification.actual_state
    record.verify_result = {"error_code": verification.error_code, "error_message": verification.error_message}
    record.metadata.update(result=result, verify_exec=verify_result)
    try:
        record.metadata["target_after"] = target_state(target, journal)
    except SafetyError:
        record.metadata["target_after"] = None
        record.status = Status.UNEXPECTED
        record.verification_complete = False
        record.verify_result["target_observation_failed"] = True
    # Любая ошибка записи оставляет ACTIVE и исходную блокировку для ручного разбора.
    try:
        journal.append(record, durable=True)
        if strict_object(read_json_file(lock)).get("txn_id") != txn_id:
            raise SafetyError("владелец барьера восстановления изменился")
        lock.unlink()
        sync_directory(lock.parent)
    except OSError as exc:
        raise SafetyError("результат не удалось надёжно зафиксировать; исходная блокировка сохранена") from exc
    return record


def _recover_managed(*, journal: Journal, source_id: str, plan_raw: str,
                     reason: str, authority: ManagedRecoveryAuthority | None,
                     allow_critical: bool = False,
                     retry_after: str | None = None) -> ActionRecord:
    """Trusted application entry; deliberately absent from the public CLI."""
    if authority is None:
        raise ManagedAuthorizationError("MANAGED_AUTHORITY_REQUIRED")
    try:
        return recover(
            journal=journal, source_id=source_id, plan_raw=plan_raw,
            approved=False, reason=reason, allow_critical=allow_critical,
            retry_after=retry_after, _managed=authority,
        )
    finally:
        authority.close()
