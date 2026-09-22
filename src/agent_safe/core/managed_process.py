"""Internal connection point for a trusted PreparedProcess permission owner."""

from __future__ import annotations

from dataclasses import dataclass, is_dataclass
from pathlib import Path
from typing import Any, Protocol

from agent_safe.adapters.fs import SafetyError
from agent_safe.core.rollback import PreparedProcess


@dataclass(frozen=True)
class RecoveryAdmission:
    """Exact local service paths covered by the trusted recovery admission."""

    source_txn_id: str
    attempt_txn_id: str
    manifest_sha256: str
    journal_path: str
    block_path: str
    active_path: str


@dataclass
class ManagedCall:
    role: str
    call_id: str
    binding: object
    pending: object
    consumed: bool = False


class ManagedAuthorizationError(SafetyError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(f"managed process authorization failed: {code}")


class ManagedRecoveryAuthority(Protocol):
    """Implemented only by the trusted in-process composition owner.

    The owner keeps HostPort private. ``approval_event`` waits for or handles a
    genuine host event; agent-safe never calls ``approve_once`` itself.
    """

    execution_port: object
    authorization_error_type: type[BaseException]

    def admit_recovery(self, admission: RecoveryAdmission) -> RecoveryAdmission: ...
    def bind(self, prepared: PreparedProcess, *, call_id: str) -> object: ...
    def approval_event(self, pending: object, binding: object) -> None: ...
    def cancel(self, pending: object) -> None: ...
    def close(self) -> None: ...


def require_admission(authority: ManagedRecoveryAuthority, admission: RecoveryAdmission) -> None:
    if authority is None:
        raise ManagedAuthorizationError("RECOVERY_ADMISSION_REQUIRED")
    port = getattr(authority, "execution_port", None)
    if port is None or not callable(getattr(port, "request", None)) or not callable(getattr(port, "consume", None)):
        raise ManagedAuthorizationError("EXECUTION_PORT_REQUIRED")
    error_type = getattr(authority, "authorization_error_type", None)
    if not isinstance(error_type, type) or not issubclass(error_type, BaseException):
        raise ManagedAuthorizationError("AUTHORIZATION_ERROR_TYPE_REQUIRED")
    try:
        accepted = authority.admit_recovery(admission)
    except BaseException as exc:
        if isinstance(exc, error_type):
            raise ManagedAuthorizationError(_error_code(exc)) from exc
        raise
    if accepted is not admission:
        raise ManagedAuthorizationError("RECOVERY_ADMISSION_REQUIRED")


def _error_code(exc: BaseException) -> str:
    code = getattr(exc, "code", None)
    return code if isinstance(code, str) and code else "AUTHORIZATION_FAILED"


def request_call(authority: ManagedRecoveryAuthority, prepared: PreparedProcess, *, call_id: str) -> ManagedCall:
    try:
        binding = authority.bind(prepared, call_id=call_id)
    except BaseException as exc:
        if isinstance(exc, authority.authorization_error_type):
            raise ManagedAuthorizationError(_error_code(exc)) from exc
        raise
    if (not is_dataclass(binding) or isinstance(binding, type)
            or getattr(binding, "call_id", None) != call_id
            or getattr(binding, "source_txn_id", None) != prepared.source_txn_id
            or getattr(binding, "attempt_txn_id", None) != prepared.attempt_txn_id
            or getattr(binding, "role", None) != prepared.role):
        raise ManagedAuthorizationError("CALL_BINDING_MISMATCH")
    try:
        pending = authority.execution_port.request(binding)
    except BaseException as exc:
        if isinstance(exc, authority.authorization_error_type):
            raise ManagedAuthorizationError(_error_code(exc)) from exc
        raise
    decision = getattr(pending, "decision", None)
    continuation = getattr(pending, "continuation", None)
    if decision == "DENY":
        raise ManagedAuthorizationError("NATIVE_DENY")
    if decision != "ASK_USER" or continuation is None:
        if continuation is not None:
            authority.cancel(pending)
        raise ManagedAuthorizationError("PENDING_CALL_INVALID")
    call = ManagedCall(prepared.role, call_id, binding, pending)
    try:
        authority.approval_event(pending, binding)
    except BaseException as exc:
        authority.cancel(pending)
        if isinstance(exc, authority.authorization_error_type):
            raise ManagedAuthorizationError(_error_code(exc)) from exc
        raise
    return call


def consume_call(authority: ManagedRecoveryAuthority, call: ManagedCall) -> None:
    try:
        projection = authority.execution_port.consume(call.pending.continuation, call.binding)
    except BaseException as exc:
        if isinstance(exc, authority.authorization_error_type):
            raise ManagedAuthorizationError(_error_code(exc)) from exc
        raise
    # ExecutionPort.consume is atomic. The grant stays consumed even if the
    # returned projection violates the trusted in-process adapter contract.
    call.consumed = True
    if projection != call.pending.projection:
        raise ManagedAuthorizationError("CONSUMED_PROJECTION_MISMATCH")


def cancel_unconsumed(authority: ManagedRecoveryAuthority, call: ManagedCall | None) -> None:
    if call is not None and not call.consumed:
        authority.cancel(call.pending)


def admission_for(*, journal_path: Path, block_path: Path, active_path: Path,
                  source_txn_id: str, attempt_txn_id: str,
                  manifest_sha256: str) -> RecoveryAdmission:
    return RecoveryAdmission(
        source_txn_id=source_txn_id,
        attempt_txn_id=attempt_txn_id,
        manifest_sha256=manifest_sha256,
        journal_path=str(journal_path.resolve()),
        block_path=str(block_path.resolve()),
        active_path=str(active_path.resolve()),
    )
