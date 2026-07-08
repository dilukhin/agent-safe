from __future__ import annotations

from pathlib import Path

from agent_safe.adapters.exec_adapter import exec_readonly, exec_risky
from agent_safe.core.journal import Journal


READONLY_YC_VERBS = {"config", "list", "get", "describe", "status", "operation", "version", "help"}


def yc_readonly(args: list[str], *, journal: Journal, reason: str, cwd: Path | None = None):
    if not args:
        args = ["--help"]
    command = ["yc", *args]
    # exec_readonly does the final risk check; this convenience wrapper also makes intent clear.
    return exec_readonly(command, journal=journal, channel="yc", domain="yc", reason=reason or "read-only yc inspection", cwd=cwd)


def yc_change(
    args: list[str],
    *,
    journal: Journal,
    target: str,
    reason: str,
    expected_state_json: str,
    rollback_command: str,
    verify_command: str | None,
    receipt_command: str | None = None,
    approved: bool,
    allow_critical: bool,
    cwd: Path | None = None,
):
    return exec_risky(
        ["yc", *args],
        journal=journal,
        channel="yc",
        domain="yc",
        target=target,
        reason=reason,
        expected_state_json=expected_state_json,
        rollback_command=rollback_command,
        verify_command=verify_command,
        receipt_command=receipt_command,
        approved=approved,
        allow_critical=allow_critical,
        cwd=cwd,
    )
