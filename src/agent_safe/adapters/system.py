from __future__ import annotations

from pathlib import Path

from agent_safe.adapters.exec_adapter import exec_readonly, exec_risky
from agent_safe.core.journal import Journal


def system_readonly(command: list[str], *, journal: Journal, reason: str, cwd: Path | None = None):
    return exec_readonly(command, journal=journal, channel="system", domain="system", reason=reason or "read-only system inspection", cwd=cwd)


def system_change(
    command: list[str],
    *,
    journal: Journal,
    target: str,
    reason: str,
    expected_state_json: str,
    rollback_command: str,
    verify_command: str | None,
    approved: bool,
    allow_critical: bool,
    cwd: Path | None = None,
):
    return exec_risky(
        command,
        journal=journal,
        channel="system",
        domain="system",
        target=target,
        reason=reason,
        expected_state_json=expected_state_json,
        rollback_command=rollback_command,
        verify_command=verify_command,
        approved=approved,
        allow_critical=allow_critical,
        cwd=cwd,
    )
