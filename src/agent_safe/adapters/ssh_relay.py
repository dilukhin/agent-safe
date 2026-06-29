from __future__ import annotations

import shlex
from pathlib import Path

from agent_safe.adapters.exec_adapter import exec_readonly, exec_risky
from agent_safe.adapters.fs import SafetyError
from agent_safe.core.journal import Journal
from agent_safe.core.risk import assess_command


def build_relay_command(relay: str, remote_command: str) -> list[str]:
    # Expected relay interface: <relay> exec "<remote command>".
    # Relay itself may be a command path; keep it explicit and split conservatively.
    try:
        base = shlex.split(relay, posix=("\\" not in relay))
    except ValueError as exc:
        raise SafetyError(f"cannot parse relay command: {relay}: {exc}") from exc
    return [*base, "exec", remote_command]


def ssh_relay_readonly(relay: str, remote_command: str, *, journal: Journal, host_label: str, reason: str, cwd: Path | None = None):
    remote_assessment = assess_command(remote_command, channel="ssh_relay")
    if remote_assessment.state_changing or remote_assessment.risk.value != "safe":
        raise SafetyError(f"remote command is not read-only: risk={remote_assessment.risk.value}; reasons={remote_assessment.reasons}")
    command = build_relay_command(relay, remote_command)
    return exec_readonly(command, journal=journal, channel="ssh_relay", domain="ssh_relay", reason=reason or f"read-only remote command on {host_label}", cwd=cwd)


def ssh_relay_risky(
    relay: str,
    remote_command: str,
    *,
    journal: Journal,
    host_label: str,
    reason: str,
    expected_state_json: str,
    rollback_command: str,
    verify_remote_command: str | None,
    approved: bool,
    allow_critical: bool,
    cwd: Path | None = None,
):
    command = build_relay_command(relay, remote_command)
    verify_command = None
    if verify_remote_command:
        verify_command = " ".join(shlex.quote(x) for x in build_relay_command(relay, verify_remote_command))
    return exec_risky(
        command,
        journal=journal,
        channel="ssh_relay",
        domain="ssh_relay",
        target=f"host:{host_label}",
        reason=reason,
        expected_state_json=expected_state_json,
        rollback_command=rollback_command,
        verify_command=verify_command,
        approved=approved,
        allow_critical=allow_critical,
        cwd=cwd,
    )
