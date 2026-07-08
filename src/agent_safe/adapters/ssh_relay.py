from __future__ import annotations

import shlex
from pathlib import Path

from agent_safe.adapters.exec_adapter import exec_readonly, exec_risky
from agent_safe.adapters.fs import SafetyError
from agent_safe.core.journal import Journal
from agent_safe.core.risk import assess_command


def build_relay_command(
    relay: str,
    remote_command: str,
    *,
    relay_name: str | None = None,
    risky: bool = False,
    receipt_path: str | None = None,
) -> list[str]:
    # Expected relay interface: <relay> exec "<remote command>".
    # Relay itself may be a command path; keep it explicit and split conservatively.
    try:
        base = shlex.split(relay, posix=("\\" not in relay))
    except ValueError as exc:
        raise SafetyError(f"cannot parse relay command: {relay}: {exc}") from exc
    command = [*base, "exec"]
    if relay_name:
        command.extend(["--name", relay_name])
    if risky:
        command.append("--risky")
    if receipt_path:
        command.extend(["--receipt-path", receipt_path])
    command.append(remote_command)
    return command


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
        raise SafetyError(f"remote command is not read-only: risk={remote_assessment.risk.value}; reasons={remote_assessment.reasons}")
    command = build_relay_command(relay, remote_command, relay_name=relay_name)
    return exec_readonly(command, journal=journal, channel="ssh_relay", domain="ssh_relay", reason=reason or f"read-only remote command on {host_label}", cwd=cwd)


def ssh_relay_risky(
    relay: str,
    remote_command: str,
    *,
    journal: Journal,
    host_label: str,
    reason: str,
    relay_name: str | None = None,
    receipt_path: str | None = None,
    expected_state_json: str,
    rollback_command: str,
    verify_remote_command: str | None,
    receipt_remote_command: str | None = None,
    approved: bool,
    allow_critical: bool,
    cwd: Path | None = None,
):
    command = build_relay_command(relay, remote_command, relay_name=relay_name, risky=True, receipt_path=receipt_path)
    verify_command = None
    if verify_remote_command:
        verify_command = " ".join(shlex.quote(x) for x in build_relay_command(relay, verify_remote_command, relay_name=relay_name))
    receipt_command = None
    if receipt_remote_command:
        receipt_command = " ".join(shlex.quote(x) for x in build_relay_command(relay, receipt_remote_command, relay_name=relay_name))
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
        receipt_command=receipt_command,
        approved=approved,
        allow_critical=allow_critical,
        cwd=cwd,
    )
