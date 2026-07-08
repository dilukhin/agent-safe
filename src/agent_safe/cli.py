from __future__ import annotations

import argparse
import json
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .adapters.exec_adapter import exec_readonly, exec_risky
from .adapters.fs import SafetyError, fs_move, fs_trash, redo_record, undo_record
from .adapters.git import git_checkpoint, git_clean_preview
from .adapters.ssh_relay import ssh_relay_readonly, ssh_relay_risky
from .adapters.system import system_change, system_readonly
from .adapters.yc import yc_change, yc_readonly
from .core.checkpoint import checkpoint as make_checkpoint
from .core.journal import Journal
from .core.risk import assess_command
from .opencode_bootstrap import opencode_bootstrap


def print_json(payload: object) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2))



def _remainder(values: list[str]) -> list[str]:
    if values and values[0] == "--":
        return values[1:]
    return values


def _require_command(values: list[str]) -> list[str]:
    command = _remainder(values)
    if not command:
        raise SafetyError("command is required after --")
    return command


def _read_text_arg(path: str | None) -> str | None:
    if not path:
        return None
    return Path(path).read_text(encoding="utf-8").strip()


def _choose_arg(value: str | None, file_path: str | None, name: str, *, required: bool = False) -> str | None:
    if value is not None and file_path is not None:
        raise SafetyError(f"use either --{name} or --{name}-file, not both")
    chosen = value if value is not None else _read_text_arg(file_path)
    if required and not chosen:
        raise SafetyError(f"--{name} or --{name}-file is required")
    return chosen


def _parse_field(value: str) -> tuple[str, str]:
    key, separator, raw = value.partition("=")
    if not separator or not key:
        raise argparse.ArgumentTypeError("field must use KEY=VALUE format")
    return key, raw


def _powershell_single_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _quote_posix_path(value: str) -> str:
    if value == "~":
        return '"$HOME"'
    if value.startswith("~/"):
        return '"$HOME"/' + shlex.quote(value[2:])
    return shlex.quote(value)


def build_receipt_payload(args: argparse.Namespace) -> dict[str, object]:
    payload: dict[str, object] = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "tool": args.tool,
        "change": args.change,
        "target": args.target,
    }
    if args.reason:
        payload["reason"] = args.reason
    if args.status:
        payload["status"] = args.status
    for key, value in args.field or []:
        payload[key] = value
    return payload


def build_receipt_command(payload: dict[str, object], *, path: str, format_name: str) -> str:
    line = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    if format_name == "posix":
        directory = str(Path(path).parent).replace("\\", "/")
        return f"mkdir -p {_quote_posix_path(directory)} && printf '%s\\n' {shlex.quote(line)} >> {_quote_posix_path(path)}"
    if format_name == "powershell":
        directory = str(Path(path).parent)
        return (
            f"$dir={_powershell_single_quote(directory)}; "
            "New-Item -ItemType Directory -Force -LiteralPath $dir | Out-Null; "
            f"Add-Content -Encoding UTF8 -LiteralPath {_powershell_single_quote(path)} -Value {_powershell_single_quote(line)}"
        )
    raise SafetyError(f"unsupported receipt format: {format_name}")


def cmd_assess(args: argparse.Namespace) -> int:
    assessment = assess_command(args.command, channel=args.channel)
    print_json(assessment.to_dict())
    if assessment.risk.value in {"critical", "unknown"}:
        return 1
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    journal = Journal(Path(args.root) if args.root else None)
    records = journal.records()
    print_json({
        "root": str(journal.root),
        "safety_dir": str(journal.safety_dir),
        "blocked": journal.is_blocked(),
        "records": len(records),
        "last": records[-1] if records else None,
    })
    return 0


def cmd_checkpoint(args: argparse.Namespace) -> int:
    journal = Journal(Path(args.root) if args.root else None)
    record = make_checkpoint(args.reason, journal)
    print_json(record.to_dict())
    return 0


def cmd_fs_move(args: argparse.Namespace) -> int:
    journal = Journal(Path(args.root) if args.root else None)
    record = fs_move(Path(args.source), Path(args.dest), args.reason, journal)
    print_json(record.to_dict())
    return 0 if record.status.value == "done" else 3


def cmd_fs_trash(args: argparse.Namespace) -> int:
    journal = Journal(Path(args.root) if args.root else None)
    record = fs_trash(Path(args.path), args.reason, journal)
    print_json(record.to_dict())
    return 0 if record.status.value == "done" else 3


def cmd_undo(args: argparse.Namespace) -> int:
    journal = Journal(Path(args.root) if args.root else None)
    rec = journal.find(args.txn_id)
    if not rec:
        raise SafetyError(f"transaction not found: {args.txn_id}")
    print_json(undo_record(rec, journal))
    return 0


def cmd_redo(args: argparse.Namespace) -> int:
    journal = Journal(Path(args.root) if args.root else None)
    rec = journal.find(args.txn_id)
    if not rec:
        raise SafetyError(f"transaction not found: {args.txn_id}")
    print_json(redo_record(rec, journal))
    return 0



def cmd_exec_readonly(args: argparse.Namespace) -> int:
    journal = Journal(Path(args.root) if args.root else None)
    record = exec_readonly(
        _require_command(args.exec_command),
        journal=journal,
        channel=args.channel,
        domain=args.domain,
        reason=args.reason,
        timeout=args.timeout,
    )
    print_json(record.to_dict())
    return 0 if record.status.value == "done" else 3


def cmd_exec_risky(args: argparse.Namespace) -> int:
    journal = Journal(Path(args.root) if args.root else None)
    expected_state = _choose_arg(args.expected_state, args.expected_state_file, "expected-state", required=True)
    rollback_command = _choose_arg(args.rollback_command, args.rollback_command_file, "rollback-command", required=True)
    verify_command = _choose_arg(args.verify_command, args.verify_command_file, "verify-command")
    receipt_command = _choose_arg(args.receipt_command, args.receipt_command_file, "receipt-command")
    record = exec_risky(
        _require_command(args.exec_command),
        journal=journal,
        channel=args.channel,
        domain=args.domain,
        target=args.target,
        reason=args.reason,
        expected_state_json=expected_state or "",
        rollback_command=rollback_command or "",
        verify_command=verify_command,
        receipt_command=receipt_command,
        approved=args.approved,
        allow_critical=args.allow_critical,
        timeout=args.timeout,
    )
    print_json(record.to_dict())
    return 0 if record.status.value == "done" else 3


def cmd_git_checkpoint(args: argparse.Namespace) -> int:
    journal = Journal(Path(args.root) if args.root else None)
    record = git_checkpoint(journal, args.reason, create_bundle=args.bundle)
    print_json(record.to_dict())
    return 0 if record.status.value == "done" else 3


def cmd_git_clean_preview(args: argparse.Namespace) -> int:
    journal = Journal(Path(args.root) if args.root else None)
    record = git_clean_preview(journal, include_ignored=args.include_ignored)
    print_json(record.to_dict())
    return 0 if record.status.value == "done" else 3


def cmd_ssh_relay_readonly(args: argparse.Namespace) -> int:
    journal = Journal(Path(args.root) if args.root else None)
    record = ssh_relay_readonly(
        args.relay,
        args.remote_command,
        journal=journal,
        host_label=args.host_label,
        reason=args.reason,
        relay_name=args.relay_name,
    )
    print_json(record.to_dict())
    return 0 if record.status.value == "done" else 3


def cmd_ssh_relay_risky(args: argparse.Namespace) -> int:
    journal = Journal(Path(args.root) if args.root else None)
    expected_state = _choose_arg(args.expected_state, args.expected_state_file, "expected-state", required=True)
    rollback_command = _choose_arg(args.rollback_command, args.rollback_command_file, "rollback-command", required=True)
    record = ssh_relay_risky(
        args.relay,
        args.remote_command,
        journal=journal,
        host_label=args.host_label,
        reason=args.reason,
        relay_name=args.relay_name,
        receipt_path=args.receipt_path,
        expected_state_json=expected_state or "",
        rollback_command=rollback_command or "",
        verify_remote_command=args.verify_remote_command,
        receipt_remote_command=args.receipt_remote_command,
        approved=args.approved,
        allow_critical=args.allow_critical,
    )
    print_json(record.to_dict())
    return 0 if record.status.value == "done" else 3


def cmd_yc_readonly(args: argparse.Namespace) -> int:
    journal = Journal(Path(args.root) if args.root else None)
    record = yc_readonly(_remainder(args.yc_args), journal=journal, reason=args.reason)
    print_json(record.to_dict())
    return 0 if record.status.value == "done" else 3


def cmd_yc_change(args: argparse.Namespace) -> int:
    journal = Journal(Path(args.root) if args.root else None)
    expected_state = _choose_arg(args.expected_state, args.expected_state_file, "expected-state", required=True)
    rollback_command = _choose_arg(args.rollback_command, args.rollback_command_file, "rollback-command", required=True)
    verify_command = _choose_arg(args.verify_command, args.verify_command_file, "verify-command")
    receipt_command = _choose_arg(args.receipt_command, args.receipt_command_file, "receipt-command")
    record = yc_change(
        _require_command(args.yc_args),
        journal=journal,
        target=args.target,
        reason=args.reason,
        expected_state_json=expected_state or "",
        rollback_command=rollback_command or "",
        verify_command=verify_command,
        receipt_command=receipt_command,
        approved=args.approved,
        allow_critical=args.allow_critical,
    )
    print_json(record.to_dict())
    return 0 if record.status.value == "done" else 3


def cmd_system_readonly(args: argparse.Namespace) -> int:
    journal = Journal(Path(args.root) if args.root else None)
    record = system_readonly(_require_command(args.exec_command), journal=journal, reason=args.reason)
    print_json(record.to_dict())
    return 0 if record.status.value == "done" else 3


def cmd_system_change(args: argparse.Namespace) -> int:
    journal = Journal(Path(args.root) if args.root else None)
    expected_state = _choose_arg(args.expected_state, args.expected_state_file, "expected-state", required=True)
    rollback_command = _choose_arg(args.rollback_command, args.rollback_command_file, "rollback-command", required=True)
    verify_command = _choose_arg(args.verify_command, args.verify_command_file, "verify-command")
    receipt_command = _choose_arg(args.receipt_command, args.receipt_command_file, "receipt-command")
    record = system_change(
        _require_command(args.exec_command),
        journal=journal,
        target=args.target,
        reason=args.reason,
        expected_state_json=expected_state or "",
        rollback_command=rollback_command or "",
        verify_command=verify_command,
        receipt_command=receipt_command,
        approved=args.approved,
        allow_critical=args.allow_critical,
    )
    print_json(record.to_dict())
    return 0 if record.status.value == "done" else 3


def cmd_opencode_bootstrap(args: argparse.Namespace) -> int:
    journal = Journal(Path(args.root) if args.root else None)
    result = opencode_bootstrap(
        scope=args.scope,
        apply=args.apply,
        root=journal.root,
        opencode_dir=args.opencode_dir,
        config_path=args.config_path,
        skills_dir=args.skills_dir,
        agents_path=args.agents_path,
        update_agents=not args.no_agents,
        update_config=not args.no_config,
        copy_skills=not args.no_skills,
        journal=journal,
    )
    print_json(result.to_dict())
    return 0


def cmd_diagnose(args: argparse.Namespace) -> int:
    journal = Journal(Path(args.root) if args.root else None)
    payload = {
        "blocked": journal.is_blocked(),
        "block": journal.block_path.read_text(encoding="utf-8") if journal.block_path.exists() else None,
        "records_tail": journal.records()[-10:],
        "allowed_now": ["status", "diagnose", "recovery-plan", "undo", "redo", "clear-block-after-manual-review"],
        "forbidden_now": ["cleanup", "delete", "overwrite", "reset", "force", "continue-original-task"],
    }
    print_json(payload)
    return 0


def cmd_recovery_plan(args: argparse.Namespace) -> int:
    journal = Journal(Path(args.root) if args.root else None)
    rec = journal.find(args.txn_id) if args.txn_id else journal.last_reversible(include_undone=True)
    plan = {
        "mode": "recovery-plan",
        "principle": "Unexpected result after high-risk action is an incident, not an obstacle.",
        "transaction": rec,
        "steps": [
            "Stop the original task.",
            "Run read-only diagnostics only.",
            "Compare expected_state with actual state.",
            "Choose undo if it restores the previous safe state and preconditions still hold.",
            "If undo preconditions do not hold, ask the user for a manual recovery plan.",
        ],
    }
    print_json(plan)
    return 0


def cmd_clear_block(args: argparse.Namespace) -> int:
    journal = Journal(Path(args.root) if args.root else None)
    journal.clear_block(args.reason)
    print_json({"cleared": True, "reason": args.reason})
    return 0


def cmd_receipt_command(args: argparse.Namespace) -> int:
    print(build_receipt_command(build_receipt_payload(args), path=args.path, format_name=args.format))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="safe", description="Cross-platform safety runtime for CLI agents")
    parser.add_argument("--version", action="version", version=f"agent-safe {__version__}")
    parser.add_argument("--root", help="Project root for .agent-safety; defaults to current directory")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("assess", help="Classify a command/action before execution")
    p.add_argument("--command", required=True)
    p.add_argument("--channel", default="unknown")
    p.set_defaults(func=cmd_assess)

    p = sub.add_parser("status", help="Show safety journal status")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("checkpoint", help="Create read-only evidence checkpoint")
    p.add_argument("--reason", required=True)
    p.set_defaults(func=cmd_checkpoint)

    p = sub.add_parser("fs-move", help="Reversible exact filesystem move")
    p.add_argument("source")
    p.add_argument("dest")
    p.add_argument("--reason", required=True)
    p.set_defaults(func=cmd_fs_move)

    p = sub.add_parser("fs-trash", help="Move a path into .agent-safety/trash instead of deleting")
    p.add_argument("path")
    p.add_argument("--reason", required=True)
    p.set_defaults(func=cmd_fs_trash)

    p = sub.add_parser("undo", help="Undo a reversible transaction")
    p.add_argument("txn_id", nargs="?", default="last")
    p.set_defaults(func=cmd_undo)

    p = sub.add_parser("redo", help="Redo a reversible transaction")
    p.add_argument("txn_id", nargs="?", default="last")
    p.set_defaults(func=cmd_redo)

    p = sub.add_parser("exec-readonly", help="Execute a read-only command through the safety journal")
    p.add_argument("--channel", default="unknown")
    p.add_argument("--domain", default="unknown")
    p.add_argument("--reason", default="read-only inspection")
    p.add_argument("--timeout", type=int, default=120)
    p.add_argument("exec_command", nargs=argparse.REMAINDER, help="command after --")
    p.set_defaults(func=cmd_exec_readonly)

    p = sub.add_parser("exec-risky", help="Execute one approved risky command with expected state and rollback")
    p.add_argument("--channel", default="unknown")
    p.add_argument("--domain", default="unknown")
    p.add_argument("--target", required=True)
    p.add_argument("--reason", required=True)
    p.add_argument("--expected-state", help="JSON object describing expected post-state")
    p.add_argument("--expected-state-file", help="file containing expected-state JSON")
    p.add_argument("--rollback-command")
    p.add_argument("--rollback-command-file", help="file containing rollback command text")
    p.add_argument("--verify-command")
    p.add_argument("--verify-command-file", help="file containing verification command text")
    p.add_argument("--receipt-command", help="command that records the completed change on the target side")
    p.add_argument("--receipt-command-file", help="file containing receipt command text")
    p.add_argument("--approved", action="store_true")
    p.add_argument("--allow-critical", action="store_true")
    p.add_argument("--timeout", type=int, default=120)
    p.add_argument("exec_command", nargs=argparse.REMAINDER, help="command after --")
    p.set_defaults(func=cmd_exec_risky)

    p = sub.add_parser("git-checkpoint", help="Create git evidence checkpoint and optional bundle")
    p.add_argument("--reason", required=True)
    p.add_argument("--bundle", action="store_true", help="also run git bundle create --all")
    p.set_defaults(func=cmd_git_checkpoint)

    p = sub.add_parser("git-clean-preview", help="Run git clean dry-run only")
    p.add_argument("--include-ignored", action="store_true", help="use git clean -ndx")
    p.set_defaults(func=cmd_git_clean_preview)

    p = sub.add_parser("ssh-relay-readonly", help="Run a read-only command via an ssh_relay-compatible CLI")
    p.add_argument("--relay", required=True, help="relay command, e.g. ssh_relay or 'python ssh_relay.py'")
    p.add_argument("--relay-name", help="ssh_relay session name passed as exec --name")
    p.add_argument("--host-label", required=True)
    p.add_argument("--remote-command", required=True)
    p.add_argument("--reason", default="read-only ssh_relay inspection")
    p.set_defaults(func=cmd_ssh_relay_readonly)

    p = sub.add_parser("ssh-relay-risky", help="Run one approved risky remote command via ssh_relay-compatible CLI")
    p.add_argument("--relay", required=True)
    p.add_argument("--relay-name", help="ssh_relay session name passed as exec --name")
    p.add_argument("--host-label", required=True)
    p.add_argument("--remote-command", required=True)
    p.add_argument("--reason", required=True)
    p.add_argument("--expected-state")
    p.add_argument("--expected-state-file")
    p.add_argument("--rollback-command")
    p.add_argument("--rollback-command-file")
    p.add_argument("--verify-remote-command")
    p.add_argument("--receipt-path", help="remote JSONL path passed to ssh_relay exec --risky --receipt-path")
    p.add_argument("--receipt-remote-command", help="remote command that records the completed change on the host")
    p.add_argument("--approved", action="store_true")
    p.add_argument("--allow-critical", action="store_true")
    p.set_defaults(func=cmd_ssh_relay_risky)

    p = sub.add_parser("yc-readonly", help="Run read-only yc command")
    p.add_argument("--reason", default="read-only yc inspection")
    p.add_argument("yc_args", nargs=argparse.REMAINDER, help="yc args after --")
    p.set_defaults(func=cmd_yc_readonly)

    p = sub.add_parser("yc-change", help="Run one approved yc change command with rollback metadata")
    p.add_argument("--target", required=True)
    p.add_argument("--reason", required=True)
    p.add_argument("--expected-state")
    p.add_argument("--expected-state-file")
    p.add_argument("--rollback-command")
    p.add_argument("--rollback-command-file")
    p.add_argument("--verify-command")
    p.add_argument("--verify-command-file")
    p.add_argument("--receipt-command")
    p.add_argument("--receipt-command-file")
    p.add_argument("--approved", action="store_true")
    p.add_argument("--allow-critical", action="store_true")
    p.add_argument("yc_args", nargs=argparse.REMAINDER, help="yc args after --")
    p.set_defaults(func=cmd_yc_change)

    p = sub.add_parser("system-readonly", help="Run a read-only system/VM command")
    p.add_argument("--reason", default="read-only system inspection")
    p.add_argument("exec_command", nargs=argparse.REMAINDER, help="command after --")
    p.set_defaults(func=cmd_system_readonly)

    p = sub.add_parser("system-change", help="Run one approved system/VM change command")
    p.add_argument("--target", required=True)
    p.add_argument("--reason", required=True)
    p.add_argument("--expected-state")
    p.add_argument("--expected-state-file")
    p.add_argument("--rollback-command")
    p.add_argument("--rollback-command-file")
    p.add_argument("--verify-command")
    p.add_argument("--verify-command-file")
    p.add_argument("--receipt-command")
    p.add_argument("--receipt-command-file")
    p.add_argument("--approved", action="store_true")
    p.add_argument("--allow-critical", action="store_true")
    p.add_argument("exec_command", nargs=argparse.REMAINDER, help="command after --")
    p.set_defaults(func=cmd_system_change)


    p = sub.add_parser("opencode-bootstrap", help="Install/update agent-safe OpenCode skills, permissions and AGENTS.md block")
    p.add_argument("--scope", choices=["global", "project"], default="global", help="global ~/.config/opencode or project-local config")
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true", help="show planned changes without writing files")
    mode.add_argument("--apply", action="store_true", help="apply planned changes and record a journal entry")
    p.add_argument("--opencode-dir", help="override OpenCode config/base directory")
    p.add_argument("--config-path", help="override opencode.json path")
    p.add_argument("--skills-dir", help="override skills directory")
    p.add_argument("--agents-path", help="override AGENTS.md path")
    p.add_argument("--no-agents", action="store_true", help="do not create/update AGENTS.md")
    p.add_argument("--no-config", action="store_true", help="do not create/update opencode.json")
    p.add_argument("--no-skills", action="store_true", help="do not copy OpenCode skills")
    p.set_defaults(func=cmd_opencode_bootstrap)

    p = sub.add_parser("diagnose", help="Read-only incident diagnostics")
    p.set_defaults(func=cmd_diagnose)

    p = sub.add_parser("recovery-plan", help="Draft recovery steps for an unexpected transaction")
    p.add_argument("txn_id", nargs="?")
    p.set_defaults(func=cmd_recovery_plan)

    p = sub.add_parser("clear-block", help="Clear INCIDENT_BLOCKED after manual review/recovery")
    p.add_argument("--reason", required=True)
    p.set_defaults(func=cmd_clear_block)

    p = sub.add_parser("receipt-command", help="Print a shell command that appends one JSONL change receipt")
    p.add_argument("--format", choices=["posix", "powershell"], default="posix")
    p.add_argument("--path", required=True, help="receipt JSONL path on the target side")
    p.add_argument("--tool", default="agent-safe")
    p.add_argument("--change", required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--reason")
    p.add_argument("--status", default="done")
    p.add_argument("--field", action="append", type=_parse_field, help="additional KEY=VALUE field; repeatable")
    p.set_defaults(func=cmd_receipt_command)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except SafetyError as exc:
        print_json({"error": str(exc), "type": "SafetyError"})
        return 2
    except KeyboardInterrupt:
        print_json({"error": "interrupted"})
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
