from __future__ import annotations

import argparse
from pathlib import Path

from . import cli as legacy_cli
from .adapters.fs import SafetyError
from .adapters.fs_lifecycle import RESOURCE_CLASSES, fs_cleanup, fs_mark, fs_status
from .adapters.ssh_relay import ssh_relay_risky
from .core.journal import Journal


def _subparsers(parser: argparse.ArgumentParser) -> argparse._SubParsersAction:  # type: ignore[attr-defined]
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):  # type: ignore[attr-defined]
            return action
    raise RuntimeError("в CLI parser отсутствует таблица подкоманд")


def cmd_fs_mark(args: argparse.Namespace) -> int:
    journal = Journal(Path(args.root) if args.root else None)
    record = fs_mark(Path(args.path), args.resource_class, args.reason, journal)
    legacy_cli.print_json(record.to_dict())
    return 0


def cmd_fs_status(args: argparse.Namespace) -> int:
    journal = Journal(Path(args.root) if args.root else None)
    legacy_cli.print_json(fs_status(Path(args.path), journal))
    return 0


def cmd_fs_cleanup(args: argparse.Namespace) -> int:
    journal = Journal(Path(args.root) if args.root else None)
    record = fs_cleanup(Path(args.path), args.reason, journal)
    legacy_cli.print_json(record.to_dict())
    return 0 if record.status.value == "done" else 3


def cmd_ssh_relay_risky(args: argparse.Namespace) -> int:
    journal = Journal(Path(args.root) if args.root else None)
    expected_state = legacy_cli._choose_arg(  # noqa: SLF001 - единая семантика файловых аргументов CLI
        args.expected_state,
        args.expected_state_file,
        "expected-state",
        required=True,
    )
    rollback_command = legacy_cli._choose_arg(  # noqa: SLF001 - единая семантика файловых аргументов CLI
        args.rollback_command,
        args.rollback_command_file,
        "rollback-command",
        required=True,
    )
    record = ssh_relay_risky(
        args.relay,
        args.remote_command,
        journal=journal,
        host_label=args.host_label,
        reason=args.reason,
        relay_name=args.relay_name,
        relay_mode=args.relay_mode,
        receipt_path=args.receipt_path,
        expected_state_json=expected_state or "",
        rollback_command=rollback_command or "",
        verify_remote_command=args.verify_remote_command,
        receipt_remote_command=args.receipt_remote_command,
        approved=args.approved,
        allow_critical=args.allow_critical,
        timeout=args.timeout,
    )
    legacy_cli.print_json(record.to_dict())
    return 0 if record.status.value == "done" else 3


def build_parser() -> argparse.ArgumentParser:
    parser = legacy_cli.build_parser()
    sub = _subparsers(parser)

    ssh_risky = sub.choices.get("ssh-relay-risky")
    if ssh_risky is None:
        raise RuntimeError("в CLI parser отсутствует ssh-relay-risky")
    for action in ssh_risky._actions:
        if "--receipt-remote-command" in action.option_strings:
            action.help = argparse.SUPPRESS
        elif "--receipt-path" in action.option_strings:
            action.help = "remote receipt path; для sudo-exec обязателен абсолютный системный POSIX-путь"

    ssh_risky.add_argument(
        "--relay-mode",
        choices=["exec", "sudo-exec"],
        default="exec",
        help="режим ssh_relay для risky-команды и verify",
    )
    ssh_risky.add_argument("--timeout", type=int, default=120, help="таймаут локального процесса relay в секундах")
    ssh_risky.set_defaults(func=cmd_ssh_relay_risky)

    p = sub.add_parser("fs-mark", help="Назначить существующему пути класс normal/temporary/protected")
    p.add_argument("path")
    p.add_argument("--class", dest="resource_class", choices=RESOURCE_CLASSES, required=True)
    p.add_argument("--reason", required=True)
    p.set_defaults(func=cmd_fs_mark)

    p = sub.add_parser("fs-status", help="Показать класс, состояние и историю пути из журнала")
    p.add_argument("path")
    p.set_defaults(func=cmd_fs_status)

    p = sub.add_parser("fs-cleanup", help="Окончательно удалить явно временный путь с сохранением записи в журнале")
    p.add_argument("path")
    p.add_argument("--reason", required=True)
    p.set_defaults(func=cmd_fs_cleanup)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except SafetyError as exc:
        legacy_cli.print_json({"error": str(exc), "type": "SafetyError"})
        return 2
    except KeyboardInterrupt:
        legacy_cli.print_json({"error": "interrupted"})
        return 130
