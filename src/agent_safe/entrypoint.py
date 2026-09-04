from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import cli as legacy_cli
from .adapters.fs import SafetyError
from .adapters.fs_lifecycle import RESOURCE_CLASSES, fs_cleanup, fs_mark, fs_status
from .build_identity import diagnostic_identity
from .core.journal import Journal


def _subparsers(parser: argparse.ArgumentParser) -> argparse._SubParsersAction:  # type: ignore[attr-defined]
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):  # type: ignore[attr-defined]
            return action
    raise RuntimeError("в CLI parser отсутствует таблица подкоманд")


def _configure_version_identity(parser: argparse.ArgumentParser) -> None:
    for action in parser._actions:
        if "--version" in action.option_strings:
            action.version = diagnostic_identity()
            return
    raise RuntimeError("в CLI parser отсутствует параметр --version")


def _emit_diagnostic_identity() -> None:
    print(diagnostic_identity(), file=sys.stderr)


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


def build_parser() -> argparse.ArgumentParser:
    parser = legacy_cli.build_parser()
    _configure_version_identity(parser)
    sub = _subparsers(parser)

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
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        if exc.code != 0:
            _emit_diagnostic_identity()
        raise

    _emit_diagnostic_identity()
    try:
        return int(args.func(args))
    except SafetyError as exc:
        legacy_cli.print_json({"error": str(exc), "type": "SafetyError"})
        return 2
    except KeyboardInterrupt:
        legacy_cli.print_json({"error": "interrupted"})
        return 130
