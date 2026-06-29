from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .adapters.fs import SafetyError, fs_move, fs_trash, redo_record, undo_record
from .core.checkpoint import checkpoint as make_checkpoint
from .core.journal import Journal
from .core.risk import assess_command


def print_json(payload: object) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2))


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

    p = sub.add_parser("diagnose", help="Read-only incident diagnostics")
    p.set_defaults(func=cmd_diagnose)

    p = sub.add_parser("recovery-plan", help="Draft recovery steps for an unexpected transaction")
    p.add_argument("txn_id", nargs="?")
    p.set_defaults(func=cmd_recovery_plan)

    p = sub.add_parser("clear-block", help="Clear INCIDENT_BLOCKED after manual review/recovery")
    p.add_argument("--reason", required=True)
    p.set_defaults(func=cmd_clear_block)

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
