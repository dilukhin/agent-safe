from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from agent_safe.adapters.exec_adapter import exec_readonly
from agent_safe.adapters.fs import SafetyError
from agent_safe.core.journal import Journal
from agent_safe.core.models import ActionRecord, Risk, Status


def _run(args: list[str], cwd: Path, timeout: int = 60) -> dict[str, Any]:
    try:
        proc = subprocess.run(args, cwd=str(cwd), text=True, capture_output=True, timeout=timeout)
        return {"args": args, "returncode": proc.returncode, "stdout": proc.stdout[-50000:], "stderr": proc.stderr[-50000:]}
    except Exception as exc:  # noqa: BLE001
        return {"args": args, "returncode": 127, "error": repr(exc)}


def git_checkpoint(journal: Journal, reason: str, create_bundle: bool = False) -> ActionRecord:
    cwd = journal.root
    txn_id = ActionRecord.new_id()
    evidence_dir = journal.safety_dir / "evidence" / txn_id
    evidence_dir.mkdir(parents=True, exist_ok=False)

    evidence = {
        "status": _run(["git", "status", "--short"], cwd),
        "log": _run(["git", "log", "--oneline", "-10"], cwd),
        "diff": _run(["git", "diff"], cwd),
        "diff_staged": _run(["git", "diff", "--staged"], cwd),
        "rev_parse_root": _run(["git", "rev-parse", "--show-toplevel"], cwd),
    }
    (evidence_dir / "git_status.txt").write_text(evidence["status"].get("stdout", ""), encoding="utf-8")
    (evidence_dir / "git_log.txt").write_text(evidence["log"].get("stdout", ""), encoding="utf-8")
    (journal.safety_dir / "patches" / f"{txn_id}_worktree.diff").write_text(evidence["diff"].get("stdout", ""), encoding="utf-8")
    (journal.safety_dir / "patches" / f"{txn_id}_staged.diff").write_text(evidence["diff_staged"].get("stdout", ""), encoding="utf-8")

    bundle_result: dict[str, Any] | None = None
    if create_bundle:
        bundle_path = journal.safety_dir / "snapshots" / f"{txn_id}.bundle"
        bundle_result = _run(["git", "bundle", "create", str(bundle_path), "--all"], cwd, timeout=120)

    status = Status.DONE if evidence["rev_parse_root"].get("returncode") == 0 else Status.FAILED
    record = ActionRecord(
        txn_id=txn_id,
        status=status,
        kind="git.checkpoint",
        risk=Risk.SAFE,
        reason=reason,
        cwd=str(cwd),
        command={"op": "git-checkpoint", "bundle": create_bundle},
        verify_result={"is_git_repo": evidence["rev_parse_root"].get("returncode") == 0},
        metadata={"evidence_dir": str(evidence_dir), "bundle_result": bundle_result},
    )
    journal.append(record)
    return record


def git_clean_preview(journal: Journal, include_ignored: bool = False) -> ActionRecord:
    args = ["git", "clean", "-nd"]
    if include_ignored:
        args = ["git", "clean", "-ndx"]
    return exec_readonly(args, journal=journal, channel="git", domain="git", reason="preview git clean without deleting")


def git_require_clean(journal: Journal) -> dict[str, Any]:
    result = _run(["git", "status", "--porcelain"], journal.root)
    if result.get("returncode") != 0:
        raise SafetyError("not a git repository or git status failed")
    dirty = bool(str(result.get("stdout", "")).strip())
    return {"clean": not dirty, "status": result.get("stdout", "")}
