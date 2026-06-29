from __future__ import annotations

import json
import subprocess
from pathlib import Path

from .journal import Journal
from .models import ActionRecord, Risk, Status


def _run(args: list[str], cwd: Path) -> dict[str, object]:
    try:
        proc = subprocess.run(args, cwd=str(cwd), text=True, capture_output=True, timeout=20)
        return {"args": args, "returncode": proc.returncode, "stdout": proc.stdout[-20000:], "stderr": proc.stderr[-20000:]}
    except Exception as exc:  # noqa: BLE001 - checkpoint must not crash on missing git
        return {"args": args, "error": repr(exc)}


def checkpoint(reason: str, journal: Journal) -> ActionRecord:
    txn_id = ActionRecord.new_id()
    evidence_dir = journal.safety_dir / "evidence" / txn_id
    evidence_dir.mkdir(parents=True, exist_ok=False)
    cwd = journal.root

    evidence = {
        "cwd": str(cwd),
        "reason": reason,
        "git_status": _run(["git", "status", "--short"], cwd),
        "git_log": _run(["git", "log", "--oneline", "-5"], cwd),
        "git_diff": _run(["git", "diff"], cwd),
        "git_diff_staged": _run(["git", "diff", "--staged"], cwd),
    }
    (evidence_dir / "checkpoint.json").write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
    if isinstance(evidence["git_diff"], dict):
        (journal.safety_dir / "patches" / f"{txn_id}_before.diff").write_text(str(evidence["git_diff"].get("stdout", "")), encoding="utf-8")
    record = ActionRecord(
        txn_id=txn_id,
        status=Status.DONE,
        kind="checkpoint",
        risk=Risk.SAFE,
        reason=reason,
        cwd=str(cwd),
        metadata={"evidence_dir": str(evidence_dir)},
    )
    journal.append(record)
    return record
