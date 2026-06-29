from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import ActionRecord, Status


SAFETY_DIR = ".agent-safety"
JOURNAL_NAME = "actions.jsonl"
BLOCK_FILE = "INCIDENT_BLOCKED"


class Journal:
    def __init__(self, root: Path | None = None) -> None:
        self.root = Path(root or Path.cwd()).resolve()
        self.safety_dir = self.root / SAFETY_DIR
        self.journal_path = self.safety_dir / JOURNAL_NAME
        self.safety_dir.mkdir(parents=True, exist_ok=True)
        for name in ["trash", "snapshots", "patches", "evidence", "recovery", "command-output"]:
            (self.safety_dir / name).mkdir(exist_ok=True)

    @property
    def block_path(self) -> Path:
        return self.safety_dir / BLOCK_FILE

    def is_blocked(self) -> bool:
        return self.block_path.exists()

    def block(self, reason: str, txn_id: str | None = None) -> None:
        payload = {"reason": reason, "txn_id": txn_id}
        self.block_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def clear_block(self, reason: str) -> None:
        if self.block_path.exists():
            archive = self.safety_dir / "recovery" / f"cleared-{ActionRecord.new_id()}.json"
            archive.write_text(self.block_path.read_text(encoding="utf-8"), encoding="utf-8")
            self.block_path.unlink()
        self.append_raw({"event": "clear-block", "reason": reason})

    def append(self, record: ActionRecord) -> None:
        self.append_raw(record.to_dict())

    def append_raw(self, payload: dict[str, Any]) -> None:
        with self.journal_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")

    def records(self) -> list[dict[str, Any]]:
        if not self.journal_path.exists():
            return []
        out: list[dict[str, Any]] = []
        for line in self.journal_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                out.append(json.loads(line))
        return out

    def last_reversible(self, include_undone: bool = False) -> dict[str, Any] | None:
        records = self.records()
        for record in reversed(records):
            if "undo" not in record or "redo" not in record:
                continue
            status = record.get("status")
            if status == Status.DONE.value or (include_undone and status == Status.UNDONE.value):
                if record.get("undo") and record.get("redo"):
                    return record
        return None

    def find(self, txn_id: str) -> dict[str, Any] | None:
        if txn_id == "last":
            return self.last_reversible(include_undone=True)
        for record in reversed(self.records()):
            if record.get("txn_id") == txn_id:
                return record
        return None
