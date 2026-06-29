from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
import uuid


class Risk(str, Enum):
    SAFE = "safe"
    CAUTIOUS = "cautious"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class Knowledge(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Predictability(str, Enum):
    DETERMINISTIC = "deterministic"
    CONTEXT_DEPENDENT = "context-dependent"
    UNKNOWN = "unknown"


class Reversibility(str, Enum):
    AUTOMATIC = "automatic"
    MANUAL = "manual"
    IRREVERSIBLE = "irreversible"
    UNKNOWN = "unknown"


class Status(str, Enum):
    PLANNED = "planned"
    DONE = "done"
    UNDONE = "undone"
    FAILED = "failed"
    UNEXPECTED = "unexpected"
    BLOCKED = "blocked"


@dataclass
class Assessment:
    command: str
    channel: str = "unknown"
    domain: str = "unknown"
    operation: str = "unknown"
    risk: Risk = Risk.UNKNOWN
    knowledge: Knowledge = Knowledge.LOW
    predictability: Predictability = Predictability.UNKNOWN
    reversibility: Reversibility = Reversibility.UNKNOWN
    state_changing: bool = True
    reasons: list[str] = field(default_factory=list)
    required_next_step: str = "inspect-read-only"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ActionRecord:
    txn_id: str
    status: Status
    kind: str
    risk: Risk
    reason: str
    cwd: str
    target_paths: list[str] = field(default_factory=list)
    command: dict[str, Any] = field(default_factory=dict)
    undo: dict[str, Any] = field(default_factory=dict)
    redo: dict[str, Any] = field(default_factory=dict)
    expected_state: dict[str, Any] = field(default_factory=dict)
    verify_result: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @classmethod
    def new_id(cls) -> str:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        return f"{stamp}-{uuid.uuid4().hex[:8]}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
