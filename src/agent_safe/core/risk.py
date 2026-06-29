from __future__ import annotations

import re
import shlex
from dataclasses import replace

from .models import Assessment, Knowledge, Predictability, Reversibility, Risk

READ_ONLY_VERBS = {
    "cat", "type", "more", "less", "head", "tail", "ls", "dir", "pwd", "whoami", "hostname",
    "get", "show", "list", "describe", "status", "diff", "log", "grep", "find", "where",
    "test-path", "select", "explain", "plan", "dry-run", "whatif", "version", "--version", "help", "--help", "-h"
}

STATE_CHANGING_VERBS = {
    "create", "new", "write", "edit", "patch", "set", "update", "modify", "apply", "move", "mv",
    "rename", "copy", "cp", "install", "uninstall", "remove", "rm", "delete", "del", "erase", "destroy",
    "drop", "truncate", "reset", "clean", "force", "revoke", "rotate", "deploy", "publish", "push",
    "start", "stop", "restart", "reboot", "shutdown", "enable", "disable", "migrate", "format",
    "chmod", "chown", "mount", "umount", "detach", "attach"
}

CRITICAL_PATTERNS = [
    r"\brm\s+-[^\n]*r[^\n]*f\b",
    r"\bRemove-Item\b.*\b-Recurse\b",
    r"\bRemove-Item\b.*\b-Force\b",
    r"\bConfirm:\$false\b",
    r"\bgit\s+reset\s+--hard\b",
    r"\bgit\s+clean\s+-[^\n]*f",
    r"\bgit\s+push\b.*\b--force\b",
    r"\byc\b.*\b(delete|remove)\b",
    r"\b(drop|truncate)\s+(database|table)\b",
    r"\b(curl|wget|iwr|Invoke-WebRequest)\b.*\|.*\b(sh|bash|iex|Invoke-Expression)\b",
    r"\bInvoke-Expression\b|\biex\b|\beval\b",
    r"\bshutdown\b|\bRestart-Computer\b|\bStop-Computer\b",
    r"\bformat\b",
]

DANGEROUS_FLAGS = {"--force", "-f", "-force", "/f", "--yes", "-y", "--assume-yes", "--no-confirm", "--confirm=false"}
WILDCARD_RE = re.compile(r"(?<!\\)[*?]")
CHAIN_RE = re.compile(r"(;|&&|\|\|?|`)")


def _tokens(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=False)
    except ValueError:
        return command.split()


def assess_command(command: str, channel: str = "unknown") -> Assessment:
    text = command.strip()
    lower = text.lower()
    tokens = [t.strip('"\'').lower() for t in _tokens(text)]
    reasons: list[str] = []

    if not text:
        return Assessment(command=command, channel=channel, state_changing=False, risk=Risk.SAFE, knowledge=Knowledge.HIGH, predictability=Predictability.DETERMINISTIC, reversibility=Reversibility.AUTOMATIC, reasons=["empty command"], required_next_step="none")


    # Explicit safe previews for otherwise dangerous tools.
    # These commands inspect planned effects without changing state.
    if re.search(r"\bgit\s+clean\s+-[^\n]*n", text, re.IGNORECASE) or re.search(r"\bgit\s+clean\s+--dry-run\b", text, re.IGNORECASE):
        return Assessment(command=command, channel=channel, domain="git", operation="clean-preview", risk=Risk.SAFE, knowledge=Knowledge.HIGH, predictability=Predictability.DETERMINISTIC, reversibility=Reversibility.AUTOMATIC, state_changing=False, reasons=["git clean preview/dry-run"], required_next_step="execute-read-only")

    if any(re.search(pattern, text, re.IGNORECASE) for pattern in CRITICAL_PATTERNS):
        reasons.append("matches known critical/destructive pattern")
        return Assessment(command=command, channel=channel, risk=Risk.CRITICAL, knowledge=Knowledge.MEDIUM, predictability=Predictability.CONTEXT_DEPENDENT, reversibility=Reversibility.UNKNOWN, state_changing=True, reasons=reasons, required_next_step="block-or-explicit-recovery-plan")

    if CHAIN_RE.search(text):
        reasons.append("contains command chaining or pipeline; not atomic")

    if any(flag in tokens for flag in DANGEROUS_FLAGS):
        reasons.append("contains force/auto-confirm flag")

    if WILDCARD_RE.search(text):
        reasons.append("contains wildcard target")

    verb_hits = [tok for tok in tokens if tok in STATE_CHANGING_VERBS]
    read_hits = [tok for tok in tokens if tok in READ_ONLY_VERBS]

    if verb_hits:
        reasons.append(f"state-changing verb(s): {', '.join(sorted(set(verb_hits)))}")
        risk = Risk.HIGH if reasons else Risk.CAUTIOUS
        if {"delete", "del", "remove", "rm", "destroy", "drop", "truncate", "reset", "clean", "format"} & set(verb_hits):
            risk = Risk.CRITICAL
        return Assessment(command=command, channel=channel, risk=risk, knowledge=Knowledge.MEDIUM, predictability=Predictability.CONTEXT_DEPENDENT if reasons else Predictability.DETERMINISTIC, reversibility=Reversibility.UNKNOWN, state_changing=True, reasons=reasons, required_next_step="use-safe-wrapper-with-checkpoint")

    if read_hits and not reasons:
        return Assessment(command=command, channel=channel, risk=Risk.SAFE, knowledge=Knowledge.HIGH, predictability=Predictability.DETERMINISTIC, reversibility=Reversibility.AUTOMATIC, state_changing=False, reasons=["read-only/discovery command"], required_next_step="execute-read-only")

    if reasons:
        return Assessment(command=command, channel=channel, risk=Risk.UNKNOWN, knowledge=Knowledge.LOW, predictability=Predictability.UNKNOWN, reversibility=Reversibility.UNKNOWN, state_changing=True, reasons=reasons, required_next_step="inspect-docs-and-read-only-first")

    return Assessment(command=command, channel=channel, risk=Risk.UNKNOWN, knowledge=Knowledge.LOW, predictability=Predictability.UNKNOWN, reversibility=Reversibility.UNKNOWN, state_changing=True, reasons=["unknown command semantics; assume state-changing until proven otherwise"], required_next_step="inspect-docs-and-read-only-first")
