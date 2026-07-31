from __future__ import annotations

import difflib
import json
import os
import shutil
from importlib import resources
try:
    from importlib.resources.abc import Traversable
except ImportError:  # Python 3.10: Traversable ещё находится в importlib.abc.
    from importlib.abc import Traversable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .core.journal import Journal
from .core.models import ActionRecord, Risk, Status

AGENT_BLOCK_BEGIN = "<!-- agent-safe:start -->"
AGENT_BLOCK_END = "<!-- agent-safe:end -->"

AGENT_SAFETY_BLOCK = f"""{AGENT_BLOCK_BEGIN}

## Agent Safety

Any action that changes external state is risky: local files, git, ssh_relay, cloud, VM, DB, services, secrets, network, unknown tools.

Before any non-read-only action:
1. classify risk, knowledge, predictability, reversibility, and blast radius;
2. identify the exact target and expected post-action state;
3. use `safe` for risky, high-impact, or unknown actions;
4. execute one atomic action only;
5. verify actual state against expected state.

If the result differs from the expected state:
- stop the main task immediately;
- enter Recovery Mode;
- use read-only diagnostics only;
- do not cleanup, delete, overwrite, reset, force, or improvise;
- load the relevant agent-safe skill and plan recovery before changing anything.

{AGENT_BLOCK_END}
"""

DEFAULT_BASH_RULES: dict[str, str] = {
    "safe *": "allow",
    "python -m agent_safe *": "allow",
    "python3 -m agent_safe *": "allow",
    "git status*": "allow",
    "git diff*": "allow",
    "git log*": "allow",
    "git ls-files*": "allow",
    "rm *": "deny",
    "rmdir *": "deny",
    "del *": "deny",
    "erase *": "deny",
    "Remove-Item *": "deny",
    "git reset --hard*": "deny",
    "git clean -f*": "deny",
    "git clean -df*": "deny",
    "git branch -D*": "deny",
    "git push --force*": "deny",
    "yc * delete *": "deny",
    "yc * remove *": "deny",
    "shutdown *": "deny",
    "Restart-Computer *": "deny",
    "Stop-Computer *": "deny",
    "curl *|*sh*": "deny",
    "wget *|*sh*": "deny",
    "iwr *|*iex*": "deny",
    "Invoke-Expression *": "deny",
    "iex *": "deny",
}

DEFAULT_READ_RULES: dict[str, str] = {
    "*": "allow",
    "*.env": "deny",
    "*.env.*": "deny",
    "*.key": "deny",
    "*.pem": "deny",
    "*.p12": "deny",
    "*.pfx": "deny",
}


@dataclass
class BootstrapResult:
    mode: str
    scope: str
    opencode_dir: str
    config_path: str
    skills_dir: str
    agents_path: str
    planned_changes: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    applied: bool = False
    journal_txn_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "scope": self.scope,
            "opencode_dir": self.opencode_dir,
            "config_path": self.config_path,
            "skills_dir": self.skills_dir,
            "agents_path": self.agents_path,
            "planned_changes": self.planned_changes,
            "warnings": self.warnings,
            "applied": self.applied,
            "journal_txn_id": self.journal_txn_id,
        }


def _template_root() -> Traversable:
    return resources.files("agent_safe").joinpath("templates", "opencode")


def default_global_opencode_dir() -> Path:
    env = os.environ.get("OPENCODE_CONFIG_DIR")
    if env:
        return Path(env).expanduser().resolve()
    return (Path.home() / ".config" / "opencode").resolve()


def _strip_jsonc_comments(text: str) -> str:
    # Conservative line-comment stripper. It is intentionally simple; if parsing still
    # fails, the caller reports the issue and leaves the file untouched.
    out: list[str] = []
    for line in text.splitlines():
        in_str = False
        escape = False
        cut_at: int | None = None
        for idx in range(len(line) - 1):
            ch = line[idx]
            if escape:
                escape = False
                continue
            if ch == "\\":
                escape = True
                continue
            if ch == '"':
                in_str = not in_str
                continue
            if not in_str and line[idx:idx + 2] == "//":
                cut_at = idx
                break
        out.append(line[:cut_at].rstrip() if cut_at is not None else line)
    return "\n".join(out)


def _load_json_file(path: Path) -> tuple[dict[str, Any], list[str]]:
    warnings: list[str] = []
    if not path.exists():
        return {}, warnings
    text = path.read_text(encoding="utf-8")
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        try:
            value = json.loads(_strip_jsonc_comments(text))
            warnings.append(f"{path} contains comments; rewritten file will be plain JSON")
        except json.JSONDecodeError as exc:
            raise ValueError(f"cannot parse JSON/JSONC config {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"config must be a JSON object: {path}")
    return value, warnings


def _stable_json(value: dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=False) + "\n"


def _dictify_permission_node(value: Any, fallback_key: str = "*") -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, str):
        return {fallback_key: value}
    if value is None:
        return {}
    return {fallback_key: value}


def merge_opencode_config(existing: dict[str, Any]) -> dict[str, Any]:
    merged = dict(existing)
    merged.setdefault("$schema", "https://opencode.ai/config.json")
    permission = _dictify_permission_node(merged.get("permission"))
    permission.setdefault("*", "ask")

    skill = _dictify_permission_node(permission.get("skill"))
    skill.setdefault("*", "allow")
    permission["skill"] = skill

    read = _dictify_permission_node(permission.get("read"))
    for key, value in DEFAULT_READ_RULES.items():
        read.setdefault(key, value)
    permission["read"] = read

    bash = _dictify_permission_node(permission.get("bash"))
    bash.setdefault("*", "ask")
    for key, value in DEFAULT_BASH_RULES.items():
        bash.setdefault(key, value)
    permission["bash"] = bash

    permission.setdefault("edit", "ask")
    permission.setdefault("external_directory", "ask")
    permission.setdefault("doom_loop", "ask")
    merged["permission"] = permission
    return merged


def _unified_diff(old: str, new: str, fromfile: str, tofile: str) -> str:
    if old == new:
        return ""
    return "".join(difflib.unified_diff(
        old.splitlines(keepends=True),
        new.splitlines(keepends=True),
        fromfile=fromfile,
        tofile=tofile,
    ))


def _backup(path: Path, backup_dir: Path) -> Path | None:
    if not path.exists():
        return None
    backup_dir.mkdir(parents=True, exist_ok=True)
    rel_name = str(path).replace(":", "").replace("\\", "_").replace("/", "_").lstrip("_")
    dest = backup_dir / rel_name
    if path.is_dir():
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(path, dest)
    else:
        shutil.copy2(path, dest)
    return dest


def _ensure_agent_block_text(existing: str) -> tuple[str, str]:
    if AGENT_BLOCK_BEGIN in existing and AGENT_BLOCK_END in existing:
        return existing, "already-present"
    if existing.strip():
        return existing.rstrip() + "\n\n" + AGENT_SAFETY_BLOCK, "append"
    return AGENT_SAFETY_BLOCK, "create"


def _iter_skill_files(src_skills: Traversable, prefix: Path | None = None) -> list[tuple[Traversable, Path]]:
    prefix = prefix or Path()
    out: list[tuple[Traversable, Path]] = []
    for child in sorted(src_skills.iterdir(), key=lambda item: item.name):
        rel = prefix / child.name
        if child.is_file():
            out.append((child, rel))
        elif child.is_dir():
            out.extend(_iter_skill_files(child, rel))
    return out


def _plan_skills(src_skills: Traversable, dst_skills: Path) -> tuple[list[dict[str, Any]], list[tuple[Traversable, Path]]]:
    changes: list[dict[str, Any]] = []
    copies: list[tuple[Traversable, Path]] = []
    for src, rel in _iter_skill_files(src_skills):
        dst = dst_skills / rel
        new_text = src.read_text(encoding="utf-8")
        if dst.exists():
            old_text = dst.read_text(encoding="utf-8")
            action = "unchanged" if old_text == new_text else "update"
        else:
            old_text = ""
            action = "create"
        if action != "unchanged":
            copies.append((src, dst))
            changes.append({
                "type": "skill-file",
                "action": action,
                "path": str(dst),
                "diff": _unified_diff(old_text, new_text, str(dst), str(dst)),
            })
    return changes, copies


def resolve_bootstrap_paths(
    *,
    scope: str,
    root: Path,
    opencode_dir: str | None = None,
    config_path: str | None = None,
    skills_dir: str | None = None,
    agents_path: str | None = None,
) -> tuple[Path, Path, Path, Path]:
    if scope not in {"global", "project"}:
        raise ValueError("scope must be 'global' or 'project'")

    if scope == "global":
        base = Path(opencode_dir).expanduser().resolve() if opencode_dir else default_global_opencode_dir()
        config = Path(config_path).expanduser().resolve() if config_path else base / "opencode.json"
        skills = Path(skills_dir).expanduser().resolve() if skills_dir else base / "skills"
        agents = Path(agents_path).expanduser().resolve() if agents_path else base / "AGENTS.md"
    else:
        base = Path(opencode_dir).expanduser().resolve() if opencode_dir else root.resolve()
        config = Path(config_path).expanduser().resolve() if config_path else base / "opencode.json"
        skills = Path(skills_dir).expanduser().resolve() if skills_dir else base / ".opencode" / "skills"
        agents = Path(agents_path).expanduser().resolve() if agents_path else base / "AGENTS.md"
    return base, config, skills, agents


def opencode_bootstrap(
    *,
    scope: str,
    apply: bool,
    root: Path | None = None,
    opencode_dir: str | None = None,
    config_path: str | None = None,
    skills_dir: str | None = None,
    agents_path: str | None = None,
    update_agents: bool = True,
    update_config: bool = True,
    copy_skills: bool = True,
    journal: Journal | None = None,
) -> BootstrapResult:
    root = Path(root or Path.cwd()).resolve()
    journal = journal or Journal(root)
    tpl = _template_root()
    tpl_skills = tpl.joinpath("skills")
    if not tpl_skills.is_dir():
        raise FileNotFoundError(f"agent-safe opencode skill templates not found: {tpl_skills}")

    base, config, skills, agents = resolve_bootstrap_paths(
        scope=scope,
        root=root,
        opencode_dir=opencode_dir,
        config_path=config_path,
        skills_dir=skills_dir,
        agents_path=agents_path,
    )
    result = BootstrapResult(
        mode="apply" if apply else "dry-run",
        scope=scope,
        opencode_dir=str(base),
        config_path=str(config),
        skills_dir=str(skills),
        agents_path=str(agents),
    )

    backups: list[str] = []
    backup_dir = journal.safety_dir / "snapshots" / f"opencode-bootstrap-{ActionRecord.new_id()}"
    rollback_commands: list[str] = []

    if update_config:
        existing_config, warnings = _load_json_file(config)
        result.warnings.extend(warnings)
        merged_config = merge_opencode_config(existing_config)
        old_text = config.read_text(encoding="utf-8") if config.exists() else ""
        new_text = _stable_json(merged_config)
        if old_text != new_text:
            result.planned_changes.append({
                "type": "opencode-config",
                "action": "update" if config.exists() else "create",
                "path": str(config),
                "diff": _unified_diff(old_text, new_text, str(config), str(config)),
            })
            if apply:
                b = _backup(config, backup_dir)
                if b:
                    backups.append(str(b))
                    rollback_commands.append(f"restore backup {b} -> {config}")
                config.parent.mkdir(parents=True, exist_ok=True)
                config.write_text(new_text, encoding="utf-8")

    if copy_skills:
        skill_changes, copies = _plan_skills(tpl_skills, skills)
        result.planned_changes.extend(skill_changes)
        if apply and copies:
            b = _backup(skills, backup_dir)
            if b:
                backups.append(str(b))
                rollback_commands.append(f"restore backup {b} -> {skills}")
            for src, dst in copies:
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")

    if update_agents:
        old_text = agents.read_text(encoding="utf-8") if agents.exists() else ""
        new_text, action = _ensure_agent_block_text(old_text)
        if action != "already-present":
            result.planned_changes.append({
                "type": "agents-md",
                "action": action,
                "path": str(agents),
                "diff": _unified_diff(old_text, new_text, str(agents), str(agents)),
            })
            if apply:
                b = _backup(agents, backup_dir)
                if b:
                    backups.append(str(b))
                    rollback_commands.append(f"restore backup {b} -> {agents}")
                agents.parent.mkdir(parents=True, exist_ok=True)
                agents.write_text(new_text, encoding="utf-8")

    if apply and not result.planned_changes:
        result.applied = False
        result.journal_txn_id = None
        return result

    if apply:
        record = ActionRecord(
            txn_id=ActionRecord.new_id(),
            status=Status.DONE,
            kind="opencode.bootstrap",
            risk=Risk.CAUTIOUS,
            reason=f"bootstrap agent-safe OpenCode integration ({scope})",
            cwd=str(root),
            target_paths=[str(config), str(skills), str(agents)],
            undo={"op": "manual-restore-backups", "backups": backups, "commands": rollback_commands},
            redo={"op": "rerun", "command": f"safe opencode-bootstrap --scope {scope} --apply"},
            expected_state={
                "config_exists": update_config,
                "skills_dir_exists": copy_skills,
                "agents_contains_agent_safe_block": update_agents,
            },
            verify_result={
                "config_exists": config.exists(),
                "skills_dir_exists": skills.exists(),
                "agents_contains_agent_safe_block": agents.exists() and AGENT_BLOCK_BEGIN in agents.read_text(encoding="utf-8"),
            },
            metadata={"bootstrap_result": result.to_dict(), "backups": backups},
        )
        journal.append(record)
        result.applied = True
        result.journal_txn_id = record.txn_id

    return result
