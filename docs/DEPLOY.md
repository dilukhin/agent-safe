# Deploy

## Windows

```powershell
python -m pip install --user -e .
safe --help
```

Or build a portable zipapp:

```powershell
python scripts/build_zipapp.py
python dist/safe.pyz --help
```

## Linux

```bash
python3 -m pip install --user -e .
safe --help
```

Or:

```bash
python3 scripts/build_zipapp.py
python3 dist/safe.pyz --help
```

## Android / Termux

```bash
pkg install python git
python -m pip install --user -e .
safe --help
```

Or copy `dist/safe.pyz` and run:

```bash
python safe.pyz --help
```

## OpenCode

Recommended bootstrap:

```bash
safe opencode-bootstrap --scope global --dry-run
safe opencode-bootstrap --scope global --apply
```

For project-local setup from the repository root:

```bash
safe opencode-bootstrap --scope project --dry-run
safe opencode-bootstrap --scope project --apply
```

Manual alternative:

- copy or merge `AGENTS.md` short safety rules;
- merge `opencode/opencode.json` into your OpenCode config;
- copy `opencode/skills/*` into either project `.opencode/skills/` or global `~/.config/opencode/skills/`.


## Portable adapter usage

All adapters are invoked through the same `safe` CLI on Windows, Linux, macOS, and Android/Termux. Avoid PowerShell-only wrappers in project instructions; keep PowerShell shell scripts only as optional convenience launchers.

Examples:

```bash
safe git-checkpoint --reason "before risky change" --bundle
safe ssh-relay-readonly --relay "ssh_relay" --host-label "server" --remote-command "pwd"
safe yc-readonly -- compute instance list
safe system-readonly -- hostname
```
