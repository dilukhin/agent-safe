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

Copy or merge:

- `AGENTS.md` short safety rules;
- `opencode/opencode.json` into your OpenCode config;
- `opencode/skills/*` into either project `.opencode/skills/` or global `~/.config/opencode/skills/`.
