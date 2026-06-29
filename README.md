# agent-safe

Cross-platform safety runtime for CLI agents such as OpenCode.

`agent-safe` provides a small `safe` command that forces risky state-changing actions through a predictable protocol:

```text
classify -> inspect -> expected_state -> checkpoint -> execute one atomic action -> verify -> continue/recovery
```

The project is intentionally Python-stdlib-only so the same code can run on Windows, Linux, macOS, and Android/Termux.

## Current MVP

Implemented now:

- universal command risk assessment;
- conservative fallback for unknown tools/subsystems;
- append-only JSONL action journal;
- recovery lock after unexpected high-risk results;
- reversible filesystem move/trash operations;
- undo/redo for recorded reversible filesystem actions;
- project checkpoint command;
- OpenCode AGENTS.md snippet, skills, and sample permissions;
- tests using Python `unittest` only.

Planned adapters:

- git high-risk operations;
- ssh/ssh_relay remote execution;
- Yandex Cloud `yc` operations;
- VM/service/network/system actions;
- database migrations and mutations;
- secrets and credentials.

## Quick start

```bash
python -m agent_safe --help
python -m agent_safe assess --command "rm -rf build"
python -m agent_safe checkpoint --reason "before risky refactor"
python -m agent_safe fs-move ./old ./new --reason "rename directory"
python -m agent_safe fs-trash ./tmp-file --reason "remove temporary file safely"
python -m agent_safe undo last
python -m agent_safe redo last
python -m agent_safe status
```

From a source checkout:

```bash
python -m pip install -e .
safe --help
```

## Build zipapp

```bash
python scripts/build_zipapp.py
python dist/safe.pyz --help
```

The `.pyz` file can be copied to Windows, Linux, or Android/Termux and run with Python 3.

## Safety model

Any command/tool/API call that changes external state is risky, regardless of channel:

- local shell;
- remote shell / ssh_relay;
- cloud CLI / API;
- VM/service/network;
- git;
- database;
- package manager;
- secrets;
- unknown tools.

Unknown subsystem + state-changing action is treated as high risk until proven otherwise.

Unexpected result after a high-risk action is treated as an incident, not an obstacle. The original task stops; only read-only diagnostics and recovery planning are allowed until resolved.
