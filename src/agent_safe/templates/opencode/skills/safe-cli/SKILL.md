---
name: safe-cli
description: How to use the cross-platform safe CLI wrapper instead of direct risky commands.
compatibility: opencode
---

# safe CLI

Use `safe` for risky actions.

Common commands:

```bash
safe assess --command "..."
safe checkpoint --reason "..."
safe fs-move SOURCE DEST --reason "..."
safe fs-trash PATH --reason "..."
safe undo last
safe redo last
safe status
safe diagnose
safe recovery-plan

# Generic/adapter commands
safe exec-readonly --channel local --domain system -- python --version
safe exec-risky --channel unknown --domain unknown --target "..." --reason "..." --expected-state '{"ok":true}' --rollback-command "..." --approved -- command args
safe exec-risky --channel remote --domain system --target "..." --reason "..." --expected-state-file expected.json --rollback-command-file rollback.txt --receipt-command-file receipt.txt --approved -- command args
safe receipt-command --format posix --path ~/.local/state/agent-safe/changes.jsonl --change "install package" --target "host:prod" --field package=nginx
safe git-checkpoint --reason "..." --bundle
safe git-clean-preview
safe ssh-relay-readonly --relay "ssh_relay" --host-label "server" --remote-command "pwd"
safe ssh-relay-risky --relay "py ssh_relay.py" --relay-name prod --host-label prod --remote-command "touch /tmp/x" --expected-state-file expected.json --rollback-command-file rollback.txt --receipt-path ~/.local/state/agent-safe/changes.jsonl --approved
safe yc-readonly -- compute instance get --id ID
safe system-readonly -- hostname
```

Never bypass `safe fs-trash` with a direct filesystem removal. Never replace `safe fs-move` with ambiguous recursive shell commands.

For unfamiliar systems, prefer `safe assess`, then `safe exec-readonly` for discovery or `safe exec-risky` with target/expected_state/rollback/approval.

On Windows PowerShell, prefer `--expected-state-file`, `--rollback-command-file`, `--verify-command-file`, and `--receipt-command-file` for nested JSON/commands. Use receipt commands to record completed remote-host changes on the host itself, for example under `C:\ProgramData\agent-safe\changes.jsonl`.

For Linux hosts through compatible `ssh_relay.py`, prefer `ssh-relay-risky --receipt-path ...`; it passes `exec --risky` to the relay. Use `safe receipt-command --format posix` for custom transports or `--receipt-command-file`.
