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
safe git-checkpoint --reason "..." --bundle
safe git-clean-preview
safe ssh-relay-readonly --relay "ssh_relay" --host-label "server" --remote-command "pwd"
safe yc-readonly -- compute instance get --id ID
safe system-readonly -- hostname
```

Never replace `safe fs-trash` with direct delete. Never replace `safe fs-move` with ambiguous recursive shell commands.


For unfamiliar systems, prefer `safe assess`, then `safe exec-readonly` for discovery or `safe exec-risky` with target/expected_state/rollback/approval.
