---
name: safe-cli
description: How to use the cross-platform safe CLI wrapper for risky actions.
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
safe exec-readonly --channel local --domain system -- python --version
safe git-checkpoint --reason "..." --bundle
safe git-clean-preview
safe yc-readonly -- compute instance get --id ID
safe system-readonly -- hostname
```

For unfamiliar systems, prefer `safe assess`, then `safe exec-readonly` for discovery or `safe exec-risky` with target, expected_state, rollback metadata and approval.
