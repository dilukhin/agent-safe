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
```

Never replace `safe fs-trash` with direct delete. Never replace `safe fs-move` with ambiguous recursive shell commands.
