---
name: recovery-mode
description: Procedure after surprising results from high-risk actions. Use when verify differs from expected_state or state is unclear after a risky action.
compatibility: opencode
---

# Recovery Mode

Unexpected result after a high-risk action is an incident, not an obstacle.

Rules:

1. Stop the original task.
2. Do not improvise further state-changing fixes.
3. Run read-only diagnostics only.
4. Preserve evidence: command, cwd, output, target, expected state, actual state.
5. Analyze why actual state differs from expected state.
6. Prepare recovery options.
7. Ask for approval before changing anything.

Use `safe diagnose` and `safe recovery-plan`.
