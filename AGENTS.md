# Agent instructions for this project

## Universal Action Safety

Any command/tool/API call that changes external state is risky, regardless of channel: local shell, remote shell, ssh_relay, cloud CLI, VM, git, database, registry, service, network, package manager, secrets, or unknown subsystem.

Before any non-read-only action:

1. Classify risk, knowledge, predictability, reversibility, and blast radius.
2. Identify exact target and environment.
3. Define expected_state before execution.
4. Prepare checkpoint/rollback before execution.
5. Use only explicit predictable commands.
6. Execute one atomic action.
7. Verify actual state.

If the command/tool/subsystem is unfamiliar, treat it as high-risk until proven otherwise. Use read-only discovery first.

Use the cross-platform `safe` CLI for risky actions. Do not call direct destructive commands such as `rm`, `del`, `Remove-Item`, `git clean -f`, `git reset --hard`, `yc ... delete`, `curl | sh`, or similar shortcuts.

If the actual result differs from expected_state, stop the original task immediately and enter Recovery Mode. Do not clean up, delete, overwrite, reset, force, or improvise. Use read-only diagnostics only, then plan recovery and ask for approval.

Load detailed skills only when needed: `risk-gate`, `unknown-system-safety`, `recovery-mode`, `safe-cli`.
