# Adapters

`agent-safe` uses a single safety protocol for every external state change:

```text
classify -> inspect -> expected_state -> checkpoint -> execute one atomic action -> verify -> continue/recovery
```

Adapters are small wrappers around different execution channels. If a channel is unknown, use the generic `exec-readonly` / `exec-risky` path and treat the action as high-risk until proven otherwise.

## Generic execution adapter

Read-only command:

```bash
safe exec-readonly --channel local --domain system -- python --version
```

Risky command:

```bash
safe exec-risky \
  --channel local \
  --domain unknown \
  --target "resource:exact-id-or-path" \
  --reason "explain why this change is needed" \
  --expected-state '{"state":"expected"}' \
  --rollback-command "exact rollback command" \
  --verify-command "exact verification command" \
  --approved \
  -- command arg1 arg2
```

`exec-risky` refuses to run unless the target, reason, expected state, rollback command, and approval are present. If the command or verification returns a non-zero exit code, the transaction is marked `unexpected` and `.agent-safety/INCIDENT_BLOCKED` is created.

## Git adapter

Create evidence before high-risk git work:

```bash
safe git-checkpoint --reason "before rebase" --bundle
```

Preview cleanup without deletion:

```bash
safe git-clean-preview
safe git-clean-preview --include-ignored
```

Direct `git clean -f`, `git reset --hard`, forced push, branch delete, and stash drop should be blocked by OpenCode permissions or handled through a future specialized adapter with explicit rollback planning.

## ssh_relay adapter

The adapter expects a relay interface compatible with:

```text
<relay command> exec "<remote command>"
```

Read-only remote command:

```bash
safe ssh-relay-readonly \
  --relay "ssh_relay" \
  --host-label "4BSDownloader2" \
  --remote-command "pwd" \
  --reason "confirm remote cwd"
```

Risky remote command:

```bash
safe ssh-relay-risky \
  --relay "ssh_relay" \
  --host-label "server-1" \
  --remote-command "systemctl restart app" \
  --reason "restart after config change" \
  --expected-state '{"service":"active"}' \
  --rollback-command "ssh_relay exec 'systemctl restart app-old'" \
  --verify-remote-command "systemctl is-active app" \
  --approved
```

If the remote command is unfamiliar or state-changing, use the risky path. The agent must know host, cwd/environment, expected state, and rollback before running it.

## Yandex Cloud adapter

Read-only inspection:

```bash
safe yc-readonly -- config list
safe yc-readonly -- compute instance get --id <instance-id>
safe yc-readonly -- compute disk list
```

Risky cloud operation:

```bash
safe yc-change \
  --target "compute.instance:<id>" \
  --reason "stop test VM" \
  --expected-state '{"status":"STOPPED"}' \
  --rollback-command "yc compute instance start --id <id>" \
  --verify-command "yc compute instance get --id <id>" \
  --approved \
  -- compute instance stop --id <id>
```

Deleting resources, changing IAM, changing network/security groups, detaching disks, changing public IPs, and stopping production VMs should be treated as critical.

## System / VM adapter

Read-only system inspection:

```bash
safe system-readonly -- hostname
safe system-readonly -- systemctl status app
```

Risky system action:

```bash
safe system-change \
  --target "service:app" \
  --reason "restart service after approved change" \
  --expected-state '{"service":"active"}' \
  --rollback-command "systemctl restart app-old" \
  --verify-command "systemctl is-active app" \
  --approved \
  -- systemctl restart app
```

If the command result is unexpected, do not retry blindly. Use `safe diagnose` and `safe recovery-plan`.

## Unknown systems

For tools without a dedicated adapter:

1. Start with `safe assess --command "..."`.
2. Run help/status/list/show/describe/dry-run only.
3. Use `safe exec-readonly` only if the action is clearly read-only.
4. Use `safe exec-risky` for any state-changing or unclear command.
5. If consequences or rollback are unclear, do not execute.
