# Universal Action Safety

This document is the full protocol. Keep only the short summary in `AGENTS.md`; load this document or the OpenCode skills only when a task may change external state.

## Universal rule

Any action that changes external state is risky, even if the subsystem is unfamiliar.

External state includes files, git, remote hosts, SSH sessions, cloud resources, VMs, services, firewall rules, databases, package managers, credentials, networks, CI/CD, and APIs.

## Required protocol

```text
classify -> inspect -> expected_state -> checkpoint -> execute one atomic action -> verify -> continue/recovery
```

Before non-read-only actions, classify:

- channel: local, remote, ssh_relay, cloud, db, git, api, unknown;
- target: exact object/resource/path/id;
- environment: local, dev, test, prod, unknown;
- operation: create, update, move, delete, restart, deploy, migrate, rotate;
- risk: safe, cautious, high, critical, unknown;
- knowledge: high, medium, low;
- predictability: deterministic, context-dependent, unknown;
- reversibility: automatic, manual, irreversible, unknown;
- blast radius: file, project, host, cloud folder, users, billing, security.

## Unknown systems

Unknown subsystem is not safe. If the command/tool/API is unfamiliar, only read-only discovery is allowed until the agent understands whether it changes state.

Unknown + state-changing = high risk.
Unknown consequences + high risk = stop.
Unexpected result + high risk = recovery mode.

## Predictable commands only

High-risk actions must use explicit targets. Avoid aliases, wildcards, pipelines, chains, force flags, hidden defaults, and best-effort cleanup.

## Unexpected result

Unexpected result after a high-risk action is an incident, not an obstacle.

The original task stops. Only read-only diagnostics and recovery planning are allowed until the situation is understood and a recovery plan is approved.


## Adapter rule

Adapters are convenience wrappers, not exceptions to the protocol. A new subsystem does not become safe because it is absent from the known adapter list. If no adapter exists, use the generic execution adapter and classify the action by effect:

```text
read-only inspection -> safe exec-readonly
state-changing or unclear -> safe exec-risky
unclear consequences or rollback -> stop
unexpected result -> recovery mode
```
