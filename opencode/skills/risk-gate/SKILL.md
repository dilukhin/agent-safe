---
name: risk-gate
description: Classify risky state-changing actions before execution. Use before any non-read-only command, tool, API call, remote action, cloud action, or unknown subsystem.
compatibility: opencode
---

# Risk Gate

Before any non-read-only action, classify:

- channel: local / remote / ssh_relay / cloud / db / git / api / unknown
- target: exact object/resource/path/id
- environment: local / dev / test / prod / unknown
- operation: create / update / move / delete / restart / deploy / migrate / rotate
- risk: safe / cautious / high / critical / unknown
- knowledge: high / medium / low
- predictability: deterministic / context-dependent / unknown
- reversibility: automatic / manual / irreversible / unknown
- blast radius: file / project / host / cloud / users / billing / security

If risk is high, critical, or unknown, use `safe` and do not execute direct destructive commands.
