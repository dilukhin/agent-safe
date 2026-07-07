---
name: risk-gate
description: Classify risky state-changing actions before execution.
compatibility: opencode
---

# Risk Gate

Before any non-read-only action, classify:

- channel: local / remote / ssh_relay / cloud / db / git / api / unknown
- target: exact object/resource/path/id
- environment: local / dev / test / prod / unknown
- operation type and expected effect
- risk: safe / cautious / high / critical / unknown
- knowledge: high / medium / low
- predictability: deterministic / context-dependent / unknown
- reversibility: automatic / manual / irreversible / unknown
- blast radius: file / project / host / cloud / users / billing / security

If risk is high, critical, or unknown, use `safe` and request approval before changing state.
