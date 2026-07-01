---
name: unknown-system-safety
description: Conservative fallback for unfamiliar commands, tools, APIs, and subsystems.
compatibility: opencode
---

# Unknown System Safety

Unknown systems are high-risk until proven otherwise.

Allowed first steps:

- read documentation/help
- run `--help`, `version`, `status`, `list`, `get`, `show`, `describe`, `plan`, `dry-run`
- identify target, environment, credentials, blast radius, and rollback

Do not run state-changing commands when semantics are unclear.

Unknown + state-changing = high risk.
Unknown consequences + high risk = stop.
