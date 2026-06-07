---
description: Runs the reviewer on the latest change to verify errors and deviations from the plan.
allowed-tools: Read, Grep, Glob, Bash, Agent
---

Delegate to the `reviewer` subagent the verification of the most recent work.

Have the reviewer:
1. Identify what changed (check `git diff` or the last touched component).
2. Run `pytest -q tests/`.
3. Verify against `docs/ARCHITECTURE.md`, `docs/CONVENTIONS.md`, v1 scope, and edge cases.
4. Return a prioritized list: BLOCKERS, IMPROVEMENTS, OK.

When the report comes back:
- If there are BLOCKERS, summarize them and propose the correction plan (which the `builder` would execute).
- If approved, confirm it and suggest the next step.

Do not fix the code directly from here; this command only verifies.
