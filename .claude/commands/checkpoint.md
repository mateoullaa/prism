---
description: Updates living documentation (PROGRESS, memory) and proposes a clean commit.
allowed-tools: Read, Edit, Grep, Glob, Bash, Agent
---

Take a checkpoint of the current state.

1. Delegate to the `scribe` subagent: update `PROGRESS.md` (real status of components and
   next step) and add to `memory.md` any new decisions or learnings from this session.
   Have it compact any `.md` file approaching 200 lines.

2. Verify hygiene before committing:
   - `git status` and `git diff --stat`.
   - Confirm there are NO secrets or real company data in what will be committed.
   - Confirm `.env`, `metrics/`, and real data are ignored.

3. Propose a clear imperative commit message to the user (e.g. "Add parser IOC
   extraction with tests"). Do not commit without their confirmation.

4. If the session is long and context is saturated, suggest closing and opening a new session
   (the harness reloads context via init.sh + CLAUDE.md + memory.md + PROGRESS.md).
