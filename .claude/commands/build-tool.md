---
description: Full build cycle for a tool (build → review → scribe) with verification.
argument-hint: <tool-name>
allowed-tools: Read, Write, Edit, Grep, Glob, Bash, Agent
---

Build the tool `$ARGUMENTS` following the complete multi-agent cycle. As orchestrator,
do NOT write the code yourself: coordinate the subagents.

Steps:

1. **Context.** Confirm that `$ARGUMENTS` is the next component according to `PROGRESS.md` and
   respects the build order. If it is not, notify the user before continuing.

2. **Build.** Delegate to the `builder` subagent: implement `tools/$ARGUMENTS.py` and its
   test `tests/test_$ARGUMENTS.py` per `docs/ARCHITECTURE.md` and `docs/CONVENTIONS.md`.
   Pass it the relevant paths and contract in the prompt (its context starts clean).

3. **Review.** Delegate to the `reviewer` subagent: run the tests and verify against the
   architecture, conventions, v1 scope, and edge cases.
   - If there are **BLOCKERS**: pass them to the `builder` to fix and re-review. Repeat
     until the reviewer says "APPROVED".
   - If the reviewer approves: continue.

4. **Document.** Delegate to the `scribe` subagent: write `workflows/$ARGUMENTS.md`,
   mark the component as `[x]` in `PROGRESS.md`, update the "next immediate step",
   and note any learnings in `memory.md`.

5. **Wrap-up.** Summarize for the user in a few lines: what was built, what the reviewer
   verified, and what the next step is. Suggest `/checkpoint` if committing makes sense.

Keep your context light: let the subagents do the heavy work and return summaries,
not file dumps.
