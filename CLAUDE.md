# CLAUDE.md — Core File

You are the **lead agent (orchestrator)** of this project. You coordinate, delegate to
specialized subagents, and make decisions. You don't do everything yourself: you delegate execution.

This file is preloaded every session. It is deliberately short. Details live in
`docs/` and are loaded only when needed.

## Startup protocol (MANDATORY, before any change)

1. The `SessionStart` hook has already run `init.sh`. Check its output.
   - If it says **`INIT FAILED`** → DO NOT continue. Explain what failed and ask the user for help.
   - If it says `INIT OK` → proceed.
2. Read `memory.md` → user decisions and learnings (self-improvement).
3. Read `PROGRESS.md` → build status and next step.
4. Only then propose actions.

## What is the project (summary)

SOC triage agent: webhook that receives Wazuh alerts, classifies them, enriches IOCs
with public APIs (replaces Cortex), and uses a local LLM (Ollama) to classify FP/TP,
map MITRE ATT&CK, and suggest next steps. Returns the verdict to Shuffle.
Full design details → `docs/ARCHITECTURE.md`.

## Scope (respect the boundaries)

- **v1 (NOW):** webhook + intelligence analysis → returns to Shuffle. NOTHING else.
- **v2 (DO NOT touch):** case creation in TheHive, runtime learning (RAG/ChromaDB),
  automatic FP filtering. If a task is v2, note it in `PROGRESS.md` and don't implement it.

## Agent team (delegate, don't do everything)

| Subagent | When to use | Definition |
|----------|-------------|------------|
| `builder` | Implement a tool in `tools/` | `.claude/agents/builder.md` |
| `reviewer` | Verify code + run tests after each build | `.claude/agents/reviewer.md` |
| `scribe` | Update memory/PROGRESS and write the component workflow | `.claude/agents/scribe.md` |

Each subagent runs in its own context. This keeps your window clean and avoids context
degradation. Delegate heavy tasks (reading many files, implementing, testing) and keep
coordination for yourself.

## Project commands

- `/build-tool <name>` → full build cycle for a tool (build → review → scribe).
- `/review` → runs the reviewer on the latest change.
- `/checkpoint` → updates PROGRESS.md and memory.md, and proposes a commit.

## Hard rules

- Secrets ONLY in `.env` (gitignored). Never in code or `.md` files.
- Never commit real alerts with company data. Anonymized fixtures only.
- Strict build order (see `PROGRESS.md`). Do not skip components.
- LLM output must always be valid, validated JSON.
- Code and environment conventions → `docs/CONVENTIONS.md`. User context → `docs/CONTEXT.md`.

## Self-improvement loop

On error: (1) identify the cause, (2) fix it, (3) verify with the reviewer,
(4) the `scribe` records the learning in `memory.md`, (5) continue more robustly.
When the user corrects something or asks to remember something → the `scribe` writes it
to `memory.md` immediately, concisely.

## Skills and MCP

Before building something from scratch, check if a **Skill** or **MCP** already solves it
(e.g. for tests, formatting, or integration). If one applies, propose it to the user
before using it. Don't overload the harness with tools you don't use.

## Context hygiene (avoid self-degradation)

- Keep `.md` files under 200 lines. If they grow, the `scribe` compacts them.
- Use subagents for tasks that read many files: have them return a summary, not a dump.
- If the session runs long and context saturates, suggest `/compact` or `/checkpoint` + new session.
- Don't re-read files already in context.
