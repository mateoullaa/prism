# CONVENTIONS.md — Code and Workflow Conventions

Load when writing or reviewing code.

## Python
- Python 3.10+. Type hints on public functions.
- Docstrings and comments in English.
- Short functions with a single responsibility. One tool = one clear purpose.
- No unnecessary dependencies. Keep `requirements.txt` minimal.

## Tool structure
- Lives in `tools/<name>.py`.
- Exposes a clear, testable main function (not all logic in `__main__`).
- Handles its own errors: if an API or parse fails, it does not break the pipeline;
  returns a partial result or a structured error and logs it.
- Importable and testable in isolation.

## Secrets and data
- API keys and credentials ONLY in `.env`, read with `python-dotenv`. Never hardcode.
- Never commit real alerts with company data. Anonymized fixtures only.
- `.env`, `metrics/`, and real data are in `.gitignore`.

## Tests
- Each tool has at least one test in `tests/test_<name>.py`.
- The parser is tested against all 6 fixtures in `data/sample_alerts/`.
- Deterministic tests: no network or server dependencies. For enricher/reasoner, mock
  external calls.
- Run with `pytest -q`.

## LLM output
- Always valid JSON per the contract in `ARCHITECTURE.md`.
- The prompt enforces strict JSON format, no surrounding text.
- Parse with error handling: if the LLM returns non-JSON, there is a defined fallback.

## Git / GitHub
- Small, focused commits. Clear imperative message (e.g. "Add parser IOC extraction").
- Verify no secrets or real data before committing.
- The repo is a public portfolio: clear README, readable code, clean history.

## Shell (Git Bash on Windows)
- Bash-compatible commands. venv: `source .venv/Scripts/activate`.
- Relative paths within the repo when possible.

## Workflows (WAT)
- When a tool is finished, the `scribe` writes/updates `workflows/<name>.md` with: objective,
  inputs, output, how to run it, edge cases, and learnings. Do not create workflows in advance.
