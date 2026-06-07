#!/usr/bin/env bash
# init.sh — Project health check. Runs at the start of each session
# (via SessionStart hook) and before any change. If something critical fails,
# prints "INIT FAILED" and exits with a non-zero code. The agent MUST NOT continue.

set -uo pipefail
FAIL=0
echo "=== INIT: Prism ==="

# 1. Required core files
REQUIRED=("CLAUDE.md" "memory.md" "PROGRESS.md" \
          "docs/ARCHITECTURE.md" "docs/CONVENTIONS.md" "docs/CONTEXT.md")
for f in "${REQUIRED[@]}"; do
  if [[ -f "$f" ]]; then echo "  ok   $f"; else echo "  MISS $f"; FAIL=1; fi
done

# 2. Directory structure
for d in tools tests workflows data/sample_alerts .claude/agents .claude/commands; do
  if [[ -d "$d" ]]; then echo "  ok   $d/"; else echo "  MISS $d/"; FAIL=1; fi
done

# 3. Test fixtures (all 6 types must exist)
FIX_COUNT=$(find data/sample_alerts -name '*.json' 2>/dev/null | wc -l | tr -d ' ')
if [[ "$FIX_COUNT" -ge 6 ]]; then echo "  ok   fixtures ($FIX_COUNT)"; else
  echo "  MISS fixtures (found $FIX_COUNT, expected >=6)"; FAIL=1; fi

# 4. Python available
if command -v python >/dev/null 2>&1 || command -v python3 >/dev/null 2>&1; then
  echo "  ok   python"; else echo "  MISS python"; FAIL=1; fi

# 5. .env (warning only — may not exist on a fresh machine)
if [[ -f ".env" ]]; then echo "  ok   .env"; else
  echo "  warn .env not found (copy .env.example to .env before running the service)"; fi

# 6. Existing tests (only if tools have been built)
if [[ -d "tests" ]] && find tests -name 'test_*.py' 2>/dev/null | grep -q .; then
  echo "  --- running tests ---"
  if command -v pytest >/dev/null 2>&1; then
    if pytest -q tests/ 2>&1 | tail -5; then echo "  ok   tests"; else
      echo "  FAIL tests failed"; FAIL=1; fi
  else echo "  warn pytest not installed (pip install -r requirements.txt)"; fi
else
  echo "  info no tests yet (early build stage)"
fi

echo "=== INIT $( [[ $FAIL -eq 0 ]] && echo OK || echo FAILED ) ==="
exit $FAIL
