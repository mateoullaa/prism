# router.md — Routing Decision (Discard or Create Case)

**Objective:** Audit-driven decision layer. After the reasoner produces a verdict, the router decides whether Prism will create a case (send to Shuffle) or discard the alert. Conservative: on any doubt, escalate to avoid missing a real threat.

**Input:** Parsed dict after the reasoner with two keys:
- `parsed["verdict"]`: dict with verdict enum (TRUE_POSITIVE / FALSE_POSITIVE / NEEDS_REVIEW), confidence, justification, MITRE, next_action, risk_score.
- `parsed["reasoner_meta"]`: dict with status ("ok" | "fallback"), fallback_reason, model, latency_ms, and optional downgrade_note.

**Output contract:**
Adds `parsed["routing"]` in-place (mutates the dict):
```json
"routing": {
  "action": "create_case" | "discard",
  "send_to_shuffle": bool,
  "reason": "string (audit trail for logger.py)"
}
```

**Decision rules:**
1. **FALSE_POSITIVE** → action=discard, send_to_shuffle=False. Reason cites verdict + confidence.
2. **TRUE_POSITIVE | NEEDS_REVIEW** → action=create_case, send_to_shuffle=True (conservative escalation).
3. **Missing / non-dict / unknown verdict** → defensive escalation: action=create_case, send_to_shuffle=True (never discard on uncertainty).
4. **When reasoner_meta.status=="fallback"** → reason appends a note that automated analysis fell back (fallback_reason included).
5. **When downgrade_note is present** → reason includes it (e.g., FP guardrail downgrade context from reasoner).

**Public function:**
```python
route(parsed: dict) -> dict
```
- Never raises, even on empty input (defensive).
- Returns the same dict object (in-place mutation).
- Always sets parsed["routing"] with all three required fields.

---

## Design highlights

**Defensive escalation:**
Missing or malformed verdict/reasoner_meta fields trigger an immediate escalation to create_case (and log a warning). A NULL or "UNKNOWN" verdict never discards an alert — it goes to the analyst.

**Audit trail:**
The `reason` field is mandatory per alert and is the sole source of audit context that logger.py persists (CSV + audit log). It must include:
- The verdict value and confidence.
- Any fallback or downgrade context that affects the decision.

**Scope (v1):**
Router ONLY decides and annotates. It does NOT call Shuffle, create TheHive cases, or write logs/CSV (logger.py does that).

---

## Running tests

```bash
"C:/Users/usuario/AppData/Local/Python/pythoncore-3.14-64/python.exe" -m pytest tests/test_router.py -q
```

**Coverage:** 29 tests (fully deterministic, no network or server).
- TRUE_POSITIVE / FALSE_POSITIVE / NEEDS_REVIEW paths (6 tests).
- Fallback status handling (5 tests).
- Downgrade note handling (4 tests).
- Defensive edge cases (empty dict, missing/malformed verdict, wrong types) (9 tests).
- In-place mutation contract (4 tests).
- End-to-end with real parsed fixtures (3 tests).

**Total test suite:** 148 tests passing (parser 25 + enricher 21 + reasoner 46 + router 29 + pipeline 2 + old 25).

---

## Edge cases handled

1. **Empty input** `route({})` → defensive escalation (create_case). No crash.
2. **Missing verdict key** → defensive escalation.
3. **verdict not a dict (e.g. a string)** → defensive escalation.
4. **Unknown verdict value** (e.g. "MAYBE_POSITIVE") → defensive escalation.
5. **Missing reasoner_meta** → route still works (defaults to {} for meta).
6. **reasoner_meta not a dict** → route normalizes to {}.
7. **downgrade_note absent** → not included in reason (optional field).
8. **Fallback with FALSE_POSITIVE** (logic boundary) → never happens in practice (reasoner FP guardrail prevents FALSE_POSITIVE from reaching router with fallback; reasoner downgrades uncertain FP to NEEDS_REVIEW upstream).

---

## Implementation notes

- Confidence default is "UNKNOWN" (effectively dead; reasoner always sets it). Router logs it for audit.
- send_to_shuffle is always a strict boolean (not truthy/falsy).
- reason string is human-readable, non-empty, and must be unique per alert.
- No external I/O. All logic is synchronous and deterministic.
