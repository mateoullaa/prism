"""
render_demo_dashboard.py — render the /dashboard view from a SYNTHETIC audit log.

Used to produce the README screenshot without exposing production metrics.
Generates a seeded, illustrative triage_log.csv (same schema as tools/logger.py)
in a temp directory, runs it through tools.metrics.compute_metrics and the
service's own _render_dashboard, and writes a standalone HTML file.

The numbers are illustrative only. They are not production data.

Usage:
    python scripts/render_demo_dashboard.py [--out PATH] [--alerts N] [--seed S]
"""

import argparse
import csv
import os
import random
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from tools.logger import _COLUMNS  # noqa: E402
from tools.metrics import compute_metrics  # noqa: E402

# (alert_type, nature, rule_id, rule_description, weight, verdict weights TP/FP/NR, known_fp)
# Rule ids and descriptions are the ones in data/sample_alerts/.
_PROFILES = [
    ("windows_event", "informational", "60602", "Windows application error event.", 52, (0, 96, 4), True),
    ("windows_event", "informational", "61061", "Multiple Windows error application events.", 6, (0, 92, 8), True),
    ("windows_event", "internal_movement", "60106", "Windows Logon Success", 9, (2, 70, 28), False),
    ("ssh", "public_attack", "5710", "sshd: Attempt to login using a non-existent user", 11, (55, 10, 35), False),
    ("network", "public_attack", "651", "Host Blocked by firewall-drop Active Response", 9, (70, 5, 25), False),
    ("apache", "public_attack", "30315", "Apache: Invalid URI (bad client request).", 6, (60, 10, 30), False),
    ("vulnerability", "unknown", "23505", "CVE-2023-24329 affects Python 3.6.2 (32-bit)", 4, (20, 15, 65), False),
    ("virustotal", "unknown", "87103", "VirusTotal: Alert - No records in VirusTotal database", 3, (5, 75, 20), False),
]
_MITRE = {"ssh": "T1110", "network": "T1595", "apache": "T1190",
          "vulnerability": "T1190", "virustotal": "T1204", "windows_event": "T1078"}


def _row(rng: random.Random, ts: datetime) -> dict:
    profile = rng.choices(_PROFILES, weights=[p[4] for p in _PROFILES])[0]
    alert_type, nature, rule_id, desc, _, vw, known_fp = profile
    verdict = rng.choices(["TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_REVIEW"], weights=vw)[0]

    status = rng.choices(["ok", "fallback"], weights=[97, 3])[0]
    if status == "fallback":
        verdict, confidence, risk = "NEEDS_REVIEW", "LOW", 5
    elif verdict == "FALSE_POSITIVE":
        confidence, risk = "HIGH", 1
    elif verdict == "TRUE_POSITIVE":
        confidence, risk = rng.choice(["HIGH", "HIGH", "MEDIUM"]), rng.randint(8, 10)
    else:
        confidence, risk = rng.choice(["MEDIUM", "LOW"]), rng.randint(4, 6)

    action = "discard" if verdict == "FALSE_POSITIVE" else "create_case"
    return {
        "timestamp": ts.isoformat(timespec="seconds"),
        "alert_type": alert_type,
        "nature_category": nature,
        "rule_id": rule_id,
        "rule_description": desc,
        "verdict": verdict,
        "confidence": confidence,
        "risk_score": risk,
        "mitre_id": "" if known_fp else _MITRE[alert_type],
        "action": action,
        "send_to_shuffle": action != "discard",
        "status": status,
        "latency_ms": int(rng.gauss(13_000, 1_500)) if status == "ok" else 30_000,
        "model": "qwen2.5:3b",
        "is_known_fp_candidate": known_fp,
        "reason": "synthetic demo row",
    }


def build_log(path: Path, alerts: int, seed: int) -> None:
    rng = random.Random(seed)
    start = datetime(2026, 6, 1, tzinfo=timezone.utc)
    span = timedelta(days=7).total_seconds()
    stamps = sorted(start + timedelta(seconds=rng.uniform(0, span)) for _ in range(alerts))
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=_COLUMNS)
        writer.writeheader()
        for ts in stamps:
            writer.writerow(_row(rng, ts))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", default=str(Path(tempfile.gettempdir()) / "prism_demo_dashboard.html"))
    ap.add_argument("--alerts", type=int, default=1200)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()

    log = Path(tempfile.gettempdir()) / "prism_demo_triage_log.csv"
    build_log(log, args.alerts, args.seed)

    # Import main only after LOG_PATH points away from the real audit log.
    os.environ["LOG_PATH"] = str(log)
    from main import _render_dashboard  # noqa: E402

    html = _render_dashboard(compute_metrics(str(log)))
    Path(args.out).write_text(html, encoding="utf-8")
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
