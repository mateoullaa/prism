# Security Policy

Prism processes security alerts, so reports about it are taken seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's
[private vulnerability reporting](https://github.com/mateoullaa/prism/security/advisories/new)
instead, with steps to reproduce and the affected version or commit.

## Scope notes

- Prism is designed to run inside a private network. `POST /analyze` has no authentication of its
  own; expose it only to the SOAR host (Shuffle) or behind a reverse proxy that enforces auth.
- API keys live only in `.env` (gitignored). Never commit real alerts: fixtures in
  `data/sample_alerts/` must be anonymized.
