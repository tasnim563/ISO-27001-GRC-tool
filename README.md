# ISO 27001 GRC Tool

A small web app to manage an ISMS against ISO/IEC 27001:2022.

## Features
- **Statement of Applicability**: all 93 Annex A controls, with applicability, justification, status, owner and evidence
- **Risk register**: asset/threat/vulnerability, 5x5 scoring, treatment, linked controls, residual risk
- **Dashboard**: overall and per-theme progress, risk levels, top risks
- **Gap report**: controls left to implement, exclusions without justification, risks with no mapped control (print to PDF)
- **CSV exports** of the SoA and the risk register

## Run
```bash
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000. Data is stored in `grc.db` (SQLite) next to `app.py`.

Environment variables: `GRC_DB` (database path), `GRC_SECRET` (session secret; random per start if unset).

## Security notes
CSRF tokens on every POST, parameterised SQL, auto-escaped templates, a restrictive Content-Security-Policy, and formula-injection protection in CSV exports. It has no login, so keep it bound to localhost (the default) or put it behind an authenticating reverse proxy.

## Ideas to extend
- Authentication and roles (admin, control owner, auditor)
- Evidence file uploads with hashes
- Audit log of every change
- ISO 27002 guidance text per control, and mapping to other frameworks (NIST CSF, SOC 2)
- Review dates and reminders
