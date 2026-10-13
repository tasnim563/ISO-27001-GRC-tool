"""ISO 27001:2022 GRC tool: Statement of Applicability, risk register, gap report.

Run:  python app.py   ->  http://127.0.0.1:5000
"""
import csv
import io
import os
import secrets
import sqlite3
from datetime import datetime

from flask import (Flask, Response, abort, g, redirect, render_template,
                   request, session, url_for)

from controls_data import CONTROLS, STATUSES, THEMES

DB_PATH = os.environ.get("GRC_DB", os.path.join(os.path.dirname(__file__), "grc.db"))
TREATMENTS = ["Mitigate", "Accept", "Transfer", "Avoid"]
RISK_STATUSES = ["Open", "Treated", "Closed"]

app = Flask(__name__)
app.secret_key = os.environ.get("GRC_SECRET") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")


# ---------------------------------------------------------------- database
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS controls (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            theme TEXT NOT NULL,
            applicable INTEGER NOT NULL DEFAULT 1,
            justification TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'Not started',
            owner TEXT NOT NULL DEFAULT '',
            evidence TEXT NOT NULL DEFAULT '',
            updated TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS risks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset TEXT NOT NULL,
            threat TEXT NOT NULL,
            vulnerability TEXT NOT NULL DEFAULT '',
            likelihood INTEGER NOT NULL,
            impact INTEGER NOT NULL,
            treatment TEXT NOT NULL DEFAULT 'Mitigate',
            controls TEXT NOT NULL DEFAULT '',
            owner TEXT NOT NULL DEFAULT '',
            res_likelihood INTEGER,
            res_impact INTEGER,
            status TEXT NOT NULL DEFAULT 'Open',
            created TEXT NOT NULL
        );
        """
    )
    for cid, title in CONTROLS:
        db.execute(
            "INSERT OR IGNORE INTO controls (id, title, theme) VALUES (?, ?, ?)",
            (cid, title, THEMES[cid.split(".")[0]]),
        )
    db.commit()
    db.close()


# ---------------------------------------------------------------- security
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def check_csrf():
    if request.method == "POST":
        sent = request.form.get("csrf", "")
        if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
            abort(400, "Bad CSRF token")


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'"
    return resp


def csv_safe(value):
    """Neutralise spreadsheet formula injection in exported cells."""
    s = "" if value is None else str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


# ---------------------------------------------------------------- helpers
def risk_level(score):
    if score is None:
        return "n/a"
    if score >= 15:
        return "Critical"
    if score >= 10:
        return "High"
    if score >= 5:
        return "Medium"
    return "Low"


app.jinja_env.globals["risk_level"] = risk_level


def clamp(value, lo, hi, default):
    try:
        return max(lo, min(hi, int(value)))
    except (TypeError, ValueError):
        return default


def compliance_stats(db):
    rows = db.execute("SELECT * FROM controls").fetchall()
    applicable = [r for r in rows if r["applicable"]]
    done = [r for r in applicable if r["status"] in ("Implemented", "Verified")]
    by_theme = {}
    for theme in THEMES.values():
        t_app = [r for r in applicable if r["theme"] == theme]
        t_done = [r for r in t_app if r["status"] in ("Implemented", "Verified")]
        by_theme[theme] = {
            "applicable": len(t_app),
            "done": len(t_done),
            "pct": round(100 * len(t_done) / len(t_app)) if t_app else 0,
        }
    by_status = {s: sum(1 for r in applicable if r["status"] == s) for s in STATUSES}
    return {
        "total": len(rows),
        "applicable": len(applicable),
        "excluded": len(rows) - len(applicable),
        "done": len(done),
        "pct": round(100 * len(done) / len(applicable)) if applicable else 0,
        "by_theme": by_theme,
        "by_status": by_status,
    }


# ---------------------------------------------------------------- pages
@app.route("/")
def dashboard():
    db = get_db()
    stats = compliance_stats(db)
    risks = db.execute("SELECT * FROM risks WHERE status != 'Closed'").fetchall()
    levels = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for r in risks:
        levels[risk_level(r["likelihood"] * r["impact"])] += 1
    top = sorted(risks, key=lambda r: r["likelihood"] * r["impact"], reverse=True)[:5]
    return render_template("dashboard.html", stats=stats, levels=levels, top=top)


@app.route("/controls")
def controls():
    db = get_db()
    q = request.args.get("status", "")
    rows = db.execute("SELECT * FROM controls ORDER BY CAST(substr(id,1,instr(id,'.')-1) AS INT), "
                      "CAST(substr(id,instr(id,'.')+1) AS INT)").fetchall()
    if q == "gaps":
        rows = [r for r in rows if r["applicable"] and r["status"] in ("Not started", "In progress")]
    grouped = {}
    for r in rows:
        grouped.setdefault(r["theme"], []).append(r)
    return render_template("controls.html", grouped=grouped, statuses=STATUSES, filt=q)


@app.route("/controls/<cid>", methods=["POST"])
def update_control(cid):
    db = get_db()
    if not db.execute("SELECT 1 FROM controls WHERE id = ?", (cid,)).fetchone():
        abort(404)
    status = request.form.get("status", "Not started")
    if status not in STATUSES:
        abort(400)
    applicable = 1 if request.form.get("applicable") == "on" else 0
    db.execute(
        "UPDATE controls SET applicable=?, justification=?, status=?, owner=?, evidence=?, updated=? WHERE id=?",
        (applicable, request.form.get("justification", "")[:1000], status,
         request.form.get("owner", "")[:100], request.form.get("evidence", "")[:1000],
         datetime.now().strftime("%Y-%m-%d %H:%M"), cid),
    )
    db.commit()
    return redirect(url_for("controls", _anchor=f"c{cid}"))


@app.route("/risks")
def risks():
    db = get_db()
    rows = db.execute("SELECT * FROM risks ORDER BY likelihood * impact DESC, id").fetchall()
    ctrl_ids = [r["id"] for r in db.execute("SELECT id FROM controls").fetchall()]
    return render_template("risks.html", risks=rows, treatments=TREATMENTS,
                           statuses=RISK_STATUSES, ctrl_ids=ctrl_ids)


@app.route("/risks/add", methods=["POST"])
def add_risk():
    db = get_db()
    asset = request.form.get("asset", "").strip()[:200]
    threat = request.form.get("threat", "").strip()[:300]
    if not asset or not threat:
        abort(400, "Asset and threat are required")
    treatment = request.form.get("treatment", "Mitigate")
    if treatment not in TREATMENTS:
        abort(400)
    valid = {r["id"] for r in db.execute("SELECT id FROM controls").fetchall()}
    linked = [c.strip() for c in request.form.get("controls", "").split(",") if c.strip() in valid]
    rl = request.form.get("res_likelihood")
    ri = request.form.get("res_impact")
    db.execute(
        "INSERT INTO risks (asset, threat, vulnerability, likelihood, impact, treatment, controls, owner, "
        "res_likelihood, res_impact, status, created) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (asset, threat, request.form.get("vulnerability", "").strip()[:300],
         clamp(request.form.get("likelihood"), 1, 5, 3), clamp(request.form.get("impact"), 1, 5, 3),
         treatment, ",".join(linked), request.form.get("owner", "").strip()[:100],
         clamp(rl, 1, 5, None) if rl else None, clamp(ri, 1, 5, None) if ri else None,
         "Open", datetime.now().strftime("%Y-%m-%d")),
    )
    db.commit()
    return redirect(url_for("risks"))


@app.route("/risks/<int:rid>/status", methods=["POST"])
def risk_status(rid):
    status = request.form.get("status")
    if status not in RISK_STATUSES:
        abort(400)
    db = get_db()
    db.execute("UPDATE risks SET status=? WHERE id=?", (status, rid))
    db.commit()
    return redirect(url_for("risks"))


@app.route("/risks/<int:rid>/delete", methods=["POST"])
def delete_risk(rid):
    db = get_db()
    db.execute("DELETE FROM risks WHERE id=?", (rid,))
    db.commit()
    return redirect(url_for("risks"))


@app.route("/report")
def report():
    db = get_db()
    stats = compliance_stats(db)
    gaps = db.execute(
        "SELECT * FROM controls WHERE applicable=1 AND status IN ('Not started','In progress') "
        "ORDER BY CAST(substr(id,1,instr(id,'.')-1) AS INT), CAST(substr(id,instr(id,'.')+1) AS INT)"
    ).fetchall()
    unjustified = db.execute(
        "SELECT * FROM controls WHERE applicable=0 AND justification='' ORDER BY id").fetchall()
    risks_ = db.execute("SELECT * FROM risks WHERE status != 'Closed' ORDER BY likelihood*impact DESC").fetchall()
    unmapped = [r for r in risks_ if r["treatment"] == "Mitigate" and not r["controls"]]
    return render_template("report.html", stats=stats, gaps=gaps, unjustified=unjustified,
                           risks=risks_, unmapped=unmapped, now=datetime.now().strftime("%Y-%m-%d %H:%M"))


# ---------------------------------------------------------------- exports
def csv_response(filename, header, rows):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    for row in rows:
        w.writerow([csv_safe(c) for c in row])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={filename}"})


@app.route("/export/soa.csv")
def export_soa():
    rows = get_db().execute("SELECT * FROM controls").fetchall()
    rows = sorted(rows, key=lambda r: tuple(int(p) for p in r["id"].split(".")))
    return csv_response(
        "statement_of_applicability.csv",
        ["Control", "Title", "Theme", "Applicable", "Justification", "Status", "Owner", "Evidence", "Updated"],
        [(r["id"], r["title"], r["theme"], "Yes" if r["applicable"] else "No", r["justification"],
          r["status"], r["owner"], r["evidence"], r["updated"]) for r in rows],
    )


@app.route("/export/risks.csv")
def export_risks():
    rows = get_db().execute("SELECT * FROM risks ORDER BY likelihood*impact DESC").fetchall()
    return csv_response(
        "risk_register.csv",
        ["ID", "Asset", "Threat", "Vulnerability", "Likelihood", "Impact", "Inherent score", "Level",
         "Treatment", "Linked controls", "Owner", "Residual score", "Status", "Created"],
        [(r["id"], r["asset"], r["threat"], r["vulnerability"], r["likelihood"], r["impact"],
          r["likelihood"] * r["impact"], risk_level(r["likelihood"] * r["impact"]), r["treatment"],
          r["controls"], r["owner"],
          (r["res_likelihood"] * r["res_impact"]) if r["res_likelihood"] and r["res_impact"] else "",
          r["status"], r["created"]) for r in rows],
    )


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
