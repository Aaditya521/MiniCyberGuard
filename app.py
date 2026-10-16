import ipaddress
import json
import re
import secrets
import socket
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, abort, flash, redirect, render_template, request, session, url_for

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "cyberguard.db"
BASELINE_PATH = BASE_DIR / "fim_baseline.json"

app = Flask(__name__)
app.secret_key = __import__("os").environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                details TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                status TEXT NOT NULL,
                notes TEXT NOT NULL
            )
        """)


def add_event(category, severity, title, details):
    with db() as conn:
        conn.execute(
            "INSERT INTO events(created_at, category, severity, title, details) VALUES (?, ?, ?, ?, ?)",
            (utc_now(), category, severity, title[:160], details[:2000]),
        )


def get_csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": get_csrf_token()}


@app.before_request
def csrf_protection():
    if request.method == "POST":
        supplied = request.form.get("csrf_token", "")
        expected = session.get("_csrf_token", "")
        if not supplied or not expected or not secrets.compare_digest(supplied, expected):
            app.logger.warning(
                "CSRF validation failed on %s (form token present=%s, session token present=%s, cookie present=%s)",
                request.path,
                bool(supplied),
                bool(expected),
                bool(request.cookies.get(app.config.get("SESSION_COOKIE_NAME", "session"))),
            )
            abort(400, description="Your form session expired or was invalid. Refresh the page and try again.")


@app.route("/")
def index():
    with db() as conn:
        event_count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        incident_count = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        recent_events = conn.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT 5"
        ).fetchall()
    return render_template(
        "index.html",
        event_count=event_count,
        incident_count=incident_count,
        recent_events=recent_events,
    )


@app.route("/logs", methods=["GET", "POST"])
def logs():
    results = []
    raw_log = ""
    if request.method == "POST":
        raw_log = request.form.get("log_text", "").strip()
        if not raw_log:
            flash("Paste at least one log line to analyze.", "warning")
        elif len(raw_log) > 20000:
            flash("Log input is too long (maximum 20,000 characters).", "danger")
        else:
            pattern = re.compile(
                r"(?P<time>\S+)\s+(?P<event>LOGIN_SUCCESS|LOGIN_FAILED)\s+user=(?P<user>\S+)\s+ip=(?P<ip>\S+)",
                re.IGNORECASE,
            )
            for line_number, line in enumerate(raw_log.splitlines(), start=1):
                match = pattern.fullmatch(line.strip())
                if not match:
                    results.append({
                        "line": line_number,
                        "time": "-",
                        "event": "UNRECOGNIZED",
                        "user": "-",
                        "ip": "-",
                        "severity": "LOW",
                        "message": "Line format not recognized",
                    })
                    continue
                data = match.groupdict()
                event_name = data["event"].upper()
                try:
                    ipaddress.ip_address(data["ip"])
                    ip_ok = True
                except ValueError:
                    ip_ok = False
                if not ip_ok:
                    severity, message = "MEDIUM", "Invalid IP address in log"
                elif event_name == "LOGIN_FAILED":
                    severity, message = "HIGH", "Failed login attempt"
                else:
                    severity, message = "INFO", "Successful login"
                results.append({
                    "line": line_number,
                    "time": data["time"],
                    "event": event_name,
                    "user": data["user"],
                    "ip": data["ip"],
                    "severity": severity,
                    "message": message,
                })
                add_event(
                    "Log Analyzer",
                    severity,
                    f"{event_name}: {data['user']}",
                    f"Line {line_number}; time={data['time']}; ip={data['ip']}",
                )
    return render_template("logs.html", results=results, raw_log=raw_log)


@app.route("/incidents", methods=["GET", "POST"])
def incidents():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        severity = request.form.get("severity", "MEDIUM").upper()
        source_ip = request.form.get("source_ip", "").strip()
        notes = request.form.get("notes", "").strip()

        if not title:
            flash("Incident title is required.", "warning")
        elif len(title) > 160 or len(notes) > 2000:
            flash("Title or notes exceed the allowed length.", "danger")
        elif severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            flash("Select a valid severity.", "danger")
        else:
            if source_ip:
                try:
                    ipaddress.ip_address(source_ip)
                except ValueError:
                    flash("Enter a valid source IP address or leave it blank.", "warning")
                    return redirect(url_for("incidents"))
            else:
                source_ip = "Unknown"
            with db() as conn:
                conn.execute(
                    "INSERT INTO incidents(created_at, title, severity, source_ip, status, notes) VALUES (?, ?, ?, ?, ?, ?)",
                    (utc_now(), title, severity, source_ip, "Open", notes),
                )
            add_event("Incident", severity, title, f"Source IP: {source_ip}; status=Open")
            flash("Incident added.", "success")
            return redirect(url_for("incidents"))

    with db() as conn:
        items = conn.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 100").fetchall()
    return render_template("incidents.html", incidents=items)


@app.route("/scanner", methods=["GET", "POST"])
def scanner():
    found = []
    target = ""
    if request.method == "POST":
        target = request.form.get("target", "").strip()
        try:
            ip = ipaddress.ip_address(target)
            if not (ip.is_private or ip.is_loopback or ip.is_link_local):
                raise ValueError("Only private, loopback, or link-local IP addresses are allowed.")
            target = str(ip)
            ports_text = request.form.get("ports", "22,80,443")
            ports = []
            for part in ports_text.split(","):
                part = part.strip()
                if not part:
                    continue
                if not part.isdigit() or not 1 <= int(part) <= 65535:
                    raise ValueError("Ports must be comma-separated numbers from 1 to 65535.")
                ports.append(int(part))
            ports = sorted(set(ports))[:30]
            if not ports:
                raise ValueError("Enter at least one port.")
            for port in ports:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(0.35)
                        if sock.connect_ex((target, port)) == 0:
                            found.append({"port": port, "service": {
                                22: "SSH", 80: "HTTP", 443: "HTTPS", 445: "SMB",
                                3306: "MySQL", 3389: "RDP", 8080: "HTTP-alt",
                            }.get(port, "Unknown")})
                except OSError:
                    pass
            add_event("Local Scanner", "INFO", f"Scan requested: {target}", f"Ports checked: {ports}")
            flash(f"Scan complete. {len(found)} open port(s) found.", "success")
        except ValueError as exc:
            flash(str(exc), "danger")
    return render_template("scanner.html", target=target, found=found)


@app.route("/url-checker", methods=["GET", "POST"])
def url_checker():
    findings = []
    value = ""
    if request.method == "POST":
        value = request.form.get("url", "").strip()
        parsed = urlparse(value if "://" in value else "https://" + value)
        host = (parsed.hostname or "").lower()
        if not host or "." not in host:
            flash("Enter a valid domain or URL.", "danger")
        else:
            checks = []
            if parsed.scheme.lower() != "https":
                checks.append(("MEDIUM", "URL does not use HTTPS"))
            if host.startswith("xn--") or ".xn--" in host:
                checks.append(("MEDIUM", "Internationalized domain label detected"))
            if host in {"bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly"}:
                checks.append(("MEDIUM", "Known URL-shortener domain"))
            suspicious_words = {"login", "verify", "update", "secure", "account", "wallet", "password", "bank"}
            hits = sorted(suspicious_words.intersection(set(re.split(r"[^a-z0-9]+", (host + parsed.path).lower()))))
            if hits:
                checks.append(("LOW", "Sensitive words in URL: " + ", ".join(hits)))
            if "@" in parsed.netloc:
                checks.append(("HIGH", "URL contains user-info before the host"))
            if not checks:
                checks.append(("INFO", "No simple heuristic warning found; this does not prove the URL is safe"))
            findings = [{"severity": s, "message": m} for s, m in checks]
            add_event("URL Checker", "INFO" if all(x["severity"] == "INFO" for x in findings) else "MEDIUM",
                      f"URL checked: {host}", "; ".join(x["message"] for x in findings))
    return render_template("url_checker.html", value=value, findings=findings)


@app.route("/events")
def events():
    with db() as conn:
        items = conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT 200").fetchall()
    return render_template("events.html", events=items)


@app.route("/fim", methods=["GET", "POST"])
def fim():
    message = None
    if request.method == "POST":
        action = request.form.get("action", "")
        raw_paths = request.form.get("paths", "").strip()
        paths = [Path(p.strip()).expanduser() for p in raw_paths.splitlines() if p.strip()]
        if not paths:
            flash("Enter at least one file or directory path.", "warning")
        elif len(paths) > 100:
            flash("Maximum 100 paths per request.", "danger")
        else:
            if action == "baseline":
                baseline = {}
                for path in paths:
                    try:
                        resolved = path.resolve(strict=True)
                        if not resolved.is_file():
                            continue
                        digest = __import__("hashlib").sha256(resolved.read_bytes()).hexdigest()
                        baseline[str(resolved)] = digest
                    except (OSError, RuntimeError):
                        continue
                BASELINE_PATH.write_text(json.dumps(baseline, indent=2), encoding="utf-8")
                message = f"Baseline saved for {len(baseline)} file(s)."
                add_event("File Integrity", "INFO", "Baseline created", message)
            elif action == "check":
                try:
                    baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    baseline = None
                if baseline is None:
                    flash("No valid baseline found. Create a baseline first.", "warning")
                else:
                    changed, unchanged, missing = [], [], []
                    for path in paths:
                        key = str(path.resolve())
                        try:
                            digest = __import__("hashlib").sha256(Path(key).read_bytes()).hexdigest()
                            (unchanged if baseline.get(key) == digest else changed).append(key)
                        except OSError:
                            missing.append(key)
                    message = f"Check complete — unchanged: {len(unchanged)}, changed/new: {len(changed)}, missing/unreadable: {len(missing)}."
                    add_event("File Integrity", "INFO", "Baseline checked", message)
            else:
                flash("Unknown file integrity action.", "danger")
    return render_template("fim.html", message=message)


@app.errorhandler(400)
def bad_request(error):
    return render_template("error.html", code=400, message=getattr(error, "description", "Bad request.")), 400


@app.errorhandler(404)
def not_found(error):
    return render_template("error.html", code=404, message="Page not found."), 404


init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)

