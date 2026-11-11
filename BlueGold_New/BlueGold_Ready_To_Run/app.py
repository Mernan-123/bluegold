"""
Login system with brute-force protection, a decoy (honeypot) console,
and an admin security dashboard with a live map of login attempts.

Branding uses a made-up company, "BlueGold Group", so the site looks like a
real business portal. Change COMPANY / PRODUCT below to rename it.

Three separate dashboards:
  /dashboard  - normal users: account page + their own recent sign-ins
  /admin      - admin only: dark security-monitoring dashboard with live
                feed, attack map, attempts log, decoy activity, add users
  /portal     - DECOY: a fake internal "Ops Console" full of fake data.
                Anyone who logs in with a trap username (HONEY_USERS) lands
                here with ANY password. Everything they do is recorded.

NOTE: IP location is approximate - usually the city of the attacker's
internet provider or VPN server, not a street address.

Run:   python app.py
Open:  http://127.0.0.1:5000
"""
import hashlib
import json
import os
import random
import secrets
import sqlite3
import urllib.request
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (Flask, abort, g, jsonify, redirect, render_template_string,
                   request, session, url_for)
from markupsafe import Markup
from werkzeug.security import check_password_hash, generate_password_hash

# On Vercel the project folder is read-only; /tmp is the only writable place
# (and it is wiped whenever Vercel starts a fresh instance).
ON_VERCEL = bool(os.environ.get("VERCEL"))
DB_PATH = os.environ.get("AUTH_DB") or (
    "/tmp/auth.db" if ON_VERCEL else
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "auth.db"))
MAX_FAILS = 5          # failed attempts allowed...
WINDOW_MINUTES = 15    # ...within this many minutes
LOCK_MINUTES = 15      # how long an IP stays blocked
TRUST_PROXY = ON_VERCEL  # Vercel is a reverse proxy; real visitor IP is in X-Forwarded-For

COMPANY = "BlueGold Security Lab"          # made-up company name shown on the pages
PRODUCT = "BlueGold SecureAccess"   # name of the "sign-in system"

# Trap usernames. No real account may use these names. Logging in with one of
# them (any password) "succeeds" into the decoy portal.
HONEY_USERS = {"root", "administrator", "test", "guest", "user", "sysadmin",
               "superuser", "webmaster", "support", "demo", "manager"}
# If True, an IP that is already blocked for brute force is also sent to the
# decoy on its next attempt instead of seeing the "too many attempts" message.
# Off by default: a real user who forgot their password could end up there too.
DECOY_WHEN_BLOCKED = False

# Password for the "admin" account (it is also saved in ADMIN_LOGIN.txt).
# An ADMIN_PASSWORD environment variable overrides it. To change the password,
# edit it here and upload again.
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")
if not ADMIN_PASSWORD:
    raise RuntimeError("Set the ADMIN_PASSWORD environment variable before starting the app.")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or (
    # Vercel runs several copies of the app; a random key per copy would log
    # people out at random. Fall back to a key derived from ADMIN_PASSWORD.
    hashlib.sha256(("session-key:" + ADMIN_PASSWORD).encode()).hexdigest()
    if ON_VERCEL else secrets.token_hex(32))


# ---------------------------------------------------------------- database
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    conn = g.pop("db", None)
    if conn:
        conn.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            ip TEXT,
            country TEXT, region TEXT, city TEXT,
            user_agent TEXT,
            result TEXT NOT NULL,  -- success | wrong_password | unknown_user | blocked | decoy
            created_at TEXT NOT NULL        -- UTC ISO timestamp
        );
        CREATE INDEX IF NOT EXISTS idx_attempts_ip_time ON login_attempts(ip, created_at);
        CREATE TABLE IF NOT EXISTS decoy_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            username TEXT,
            action TEXT NOT NULL,           -- page viewed / button clicked / text typed
            detail TEXT,
            user_agent TEXT,
            created_at TEXT NOT NULL
        );
    """)
    # Upgrade older databases: add map coordinates and ISP columns.
    cols = {r[1] for r in conn.execute("PRAGMA table_info(login_attempts)")}
    for col, typ in (("lat", "REAL"), ("lon", "REAL"), ("isp", "TEXT")):
        if col not in cols:
            conn.execute(f"ALTER TABLE login_attempts ADD COLUMN {col} {typ}")
    # Create a default admin on first run so you can log in and see the logs.
    if not conn.execute("SELECT 1 FROM users").fetchone():
        conn.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (?,?,1)",
                     ("admin", generate_password_hash(ADMIN_PASSWORD)))
        print("\n*** Created admin account -> username: admin (password: see ADMIN_LOGIN.txt)\n")
    else:
        # Keep the admin password in step with ADMIN_PASSWORD, so changing it
        # here (or in the environment variable) changes the password.
        row = conn.execute("SELECT password_hash FROM users WHERE username='admin'").fetchone()
        if row and not check_password_hash(row[0], ADMIN_PASSWORD):
            conn.execute("UPDATE users SET password_hash=? WHERE username='admin'",
                         (generate_password_hash(ADMIN_PASSWORD),))
    clash = [r[0] for r in conn.execute("SELECT username FROM users")
             if r[0].lower() in HONEY_USERS]
    if clash:
        print(f"*** WARNING: real accounts use trap names {clash}; they can't log in "
              "normally. Rename them or remove the names from HONEY_USERS.")
    conn.commit()
    conn.close()


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------- helpers
def client_ip():
    if TRUST_PROXY and request.headers.get("X-Forwarded-For"):
        return request.headers["X-Forwarded-For"].split(",")[0].strip()
    return request.remote_addr or "unknown"


_geo_cache = {}


def lookup_location(ip):
    """Approximate location from an IP: (country, region, city, isp, lat, lon).
    City-level at best - usually the internet provider's or VPN's location."""
    if ip in _geo_cache:
        return _geo_cache[ip]
    private = is_private_ip(ip)
    # A local-network address (127.x, 192.168.x, ...) has no location of its own.
    # Asking ip-api.com with no IP returns the location of THIS computer's
    # internet connection, which is where a local visitor really is.
    try:
        with urllib.request.urlopen(
                f"http://ip-api.com/json/{'' if private else ip}"
                "?fields=status,country,regionName,city,isp,lat,lon",
                timeout=3) as r:
            data = json.load(r)
        if data.get("status") == "success":
            isp = data.get("isp", "")
            if private:
                isp = f"{isp} (local network)" if isp else "Local network"
            result = (data.get("country", ""), data.get("regionName", ""),
                      data.get("city", ""), isp, data.get("lat"), data.get("lon"))
        else:
            result = ("Local network" if private else "Unknown", "", "", "", None, None)
    except Exception:
        # Don't cache failures, so the next attempt tries again.
        return ("Local network" if private else "Lookup failed", "", "", "", None, None)
    _geo_cache[ip] = result
    return result


def is_private_ip(ip):
    return (ip.startswith(("127.", "10.", "192.168.", "::1", "fe80", "::ffff:127."))
            or (ip.startswith("172.") and ip.count(".") == 3
                and ip.split(".")[1].isdigit() and 16 <= int(ip.split(".")[1]) <= 31))


def fill_missing_locations():
    """Give older attempts that have no map position (e.g. 'Local network')
    a location now. Runs once at start-up."""
    conn = sqlite3.connect(DB_PATH)
    ips = [r[0] for r in conn.execute(
        "SELECT DISTINCT ip FROM login_attempts WHERE lat IS NULL AND ip IS NOT NULL LIMIT 40")]
    fixed = 0
    for ip in ips:
        country, region, city, isp, lat, lon = lookup_location(ip)
        if lat is not None:
            conn.execute("UPDATE login_attempts SET country=?, region=?, city=?, isp=?, lat=?, lon=?"
                         " WHERE ip=? AND lat IS NULL", (country, region, city, isp, lat, lon, ip))
            fixed += 1
    conn.commit()
    conn.close()
    if fixed:
        print(f"*** Added map locations for {fixed} IP address(es) from older attempts.")


def log_attempt(username, result):
    ip = client_ip()
    country, region, city, isp, lat, lon = lookup_location(ip)
    db().execute(
        "INSERT INTO login_attempts (username, ip, country, region, city, isp, lat, lon,"
        " user_agent, result, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (username, ip, country, region, city, isp, lat, lon,
         request.headers.get("User-Agent", "")[:300], result, now_iso()))
    db().commit()


def log_decoy(action, detail=""):
    db().execute(
        "INSERT INTO decoy_events (ip, username, action, detail, user_agent, created_at)"
        " VALUES (?,?,?,?,?,?)",
        (client_ip(), session.get("decoy_user", ""), action, str(detail)[:500],
         request.headers.get("User-Agent", "")[:300], now_iso()))
    db().commit()


def blocked_until(ip):
    """Return the time the IP is unblocked, or None if it isn't blocked."""
    since = (datetime.now(timezone.utc) - timedelta(minutes=WINDOW_MINUTES)).isoformat()
    rows = db().execute(
        "SELECT created_at FROM login_attempts WHERE ip=? AND created_at>=? "
        "AND result IN ('wrong_password','unknown_user') ORDER BY created_at DESC",
        (ip, since)).fetchall()
    if len(rows) < MAX_FAILS:
        return None
    # A success after the failures resets the counter.
    last_ok = db().execute(
        "SELECT MAX(created_at) FROM login_attempts WHERE ip=? AND result='success'", (ip,)).fetchone()[0]
    if last_ok and last_ok > rows[MAX_FAILS - 1]["created_at"]:
        return None
    until = datetime.fromisoformat(rows[0]["created_at"]) + timedelta(minutes=LOCK_MINUTES)
    return until if until > datetime.now(timezone.utc) else None


def login_required(admin=False):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            if session.get("decoy"):               # trapped visitors never reach real pages
                return redirect(url_for("portal"))
            if "user_id" not in session:
                return redirect(url_for("login"))
            if admin and not session.get("is_admin"):
                abort(404)                          # don't reveal that admin pages exist
            return fn(*a, **kw)
        return wrapper
    return deco


def decoy_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not session.get("decoy"):
            abort(404)
        return fn(*a, **kw)
    return wrapper


# ---------------------------------------------------------------- icons & bits
_ICON_PATHS = {
    "home": "M3 10.5 12 3l9 7.5V20a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1z",
    "users": "M16 19v-1a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v1M9 10a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7m13 9v-1a4 4 0 0 0-3-3.87M16 3.13a3.5 3.5 0 0 1 0 6.75",
    "folder": "M3 6a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z",
    "server": "M4 4h16v6H4zM4 14h16v6H4zM8 7h.01M8 17h.01",
    "settings": "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6m7.4-3a7.4 7.4 0 0 0-.1-1.2l2-1.6-2-3.4-2.4 1a7 7 0 0 0-2-1.2L14.5 3h-5l-.4 2.6a7 7 0 0 0-2 1.2l-2.4-1-2 3.4 2 1.6a7.4 7.4 0 0 0 0 2.4l-2 1.6 2 3.4 2.4-1a7 7 0 0 0 2 1.2l.4 2.6h5l.4-2.6a7 7 0 0 0 2-1.2l2.4 1 2-3.4-2-1.6c.1-.4.1-.8.1-1.2",
    "bell": "M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9M13.7 21a2 2 0 0 1-3.4 0",
    "search": "M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16m10 2-4.3-4.3",
    "logout": "M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4m7 14 5-5-5-5m5 5H9",
    "lock": "M5 11h14v10H5zM8 11V7a4 4 0 0 1 8 0v4",
    "shield": "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10",
    "eye": "M1 12s4-8 11-8 11 8 11 8-4 8-11 8S1 12 1 12m11 3a3 3 0 1 0 0-6 3 3 0 0 0 0 6",
    "file": "M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6",
    "download": "M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4m4-5 5 5 5-5m-5 5V3",
    "map": "M9 3 3 6v15l6-3 6 3 6-3V3l-6 3zM9 3v15m6-12v15",
    "list": "M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01",
    "target": "M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20m0-4a6 6 0 1 0 0-12 6 6 0 0 0 0 12m0-4a2 2 0 1 0 0-4 2 2 0 0 0 0 4",
    "plus": "M12 5v14M5 12h14",
    "alert": "M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0M12 9v4m0 4h.01",
    "chart": "M3 3v18h18M7 15l4-4 3 3 6-6",
}


def icon(name, size=18):
    return Markup(
        f'<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
        f'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
        f'<path d="{_ICON_PATHS[name]}"/></svg>')


LOGO = Markup(
    '<svg width="34" height="34" viewBox="0 0 40 40" aria-hidden="true">'
    '<rect width="40" height="40" rx="10" fill="#0b5cff"/>'
    '<path d="M11 10v20M29 10v20M11 20h18" stroke="#fff" stroke-width="4" stroke-linecap="round"/>'
    '<circle cx="29" cy="10" r="3" fill="#7dd3fc"/></svg>')


def avatar(name, size=32):
    h = int(hashlib.md5(name.encode()).hexdigest(), 16)
    colors = ["#0b5cff", "#7c3aed", "#0891b2", "#059669", "#d97706", "#db2777", "#4f46e5", "#0d9488"]
    initials = "".join(p[0] for p in name.replace(".", " ").split()[:2]).upper() or "?"
    return Markup(f'<span class="av" style="width:{size}px;height:{size}px;background:{colors[h % 8]};'
                  f'font-size:{size * .4:.0f}px">{initials}</span>')


def sparkline(values, color, w=110, h=34):
    lo, hi = min(values), max(values)
    pts = " ".join(f"{i * w / (len(values) - 1):.1f},{h - 3 - (v - lo) / ((hi - lo) or 1) * (h - 6):.1f}"
                   for i, v in enumerate(values))
    return Markup(f'<svg width="{w}" height="{h}" viewBox="0 0 {w} {h}"><polyline points="{pts}" '
                  f'fill="none" stroke="{color}" stroke-width="2" stroke-linejoin="round"/></svg>')


app.jinja_env.globals.update(icon=icon, LOGO=LOGO, avatar=avatar, COMPANY=COMPANY, PRODUCT=PRODUCT)


# ---------------------------------------------------------------- page shell
BASE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{{title}}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
{{head|safe}}
<style>
 *{box-sizing:border-box}
 body{font-family:Inter,system-ui,-apple-system,"Segoe UI",sans-serif;margin:0;-webkit-font-smoothing:antialiased}
 a{color:inherit;text-decoration:none}
 table{border-collapse:collapse;width:100%;font-size:13.5px}
 th,td{padding:10px 12px;text-align:left;white-space:nowrap}
 .wrap{overflow-x:auto}
 .av{display:inline-flex;align-items:center;justify-content:center;border-radius:50%;color:#fff;font-weight:600;flex-shrink:0}
 .muted{opacity:.65;font-size:13px}
</style>{{css|safe}}</head><body class="{{body_class}}">{{body|safe}}</body></html>"""


def page(title, body, head="", css="", body_class="", **ctx):
    return render_template_string(BASE, title=title, head=head, css=css, body_class=body_class,
                                  body=render_template_string(body, **ctx))


# Light corporate look shared by the login page, user page and decoy console.
CORP_CSS = """<style>
 body.corp{background:#f5f7fb;color:#0f172a}
 .corp .card{background:#fff;border:1px solid #e6eaf2;border-radius:14px;padding:20px}
 .corp th{color:#64748b;font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em;border-bottom:1px solid #eef1f6}
 .corp td{border-bottom:1px solid #f1f4f9}
 .corp tr:last-child td{border-bottom:0}
 .corp input,.corp select{width:100%;padding:11px 12px;border:1px solid #d6dce8;border-radius:10px;font:inherit;background:#fff;color:#0f172a;outline:none;transition:border .15s,box-shadow .15s}
 .corp input:focus,.corp select:focus{border-color:#0b5cff;box-shadow:0 0 0 4px #0b5cff22}
 .corp label{font-size:13px;font-weight:500;color:#334155;display:block;margin:0 0 6px}
 .corp .btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:11px 18px;background:#0b5cff;color:#fff;border:0;border-radius:10px;font:inherit;font-weight:600;cursor:pointer;transition:background .15s}
 .corp .btn:hover{background:#0848cc}
 .corp .btn.ghost{background:#fff;color:#0f172a;border:1px solid #d6dce8}
 .corp .btn.ghost:hover{background:#f5f7fb}
 .corp .btn.sm{padding:7px 12px;font-size:13px}
 .badge{display:inline-block;padding:3px 9px;border-radius:999px;font-size:12px;font-weight:600}
 .b-green{background:#dcfce7;color:#166534}.b-gray{background:#eef1f6;color:#475569}
 .b-blue{background:#dbeafe;color:#1e40af}.b-amber{background:#fef3c7;color:#92400e}
 .b-red{background:#fee2e2;color:#991b1b}.b-purple{background:#ede9fe;color:#5b21b6}
 .alert{display:flex;gap:10px;align-items:flex-start;padding:12px 14px;border-radius:10px;font-size:14px;margin-bottom:16px}
 .alert.err{background:#fef2f2;color:#991b1b;border:1px solid #fecaca}
 .alert.ok{background:#f0fdf4;color:#166534;border:1px solid #bbf7d0}
</style>"""


# ---------------------------------------------------------------- login
@app.route("/", methods=["GET"])
def home():
    if session.get("decoy"):
        return redirect(url_for("portal"))
    if "user_id" in session:
        return redirect(url_for("admin" if session.get("is_admin") else "dashboard"))
    return redirect(url_for("login"))


def enter_decoy(username):
    log_attempt(username, "decoy")
    session.clear()
    session["decoy"], session["decoy_user"] = True, username
    log_decoy("Logged in to decoy", f"username={username}")
    return redirect(url_for("portal"))


LOGIN_CSS = """<style>
 .split{display:grid;grid-template-columns:1.05fr 1fr;min-height:100vh}
 .brand{position:relative;overflow:hidden;color:#fff;padding:48px 56px;display:flex;flex-direction:column;justify-content:space-between;
   background:radial-gradient(1200px 600px at -10% -10%,#2563eb 0%,transparent 60%),radial-gradient(900px 600px at 110% 110%,#0891b2 0%,transparent 55%),#061a40}
 .brand::after{content:"";position:absolute;inset:0;background-image:linear-gradient(#ffffff0d 1px,transparent 1px),linear-gradient(90deg,#ffffff0d 1px,transparent 1px);background-size:44px 44px;mask-image:linear-gradient(180deg,#000,transparent 85%)}
 .brand>*{position:relative;z-index:1}
 .brand h1{font-size:40px;line-height:1.1;margin:0 0 16px;font-weight:700;letter-spacing:-.02em;max-width:460px}
 .brand p{color:#cbd5e1;max-width:420px;line-height:1.6;margin:0}
 .feat{display:flex;gap:28px;margin-top:36px;flex-wrap:wrap}
 .feat div{display:flex;gap:10px;align-items:center;color:#e2e8f0;font-size:14px}
 .feat svg{color:#7dd3fc}
 .formside{display:flex;flex-direction:column;justify-content:center;align-items:center;padding:40px 24px;background:#fff}
 .box{width:100%;max-width:400px}
 .box h2{font-size:26px;margin:0 0 6px;letter-spacing:-.01em}
 .field{margin-bottom:16px}
 .pw{position:relative}.pw input{padding-right:44px}
 .pw button{position:absolute;right:6px;top:50%;transform:translateY(-50%);background:none;border:0;color:#64748b;cursor:pointer;padding:6px}
 .row{display:flex;justify-content:space-between;align-items:center;font-size:13.5px;margin:4px 0 22px}
 .row label{display:flex;align-items:center;gap:8px;margin:0;font-weight:400;color:#334155}
 .row input{width:16px;height:16px;margin:0;accent-color:#0b5cff}
 .link{color:#0b5cff;font-weight:500}.link:hover{text-decoration:underline}
 .full{width:100%}
 .spin{width:16px;height:16px;border:2px solid #ffffff66;border-top-color:#fff;border-radius:50%;animation:s .7s linear infinite;display:none}
 .loading .spin{display:inline-block}.loading .lbl{opacity:.8}
 @keyframes s{to{transform:rotate(360deg)}}
 .or{display:flex;align-items:center;gap:12px;color:#94a3b8;font-size:12px;margin:22px 0}
 .or::before,.or::after{content:"";flex:1;height:1px;background:#e6eaf2}
 .secure{display:flex;align-items:center;justify-content:center;gap:8px;color:#64748b;font-size:12.5px;margin-top:26px}
 .foot{margin-top:40px;color:#94a3b8;font-size:12px;display:flex;gap:16px;justify-content:center;flex-wrap:wrap}
 .foot a:hover{color:#475569}
 .mlogo{display:none;align-items:center;gap:10px;font-weight:700;margin-bottom:28px}
 @media(max-width:900px){.split{grid-template-columns:1fr}.brand{display:none}.mlogo{display:flex}}
</style>"""

BANK_LOGIN_THEME = """<style>
  body.corp{background:#f3f6fb;color:#14243a}
  .brand{background:radial-gradient(900px 520px at -10% -10%,#1d5b9e 0%,transparent 62%),radial-gradient(720px 500px at 110% 110%,#b88a25 0%,transparent 48%),linear-gradient(135deg,#062b59,#0b477f 60%,#082d59)}
  .brand h1{max-width:520px}.brand p{color:#dce8f6}.feat svg{color:#f0cf70}
  .corp .btn{background:#0b3b78}.corp .btn:hover{background:#082e5d}
  .corp .btn.ghost{color:#0b3b78;border-color:#d6dfeb}
  .corp input:focus,.corp select:focus{border-color:#b58a2b;box-shadow:0 0 0 4px #d8b24a2b}
  .link{color:#0b4b88}.row input{accent-color:#0b3b78}
  .formside{background:linear-gradient(180deg,#fff,#f7f9fc)}
  .box{max-width:420px}.box h2{color:#102d50}.mlogo{color:#0b3b78}
  .secure{color:#6b7890}.foot a:hover{color:#0b3b78}
  .login-wordmark{display:flex;align-items:center;gap:14px;font-size:clamp(21px,2vw,25px);font-weight:700;line-height:1.2}
  .login-wordmark svg,.split .mlogo svg{width:42px;height:42px;flex:none}
  .split .mlogo{font-size:21px;line-height:1.2}
  .brand.login-brand{padding:clamp(30px,5vw,76px);background:radial-gradient(ellipse at 80% 65%,#15548c,transparent 66%),linear-gradient(145deg,#08294e,#0b3d70);gap:32px}
  .brand.login-brand::after{display:none}
  .login-brand-title{padding:0 0 0 22px;border-left:3px solid #f0cf70}
  .brand .login-brand-title h1{font-size:clamp(36px,4vw,62px);letter-spacing:-.045em;line-height:1.06;margin:0 0 16px}
  .login-brand-title h1 span{display:block;color:#f4d77e}
  .brand .login-brand-title p{color:#e0ecf8;font-size:clamp(15px,1.4vw,18px)}
  .login-brand-footer{font-size:13px;color:#c2d6ed}
</style>"""

LOGIN_HTML = """
<div class="split">
 <section class="brand login-brand">
  <div class="login-wordmark">{{LOGO}} <span>{{COMPANY}}</span></div>
  <div class="login-brand-title">
   <h1>Access with <span>confidence.</span></h1>
   <p>Sign in to manage accounts and review sign-in activity.</p>
  </div>
  <div class="login-brand-footer">Authorized training use only · Not affiliated with BDO</div>
 </section>
 <section class="formside">
  <div class="box">
   <div class="mlogo">{{LOGO}} {{COMPANY}}</div>
   <h2>Sign in</h2>
   <p class="muted" style="margin:0 0 26px">Administrator access for the security training simulator.</p>
   {% if error %}<div class="alert err">{{icon('alert')}}<div>{{error}}</div></div>{% endif %}
   {% if notice %}<div class="alert ok">{{icon('shield')}}<div>{{notice}}</div></div>{% endif %}
   <form method="post" id="f" autocomplete="on">
    <div class="field"><label for="u">Username or work email</label>
     <input id="u" name="username" required autofocus autocomplete="username" placeholder="name@bluegold-lab.local" value="{{last_user}}"></div>
    <div class="field"><label for="p">Password</label>
     <div class="pw"><input id="p" name="password" type="password" required autocomplete="current-password" placeholder="Enter your password">
      <button type="button" onclick="const p=document.getElementById('p');p.type=p.type==='password'?'text':'password'" aria-label="Show password">{{icon('eye')}}</button></div></div>
    <div class="row"><label><input type="checkbox" name="remember"> Keep me signed in</label>
     <a class="link" href="{{url_for('forgot')}}">Forgot password?</a></div>
    <button class="btn full" id="go"><span class="spin"></span><span class="lbl">Sign in</span></button>
   </form>
   <div class="or">OR</div>
   <a class="btn ghost full" href="{{url_for('sso')}}">{{icon('shield')}} Sign in with company SSO</a>
   <div class="secure">{{icon('lock',14)}} Protected by {{PRODUCT}}</div><p style="margin:12px 0 0;text-align:center;color:#9A6700;font-size:11px;font-weight:600">Demo environment only. Never enter real banking credentials.</p>
   <div class="foot"><a href="{{url_for('help_page')}}">Help</a><a href="{{url_for('help_page')}}">Privacy</a><a href="{{url_for('help_page')}}">Terms of use</a><span>English (US)</span></div>
  </div>
 </section>
</div>
<script>document.getElementById('f').addEventListener('submit',()=>{const b=document.getElementById('go');b.classList.add('loading');b.querySelector('.lbl').textContent='Signing in…'});</script>"""


def login_page(error=None, notice=None, last_user=""):
    return page(f"Sign in – {COMPANY}", LOGIN_HTML, css=CORP_CSS + LOGIN_CSS + BANK_LOGIN_THEME, body_class="corp",
                error=error, notice=notice, last_user=last_user)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    username = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()[:100]
        password = request.form.get("password", "")
        until = blocked_until(client_ip())
        if username.lower() in HONEY_USERS:
            return enter_decoy(username)
        if until:
            if DECOY_WHEN_BLOCKED:
                return enter_decoy(username)
            log_attempt(username, "blocked")
            mins = max(1, int((until - datetime.now(timezone.utc)).total_seconds() // 60) + 1)
            error = (f"Your account has been temporarily locked because of too many sign-in attempts. "
                     f"Try again in about {mins} minute(s).")
        else:
            user = db().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            if user is None:
                log_attempt(username, "unknown_user")
                error = "Your username or password is incorrect. Please try again."
            elif not check_password_hash(user["password_hash"], password):
                log_attempt(username, "wrong_password")
                error = "Your username or password is incorrect. Please try again."
            else:
                log_attempt(username, "success")
                session.clear()
                session["user_id"], session["username"], session["is_admin"] = \
                    user["id"], user["username"], bool(user["is_admin"])
                return redirect(url_for("admin" if user["is_admin"] else "dashboard"))
    return login_page(error=error, last_user=username)


@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    """Looks like a real reset page. Nothing is sent - the request is just logged."""
    sent = False
    if request.method == "POST":
        log_decoy("Password reset requested", "email value not recorded")
        sent = True
    return page(f"Reset password – {COMPANY}", """
      <div class="formside" style="min-height:100vh;background:#f5f7fb"><div class="box card" style="padding:32px">
       <div style="display:flex;align-items:center;gap:10px;font-weight:700;margin-bottom:24px">{{LOGO}} {{COMPANY}}</div>
       {% if sent %}
        <h2>Check your email</h2>
        <p class="muted" style="line-height:1.6">If an account exists for that address, we've sent a link to reset your password. The link expires in 30 minutes.</p>
       {% else %}
        <h2>Reset your password</h2>
        <p class="muted" style="margin:0 0 22px">Enter your work email and we'll send you a reset link.</p>
        <form method="post"><div class="field"><label>Work email</label><input name="email" type="email" required placeholder="name@bluegold-lab.local"></div>
        <button class="btn full">Send reset link</button></form>
       {% endif %}
       <p style="margin-top:22px;font-size:14px"><a class="link" href="{{url_for('login')}}">&larr; Back to sign in</a></p>
      </div></div>""", css=CORP_CSS + LOGIN_CSS + BANK_LOGIN_THEME, body_class="corp", sent=sent)


@app.route("/sso")
def sso():
    return login_page(error="Company SSO is temporarily unavailable. Please sign in with your username and password.")


@app.route("/help")
def help_page():
    return page(f"Help – {COMPANY}", """
      <div class="formside" style="min-height:100vh;background:#f5f7fb"><div class="box card" style="padding:32px;max-width:520px">
       <div style="display:flex;align-items:center;gap:10px;font-weight:700;margin-bottom:20px">{{LOGO}} {{COMPANY}}</div>
       <h2>IT Service Desk</h2>
       <p class="muted" style="line-height:1.7">Having trouble signing in? Contact the IT Service Desk, Monday–Friday 8:00–18:00.
       This system is for authorised users only. Activity may be monitored and recorded.</p>
       <p style="margin-top:22px;font-size:14px"><a class="link" href="{{url_for('login')}}">&larr; Back to sign in</a></p>
      </div></div>""", css=CORP_CSS + LOGIN_CSS, body_class="corp")


@app.route("/logout")
def logout():
    if session.get("decoy"):
        log_decoy("Logged out")
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------- user dashboard
@app.route("/dashboard")
@login_required()
def dashboard():
    if session.get("is_admin"):
        return redirect(url_for("admin"))
    rows = db().execute(
        "SELECT * FROM login_attempts WHERE username=? AND result='success' "
        "ORDER BY id DESC LIMIT 10", (session["username"],)).fetchall()
    return page(f"My account – {COMPANY}", """
      <header style="background:#fff;border-bottom:1px solid #e6eaf2">
       <div style="max-width:1000px;margin:0 auto;padding:14px 20px;display:flex;justify-content:space-between;align-items:center">
        <div style="display:flex;align-items:center;gap:10px;font-weight:700">{{LOGO}} {{COMPANY}}</div>
        <div style="display:flex;align-items:center;gap:12px">{{avatar(u)}}<span style="font-weight:500">{{u}}</span>
         <a class="btn ghost sm" href="{{url_for('logout')}}">{{icon('logout',15)}} Sign out</a></div></div></header>
      <main style="max-width:1000px;margin:0 auto;padding:28px 20px;display:grid;gap:18px">
       <div class="card" style="display:flex;gap:18px;align-items:center;padding:26px">{{avatar(u,56)}}
        <div><h1 style="margin:0;font-size:22px">Welcome back, {{u}}</h1>
        <p class="muted" style="margin:4px 0 0">Your account is active and in good standing.</p></div></div>
       <div class="card"><h2 style="margin:0 0 4px;font-size:16px">Recent sign-in activity</h2>
        <p class="muted" style="margin:0 0 14px">Don't recognise a sign-in? Change your password and contact the IT Service Desk.</p>
        <div class="wrap"><table>
        <tr><th>Date &amp; time (UTC)</th><th>IP address</th><th>Location</th><th>Device / browser</th></tr>
        {% for r in rows %}<tr><td>{{r.created_at.replace('T',' ')[:16]}}</td><td>{{r.ip}}</td>
          <td>{{[r.city, r.country]|select|join(', ')}}</td>
          <td title="{{r.user_agent}}">{{r.user_agent[:44]}}</td></tr>
        {% else %}<tr><td colspan="4">No sign-ins yet.</td></tr>{% endfor %}
        </table></div></div>
      </main>""", css=CORP_CSS, body_class="corp", u=session["username"], rows=rows)


# ---------------------------------------------------------------- admin dashboard (dark SOC style)
LABELS = {"success": ("Success", "ok"), "wrong_password": ("Wrong password", "bad"),
          "unknown_user": ("Unknown user", "bad"), "blocked": ("Blocked", "warn"),
          "decoy": ("Trapped", "trap")}

LEAFLET = """<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>"""

ADMIN_CSS = """<style>
 body.soc{background:#0a0f1c;color:#e2e8f0}
 .soc .bar{position:sticky;top:0;z-index:1000;background:#0d1426ee;backdrop-filter:blur(8px);border-bottom:1px solid #1e293b}
 .soc .bar-in{max-width:1400px;margin:0 auto;padding:12px 20px;display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap}
 .soc .nav{display:flex;gap:4px;flex-wrap:wrap}
 .soc .nav a{display:flex;align-items:center;gap:7px;padding:8px 12px;border-radius:8px;color:#94a3b8;font-size:14px;font-weight:500}
 .soc .nav a:hover{background:#1e293b;color:#e2e8f0}
 .soc .nav a.on{background:#1e3a8a55;color:#93c5fd}
 .soc .nav a.out{color:#fca5a5}
 .soc main{max-width:1400px;margin:0 auto;padding:22px 20px 40px;display:grid;gap:18px}
 .soc .panel{background:#0f172a;border:1px solid #1e293b;border-radius:14px;padding:18px}
 .soc .ph{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:14px}
 .soc .ph h2{margin:0;font-size:15px;font-weight:600;display:flex;align-items:center;gap:8px}
 .soc th{color:#64748b;font-weight:600;font-size:11.5px;text-transform:uppercase;letter-spacing:.06em;border-bottom:1px solid #1e293b}
 .soc td{border-bottom:1px solid #131c31;color:#cbd5e1}
 .soc tr:hover td{background:#111a2e}
 .soc .kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px}
 .soc .kpi{background:#0f172a;border:1px solid #1e293b;border-radius:14px;padding:16px;position:relative;overflow:hidden}
 .soc .kpi .n{font-size:30px;font-weight:700;letter-spacing:-.02em;margin-top:6px}
 .soc .kpi .l{color:#94a3b8;font-size:13px;display:flex;align-items:center;gap:7px}
 .soc .kpi::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--c)}
 .tag{display:inline-block;padding:3px 9px;border-radius:999px;font-size:11.5px;font-weight:600}
 .tag.ok{background:#14532d66;color:#86efac}.tag.bad{background:#7f1d1d66;color:#fca5a5}
 .tag.warn{background:#78350f66;color:#fcd34d}.tag.trap{background:#4c1d9566;color:#c4b5fd}
 .live{display:inline-flex;align-items:center;gap:7px;font-size:12px;color:#86efac;background:#14532d44;padding:4px 10px;border-radius:999px}
 .live i{width:8px;height:8px;border-radius:50%;background:#22c55e;box-shadow:0 0 0 0 #22c55e;animation:pl 1.6s infinite}
 @keyframes pl{0%{box-shadow:0 0 0 0 #22c55e99}70%{box-shadow:0 0 0 8px #22c55e00}100%{box-shadow:0 0 0 0 #22c55e00}}
 .soc .grid2{display:grid;grid-template-columns:2fr 1fr;gap:18px}
 .soc .grid2b{display:grid;grid-template-columns:1fr 1fr;gap:18px}
 @media(max-width:1000px){.soc .grid2,.soc .grid2b{grid-template-columns:1fr}}
 .soc #map{height:470px;border-radius:10px;background:#0a0f1c}
 .soc .darktiles{filter:invert(1) hue-rotate(200deg) brightness(.85) contrast(.9) saturate(.6)}
 .soc .leaflet-popup-content-wrapper,.soc .leaflet-popup-tip{background:#0f172a;color:#e2e8f0;border:1px solid #334155}
 .soc .leaflet-popup-content{font-size:13px;line-height:1.55}
 .soc .leaflet-popup-content a{color:#93c5fd}
 .soc .leaflet-control-attribution{background:#0f172acc!important;color:#64748b}
 .soc .leaflet-control-attribution a{color:#94a3b8}
 .soc .leaflet-bar a{background:#0f172a;color:#e2e8f0;border-color:#1e293b}
 .pulse{animation:pm 1.8s ease-out infinite}
 @keyframes pm{0%{stroke-opacity:1;stroke-width:2}100%{stroke-opacity:.15;stroke-width:14}}
 .feed{max-height:470px;overflow:auto;display:flex;flex-direction:column;gap:8px}
 .ev{display:flex;gap:10px;padding:10px;border-radius:10px;background:#0b1222;border:1px solid #16203a;font-size:13px}
 .ev .dot{width:9px;height:9px;border-radius:50%;margin-top:5px;flex-shrink:0}
 .ev.new{animation:flash 2s}
 @keyframes flash{from{background:#1e3a8a66}to{background:#0b1222}}
 .soc input{width:100%;padding:10px 12px;margin:6px 0 14px;border:1px solid #334155;border-radius:9px;background:#0b1222;color:#e2e8f0;font:inherit}
 .soc .btn{display:inline-block;padding:10px 16px;background:#2563eb;color:#fff;border:0;border-radius:9px;cursor:pointer;font:inherit;font-weight:600}
 .soc .msg{padding:10px 12px;border-radius:9px;margin-bottom:14px;font-size:14px}
 .soc .msg.ok{background:#14532d55;color:#86efac}.soc .msg.err{background:#7f1d1d55;color:#fca5a5}
 .soc .legend{display:flex;gap:14px;flex-wrap:wrap;font-size:12px;color:#94a3b8}
 .soc .legend span{display:flex;align-items:center;gap:6px}
 .soc .legend b{width:10px;height:10px;border-radius:50%;display:inline-block}
 .soc .legend button,.soc .plist button{display:flex;align-items:center;gap:6px;background:#0b1222;border:1px solid #1e293b;color:#94a3b8;padding:5px 11px;border-radius:999px;cursor:pointer;font:inherit;font-size:12px}
 .soc .legend button:hover,.soc .plist button:hover{border-color:#475569;color:#e2e8f0}
 .soc .legend button.on{border-color:#3b82f6;color:#e2e8f0;background:#1e3a8a55}
 .soc .legend button em,.soc .plist button em{font-style:normal;color:#64748b}
 .soc .plist{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px;max-height:110px;overflow:auto}
 .soc .plist b{width:9px;height:9px;border-radius:50%;display:inline-block}
 .soc .leaflet-tooltip.plabel{background:#0f172ae6;color:#e2e8f0;border:1px solid #334155;border-radius:6px;font-size:11.5px;font-weight:600;padding:2px 7px;box-shadow:none;white-space:nowrap}
 .soc .leaflet-tooltip.plabel::before{display:none}
 .soc [data-ip]{cursor:pointer}
 .soc tr[data-ip]:hover td{background:#16203a}
 .soc .ev[data-ip]:hover{border-color:#334155}
</style>"""

ADMIN_BANK_THEME = """<style>
  body.soc{background:radial-gradient(900px 520px at -10% -10%,#1d5b9e 0%,transparent 62%),radial-gradient(720px 500px at 110% 110%,#b88a25 0%,transparent 48%),linear-gradient(135deg,#062b59,#0b477f 60%,#082d59);color:#172b45}
  .soc main > div:first-child:not(.panel):not(.grid2b) h1{color:#fff}
  .soc main > div:first-child:not(.panel):not(.grid2b) > div > .muted{color:#e0eafa}
  .soc .bar{background:#0b3b78f5;border-bottom:3px solid #d7ad42;box-shadow:0 4px 18px #092b5018}
  .soc .bar-in{max-width:1500px}
  .soc .admin-wordmark{color:#fff;font-size:17px;letter-spacing:-.01em}
  .soc .admin-wordmark span:first-child{color:#a9d4ff}
  .soc .admin-wordmark span:nth-child(2){color:#ffdb79}
  .soc .bar .nav a{color:#dce8f6}.soc .bar .nav a:hover{background:#ffffff18;color:#fff}
  .soc .bar .nav a.on{background:#ffffff20;color:#f4d77e}.soc .bar .nav a.out{color:#ffe0d8}
  .soc main{max-width:1500px;padding-top:28px}
  .soc .panel,.soc .kpi{background:#fff;border:1px solid #dfe6ef;border-radius:15px;box-shadow:0 5px 18px #193b6010}
  .soc .kpi{padding:18px}.soc .kpi .n{color:#102d50}.soc .kpi .l{color:#64748b}
  .soc .ph h2{color:#16395f}.soc th{color:#66778d;border-bottom:1px solid #e4eaf2}
  .soc td{color:#34465e;border-bottom:1px solid #edf1f6}.soc tr:hover td{background:#f7f9fc}
  .soc .feed .ev{background:#f8fafd;border:1px solid #e5ebf3;color:#34465e}
  .soc .live{background:#e8f5ed;color:#17653a}.soc .live i{background:#1a9b55}
  .soc .legend{color:#65758b}
  .soc .legend button,.soc .plist button{background:#f8fafd;border-color:#dfe6ef;color:#4b5f78}
  .soc .legend button.on{background:#eaf1fa;border-color:#0b4b88;color:#0b3b78}
  .soc input{background:#fff;color:#172b45;border-color:#d5deea}
  .soc .btn{background:#0b3b78}.soc .btn:hover{background:#082e5d}
  .soc #map{border:1px solid #dfe6ef}
  .soc .leaflet-popup-content-wrapper,.soc .leaflet-popup-tip{background:#fff;color:#172b45;border:1px solid #d7e0eb}
  .soc .leaflet-popup-content a{color:#0b4b88}
  .soc .leaflet-tooltip.plabel{background:#fff;color:#172b45;border-color:#d7e0eb}
  .soc .leaflet-bar a{background:#fff;color:#17395e;border-color:#d7e0eb}
  .soc .leaflet-control-attribution{background:#ffffffdd!important;color:#68798e}
  .soc .leaflet-control-attribution a{color:#0b4b88}
  @media(max-width:720px){.soc .bar-in{padding:12px}.soc .nav{width:100%}.soc .nav a{font-size:12px;padding:7px 8px}}
  .soc main{padding:26px clamp(16px,3vw,44px) 48px;gap:22px}
  .soc .overview-intro{background:#082d598c;border:1px solid #ffffff32;border-radius:16px;padding:20px 22px;box-shadow:inset 3px 0 #d7ad42}
  .soc .panel,.soc .kpi{border-radius:16px;box-shadow:0 8px 24px #041e3d29}
  .soc .grid2 > *, .soc .grid2b > *{min-width:0}
  .soc .wrap{overflow-x:auto}
  .soc .ph{flex-wrap:wrap}
</style>"""


def admin_shell(active, content, title, head="", **ctx):
    nav = [("admin", "chart", "Overview"), ("logs", "list", "All attempts"),
           ("decoy_log", "target", "Decoy activity"), ("add_user", "plus", "Add user")]
    shell = """
     <div class="bar"><div class="bar-in">
      <div style="display:flex;align-items:center;gap:10px;font-weight:700">{{LOGO}}
       <span class="admin-wordmark"><span>Blue</span><span>Gold</span> SecureAccess</span></div>
      <nav class="nav">{% for ep, ic, name in nav %}<a href="{{url_for(ep)}}" class="{{'on' if ep==active}}">{{icon(ic,16)}} {{name}}</a>{% endfor %}
       <a class="out" href="{{url_for('logout')}}">{{icon('logout',16)}} Log out</a></nav>
     </div></div><main>CONTENT</main>"""
    return page(title, shell.replace("CONTENT", content), head=head, css=ADMIN_CSS + ADMIN_BANK_THEME,
                body_class="soc", nav=nav, active=active, **ctx)


def admin_data():
    q = lambda sql, *a: db().execute(sql, a).fetchone()[0]
    day = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    stats = [
        {"label": "Attempts · 24h", "n": q("SELECT COUNT(*) FROM login_attempts WHERE created_at>=?", day), "c": "#3b82f6", "i": "chart"},
        {"label": "Failed · 24h", "n": q("SELECT COUNT(*) FROM login_attempts WHERE created_at>=? AND result IN ('wrong_password','unknown_user')", day), "c": "#ef4444", "i": "alert"},
        {"label": "Blocked · 24h", "n": q("SELECT COUNT(*) FROM login_attempts WHERE created_at>=? AND result='blocked'", day), "c": "#f59e0b", "i": "lock"},
        {"label": "Decoy sign-ins", "n": q("SELECT COUNT(*) FROM login_attempts WHERE result='decoy'"), "c": "#8b5cf6", "i": "target"},
        {"label": "Decoy actions", "n": q("SELECT COUNT(*) FROM decoy_events"), "c": "#ec4899", "i": "eye"},
        {"label": "Unique IPs", "n": q("SELECT COUNT(DISTINCT ip) FROM login_attempts"), "c": "#14b8a6", "i": "map"},
    ]
    places = [dict(r) for r in db().execute("""
        SELECT ip, MAX(country) country, MAX(region) region, MAX(city) city, MAX(isp) isp,
               MAX(lat) lat, MAX(lon) lon, COUNT(*) total,
               SUM(result IN ('wrong_password','unknown_user','blocked')) failed,
               SUM(result='decoy') trapped, SUM(result='success') ok,
               MAX(created_at) last_seen, GROUP_CONCAT(DISTINCT username) usernames
        FROM login_attempts WHERE lat IS NOT NULL GROUP BY ip""")]
    recent = [dict(r) for r in db().execute(
        "SELECT id, username, ip, country, city, isp, result, created_at FROM login_attempts "
        "ORDER BY id DESC LIMIT 30")]
    attackers = [dict(r) for r in db().execute("""
        SELECT ip, MAX(country) country, MAX(city) city, MAX(isp) isp, COUNT(*) n,
               SUM(result='decoy') trapped, MAX(created_at) last_seen
        FROM login_attempts WHERE result!='success'
        GROUP BY ip ORDER BY n DESC LIMIT 8""")]
    usernames = [dict(r) for r in db().execute("""
        SELECT username, COUNT(*) n FROM login_attempts WHERE result!='success'
        GROUP BY username ORDER BY n DESC LIMIT 8""")]
    hours = [0] * 24
    for r in db().execute("SELECT created_at FROM login_attempts WHERE created_at>=?", (day,)):
        hrs = int((datetime.now(timezone.utc) - datetime.fromisoformat(r[0])).total_seconds() // 3600)
        if 0 <= hrs < 24:
            hours[23 - hrs] += 1
    no_coords = q("SELECT COUNT(DISTINCT ip) FROM login_attempts WHERE lat IS NULL")
    return {"stats": stats, "places": places, "recent": recent, "attackers": attackers,
            "usernames": usernames, "hours": hours, "no_coords": no_coords, "labels": LABELS}


@app.route("/admin/api/feed")
@login_required(admin=True)
def admin_feed():
    return jsonify(admin_data())


@app.route("/admin")
@login_required(admin=True)
def admin():
    return admin_shell("admin", """
      <div class="overview-intro" style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">
       <div><h1 style="margin:0;font-size:22px;letter-spacing:-.01em">Security overview</h1>
        <div class="muted">Sign-in activity and access monitoring</div></div>
       <span class="live"><i></i> Live · updates every 10s</span></div>
      <div class="kpis" id="kpis"></div>
      <div class="grid2">
       <div class="panel"><div class="ph"><h2>{{icon('map',16)}} Login activity map</h2>
         <div class="legend" id="mfilter">
          <button data-f="all" class="on">All <em id="c-all"></em></button>
          <button data-f="ok"><b style="background:#22c55e"></b>Success <em id="c-ok"></em></button>
          <button data-f="bad"><b style="background:#ef4444"></b>Failed / blocked <em id="c-bad"></em></button>
          <button data-f="trap"><b style="background:#a78bfa"></b>Decoy <em id="c-trap"></em></button></div></div>
        <div id="map"></div>
        <div class="plist" id="plist"></div>
        <p class="muted" style="margin:10px 0 0;font-size:12px">Location comes from the IP address: roughly the city of the internet provider or VPN, not a street address.
         <span id="nocoords"></span></p></div>
       <div class="panel"><div class="ph"><h2>{{icon('bell',16)}} Live event feed</h2></div><div class="feed" id="feed"></div></div>
      </div>
      <div class="grid2b">
       <div class="panel"><div class="ph"><h2>{{icon('chart',16)}} Attempts per hour · last 24h</h2></div><div id="hours"></div></div>
       <div class="panel"><div class="ph"><h2>{{icon('users',16)}} Most-tried usernames</h2></div><div id="unames"></div></div>
      </div>
      <div class="panel"><div class="ph"><h2>{{icon('alert',16)}} Most active source IPs</h2><a class="muted" href="{{url_for('logs')}}">All attempts &rarr;</a></div>
       <div class="wrap"><table id="att"></table></div></div>
      <script>
       let data = {{data|tojson}};
       const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
       const where = (...a) => a.filter(Boolean).map(esc).join(', ') || '—';
       const ago = iso => { const s=(Date.now()-new Date(iso))/1000; return s<60?Math.floor(s)+'s ago':s<3600?Math.floor(s/60)+'m ago':s<86400?Math.floor(s/3600)+'h ago':Math.floor(s/86400)+'d ago'; };
       const ICON = {{icons|tojson}};
       const map = L.map('map', {worldCopyJump:true, zoomControl:true}).setView([20,10], 2);
       L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png',
         {maxZoom:18, className:'darktiles', attribution:'&copy; OpenStreetMap contributors'}).addTo(map);
       const layer = L.layerGroup().addTo(map);
       let seen = new Set(), first = true, filter = 'all', openIp = null, markers = {};
       const FILTERS = {all: p => true, ok: p => p.ok > 0, bad: p => p.failed > 0, trap: p => p.trapped > 0};
       // One IP can have successes AND failures (e.g. you typed a wrong password once).
       // With a filter on, its dot takes that filter's colour and counts; on "All" it
       // shows every type in its label.
       const COLORS = {ok:'#22c55e', bad:'#ef4444', trap:'#a78bfa'};
       const NAMES = {ok:'success', bad:'failed', trap:'trapped'};
       const COUNT = {ok: p => p.ok, bad: p => p.failed, trap: p => p.trapped};
       const kindsOf = p => (filter==='all' ? ['ok','bad','trap'] : [filter]).filter(k => COUNT[k](p) > 0);
       const placeColor = p => filter!=='all' ? COLORS[filter] : (p.trapped ? COLORS.trap : (p.failed ? COLORS.bad : COLORS.ok));
       const countText = p => kindsOf(p).map(k => `${COUNT[k](p)} ${NAMES[k]}`).join(' · ');
       const placeName = p => [p.city, p.country].filter(Boolean).join(', ') || p.region || p.country || p.ip;
       function fitVisible(){
         const pts = data.places.filter(FILTERS[filter]).map(p => [p.lat,p.lon]);
         if (pts.length===1) map.flyTo(pts[0],6); else if (pts.length>1) map.flyToBounds(pts,{padding:[40,40],maxZoom:6});
       }
       function setFilter(f, fit=true){
         filter = f;
         document.querySelectorAll('#mfilter button').forEach(b => b.classList.toggle('on', b.dataset.f===f));
         openIp = null; map.closePopup(); render(); if (fit) fitVisible();
       }
       function goTo(ip, f){
         const p = data.places.find(x => x.ip===ip); if (!p) return;
         if (f && f!==filter) setFilter(f, false); else if (!markers[ip]) setFilter('all', false);
         const m = markers[ip], ll = L.latLng(p.lat,p.lon), z = Math.max(map.getZoom(), 8);
         document.getElementById('map').scrollIntoView({behavior:'smooth', block:'center'});
         if (map.getCenter().distanceTo(ll) < 500 && map.getZoom() >= z) { m.openPopup(); return; }
         map.once('moveend', () => m.openPopup());
         map.flyTo(ll, z, {duration:1.2});
       }
       document.getElementById('mfilter').addEventListener('click', e => { const b = e.target.closest('button'); if (b) setFilter(b.dataset.f); });
       for (const id of ['plist','feed','att'])
         document.getElementById(id).addEventListener('click', e => { const el = e.target.closest('[data-ip]'); if (el && !e.target.closest('a')) goTo(el.dataset.ip, el.dataset.f); });
       function render(){
         document.getElementById('kpis').innerHTML = data.stats.map(s =>
           `<div class="kpi" style="--c:${s.c}"><div class="l" style="color:${s.c}">${ICON[s.i]}<span style="color:#94a3b8">${esc(s.label)}</span></div><div class="n">${s.n}</div></div>`).join('');
         const keepOpen = openIp;
         layer.clearLayers(); markers = {}; const pts=[];
         for (const f in FILTERS) document.getElementById('c-'+f).textContent = data.places.filter(FILTERS[f]).length;
         const visible = data.places.filter(FILTERS[filter]);
         for (const p of visible) {
           const color = placeColor(p);
           const r = Math.min(6 + Math.sqrt(p.total)*2.2, 24);
           if (kindsOf(p).some(k => k!=='ok')) L.circleMarker([p.lat,p.lon],{radius:r,color,fill:false,className:'pulse',interactive:false}).addTo(layer);
           const m = L.circleMarker([p.lat,p.lon],{radius:r,color,fillColor:color,fillOpacity:.45,weight:1.5})
            .bindTooltip(`From ${esc(placeName(p))} · ${countText(p)}`, {permanent:true, direction:'right', offset:[r,0], className:'plabel'})
            .on('popupopen', () => { openIp = p.ip; })
            .on('popupclose', () => { if (openIp===p.ip) openIp = null; });
           markers[p.ip] = m;
           m.bindPopup(`<b style="font-size:14px">${esc(p.ip)}</b><br>${where(p.city,p.region,p.country)}<br>
              <span style="color:#94a3b8">ISP:</span> ${esc(p.isp)}<br>
              <span style="color:#94a3b8">Attempts:</span> ${p.total} &nbsp;(<span style="color:#fca5a5">${p.failed} failed</span>, <span style="color:#86efac">${p.ok} ok</span>, <span style="color:#c4b5fd">${p.trapped} trapped</span>)<br>
              <span style="color:#94a3b8">Usernames:</span> ${esc(p.usernames)}<br>
              <span style="color:#94a3b8">Last seen:</span> ${ago(p.last_seen)}<br>
              <a target="_blank" href="https://www.openstreetmap.org/?mlat=${p.lat}&mlon=${p.lon}#map=11/${p.lat}/${p.lon}">Open area map ↗</a>`)
           m.addTo(layer);
           pts.push([p.lat,p.lon]);
         }
         if (keepOpen && markers[keepOpen]) markers[keepOpen].openPopup();
         if (first) { if (pts.length===1) map.setView(pts[0],6); else if (pts.length>1) map.fitBounds(pts,{padding:[40,40],maxZoom:6}); }
         const shown = p => kindsOf(p).reduce((n,k) => n + COUNT[k](p), 0);
         document.getElementById('plist').innerHTML = visible.length ? [...visible].sort((a,b) => shown(b)-shown(a)).map(p =>
           `<button data-ip="${esc(p.ip)}" title="${esc(p.ip)} – click to go there">${kindsOf(p).map(k => `<b style="background:${COLORS[k]}"></b>`).join('')}${esc(placeName(p))} <em>${countText(p)}</em></button>`).join('')
           : '<span class="muted" style="font-size:12px">No places in this category yet.</span>';
         const onMap = new Set(data.places.map(p => p.ip));
         const KIND = {ok:'ok', bad:'bad', warn:'bad', trap:'trap'};   // feed tag -> map filter
         const ipAttr = (ip, cls) => onMap.has(ip) ? ` data-ip="${esc(ip)}"${cls ? ` data-f="${KIND[cls]}"` : ''} title="Show on map"` : '';
         document.getElementById('nocoords').textContent = data.no_coords ? `${data.no_coords} IP(s) not on the map (local network or lookup failed).` : '';
         const col = {ok:'#22c55e',bad:'#ef4444',warn:'#f59e0b',trap:'#a78bfa'};
         document.getElementById('feed').innerHTML = data.recent.length ? data.recent.map(r => {
           const [lbl, cls] = data.labels[r.result]; const isNew = !first && !seen.has(r.id);
           return `<div class="ev ${isNew?'new':''}"${ipAttr(r.ip, cls)}><span class="dot" style="background:${col[cls]}"></span><div style="min-width:0;flex:1">
             <div style="display:flex;justify-content:space-between;gap:8px"><b>${esc(r.username)||'<i>empty</i>'}</b><span class="tag ${cls}">${lbl}</span></div>
             <div class="muted" style="font-size:12px;margin-top:3px">${esc(r.ip)} · ${where(r.city,r.country)} · ${ago(r.created_at)}</div></div></div>`;
         }).join('') : '<div class="muted">No sign-in attempts yet.</div>';
         data.recent.forEach(r => seen.add(r.id));
         const mx = Math.max(1, ...data.hours);
         document.getElementById('hours').innerHTML = `<div style="display:flex;align-items:flex-end;gap:4px;height:150px">${data.hours.map((v,i)=>
           `<div title="${v} attempt(s), ${23-i}h ago" style="flex:1;height:${Math.max(3, v/mx*100)}%;background:${v?'linear-gradient(#3b82f6,#1d4ed8)':'#1e293b'};border-radius:4px 4px 0 0"></div>`).join('')}</div>
           <div class="muted" style="display:flex;justify-content:space-between;font-size:11px;margin-top:6px"><span>24h ago</span><span>12h ago</span><span>now</span></div>`;
         const um = Math.max(1, ...data.usernames.map(u=>u.n));
         document.getElementById('unames').innerHTML = data.usernames.length ? data.usernames.map(u =>
           `<div style="margin-bottom:10px"><div style="display:flex;justify-content:space-between;font-size:13px;margin-bottom:4px"><span>${esc(u.username)||'<i>empty</i>'}</span><span class="muted">${u.n}</span></div>
            <div style="height:7px;background:#1e293b;border-radius:9px"><div style="height:100%;width:${u.n/um*100}%;background:linear-gradient(90deg,#8b5cf6,#ec4899);border-radius:9px"></div></div></div>`).join('')
           : '<div class="muted">No failed attempts yet.</div>';
         document.getElementById('att').innerHTML = '<tr><th>IP address</th><th>Location</th><th>ISP</th><th>Attempts</th><th>Status</th><th>Last seen</th></tr>' +
           (data.attackers.length ? data.attackers.map(a => `<tr${ipAttr(a.ip)}><td style="font-family:ui-monospace,monospace">${esc(a.ip)}</td><td>${where(a.city,a.country)}</td>
             <td>${esc((a.isp||'').slice(0,30))}</td><td><b>${a.n}</b></td><td>${a.trapped?'<span class="tag trap">Trapped</span>':'<span class="tag bad">Attacking</span>'}</td><td class="muted">${ago(a.last_seen)}</td></tr>`).join('')
             : '<tr><td colspan="6" class="muted">No failed attempts yet.</td></tr>');
         first = false;
       }
       render();
       setInterval(async () => { try { const r = await fetch('{{url_for("admin_feed")}}'); if (r.ok && r.headers.get('content-type','').includes('json')) { data = await r.json(); render(); } } catch(e){} }, 10000);
      </script>""", f"Admin Security Center – {PRODUCT}", head=LEAFLET, data=admin_data(),
                       icons={k: str(icon(k, 15)) for k in ("chart", "alert", "lock", "target", "eye", "map")})


def browser_name(agent):
    agent = (agent or "").lower()
    for tokens, name in (
        (("edg/", "edga/", "edgios/"), "Edge"),
        (("opr/", "opios/"), "Opera"),
        (("samsungbrowser/",), "Samsung Internet"),
        (("firefox/", "fxios/"), "Firefox"),
        (("chrome/", "crios/"), "Chrome"),
        (("safari/",), "Safari"),
        (("werkzeug/",), "Werkzeug"),
    ):
        if any(token in agent for token in tokens):
            return name
    return "Unknown browser"


def browser_and_device(agent):
    browser = browser_name(agent)
    agent = (agent or "").lower()
    if "iphone" in agent:
        return f"iPhone · {browser}"
    if "ipad" in agent:
        return f"iPad · {browser}"
    if "android" in agent:
        device = "Android phone" if "mobile" in agent else "Android device"
        return f"{device} · {browser}"
    if "mobile" in agent:
        return f"Mobile device · {browser}"
    return browser


@app.route("/logs")
@login_required(admin=True)
def logs():
    rows = db().execute("SELECT * FROM login_attempts ORDER BY id DESC LIMIT 500").fetchall()
    return admin_shell("logs", """
      <div class="panel"><div class="ph"><h2>{{icon('list',16)}} All sign-in attempts <span class="muted">(latest 500)</span></h2></div>
      <div class="wrap"><table>
      <tr><th>Time (UTC)</th><th>Username</th><th>Result</th><th>IP</th>
          <th>Country</th><th>Region</th><th>City</th><th>ISP</th><th>Map</th><th>Browser / device</th></tr>
      {% for r in rows %}<tr>
        <td>{{r.created_at.replace('T',' ')[:19]}}</td><td><b>{{r.username}}</b></td>
        <td><span class="tag {{labels[r.result][1]}}">{{labels[r.result][0]}}</span></td>
        <td style="font-family:ui-monospace,monospace">{{r.ip}}</td><td>{{r.country}}</td><td>{{r.region}}</td><td>{{r.city}}</td>
        <td>{{(r.isp or '')[:28]}}</td>
        <td>{% if r.lat is not none %}<a style="color:#93c5fd" target="_blank"
            href="https://www.openstreetmap.org/?mlat={{r.lat}}&mlon={{r.lon}}#map=11/{{r.lat}}/{{r.lon}}">📍 map</a>{% endif %}</td>
        <td class="muted" title="{{r.user_agent}}">{{browser_and_device(r.user_agent)}}</td></tr>
      {% else %}<tr><td colspan="10" class="muted">No attempts yet.</td></tr>{% endfor %}
      </table></div></div>""", f"All attempts – {PRODUCT}", rows=rows, labels=LABELS, browser_and_device=browser_and_device)


@app.route("/admin/decoy")
@login_required(admin=True)
def decoy_log():
    rows = db().execute("SELECT * FROM decoy_events ORDER BY id DESC LIMIT 500").fetchall()
    return admin_shell("decoy_log", """
      <div class="panel"><div class="ph"><h2>{{icon('target',16)}} Decoy activity <span class="muted">(latest 500)</span></h2></div>
      <p class="muted" style="margin:-4px 0 14px">People who logged in with a trap username and believe they are inside the real Ops Console. Everything they did:</p>
      <div class="wrap"><table>
      <tr><th>Time (UTC)</th><th>IP</th><th>Username used</th><th>Action</th><th>Detail</th><th>Browser</th></tr>
      {% for r in rows %}<tr><td>{{r.created_at.replace('T',' ')[:19]}}</td><td style="font-family:ui-monospace,monospace">{{r.ip}}</td>
        <td>{{r.username}}</td><td><span class="tag trap">{{r.action}}</span></td>
        <td style="white-space:normal;max-width:420px">{{r.detail}}</td>
        <td class="muted" title="{{r.user_agent}}">{{r.user_agent[:30]}}</td></tr>
      {% else %}<tr><td colspan="6" class="muted">Nobody has fallen into the decoy yet.</td></tr>{% endfor %}
      </table></div></div>""", f"Decoy activity – {PRODUCT}", rows=rows)


@app.route("/add-user", methods=["GET", "POST"])
@login_required(admin=True)
def add_user():
    msg = err = None
    if request.method == "POST":
        u, p = request.form.get("username", "").strip(), request.form.get("password", "")
        if len(u) < 3 or len(p) < 8:
            err = "Username needs 3+ characters and password 8+ characters."
        elif u.lower() in HONEY_USERS:
            err = f"'{u}' is a trap username (HONEY_USERS) – choose another."
        else:
            try:
                db().execute("INSERT INTO users (username, password_hash) VALUES (?,?)",
                             (u, generate_password_hash(p)))
                db().commit()
                msg = f"User '{u}' created."
            except sqlite3.IntegrityError:
                err = "That username already exists."
    users = db().execute("SELECT username, is_admin FROM users ORDER BY id").fetchall()
    return admin_shell("add_user", """
      <div class="grid2b">
       <div class="panel"><div class="ph"><h2>{{icon('plus',16)}} Add user</h2></div>
        {% if msg %}<div class="msg ok">{{msg}}</div>{% endif %}
        {% if err %}<div class="msg err">{{err}}</div>{% endif %}
        <form method="post"><label class="muted">Username</label><input name="username" required>
        <label class="muted">Password (8+ characters)</label><input name="password" type="password" required>
        <button class="btn">Create user</button></form></div>
       <div class="panel"><div class="ph"><h2>{{icon('users',16)}} Accounts</h2></div><table>
        {% for u in users %}<tr><td style="display:flex;align-items:center;gap:10px">{{avatar(u.username,28)}} {{u.username}}</td>
        <td>{% if u.is_admin %}<span class="tag trap">Admin</span>{% else %}<span class="tag ok">User</span>{% endif %}</td></tr>{% endfor %}
       </table></div>
      </div>""", f"Add user – {PRODUCT}", msg=msg, err=err, users=users)


# ---------------------------------------------------------------- DECOY portal
# Everything below is fake. It looks like a real company operations console so
# a trapped intruder keeps clicking around while everything they do is logged.
_rng = random.Random(42)
FAKE_FIRST = ["James", "Maria", "John", "Ana", "Peter", "Grace", "David", "Sarah", "Paul", "Linda",
              "Mark", "Joy", "Daniel", "Ruth", "Kevin", "Faith", "Erik", "Nina", "Tomas", "Lea"]
FAKE_LAST = ["Santos", "Reyes", "Cruz", "Garcia", "Mendoza", "Torres", "Ramos", "Flores", "Rivera",
             "Bautista", "Lopez", "Castillo", "Lindqvist", "Berg", "Holm", "Novak"]
DEPTS = ["Finance", "Operations", "IT", "HR", "Sales", "Logistics", "Legal"]
FAKE_USERS = []
for i in range(28):
    f, l = _rng.choice(FAKE_FIRST), _rng.choice(FAKE_LAST)
    FAKE_USERS.append({
        "id": 1000 + i, "name": f"{f} {l}", "email": f"{f[0].lower()}.{l.lower()}@bluegold-lab.local",
        "dept": _rng.choice(DEPTS),
        "role": _rng.choice(["Member", "Member", "Member", "Manager", "Admin"]),
        "last": f"{_rng.randint(1, 59)} min ago" if i < 6 else f"Nov {_rng.randint(1, 8)}, 2026",
        "status": _rng.choice(["Active", "Active", "Active", "Active", "Suspended"]),
        "mfa": _rng.choice([True, True, False])})
FAKE_FILES = [
    ("Payroll_2026_Q3_FINAL.xlsx", "Finance", "2.4 MB", "Nov 3, 2026", "xlsx"),
    ("prod-db_backup_2026-11-07.sql.gz", "Backups", "418 MB", "Nov 7, 2026", "gz"),
    ("vpn-staff-config.ovpn", "IT", "6 KB", "Oct 28, 2026", "ovpn"),
    ("service_accounts_OLD.txt", "IT", "3 KB", "Aug 14, 2026", "txt"),
    ("Client_Contracts_2026.zip", "Legal", "88 MB", "Oct 30, 2026", "zip"),
    ("Network_Topology_v4.pdf", "IT", "1.1 MB", "Sep 21, 2026", "pdf"),
    ("Board_Meeting_Notes_Oct.docx", "Executive", "412 KB", "Oct 31, 2026", "docx"),
    ("Employee_Directory_Export.csv", "HR", "1.9 MB", "Nov 5, 2026", "csv"),
]
FAKE_SERVERS = [
    ("bg-web-01", "10.20.1.11", "Web frontend", "Ubuntu 24.04", 34, 61, "Healthy"),
    ("bg-web-02", "10.20.1.12", "Web frontend", "Ubuntu 24.04", 29, 58, "Healthy"),
    ("bg-db-primary", "10.20.2.5", "PostgreSQL 16", "Debian 12", 71, 83, "Healthy"),
    ("bg-db-replica", "10.20.2.6", "PostgreSQL 16", "Debian 12", 22, 64, "Healthy"),
    ("bg-files-01", "10.20.3.40", "File server", "Windows Server 2022", 12, 47, "Healthy"),
    ("bg-backup-01", "10.20.3.90", "Backup vault", "Ubuntu 22.04", 88, 72, "Warning"),
    ("bg-vpn-gw", "10.20.0.1", "VPN gateway", "OPNsense", 18, 33, "Healthy"),
    ("bg-dc-01", "10.20.0.10", "Domain controller", "Windows Server 2022", 9, 41, "Healthy"),
]
FILE_COLORS = {"xlsx": "#16a34a", "gz": "#64748b", "ovpn": "#0891b2", "txt": "#475569", "zip": "#d97706",
               "pdf": "#dc2626", "docx": "#2563eb", "csv": "#059669"}
_spark_rng = random.Random(7)
SPARKS = {k: [_spark_rng.randint(40, 100) for _ in range(14)] for k in ("emp", "rev", "srv", "tix")}
MONTHS = list(zip(["Dec", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov"],
                  [1.62, 1.71, 1.58, 1.84, 1.92, 1.88, 2.05, 2.11, 1.97, 2.24, 2.31, 1.46]))

PORTAL_CSS = """<style>
 .app{display:flex;min-height:100vh}
 .side{width:248px;background:#0b1530;color:#a5b4cf;display:flex;flex-direction:column;flex-shrink:0;position:sticky;top:0;height:100vh}
 .side .lg{display:flex;align-items:center;gap:10px;padding:18px 20px;color:#fff;font-weight:700;border-bottom:1px solid #16224a}
 .side .sec{padding:16px 20px 6px;font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:#5d6f96}
 .side a{display:flex;align-items:center;gap:11px;padding:9px 14px;margin:1px 10px;border-radius:9px;font-size:14px;font-weight:500}
 .side a:hover{background:#13214a;color:#fff}
 .side a.on{background:#0b5cff;color:#fff}
 .side .me{margin-top:auto;padding:14px 16px;border-top:1px solid #16224a;display:flex;align-items:center;gap:10px}
 .topb{background:#fff;border-bottom:1px solid #e6eaf2;padding:12px 26px;display:flex;align-items:center;gap:16px;position:sticky;top:0;z-index:5}
 .srch{flex:1;max-width:460px;position:relative}
 .srch input{padding-left:38px;background:#f5f7fb;border-color:#eef1f6}
 .srch svg{position:absolute;left:12px;top:50%;transform:translateY(-50%);color:#94a3b8}
 .ibtn{position:relative;width:38px;height:38px;border-radius:10px;display:flex;align-items:center;justify-content:center;color:#475569;border:1px solid #e6eaf2;background:#fff;cursor:pointer;list-style:none}
 .ibtn::-webkit-details-marker{display:none}
 .ibtn .dotn{position:absolute;top:6px;right:7px;width:8px;height:8px;border-radius:50%;background:#ef4444;border:2px solid #fff}
 details.dd{position:relative}
 details.dd .menu{position:absolute;right:0;top:46px;width:330px;background:#fff;border:1px solid #e6eaf2;border-radius:12px;box-shadow:0 12px 32px #0f172a1f;padding:8px;z-index:20}
 .menu .it{display:flex;gap:10px;padding:10px;border-radius:9px;font-size:13px}
 .menu .it:hover{background:#f5f7fb}
 .content{padding:26px;max-width:1280px;width:100%;margin:0 auto}
 .ttl{display:flex;justify-content:space-between;align-items:flex-end;gap:16px;margin-bottom:20px;flex-wrap:wrap}
 .ttl h1{margin:0;font-size:24px;letter-spacing:-.01em}
 .kp{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-bottom:18px}
 .kp .card{display:flex;justify-content:space-between;align-items:flex-end}
 .kp .v{font-size:28px;font-weight:700;letter-spacing:-.02em;margin-top:4px}
 .kp .d{font-size:12.5px;font-weight:600;margin-top:4px}
 .g2{display:grid;grid-template-columns:1.6fr 1fr;gap:16px;margin-bottom:16px}
 @media(max-width:1100px){.g2{grid-template-columns:1fr}}
 @media(max-width:820px){.side{display:none}.content{padding:16px}.topb{padding:12px 16px}}
 .bars{display:flex;align-items:flex-end;gap:10px;height:200px;padding-top:10px}
 .bars div{flex:1;display:flex;flex-direction:column;align-items:center;gap:6px;height:100%;justify-content:flex-end;font-size:11px;color:#94a3b8}
 .bars span{width:100%;border-radius:6px 6px 0 0;background:linear-gradient(#5b8cff,#0b5cff)}
 .bars div:last-child span{background:repeating-linear-gradient(45deg,#c7d7ff,#c7d7ff 4px,#dfe8ff 4px,#dfe8ff 8px)}
 .meter{height:7px;background:#eef1f6;border-radius:9px;overflow:hidden;width:110px}
 .meter i{display:block;height:100%;border-radius:9px}
 .st{display:inline-flex;align-items:center;gap:6px;font-size:13px}
 .st::before{content:"";width:8px;height:8px;border-radius:50%;background:currentColor}
 .fi{width:34px;height:40px;border-radius:6px;display:flex;align-items:flex-end;justify-content:center;color:#fff;font-size:9px;font-weight:700;padding-bottom:5px;text-transform:uppercase;flex-shrink:0}
 .tabs{display:flex;gap:6px;border-bottom:1px solid #e6eaf2;margin-bottom:18px}
 .tabs a{padding:10px 14px;font-size:14px;font-weight:500;color:#64748b;border-bottom:2px solid transparent;margin-bottom:-1px}
 .tabs a.on{color:#0b5cff;border-color:#0b5cff}
</style>"""

DECOY_LINKS = [("portal", "home", "Dashboard"), ("portal_users", "users", "Users & access"),
               ("portal_files", "folder", "Files & backups"), ("portal_servers", "server", "Servers"),
               ("portal_settings", "settings", "Settings")]

DECOY_SHELL = """
<div class="app">
 <aside class="side">
  <div class="lg">{{LOGO}} <div>BlueGold<div style="font-size:11px;color:#f0cf70;font-weight:600">Simulation Workspace</div></div></div>
  <div class="sec">Workspace</div>
  {% for ep, ic, name in links %}<a href="{{url_for(ep)}}" class="{{'on' if ep==active}}">{{icon(ic)}} {{name}}</a>{% endfor %}
  <div class="sec">Account</div>
  <a href="{{url_for('logout')}}">{{icon('logout')}} Sign out</a>
  <div class="me">{{avatar(who,34)}}<div style="min-width:0"><div style="color:#fff;font-size:13.5px;font-weight:600">{{who}}</div>
   <div style="font-size:12px">Lab Administrator</div></div></div>
 </aside>
 <div style="flex:1;min-width:0">
  <div class="topb">
   <form class="srch" action="{{url_for('portal_search')}}">{{icon('search',16)}}<input name="q" placeholder="Search users, files, servers…" value="{{q or ''}}"></form>
   <div style="margin-left:auto;display:flex;gap:10px;align-items:center">
    <details class="dd"><summary class="ibtn">{{icon('bell')}}<span class="dotn"></span></summary>
     <div class="menu"><div style="padding:8px 10px;font-weight:600;font-size:14px">Notifications</div>
      <div class="it"><span class="badge b-amber" style="height:fit-content">!</span><div><b>Backup vault at 88% capacity</b><div class="muted">bg-backup-01 · 12 min ago</div></div></div>
      <div class="it"><span class="badge b-blue" style="height:fit-content">i</span><div><b>3 accounts awaiting approval</b><div class="muted">Users &amp; access · 1 h ago</div></div></div>
      <div class="it"><span class="badge b-green" style="height:fit-content">✓</span><div><b>Nightly backup completed</b><div class="muted">prod-db · 4 h ago</div></div></div>
     </div></details>
    <a class="ibtn" href="{{url_for('portal_settings')}}">{{icon('settings')}}</a>
    {{avatar(who,38)}}
   </div>
  </div>
  <div class="content"><div style="padding:10px 14px;margin-bottom:18px;border:1px solid #e6c76b;background:#fff9e8;color:#795a13;border-radius:10px;font-size:12px;font-weight:600">TRAINING SIMULATION — fictional data only; not connected to any bank or financial service.</div>CONTENT</div>
 </div>
</div>"""


def decoy_page(title, active, content, **ctx):
    body = DECOY_SHELL.replace("CONTENT", content)
    ctx.setdefault("q", "")
    return page(f"{title} · BlueGold Simulation Workspace", body, css=CORP_CSS + PORTAL_CSS, body_class="corp",
                links=DECOY_LINKS, active=active, who=session.get("decoy_user", "admin"), **ctx)


@app.route("/portal")
@decoy_required
def portal():
    log_decoy("Viewed page", "Dashboard")
    kpis = [("Active employees", "1,284", "+12 this month", "#16a34a", sparkline(SPARKS["emp"], "#16a34a")),
            ("Revenue (MTD)", "$1.46M", "64% of target", "#0b5cff", sparkline(SPARKS["rev"], "#0b5cff")),
            ("Servers online", "17 / 18", "1 warning", "#d97706", sparkline(SPARKS["srv"], "#d97706")),
            ("Open IT tickets", "23", "-5 since yesterday", "#7c3aed", sparkline(SPARKS["tix"], "#7c3aed"))]
    activity = [("Maria Reyes", "reset password for", "j.santos@bluegold-lab.local", "8 min ago"),
                ("System", "completed nightly backup", "prod-db_backup_2026-11-07.sql.gz", "4 h ago"),
                ("Erik Lindqvist", "exported", "Payroll_2026_Q3_FINAL.xlsx", "6 h ago"),
                ("Ana Cruz", "granted VPN access to", "3 contractors", "Yesterday"),
                ("System", "rotated TLS certificate on", "bg-web-01", "Yesterday")]
    mx = max(v for _, v in MONTHS)
    return decoy_page("Dashboard", "portal", """
      <div class="ttl"><div><div class="muted">Good day, {{who}}</div><h1>Operations overview</h1></div>
       <div style="display:flex;gap:8px"><a class="btn ghost sm" href="{{url_for('portal_action', what='export-report', target='operations-overview')}}">{{icon('download',15)}} Export report</a>
        <a class="btn sm" href="{{url_for('portal_users')}}">{{icon('plus',15)}} Invite user</a></div></div>
      <div class="kp">{% for l, v, d, c, s in kpis %}<div class="card"><div><div class="muted">{{l}}</div><div class="v">{{v}}</div>
        <div class="d" style="color:{{c}}">{{d}}</div></div>{{s}}</div>{% endfor %}</div>
      <div class="g2">
       <div class="card"><div style="display:flex;justify-content:space-between;align-items:center"><h3 style="margin:0;font-size:15px">Monthly revenue</h3><span class="muted">USD millions · last 12 months</span></div>
        <div class="bars">{% for m, v in months %}<div><b style="color:#334155;font-weight:600">{{v}}</b><span style="height:{{(v/mx*85)|round(1)}}%"></span>{{m}}</div>{% endfor %}</div></div>
       <div class="card"><h3 style="margin:0 0 12px;font-size:15px">Recent activity</h3>
        {% for who_, what, obj, t in activity %}<div style="display:flex;gap:10px;padding:9px 0;border-bottom:1px solid #f1f4f9;font-size:13.5px">
         {{avatar(who_,30)}}<div><b>{{who_}}</b> {{what}} <span style="color:#0b5cff">{{obj}}</span><div class="muted" style="font-size:12px">{{t}}</div></div></div>{% endfor %}</div>
      </div>
      <div class="card"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px"><h3 style="margin:0;font-size:15px">Infrastructure health</h3>
        <a class="muted" href="{{url_for('portal_servers')}}">View all servers &rarr;</a></div>
       <div class="wrap"><table><tr><th>Host</th><th>Role</th><th>CPU</th><th>Memory</th><th>Status</th></tr>
       {% for h, ip, role, os_, cpu, mem, st in servers[:5] %}<tr><td><b>{{h}}</b><div class="muted" style="font-size:12px">{{ip}}</div></td><td>{{role}}</td>
        <td><div class="meter"><i style="width:{{cpu}}%;background:{{'#d97706' if cpu>80 else '#0b5cff'}}"></i></div></td>
        <td><div class="meter"><i style="width:{{mem}}%;background:#7c3aed"></i></div></td>
        <td><span class="st" style="color:{{'#d97706' if st=='Warning' else '#16a34a'}}">{{st}}</span></td></tr>{% endfor %}
       </table></div></div>""", kpis=kpis, months=MONTHS, mx=mx, activity=activity, servers=FAKE_SERVERS)


@app.route("/portal/users")
@decoy_required
def portal_users():
    log_decoy("Viewed page", "Users & access")
    return decoy_page("Users & access", "portal_users", """
      <div class="ttl"><div><h1>Users &amp; access</h1><div class="muted">{{users|length}} accounts · 3 pending approval</div></div>
       <a class="btn sm" href="{{url_for('portal_action', what='invite-user', target='new user')}}">{{icon('plus',15)}} Invite user</a></div>
      <div class="tabs"><a class="on" href="#">All users</a><a href="{{url_for('portal_action', what='view-admins', target='admins tab')}}">Administrators</a>
       <a href="{{url_for('portal_action', what='view-service-accounts', target='service accounts tab')}}">Service accounts</a></div>
      <div class="card" style="padding:6px 6px"><div class="wrap"><table>
      <tr><th>Name</th><th>Department</th><th>Role</th><th>MFA</th><th>Last active</th><th>Status</th><th></th></tr>
      {% for u in users %}<tr>
        <td><div style="display:flex;align-items:center;gap:10px">{{avatar(u.name,32)}}<div><b>{{u.name}}</b><div class="muted" style="font-size:12px">{{u.email}}</div></div></div></td>
        <td>{{u.dept}}</td>
        <td><span class="badge {{'b-purple' if u.role=='Admin' else 'b-blue' if u.role=='Manager' else 'b-gray'}}">{{u.role}}</span></td>
        <td>{% if u.mfa %}<span class="badge b-green">On</span>{% else %}<span class="badge b-amber">Off</span>{% endif %}</td>
        <td class="muted">{{u.last}}</td>
        <td><span class="st" style="color:{{'#16a34a' if u.status=='Active' else '#94a3b8'}}">{{u.status}}</span></td>
        <td><a class="btn ghost sm" href="{{url_for('portal_action', what='reset-password', target=u.email)}}">Reset password</a></td></tr>{% endfor %}
      </table></div></div>""", users=FAKE_USERS)


@app.route("/portal/files")
@decoy_required
def portal_files():
    log_decoy("Viewed page", "Files & backups")
    return decoy_page("Files & backups", "portal_files", """
      <div class="ttl"><div><h1>Files &amp; backups</h1><div class="muted">Shared drive · 1.2 TB of 2 TB used</div></div>
       <a class="btn sm" href="{{url_for('portal_action', what='upload', target='file upload')}}">{{icon('plus',15)}} Upload</a></div>
      <div class="card" style="padding:6px"><div class="wrap"><table>
      <tr><th>Name</th><th>Folder</th><th>Size</th><th>Modified</th><th></th></tr>
      {% for name, folder, size, mod, ext in files %}<tr>
        <td><div style="display:flex;align-items:center;gap:12px"><span class="fi" style="background:{{colors[ext]}}">{{ext}}</span><b>{{name}}</b></div></td>
        <td>{{folder}}</td><td>{{size}}</td><td class="muted">{{mod}}</td>
        <td><a class="btn ghost sm" href="{{url_for('portal_action', what='download', target=name)}}">{{icon('download',14)}} Download</a></td></tr>
      {% endfor %}</table></div></div>""", files=FAKE_FILES, colors=FILE_COLORS)


@app.route("/portal/servers")
@decoy_required
def portal_servers():
    log_decoy("Viewed page", "Servers")
    return decoy_page("Servers", "portal_servers", """
      <div class="ttl"><div><h1>Servers</h1><div class="muted">Production · eu-north datacenter</div></div></div>
      <div class="card" style="padding:6px"><div class="wrap"><table>
      <tr><th>Host</th><th>Private IP</th><th>Role</th><th>OS</th><th>CPU</th><th>Memory</th><th>Status</th><th></th></tr>
      {% for h, ip, role, os_, cpu, mem, st in servers %}<tr><td><b>{{h}}</b></td><td style="font-family:ui-monospace,monospace">{{ip}}</td><td>{{role}}</td><td>{{os_}}</td>
        <td><div style="display:flex;align-items:center;gap:8px"><div class="meter"><i style="width:{{cpu}}%;background:{{'#d97706' if cpu>80 else '#0b5cff'}}"></i></div><span class="muted">{{cpu}}%</span></div></td>
        <td><div style="display:flex;align-items:center;gap:8px"><div class="meter"><i style="width:{{mem}}%;background:#7c3aed"></i></div><span class="muted">{{mem}}%</span></div></td>
        <td><span class="st" style="color:{{'#d97706' if st=='Warning' else '#16a34a'}}">{{st}}</span></td>
        <td style="display:flex;gap:6px"><a class="btn ghost sm" href="{{url_for('portal_action', what='open-console', target=h)}}">Console</a>
         <a class="btn ghost sm" href="{{url_for('portal_action', what='restart', target=h)}}">Restart</a></td></tr>{% endfor %}
      </table></div></div>""", servers=FAKE_SERVERS)


@app.route("/portal/settings", methods=["GET", "POST"])
@decoy_required
def portal_settings():
    msg = None
    if request.method == "POST":
        log_decoy("Submitted settings form", "form values not recorded")
        msg = "Changes saved. They will apply after the next scheduled maintenance window (02:00 UTC)."
    else:
        log_decoy("Viewed page", "Settings")
    return decoy_page("Settings", "portal_settings", """
      <div class="ttl"><div><h1>Settings</h1><div class="muted">Security and maintenance configuration</div></div></div>
      {% if msg %}<div class="alert ok">{{icon('shield')}}<div>{{msg}}</div></div>{% endif %}
      <form method="post" class="card" style="max-width:640px;display:grid;gap:16px">
        <div><label>Security contact email</label><input name="admin_email" value="it-security@bluegold-lab.local"></div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
         <div><label>SSH port</label><input name="ssh_port" value="22"></div>
         <div><label>Firewall</label><select name="firewall"><option>Enabled</option><option>Disabled</option></select></div></div>
        <div><label>Require MFA for administrators</label><select name="mfa"><option>Yes</option><option>No</option></select></div>
        <div><label>Run maintenance command</label><input name="command" placeholder="e.g. systemctl restart nginx" style="font-family:ui-monospace,monospace"></div>
        <div><button class="btn">Save changes</button></div>
      </form>""", msg=msg)


@app.route("/portal/search")
@decoy_required
def portal_search():
    q = request.args.get("q", "").strip()[:200]
    log_decoy("Searched", "search text not recorded")
    ql = q.lower()
    users = [u for u in FAKE_USERS if ql and (ql in u["name"].lower() or ql in u["email"] or ql in u["dept"].lower())]
    files = [f for f in FAKE_FILES if ql and ql in f[0].lower()]
    return decoy_page("Search", "", """
      <div class="ttl"><div><h1>Search results</h1><div class="muted">{{users|length + files|length}} results for “{{q}}”</div></div></div>
      <div class="card"><div class="wrap"><table>
      {% for u in users %}<tr><td style="display:flex;align-items:center;gap:10px">{{avatar(u.name,28)}}<b>{{u.name}}</b></td><td>{{u.email}}</td><td>{{u.dept}}</td></tr>{% endfor %}
      {% for f in files %}<tr><td>📄 <b>{{f[0]}}</b></td><td>{{f[1]}}</td><td><a class="btn ghost sm" href="{{url_for('portal_action', what='download', target=f[0])}}">Download</a></td></tr>{% endfor %}
      {% if not users and not files %}<tr><td class="muted">No results. Try a different search.</td></tr>{% endif %}
      </table></div></div>""", q=q, users=users, files=files)


@app.route("/portal/action/<what>")
@decoy_required
def portal_action(what):
    target = request.args.get("target", "")
    log_decoy(f"Clicked: {what}", target)
    msg = {"download": "Your download is being prepared. Large files are delivered to your email within 30 minutes.",
           "reset-password": "A password reset link has been sent to the user.",
           "restart": "Restart scheduled. The server will reboot during the next maintenance window.",
           "open-console": "Console session requested. Approval from a second administrator is required.",
           "export-report": "Report export started. You'll receive an email when it's ready.",
           }.get(what, "Your request has been submitted and is awaiting approval.")
    return decoy_page("Request submitted", "", """
      <div class="card" style="max-width:560px;margin:40px auto;text-align:center;padding:36px">
       <div style="width:56px;height:56px;border-radius:50%;background:#dcfce7;color:#16a34a;display:flex;align-items:center;justify-content:center;margin:0 auto 16px">{{icon('shield',26)}}</div>
       <h2 style="margin:0 0 8px">Request submitted</h2><p class="muted" style="line-height:1.6">{{msg}}</p>
       <p class="muted" style="font-size:12px">Reference #HG-{{ref}}</p>
       <a class="btn" href="{{url_for('portal')}}" style="margin-top:10px">Back to dashboard</a></div>""",
                      msg=msg, ref=secrets.randbelow(900000) + 100000)


@app.errorhandler(404)
def not_found(_):
    if session.get("decoy"):
        log_decoy("Tried hidden URL", request.path)
        return decoy_page("Not found", "", """
          <div class="card" style="max-width:520px;margin:40px auto;text-align:center;padding:36px">
           <h2 style="margin:0 0 8px">Page not found</h2><p class="muted">The page you requested does not exist or you don't have access.</p>
           <a class="btn" href="{{url_for('portal')}}">Back to dashboard</a></div>"""), 404
    return page("Page not found", """<div class="formside" style="min-height:100vh;background:#f5f7fb"><div class="box card" style="text-align:center;padding:36px">
      <div style="display:flex;justify-content:center;margin-bottom:16px">{{LOGO}}</div><h2>Page not found</h2>
      <p class="muted">The page you're looking for doesn't exist.</p><a class="btn" href="/">Go to sign in</a></div></div>""",
                css=CORP_CSS + LOGIN_CSS, body_class="corp"), 404


# Vercel imports this file instead of running it, so the block under
# `if __name__ == "__main__"` never runs there. Create the tables at import.
if ON_VERCEL:
    init_db()


if __name__ == "__main__":
    init_db()
    fill_missing_locations()
    # HOST=127.0.0.1 (default): only this computer can open the site.
    # HOST=0.0.0.0: other devices on the same Wi-Fi/network can open it too.
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    if host == "0.0.0.0":
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            lan_ip = s.getsockname()[0]
            s.close()
        except OSError:
            lan_ip = "<this computer's IP>"
        print(f"\n*** Other devices on the same network can open:  http://{lan_ip}:{port}\n")
    app.run(host=host, port=port, debug=False)
