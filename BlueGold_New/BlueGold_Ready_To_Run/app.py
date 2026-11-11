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
MAX_FAILS = 5         # failed attempts allowed...
WINDOW_MINUTES = 15   # ...within this many minutes
LOCK_MINUTES = 15     # how long an IP stays blocked
TRUST_PROXY = ON_VERCEL  # Vercel is a reverse proxy; real visitor IP is in X-Forwarded-For

COMPANY = "BlueGold Security Lab"         # made-up company name shown on the pages
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
                f"?fields=status,country,regionName,city,isp,lat,lon",
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
            if session.get("decoy"):                # trapped visitors never reach real pages
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
</style>{{css|safe}}</head><body class="{{body_class}}">{{body|safe}}</html>"""


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
          <td title="{{r.user_agent}}">{{r.user_agent}}</td></tr>
        {% endfor %}
        </table></div></div></main>""", u=session["username"])


# ---------------------------------------------------------------- admin dashboard
@app.route("/admin")
@login_required(admin=True)
def admin():
    stats = {
        "total_attempts": db().execute("SELECT COUNT(*) FROM login_attempts").fetchone()[0],
        "success": db().execute("SELECT COUNT(*) FROM login_attempts WHERE result='success'").fetchone()[0],
        "failed": db().execute("SELECT COUNT(*) FROM login_attempts WHERE result IN ('wrong_password','unknown_user')").fetchone()[0],
        "decoy": db().execute("SELECT COUNT(*) FROM login_attempts WHERE result='decoy'").fetchone()[0],
    }
    attempts = db().execute("SELECT * FROM login_attempts ORDER BY id DESC LIMIT 50").fetchall()
    decoys = db().execute("SELECT * FROM decoy_events ORDER BY id DESC LIMIT 50").fetchall()
    users = db().execute("SELECT id, username, is_admin FROM users ORDER BY id").fetchall()
    # Recent login counts by hour for a quick sparkline
    spark = [db().execute("SELECT COUNT(*) FROM login_attempts WHERE datetime(created_at) >= datetime('now', ?)",
                          (f"-{i} hour",)).fetchone()[0] for i in range(12, 0, -1)]

    body = """<!doctype html><html lang="en"><head><meta charset="utf-8">
    <title>Security Dashboard – {{COMPANY}}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" crossorigin="">
    <style>
      *:box-sizing:border-box}
      body{font-family:Inter,system-ui,sans-serif;background:#090d16;color:#e2e8f0;margin:0;font-size:14px}
      a{color:inherit;text-decoration:none}
      header{background:#0f172a;border-bottom:1px solid #1e293b;padding:14px 24px;display:flex;justify-content:space-between;align-items:center}
      .nav-left{display:flex;align-items:center;gap:12px;font-weight:700;font-size:16px;color:#fff}
      .nav-right{display:flex;align-items:center;gap:14px}
      .badge-live{display:inline-flex;align-items:center;gap:6px;background:#065f4633;color:#34d399;border:1px solid #065f4666;padding:4px 10px;border-radius:999px;font-size:12px;font-weight:600}
      .badge-live::before{content:"";width:7px;height:7px;background:#34d399;border-radius:50%;animation:pulse 2s infinite}
      @keyframes pulse{0%{opacity:1}50%{opacity:.3}100%{opacity:1}}
      main{max-width:1400px;margin:0 auto;padding:24px;display:grid;gap:24px}
      .grid-4{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px}
      .card{background:#0f172a;border:1px solid #1e293b;border-radius:12px;padding:20px}
      .stat-num{font-size:28px;font-weight:700;color:#fff;margin-top:6px;font-family:'JetBrains Mono',monospace}
      .grid-2{display:grid;grid-template-columns:1.2fr 1fr;gap:24px}
      @media(max-width:1024px){.grid-2{grid-template-columns:1fr}}
      #map{height:380px;border-radius:8px;border:1px solid #1e293b}
      table{width:100%;border-collapse:collapse;font-size:13px}
      th,td{padding:10px 12px;text-align:left;border-bottom:1px solid #1e293b;white-space:nowrap}
      th{color:#94a3b8;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.05em}
      tr:hover td{background:#1e293b44}
      .tabs{display:flex;gap:8px;margin-bottom:16px;border-bottom:1px solid #1e293b;padding-bottom:12px}
      .tab-btn{background:#1e293b;border:0;color:#94a3b8;padding:8px 16px;border-radius:8px;font:inherit;font-weight:600;cursor:pointer}
      .tab-btn.active{background:#2563eb;color:#fff}
      .tab-content{display:none}
      .tab-content.active{display:block}
      .mono{font-family:'JetBrains Mono',monospace}
      input,select{background:#090d16;border:1px solid #334155;color:#fff;padding:8px 12px;border-radius:6px;font:inherit;width:100%}
      .btn{background:#2563eb;color:#fff;border:0;padding:8px 16px;border-radius:6px;font:inherit;font-weight:600;cursor:pointer}
      .btn:hover{background:#1d4ed8}
      .alert-box{background:#451a03;border:1px solid #78350f;color:#fde68a;padding:12px 16px;border-radius:8px;margin-bottom:16px;font-size:13px}
      </style></head>
    <body>
    <header>
     <div class="nav-left">{{LOGO}} {{COMPANY}} — Security Operations</div>
     <div class="nav-right">
      <div class="badge-live">Live Feed Active</div>
      <span class="mono" style="color:#94a3b8">{{u}}</span>
      <a class="btn" style="background:#1e293b;font-size:13px;padding:6px 12px" href="{{url_for('logout')}}">Sign out</a>
     </div>
    </header>
    <main>
     {% if stats.decoy > 0 %}
     <div class="alert-box">
      <strong>⚠️ Honeypot Triggered!</strong> {{stats.decoy}} attacker(s) have wandered into the decoy portal and their actions are being logged.
     </div>
     {% endif %}
     <div class="grid-4">
      <div class="card"><div class="muted">Total Logins</div><div class="stat-num">{{stats.total_attempts}}</div></div>
      <div class="card"><div class="muted">Successful Sign-ins</div><div class="stat-num" style="color:#34d399">{{stats.success}}</div></div>
      <div class="card"><div class="muted">Blocked / Failed</div><div class="stat-num" style="color:#f87171">{{stats.failed}}</div></div>
      <div class="card"><div class="muted">Decoy Traps</div><div class="stat-num" style="color:#fbbf24">{{stats.decoy}}</div></div>
     </div>

     <div class="grid-2">
      <div class="card">
       <h3 style="margin:0 0 14px">Geographic Threat Map</h3>
       <div id="map"></div>
      </div>
      <div class="card">
       <h3 style="margin:0 0 14px">Attack Volume (Past 12 Hours)</h3>
       <div style="display:flex;align-items:center;justify-content:center;height:340px;background:#090d16;border-radius:8px;border:1px solid #1e293b">
        {{sparkline(spark, '#3b82f6', 320, 160)}}
       </div>
      </div>
     </div>

     <div class="card">
      <div class="tabs">
       <button class="tab-btn active" onclick="switchTab(event, 'tab-attempts')">Login Attempts Log</button>
       <button class="tab-btn" onclick="switchTab(event, 'tab-decoy')">Decoy Activity Log</button>
       <button class="tab-btn" onclick="switchTab(event, 'tab-users')">User Management</button>
      </div>

      <div id="tab-attempts" class="tab-content active">
       <div style="overflow-x:auto">
        <table>
         <tr><th>Time (UTC)</th><th>IP Address</th><th>Location</th><th>Username</th><th>Result</th><th>User Agent</th></tr>
         {% for a in attempts %}
         <tr>
          <td class="mono">{{a.created_at.replace('T',' ')[:19]}}</td>
          <td class="mono">{{a.ip}}</td>
          <td>{{[a.city, a.country]|select|join(', ')}}</td>
          <td class="mono">{{a.username or '-'}}</td>
          <td>
           {% if a.result == 'success' %}<span style="color:#34d399">success</span>
           {% elif a.result == 'decoy' %}<span style="color:#fbbf24;font-weight:bold">decoy trap</span>
           {% elif a.result == 'blocked' %}<span style="color:#f87171">blocked</span>
           {% else %}<span style="color:#94a3b8">{{a.result}}</span>{% endif %}
          </td>
          <td class="muted" style="max-width:260px;overflow:hidden;text-overflow:ellipsis" title="{{a.user_agent}}">{{a.user_agent}}</td>
         </tr>
         {% endfor %}
        </table>
       </div>
      </div>

      <div id="tab-decoy" class="tab-content">
       <div style="overflow-x:auto">
        <table>
         <tr><th>Time (UTC)</th><th>IP Address</th><th>Trap User</th><th>Action</th><th>Detail</th></tr>
         {% for d in decoys %}
         <tr>
          <td class="mono">{{d.created_at.replace('T',' ')[:19]}}</td>
          <td class="mono">{{d.ip}}</td>
          <td class="mono" style="color:#fbbf24">{{d.username}}</td>
          <td><strong>{{d.action}}</strong></td>
          <td class="muted">{{d.detail}}</td>
         </tr>
         {% endfor %}
        </table>
       </div>
      </div>

      <div id="tab-users" class="tab-content">
       <h4 style="margin-top:0">Registered Accounts</h4>
       <div style="max-width:600px;margin-bottom:24px">
        <table>
         <tr><th>ID</th><th>Username</th><th>Role</th></tr>
         {% for usr in users %}
         <tr>
          <td>{{usr.id}}</td>
          <td class="mono">{{usr.username}}</td>
          <td>{% if usr.is_admin %}<span style="color:#34d399">Admin</span>{% else %}Standard User{% endif %}</td>
         </tr>
         {% endfor %}
        </table>
       </div>
      </div>
     </div>
    </main>
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js" crossorigin=""></script>
    <script>
     function switchTab(evt, tabId) {
         document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
         document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
         document.getElementById(tabId).classList.add('active');
         evt.currentTarget.classList.add('active');
         if(tabId === 'tab-attempts') { setTimeout(() => map.invalidateSize(), 100); }
     }

     const map = L.map('map').setView([20, 0], 2);
     L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
         attribution: '&copy; OpenStreetMap contributors &copy; CARTO',
         maxZoom: 18
     }).addTo(map);

     const markers = [
         {% for a in attempts if a.lat is not none and a.lon is not none %}
         [{{a.lat}}, {{a.lon}}, "{{a.ip}}", "{{a.username}}", "{{a.result}}", "{{a.city}}, {{a.country}}"],
         {% endfor %}
     ];

     markers.forEach(m => {
         let color = '#3b82f6';
         if(m[4] === 'success') color = '#34d399';
         else if(m[4] === 'decoy') color = '#fbbf24';
         else if(m[4] === 'blocked') color = '#f87171';

         const circle = L.circleMarker([m[0], m[1]], {
             radius: 6,
             fillColor: color,
             color: '#fff',
             weight: 1,
             opacity: 1,
             fillOpacity: 0.8
         }).addTo(map);
         circle.bindPopup(`<strong>IP:</strong> \${m[2]}<br><strong>Location:</strong> \${m[5]}<br><strong>User:</strong> \${m[3]}<br><strong>Result:</strong> \${m[4]}`);
     });
    </script></body></html>
""", u=session["username"], stats=stats, attempts=attempts, decoys=decoys, users=users, spark=spark)


# ---------------------------------------------------------------- Decoy Portal (`/portal`)
@app.route("/portal")
@decoy_required
def portal():
    log_decoy("Viewed Ops Console")
    return page(f"Ops Console – {COMPANY}", """
      <header style="background:#111;color:#fff;padding:14px 24px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #333">
       <div style="font-weight:700">🔒 INTERNAL OPERATIONS CONSOLE // DECOY MODE</div>
       <div><span style="color:#f59e0b">Logged in as: {{user}}</span> | <a href="{{url_for('logout')}}" style="color:#ef4444;margin-left:12px">Exit</a></div>
      </header>
      <main style="max-width:1100px;margin:24px auto;padding:0 20px;font-family:monospace">
       <h2>Restricted Node Database</h2>
       <p style="color:#888">Welcome to the internal administration node. Select an action below to audit system configurations.</p>
       <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px;margin-top:20px">
        <div style="background:#1a1a1a;border:1px solid #333;padding:20px;border-radius:8px">
         <h3>AWS Root Credentials</h3>
         <p style="color:#888;font-size:12px">Access keys and secret tokens for primary cloud infrastructure.</p>
         <a href="{{url_for('portal_action', action='aws_keys')}}" class="btn" style="background:#d97706;display:inline-block;margin-top:10px;text-decoration:none;text-align:center">Reveal Credentials</a>
        </div>
        <div style="background:#1a1a1a;border:1px solid #333;padding:20px;border-radius:8px">
         <h3>Database Dump (SQL)</h3>
         <p style="color:#888;font-size:12px">Full export of user password hashes and internal records.</p>
         <a href="{{url_for('portal_action', action='db_dump')}}" class="btn" style="background:#d97706;display:inline-block;margin-top:10px;text-decoration:none;text-align:center">Download Archive</a>
        </div>
        <div style="background:#1a1a1a;border:1px solid #333;padding:20px;border-radius:8px">
         <h3>Internal API Tokens</h3>
         <p style="color:#888;font-size:12px">Master API tokens granting administrative cluster control.</p>
         <a href="{{url_for('portal_action', action='api_tokens')}}" class="btn" style="background:#d97706;display:inline-block;margin-top:10px;text-decoration:none;text-align:center">Fetch Tokens</a>
        </div>
       </div>
      </main>""", user=session.get("decoy_user"))


@app.route("/portal/action/<action>")
@decoy_required
def portal_action(action):
    log_decoy(f"Clicked action: {action}")
    fake_data = {
        "aws_keys": "AKIAIOSFODNN7EXAMPLE / wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY (SIMULATED HONEYPOT DATA)",
        "db_dump": "INSERT INTO users VALUES (99, 'root', 'pbkdf2:sha256:600000\\$fakehash', 1); (SIMULATED HONEYPOT DATA)",
        "api_tokens": "bg_live_sec_99a8bc7654321fedcba0 (SIMULATED HONEYPOT DATA)"
    }
    return jsonify({"status": "success", "data": fake_data.get(action, "Invalid action"), "warning": "Logged & Monitored"})


# ---------------------------------------------------------------- Application Entry Point
if __name__ == "__main__":
    import os
    if not os.path.exists("ADMIN_LOGIN.txt"):
        with open("ADMIN_LOGIN.txt", "w") as f:
            f.write(f"Admin Username: admin\nAdmin Password: {ADMIN_PASSWORD}\n")
        print("*** Saved admin credentials to ADMIN_LOGIN.txt ***")

    init_db()
    fill_missing_locations()
    print(f"\nStarting {COMPANY} server on http://127.0.0.1:5000 ...\n")
    app.run(debug=True, port=5000)
