"""Account and shared-code gate for ThreatVizDefend.

App Platform routes /api to this service and removes that prefix by default.
Never publish an analysis route outside this gate.
"""

import hashlib
import hmac
import os
import re
import secrets
from functools import wraps

import psycopg
from flask import Flask, jsonify, make_response, request
from psycopg.rows import dict_row
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash


DATABASE_URL = os.environ.get("DATABASE_URL", "")
ACCESS_CODE = os.environ.get("ACCESS_CODE", "")
SITE_ORIGIN = os.environ.get("SITE_ORIGIN", "").rstrip("/")
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "true").lower() == "true"
MAX_ACCOUNTS = int(os.environ.get("MAX_ACCOUNTS", "250"))
SESSION_SECONDS = 8 * 60 * 60
USERNAME = re.compile(r"^[a-zA-Z0-9_]{3,40}$")

if not DATABASE_URL or not SITE_ORIGIN or len(ACCESS_CODE) < 24:
    raise RuntimeError("Set DATABASE_URL, SITE_ORIGIN and a random ACCESS_CODE of at least 24 characters")
if not SITE_ORIGIN.startswith("https://") and COOKIE_SECURE:
    raise RuntimeError("SITE_ORIGIN must use HTTPS in production")

app = Flask(__name__)
# DigitalOcean App Platform is the only trusted reverse proxy in this deployment.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)
app.config["MAX_CONTENT_LENGTH"] = 25_000


def db():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def init_db():
    with db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS users (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            approved BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at TIMESTAMPTZ NOT NULL
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS attempts (
            bucket TEXT PRIMARY KEY,
            hits INT NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL
        )""")


init_db()


def error(message, status):
    return jsonify(error=message), status


@app.after_request
def no_store(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.before_request
def check_request_origin():
    if request.method == "POST":
        # A strict Origin check also protects cookie-authenticated writes from CSRF.
        if request.headers.get("Origin") != SITE_ORIGIN:
            return error("Request origin is not allowed.", 403)
        if not request.is_json:
            return error("Send JSON.", 415)


def payload():
    value = request.get_json(silent=True)
    return value if isinstance(value, dict) else {}


def limited(conn, kind, identifier, maximum, seconds):
    # Shared Postgres counters work across web-service instances. The identifier
    # is hashed so IPs and usernames are not stored in the rate-limit table.
    bucket = hashlib.sha256(f"{kind}:{identifier}".encode()).hexdigest()
    row = conn.execute("""INSERT INTO attempts(bucket, hits, expires_at)
        VALUES (%s, 1, now() + (%s * interval '1 second'))
        ON CONFLICT (bucket) DO UPDATE SET
          hits = CASE WHEN attempts.expires_at <= now() THEN 1 ELSE attempts.hits + 1 END,
          expires_at = CASE WHEN attempts.expires_at <= now()
            THEN now() + (%s * interval '1 second') ELSE attempts.expires_at END
        RETURNING hits""", (bucket, seconds, seconds)).fetchone()
    return row["hits"] > maximum


def client_ip():
    return request.remote_addr or "unknown"


def current_user(conn):
    token = request.cookies.get("tvd_session", "")
    if not token or len(token) != 64:
        return None
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    return conn.execute("""SELECT u.id, u.username, u.approved FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token_hash = %s AND s.expires_at > now()""", (token_hash,)).fetchone()


def set_session(conn, user_id):
    token = secrets.token_hex(32)
    conn.execute("INSERT INTO sessions(token_hash, user_id, expires_at) VALUES (%s, %s, now() + interval '8 hours')",
                 (hashlib.sha256(token.encode()).hexdigest(), user_id))
    response = make_response(jsonify(ok=True))
    response.set_cookie("tvd_session", token, max_age=SESSION_SECONDS,
                        httponly=True, secure=COOKIE_SECURE, samesite="Lax", path="/")
    return response


@app.get("/health")
def health():
    return jsonify(ok=True)


@app.get("/session")
def session():
    with db() as conn:
        user = current_user(conn)
    return jsonify(authenticated=bool(user), approved=bool(user and user["approved"]))


@app.post("/auth/signup")
def signup():
    data = payload()
    username = str(data.get("username", "")).strip().lower()
    password = data.get("password", "")
    if not USERNAME.fullmatch(username) or not isinstance(password, str) or not 12 <= len(password) <= 256:
        return error("Use a 3–40 character username and a password of 12–256 characters.", 400)
    # Hash before opening the transaction to avoid holding a DB lock while hashing.
    password_hash = generate_password_hash(password, method="scrypt")
    with db() as conn:
        if limited(conn, "signup-ip", client_ip(), 5, 3600):
            return error("Too many attempts. Try again later.", 429)
        # Serialize signups so the overall account limit cannot race.
        conn.execute("SELECT pg_advisory_xact_lock(74123901)")
        if conn.execute("SELECT count(*) AS n FROM users").fetchone()["n"] >= MAX_ACCOUNTS:
            return error("Account creation is temporarily unavailable.", 403)
        row = conn.execute("""INSERT INTO users(username, password_hash)
            VALUES (%s, %s) ON CONFLICT (username) DO NOTHING RETURNING id""",
            (username, password_hash)).fetchone()
        if not row:
            return error("This username is unavailable.", 409)
        return set_session(conn, row["id"])


@app.post("/auth/login")
def login():
    data = payload()
    username = str(data.get("username", "")).strip().lower()[:40]
    password = data.get("password", "")
    if not isinstance(password, str) or len(password) > 256:
        return error("Invalid username or password.", 401)
    with db() as conn:
        if (limited(conn, "login-ip", client_ip(), 15, 900) or
                limited(conn, "login-user", username, 8, 900)):
            return error("Too many attempts. Try again later.", 429)
        row = conn.execute("SELECT id, password_hash FROM users WHERE username = %s", (username,)).fetchone()
        # Use a real scrypt hash even for missing accounts to reduce timing clues.
        hash_to_check = row["password_hash"] if row else DUMMY_HASH
        valid = check_password_hash(hash_to_check, password)
        if not row or not valid:
            return error("Invalid username or password.", 401)
        return set_session(conn, row["id"])


DUMMY_HASH = generate_password_hash(secrets.token_hex(16), method="scrypt")


@app.post("/access/redeem")
def redeem():
    code = payload().get("code", "")
    with db() as conn:
        user = current_user(conn)
        if not user:
            return error("Please log in.", 401)
        if user["approved"]:
            return jsonify(ok=True)
        if (limited(conn, "redeem-ip", client_ip(), 20, 3600) or
                limited(conn, "redeem-user", user["id"], 5, 3600)):
            return error("Too many attempts. Try again later.", 429)
        if not isinstance(code, str) or not hmac.compare_digest(code, ACCESS_CODE):
            return error("That access code is incorrect.", 403)
        conn.execute("UPDATE users SET approved = TRUE WHERE id = %s", (user["id"],))
    return jsonify(ok=True)


@app.post("/auth/logout")
def logout():
    token = request.cookies.get("tvd_session", "")
    if token:
        with db() as conn:
            conn.execute("DELETE FROM sessions WHERE token_hash = %s", (hashlib.sha256(token.encode()).hexdigest(),))
    response = make_response(jsonify(ok=True))
    response.delete_cookie("tvd_session", path="/", secure=COOKIE_SECURE, samesite="Lax")
    return response


def approved_only(fn):
    @wraps(fn)
    def guarded(*args, **kwargs):
        with db() as conn:
            user = current_user(conn)
            if not user:
                return error("Please log in.", 401)
            if not user["approved"]:
                return error("Enter your access code first.", 403)
        return fn(user, *args, **kwargs)
    return guarded


@app.post("/analyze")
@approved_only
def analyze(user):
    # Replace with the team's analysis implementation. Keep this decorator,
    # account-level usage limits, and per-user ownership checks on run IDs.
    with db() as conn:
        if limited(conn, "analysis-user", user["id"], 30, 3600):
            return error("Too many scans. Try again later.", 429)
    return error("Code analysis is not connected yet.", 503)


@app.get("/runs/<run_id>/state")
@approved_only
def run_state(user, run_id):
    return error("Code analysis is not connected yet.", 503)


@app.errorhandler(413)
def too_large(_):
    return error("Request is too large.", 413)
