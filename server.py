#!/usr/bin/env python3
"""Small standard-library forum server for the Masaha demo project."""
import base64
import binascii
import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import smtplib
import sqlite3
import ssl
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from email.message import EmailMessage
from http import cookies
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("MASAHA_DB", ROOT / "masaha.sqlite3"))
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8000"))
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "").strip().lower()
SITE_URL = os.environ.get("SITE_URL", "").rstrip("/")
SESSION_SECONDS = 14 * 24 * 60 * 60
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "0") == "1"
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USER)
RATE_BUCKETS = {}
UPLOAD_DIR = ROOT / "uploads"


@contextmanager
def connect():
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db():
    with connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE,
          display_name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
          password_hash TEXT NOT NULL, bio TEXT NOT NULL DEFAULT '', avatar_url TEXT NOT NULL DEFAULT '',
          email_verified INTEGER NOT NULL DEFAULT 0, is_banned INTEGER NOT NULL DEFAULT 0,
          role TEXT NOT NULL DEFAULT 'member', created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
          token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          expires_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS topics (
          id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          title TEXT NOT NULL, body TEXT NOT NULL, category TEXT NOT NULL,
          created_at INTEGER NOT NULL, deleted INTEGER NOT NULL DEFAULT 0,
          image_url TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS comments (
          id INTEGER PRIMARY KEY, topic_id INTEGER NOT NULL REFERENCES topics(id) ON DELETE CASCADE,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          body TEXT NOT NULL, created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS reports (
          id INTEGER PRIMARY KEY, reporter_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          target_type TEXT NOT NULL, target_id INTEGER NOT NULL, reason TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'open', created_at INTEGER NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS users_username_nocase ON users(username COLLATE NOCASE);
        CREATE INDEX IF NOT EXISTS topics_created ON topics(created_at DESC);
        CREATE INDEX IF NOT EXISTS comments_topic ON comments(topic_id, created_at);
        CREATE INDEX IF NOT EXISTS reports_status ON reports(status, created_at);
        CREATE TABLE IF NOT EXISTS likes (
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          topic_id INTEGER NOT NULL REFERENCES topics(id) ON DELETE CASCADE,
          created_at INTEGER NOT NULL, PRIMARY KEY(user_id, topic_id)
        );
        CREATE TABLE IF NOT EXISTS bookmarks (
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          topic_id INTEGER NOT NULL REFERENCES topics(id) ON DELETE CASCADE,
          created_at INTEGER NOT NULL, PRIMARY KEY(user_id, topic_id)
        );
        CREATE TABLE IF NOT EXISTS notifications (
          id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          actor_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          topic_id INTEGER NOT NULL REFERENCES topics(id) ON DELETE CASCADE,
          kind TEXT NOT NULL, created_at INTEGER NOT NULL, read_at INTEGER
        );
        CREATE TABLE IF NOT EXISTS email_tokens (
          token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          purpose TEXT NOT NULL, expires_at INTEGER NOT NULL
        );
        """)
        # Migrate databases created by earlier versions without losing existing content.
        for table, column, declaration in (
            ("users", "avatar_url", "TEXT NOT NULL DEFAULT ''"),
            ("users", "email_verified", "INTEGER NOT NULL DEFAULT 1"),
            ("users", "is_banned", "INTEGER NOT NULL DEFAULT 0"),
            ("topics", "image_url", "TEXT NOT NULL DEFAULT ''"),
        ):
            columns = {row[1] for row in db.execute(f"PRAGMA table_info({table})")}
            if column not in columns:
                db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")


def now():
    return int(time.time())


def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def send_mail(recipient, subject, body):
    if not (SMTP_HOST and SMTP_FROM):
        print(f"[email setup required] To: {recipient} | {subject}\n{body}")
        return False
    message = EmailMessage()
    message["From"] = SMTP_FROM
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(body)
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as client:
        client.starttls(context=ssl.create_default_context())
        if SMTP_USER:
            client.login(SMTP_USER, SMTP_PASSWORD)
        client.send_message(message)
    return True


def allow_rate(key, limit, window):
    stamp = time.time()
    recent = [value for value in RATE_BUCKETS.get(key, []) if value > stamp-window]
    if len(recent) >= limit:
        RATE_BUCKETS[key] = recent
        return False
    recent.append(stamp)
    RATE_BUCKETS[key] = recent
    return True


def save_image(data_url):
    match = re.fullmatch(r"data:image/(png|jpeg|webp);base64,([A-Za-z0-9+/=]+)", str(data_url or ""))
    if not match:
        raise ValueError("Choose a PNG, JPG, or WebP image")
    ext, encoded = match.groups()
    raw = base64.b64decode(encoded, validate=True)
    if not raw or len(raw) > 2_000_000:
        raise ValueError("Image must be smaller than 2 MB")
    signatures = {"png": b"\x89PNG\r\n\x1a\n", "jpeg": b"\xff\xd8\xff", "webp": b"RIFF"}
    if not raw.startswith(signatures[ext]) or (ext == "webp" and raw[8:12] != b"WEBP"):
        raise ValueError("Image data does not match its file type")
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    filename = secrets.token_hex(20) + {"jpeg": ".jpg"}.get(ext, "." + ext)
    (UPLOAD_DIR / filename).write_bytes(raw)
    return "/uploads/" + filename


def public_user(row):
    if not row:
        return None
    return {"id": row["id"], "username": row["username"],
            "displayName": row["display_name"], "bio": row["bio"],
            "avatarUrl": row["avatar_url"], "emailVerified": bool(row["email_verified"]),
            "banned": bool(row["is_banned"]), "role": row["role"], "createdAt": row["created_at"]}


class ForumHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def log_message(self, fmt, *args):
        print("[%s] %s" % (self.log_date_time_string(), fmt % args))

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        super().end_headers()

    def do_HEAD(self):
        path = urlparse(self.path).path
        allowed = {"/": ROOT / "index.html", "/index.html": ROOT / "index.html",
                   "/app.js": ROOT / "app.js", "/style.css": ROOT / "style.css"}
        target = allowed.get(path)
        if path.startswith("/uploads/") and re.fullmatch(r"/uploads/[a-f0-9]{40}\.(png|jpg|webp)", path):
            target = ROOT / path.lstrip("/")
        if not target or not target.is_file():
            return self.send_error(404)
        self.send_response(200)
        self.send_header("Content-Type", mimetypes.guess_type(str(target))[0] or "application/octet-stream")
        self.send_header("Content-Length", str(target.stat().st_size))
        self.end_headers()

    def send_json(self, status, data, extra_headers=None):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for key, value in (extra_headers or []):
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("Invalid content length")
        if size > 3_000_000:
            raise ValueError("Request is too large")
        raw = self.rfile.read(size)
        try:
            data = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            raise ValueError("Invalid JSON")
        if not isinstance(data, dict):
            raise ValueError("Invalid request")
        return data

    def cookie_headers(self, token, max_age):
        c = cookies.SimpleCookie()
        c["masaha_session"] = token or ""
        c["masaha_session"]["path"] = "/"
        c["masaha_session"]["httponly"] = True
        c["masaha_session"]["samesite"] = "Strict"
        c["masaha_session"]["max-age"] = str(max_age)
        if COOKIE_SECURE:
            c["masaha_session"]["secure"] = True
        return [("Set-Cookie", c.output(header="").strip())]

    def session_user(self, db):
        raw = self.headers.get("Cookie", "")
        jar = cookies.SimpleCookie()
        try:
            jar.load(raw)
            token = jar["masaha_session"].value
        except (KeyError, cookies.CookieError):
            return None
        digest = hashlib.sha256(token.encode()).hexdigest()
        row = db.execute("""SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id
                          WHERE s.token_hash=? AND s.expires_at>?""", (digest, now())).fetchone()
        return row

    def require_user(self, db):
        user = self.session_user(db)
        if not user:
            self.send_json(401, {"error": "Please log in first"})
            return None
        if user["is_banned"]:
            self.send_json(403, {"error": "This account is suspended"})
            return None
        return user

    def require_admin(self, user):
        if not user or user["role"] != "admin":
            self.send_json(403, {"error": "Admin access required"})
            return False
        return True

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if not path.startswith("/api/"):
            if path == "/robots.txt":
                body = ("User-agent: *\nAllow: /\n" + (f"Sitemap: {SITE_URL}/sitemap.xml\n" if SITE_URL else "")).encode()
                self.send_response(200); self.send_header("Content-Type", "text/plain; charset=utf-8"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body); return
            if path == "/sitemap.xml":
                if not SITE_URL:
                    self.send_error(503, "Set SITE_URL to your public https URL before submitting a sitemap")
                    return
                with connect() as db:
                    ids = [row[0] for row in db.execute("SELECT id FROM topics WHERE deleted=0 ORDER BY created_at DESC LIMIT 50000")]
                locs = [f"<url><loc>{SITE_URL}/</loc></url>"] + [f"<url><loc>{SITE_URL}/?topic={topic_id}</loc></url>" for topic_id in ids]
                body = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?><urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">" + "".join(locs) + "</urlset>").encode()
                self.send_response(200); self.send_header("Content-Type", "application/xml; charset=utf-8"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body); return
            if path.startswith("/uploads/") and re.fullmatch(r"/uploads/[a-f0-9]{40}\.(png|jpg|webp)", path):
                target = ROOT / path.lstrip("/")
                if not target.is_file(): return self.send_error(404)
                return super().do_GET()
            if path not in ("/", "/index.html", "/app.js", "/style.css"):
                return self.send_error(404)
            return super().do_GET()
        with connect() as db:
            if path == "/api/me":
                return self.send_json(200, {"user": public_user(self.session_user(db))})
            if path == "/api/topics":
                query = parse_qs(parsed.query)
                search = query.get("q", [""])[0].strip()[:100]
                category = query.get("category", [""])[0]
                sql = """SELECT t.*, u.username, u.display_name, u.avatar_url,
                         (SELECT COUNT(*) FROM comments c WHERE c.topic_id=t.id) AS comment_count,
                         (SELECT COUNT(*) FROM likes l WHERE l.topic_id=t.id) AS like_count
                         FROM topics t JOIN users u ON u.id=t.user_id WHERE t.deleted=0"""
                values = []
                if search:
                    sql += " AND (t.title LIKE ? OR t.body LIKE ? OR u.display_name LIKE ?)"
                    needle = "%" + search.replace("%", "\\%").replace("_", "\\_") + "%"
                    values.extend([needle, needle, needle])
                if category in ("programming", "learning", "general"):
                    sql += " AND t.category=?"; values.append(category)
                sql += " ORDER BY t.created_at DESC LIMIT 100"
                rows = db.execute(sql, values).fetchall()
                return self.send_json(200, {"topics": [self.topic_json(row) for row in rows]})
            if path.startswith("/api/topics/"):
                try: topic_id = int(path.rsplit("/", 1)[1])
                except ValueError: return self.send_json(400, {"error": "Invalid topic id"})
                topic = db.execute("""SELECT t.*,u.username,u.display_name,u.avatar_url,
                    (SELECT COUNT(*) FROM comments c WHERE c.topic_id=t.id) AS comment_count,
                    (SELECT COUNT(*) FROM likes l WHERE l.topic_id=t.id) AS like_count
                    FROM topics t JOIN users u ON u.id=t.user_id WHERE t.id=? AND t.deleted=0""", (topic_id,)).fetchone()
                if not topic: return self.send_json(404, {"error": "Topic not found"})
                viewer=self.session_user(db)
                liked=bool(viewer and db.execute("SELECT 1 FROM likes WHERE user_id=? AND topic_id=?",(viewer["id"],topic_id)).fetchone())
                bookmarked=bool(viewer and db.execute("SELECT 1 FROM bookmarks WHERE user_id=? AND topic_id=?",(viewer["id"],topic_id)).fetchone())
                comments = db.execute("""SELECT c.*,u.username,u.display_name,u.avatar_url FROM comments c
                    JOIN users u ON u.id=c.user_id WHERE c.topic_id=? ORDER BY c.created_at""", (topic_id,)).fetchall()
                return self.send_json(200, {"topic": {**self.topic_json(topic), "likedByMe": liked, "bookmarkedByMe": bookmarked}, "comments": [self.comment_json(x) for x in comments]})
            if path.startswith("/api/users/"):
                try: user_id = int(path.rsplit("/", 1)[1])
                except ValueError: return self.send_json(400, {"error": "Invalid user id"})
                user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
                if not user: return self.send_json(404, {"error": "Profile not found"})
                posts = db.execute("""SELECT t.*,u.username,u.display_name,u.avatar_url,
                    (SELECT COUNT(*) FROM comments c WHERE c.topic_id=t.id) AS comment_count,
                    (SELECT COUNT(*) FROM likes l WHERE l.topic_id=t.id) AS like_count
                    FROM topics t JOIN users u ON u.id=t.user_id WHERE t.user_id=? AND t.deleted=0
                    ORDER BY t.created_at DESC LIMIT 50""", (user_id,)).fetchall()
                return self.send_json(200, {"user": public_user(user), "topics": [self.topic_json(x) for x in posts]})
            if path == "/api/verify":
                token = parse_qs(parsed.query).get("token", [""])[0]
                row = db.execute("SELECT * FROM email_tokens WHERE token_hash=? AND purpose='verify' AND expires_at>?", (hash_token(token), now())).fetchone()
                if not row: return self.send_json(400, {"error": "Verification link is invalid or expired"})
                db.execute("UPDATE users SET email_verified=1 WHERE id=?", (row["user_id"],))
                db.execute("DELETE FROM email_tokens WHERE token_hash=?", (row["token_hash"],))
                return self.send_json(200, {"ok": True})
            if path == "/api/notifications":
                user = self.require_user(db)
                if not user: return
                rows = db.execute("""SELECT n.id,n.topic_id,n.kind,n.created_at,u.display_name AS actor,t.title
                    FROM notifications n JOIN users u ON u.id=n.actor_id JOIN topics t ON t.id=n.topic_id
                    WHERE n.user_id=? ORDER BY n.created_at DESC LIMIT 50""", (user["id"],)).fetchall()
                unread = db.execute("SELECT COUNT(*) FROM notifications WHERE user_id=? AND read_at IS NULL", (user["id"],)).fetchone()[0]
                if parse_qs(parsed.query).get("mark", ["0"])[0] == "1":
                    db.execute("UPDATE notifications SET read_at=? WHERE user_id=? AND read_at IS NULL", (now(),user["id"]))
                return self.send_json(200, {"notifications": [dict(x) for x in rows], "unread": unread})
            if path == "/api/bookmarks":
                user = self.require_user(db)
                if not user: return
                rows = db.execute("""SELECT t.*,u.username,u.display_name,u.avatar_url,
                    (SELECT COUNT(*) FROM comments c WHERE c.topic_id=t.id) AS comment_count,
                    (SELECT COUNT(*) FROM likes l WHERE l.topic_id=t.id) AS like_count
                    FROM bookmarks b JOIN topics t ON t.id=b.topic_id JOIN users u ON u.id=t.user_id
                    WHERE b.user_id=? AND t.deleted=0 ORDER BY b.created_at DESC""", (user["id"],)).fetchall()
                return self.send_json(200, {"topics": [self.topic_json(x) for x in rows]})
            if path == "/api/admin/users":
                user = self.require_user(db)
                if not user or not self.require_admin(user): return
                rows = db.execute("SELECT id,username,display_name,is_banned,role,created_at FROM users ORDER BY created_at DESC LIMIT 200").fetchall()
                return self.send_json(200, {"users": [dict(x) for x in rows]})
            if path == "/api/admin/reports":
                user = self.require_user(db)
                if not user or not self.require_admin(user): return
                rows = db.execute("""SELECT r.*,u.username AS reporter FROM reports r
                    JOIN users u ON u.id=r.reporter_id WHERE r.status='open' ORDER BY r.created_at""").fetchall()
                return self.send_json(200, {"reports": [dict(x) for x in rows]})
        return self.send_json(404, {"error": "API route not found"})

    @staticmethod
    def topic_json(row):
        return {"id": row["id"], "title": row["title"], "body": row["body"],
                "category": row["category"], "createdAt": row["created_at"],
                "commentCount": row["comment_count"], "likeCount": row["like_count"],
                "imageUrl": row["image_url"], "user": {"id": row["user_id"],
                "username": row["username"], "displayName": row["display_name"], "avatarUrl": row["avatar_url"]}}

    @staticmethod
    def comment_json(row):
        return {"id": row["id"], "body": row["body"], "createdAt": row["created_at"],
                "user": {"id": row["user_id"], "username": row["username"],
                         "displayName": row["display_name"], "avatarUrl": row["avatar_url"]}}

    def do_POST(self):
        path = urlparse(self.path).path
        if not path.startswith("/api/"):
            return self.send_json(404, {"error": "API route not found"})
        bucket = "auth" if path in ("/api/login", "/api/register", "/api/forgot-password", "/api/reset-password") else "write"
        remote = self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()
        if len(RATE_BUCKETS) > 5000:
            cutoff=time.time()-3600
            for old_key in list(RATE_BUCKETS):
                RATE_BUCKETS[old_key]=[stamp for stamp in RATE_BUCKETS[old_key] if stamp>cutoff]
                if not RATE_BUCKETS[old_key]: RATE_BUCKETS.pop(old_key,None)
        if not allow_rate(remote + ":" + bucket, 10 if bucket == "auth" else 40, 60):
            return self.send_json(429, {"error": "Too many requests. Please wait a minute."})
        try:
            data = self.read_json()
            with connect() as db:
                if path == "/api/forgot-password":
                    email = str(data.get("email", "")).strip().lower()[:254]
                    account = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
                    if account:
                        token = secrets.token_urlsafe(32)
                        digest = hash_token(token)
                        db.execute("DELETE FROM email_tokens WHERE user_id=? AND purpose='reset'", (account["id"],))
                        db.execute("INSERT INTO email_tokens(token_hash,user_id,purpose,expires_at) VALUES(?,?,?,?)", (digest,account["id"],"reset",now()+3600))
                        link = f"{SITE_URL or f'http://localhost:{PORT}'}/?reset={token}"
                        send_mail(email,"Reset your Masaha password",f"Use this link within one hour to reset your password:\n{link}")
                    return self.send_json(200, {"ok": True})
                if path == "/api/reset-password":
                    token = str(data.get("token", ""))
                    password = str(data.get("password", ""))
                    if len(password) < 10: return self.send_json(400, {"error": "Password must have at least 10 characters"})
                    row = db.execute("SELECT * FROM email_tokens WHERE token_hash=? AND purpose='reset' AND expires_at>?", (hash_token(token),now())).fetchone()
                    if not row: return self.send_json(400, {"error": "Reset link is invalid or expired"})
                    salt=secrets.token_bytes(16); password_hash="scrypt$"+salt.hex()+"$"+hashlib.scrypt(password.encode(),salt=salt,n=2**14,r=8,p=1).hex()
                    db.execute("UPDATE users SET password_hash=? WHERE id=?", (password_hash,row["user_id"]))
                    db.execute("DELETE FROM sessions WHERE user_id=?", (row["user_id"],))
                    db.execute("DELETE FROM email_tokens WHERE token_hash=?", (row["token_hash"],))
                    return self.send_json(200, {"ok": True})
                if path == "/api/register":
                    name = str(data.get("displayName", "")).strip()[:50]
                    username = str(data.get("username", "")).strip().lower()
                    email = str(data.get("email", "")).strip().lower()[:254]
                    password = str(data.get("password", ""))
                    if len(name) < 2 or "@" not in email or len(password) < 10:
                        return self.send_json(400, {"error": "Name, valid email, and password (10+ characters) required"})
                    if not re.fullmatch(r"[a-z0-9_]{3,24}", username):
                        return self.send_json(400, {"error": "USERNAME_INVALID"})
                    if db.execute("SELECT 1 FROM users WHERE username=? COLLATE NOCASE", (username,)).fetchone():
                        return self.send_json(409, {"error": "USERNAME_TAKEN"})
                    salt = secrets.token_bytes(16)
                    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
                    encoded = "scrypt$" + salt.hex() + "$" + digest.hex()
                    role = "admin" if ADMIN_EMAIL and email == ADMIN_EMAIL else "member"
                    try:
                        cur = db.execute("INSERT INTO users(username,display_name,email,password_hash,role,created_at) VALUES(?,?,?,?,?,?)",
                                         (username, name, email, encoded, role, now()))
                    except sqlite3.IntegrityError:
                        if db.execute("SELECT 1 FROM users WHERE username=? COLLATE NOCASE", (username,)).fetchone():
                            return self.send_json(409, {"error": "USERNAME_TAKEN"})
                        return self.send_json(409, {"error": "That email is already registered"})
                    user = db.execute("SELECT * FROM users WHERE id=?", (cur.lastrowid,)).fetchone()
                    token = secrets.token_urlsafe(32)
                    db.execute("INSERT INTO email_tokens(token_hash,user_id,purpose,expires_at) VALUES(?,?,?,?)", (hash_token(token),user["id"],"verify",now()+86400))
                    link = f"{SITE_URL or f'http://localhost:{PORT}'}/?verify={token}"
                    send_mail(email,"Verify your Masaha account",f"Open this link within 24 hours to verify your email:\n{link}")
                    return self.send_json(201, {"verificationRequired": True})
                if path == "/api/login":
                    email = str(data.get("email", "")).strip().lower()
                    password = str(data.get("password", ""))
                    user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
                    valid = False
                    if user:
                        try:
                            _, salt_hex, hash_hex = user["password_hash"].split("$")
                            candidate = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1)
                            valid = hmac.compare_digest(candidate.hex(), hash_hex)
                        except (ValueError, TypeError):
                            pass
                    if not valid:
                        return self.send_json(401, {"error": "Email or password is incorrect"})
                    if user["is_banned"]:
                        return self.send_json(403, {"error": "This account is suspended"})
                    if not user["email_verified"]:
                        return self.send_json(403, {"error": "Verify your email first. Check your email or server log."})
                    if ADMIN_EMAIL and email == ADMIN_EMAIL and user["role"] != "admin":
                        db.execute("UPDATE users SET role='admin' WHERE id=?", (user["id"],))
                        user = db.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
                    token = secrets.token_urlsafe(32)
                    db.execute("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)",
                               (hashlib.sha256(token.encode()).hexdigest(), user["id"], now()+SESSION_SECONDS))
                    return self.send_json(200, {"user": public_user(user)}, self.cookie_headers(token, SESSION_SECONDS))
                if path == "/api/logout":
                    user = self.session_user(db)
                    if user:
                        raw = cookies.SimpleCookie(self.headers.get("Cookie", ""))["masaha_session"].value
                        db.execute("DELETE FROM sessions WHERE token_hash=?", (hashlib.sha256(raw.encode()).hexdigest(),))
                    return self.send_json(200, {"ok": True}, self.cookie_headers("", 0))
                user = self.require_user(db)
                if not user: return
                if path == "/api/topics":
                    title = str(data.get("title", "")).strip()
                    body = str(data.get("body", "")).strip()
                    category = str(data.get("category", "general"))
                    if not title or len(title) > 120 or not body or len(body) > 5000 or category not in ("programming", "learning", "general"):
                        return self.send_json(400, {"error": "Check the title, message, and category"})
                    try: image_url = save_image(data.get("image", "")) if data.get("image") else ""
                    except (ValueError, binascii.Error) as exc: return self.send_json(400, {"error": str(exc)})
                    cur = db.execute("INSERT INTO topics(user_id,title,body,category,created_at,image_url) VALUES(?,?,?,?,?,?)",
                                     (user["id"], title, body, category, now(), image_url))
                    return self.send_json(201, {"id": cur.lastrowid})
                if path.startswith("/api/topics/") and path.endswith("/comments"):
                    try: topic_id = int(path.split("/")[3])
                    except (ValueError, IndexError): return self.send_json(400, {"error": "Invalid topic id"})
                    body = str(data.get("body", "")).strip()
                    topic = db.execute("SELECT id FROM topics WHERE id=? AND deleted=0", (topic_id,)).fetchone()
                    if not topic: return self.send_json(404, {"error": "Topic not found"})
                    if not body or len(body) > 3000: return self.send_json(400, {"error": "Comment must be 1–3000 characters"})
                    cur = db.execute("INSERT INTO comments(topic_id,user_id,body,created_at) VALUES(?,?,?,?)",
                                     (topic_id, user["id"], body, now()))
                    owner = db.execute("SELECT user_id FROM topics WHERE id=?", (topic_id,)).fetchone()[0]
                    if owner != user["id"]: db.execute("INSERT INTO notifications(user_id,actor_id,topic_id,kind,created_at) VALUES(?,?,?,?,?)", (owner,user["id"],topic_id,"reply",now()))
                    return self.send_json(201, {"id": cur.lastrowid})
                if path == "/api/me/avatar":
                    try: avatar = save_image(data.get("image"))
                    except (ValueError, binascii.Error) as exc: return self.send_json(400, {"error": str(exc)})
                    db.execute("UPDATE users SET avatar_url=? WHERE id=?", (avatar,user["id"]))
                    return self.send_json(200, {"avatarUrl": avatar})
                if path.startswith("/api/topics/") and path.endswith("/like"):
                    try: topic_id=int(path.split("/")[3])
                    except (ValueError,IndexError): return self.send_json(400,{"error":"Invalid topic id"})
                    topic=db.execute("SELECT user_id FROM topics WHERE id=? AND deleted=0",(topic_id,)).fetchone()
                    if not topic: return self.send_json(404,{"error":"Topic not found"})
                    old=db.execute("SELECT 1 FROM likes WHERE user_id=? AND topic_id=?",(user["id"],topic_id)).fetchone()
                    if old: db.execute("DELETE FROM likes WHERE user_id=? AND topic_id=?",(user["id"],topic_id)); liked=False
                    else:
                        db.execute("INSERT INTO likes(user_id,topic_id,created_at) VALUES(?,?,?)",(user["id"],topic_id,now())); liked=True
                        if topic["user_id"]!=user["id"]: db.execute("INSERT INTO notifications(user_id,actor_id,topic_id,kind,created_at) VALUES(?,?,?,?,?)",(topic["user_id"],user["id"],topic_id,"like",now()))
                    count=db.execute("SELECT COUNT(*) FROM likes WHERE topic_id=?",(topic_id,)).fetchone()[0]
                    return self.send_json(200,{"liked":liked,"likeCount":count})
                if path.startswith("/api/topics/") and path.endswith("/bookmark"):
                    try: topic_id=int(path.split("/")[3])
                    except (ValueError,IndexError): return self.send_json(400,{"error":"Invalid topic id"})
                    if not db.execute("SELECT 1 FROM topics WHERE id=? AND deleted=0",(topic_id,)).fetchone(): return self.send_json(404,{"error":"Topic not found"})
                    old=db.execute("SELECT 1 FROM bookmarks WHERE user_id=? AND topic_id=?",(user["id"],topic_id)).fetchone()
                    if old: db.execute("DELETE FROM bookmarks WHERE user_id=? AND topic_id=?",(user["id"],topic_id)); saved=False
                    else: db.execute("INSERT INTO bookmarks(user_id,topic_id,created_at) VALUES(?,?,?)",(user["id"],topic_id,now())); saved=True
                    return self.send_json(200,{"saved":saved})
                if path.startswith("/api/admin/users/") and path.endswith("/ban"):
                    if not self.require_admin(user): return
                    try: target=int(path.split("/")[4])
                    except (ValueError,IndexError): return self.send_json(400,{"error":"Invalid user id"})
                    member=db.execute("SELECT role,is_banned FROM users WHERE id=?",(target,)).fetchone()
                    if not member or member["role"]=="admin" or target==user["id"]: return self.send_json(400,{"error":"This account cannot be suspended"})
                    banned=not bool(member["is_banned"]); db.execute("UPDATE users SET is_banned=? WHERE id=?",(int(banned),target))
                    if banned: db.execute("DELETE FROM sessions WHERE user_id=?",(target,))
                    return self.send_json(200,{"banned":banned})
                if path == "/api/reports":
                    kind = data.get("targetType")
                    try: target_id = int(data.get("targetId"))
                    except (ValueError, TypeError): return self.send_json(400, {"error": "Invalid report target"})
                    reason = str(data.get("reason", "")).strip()[:500]
                    if kind not in ("topic", "comment") or not reason:
                        return self.send_json(400, {"error": "Choose a reason for the report"})
                    exists = db.execute("SELECT id FROM topics WHERE id=? AND deleted=0", (target_id,)).fetchone() if kind == "topic" else db.execute("SELECT id FROM comments WHERE id=?", (target_id,)).fetchone()
                    if not exists: return self.send_json(404, {"error": "Content not found"})
                    db.execute("INSERT INTO reports(reporter_id,target_type,target_id,reason,created_at) VALUES(?,?,?,?,?)",
                               (user["id"], kind, target_id, reason, now()))
                    return self.send_json(201, {"ok": True})
                if path.startswith("/api/topics/") and path.endswith("/delete"):
                    if not self.require_admin(user): return
                    try: topic_id = int(path.split("/")[3])
                    except (ValueError, IndexError): return self.send_json(400, {"error": "Invalid topic id"})
                    db.execute("UPDATE topics SET deleted=1 WHERE id=?", (topic_id,))
                    db.execute("UPDATE reports SET status='resolved' WHERE target_type='topic' AND target_id=?", (topic_id,))
                    return self.send_json(200, {"ok": True})
                if path.startswith("/api/comments/") and path.endswith("/delete"):
                    if not self.require_admin(user): return
                    try: comment_id = int(path.split("/")[3])
                    except (ValueError, IndexError): return self.send_json(400, {"error": "Invalid comment id"})
                    db.execute("DELETE FROM comments WHERE id=?", (comment_id,))
                    db.execute("UPDATE reports SET status='resolved' WHERE target_type='comment' AND target_id=?", (comment_id,))
                    return self.send_json(200, {"ok": True})
                if path.startswith("/api/reports/") and path.endswith("/resolve"):
                    if not self.require_admin(user): return
                    try: report_id = int(path.split("/")[3])
                    except (ValueError, IndexError): return self.send_json(400, {"error": "Invalid report id"})
                    db.execute("UPDATE reports SET status='resolved' WHERE id=?", (report_id,))
                    return self.send_json(200, {"ok": True})
        except ValueError as exc:
            return self.send_json(400, {"error": str(exc)})
        except Exception as exc:
            print("Request error:", repr(exc))
            return self.send_json(500, {"error": "Server error"})
        return self.send_json(404, {"error": "API route not found"})

    def do_PUT(self):
        if urlparse(self.path).path != "/api/me/profile":
            return self.send_json(404, {"error": "API route not found"})
        try:
            data = self.read_json()
            with connect() as db:
                user = self.require_user(db)
                if not user: return
                display_name = str(data.get("displayName", user["display_name"])).strip()[:50]
                bio = str(data.get("bio", "")).strip()[:500]
                if len(display_name) < 2:
                    return self.send_json(400, {"error": "Display name must have at least 2 characters"})
                db.execute("UPDATE users SET display_name=?,bio=? WHERE id=?", (display_name,bio,user["id"]))
                updated = db.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
                return self.send_json(200, {"user": public_user(updated)})
        except ValueError as exc:
            return self.send_json(400, {"error": str(exc)})
        except Exception as exc:
            print("Request error:", repr(exc))
            return self.send_json(500, {"error": "Server error"})


if __name__ == "__main__":
    init_db()
    print(f"Masaha forum running at http://{HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), ForumHandler).serve_forever()
