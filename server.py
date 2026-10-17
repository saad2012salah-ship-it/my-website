#!/usr/bin/env python3
"""Small standard-library forum server for the Masaha demo project."""
import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import shutil
import smtplib
import sqlite3
import ssl
import subprocess
import time
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from email.message import EmailMessage
from http import cookies
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("MASAHA_DB", ROOT / "masaha.sqlite3"))
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "10000"))
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "").strip().lower()
SITE_URL = os.environ.get("SITE_URL", "").rstrip("/")
SESSION_SECONDS = 14 * 24 * 60 * 60
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "0") == "1"
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USER)
BACKUP_DIR = Path(os.environ.get("MASAHA_BACKUP_DIR", ROOT / "backups"))
BACKUP_INTERVAL = max(3600, int(os.environ.get("MASAHA_BACKUP_INTERVAL", "86400")))
BACKUP_KEEP = max(1, int(os.environ.get("MASAHA_BACKUP_KEEP", "7")))
BACKUP_BUCKET = os.environ.get("MASAHA_BACKUP_BUCKET", "").rstrip("/")


def send_email(to, subject, body):
    if not SMTP_HOST or not SMTP_FROM:
        return False
    message = EmailMessage()
    message["From"] = SMTP_FROM
    message["To"] = to
    message["Subject"] = subject
    message.set_content(body)
    context = ssl.create_default_context()
    if SMTP_PORT == 465:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context, timeout=15) as smtp:
            if SMTP_USER: smtp.login(SMTP_USER, SMTP_PASSWORD)
            smtp.send_message(message)
    else:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as smtp:
            smtp.starttls(context=context)
            if SMTP_USER: smtp.login(SMTP_USER, SMTP_PASSWORD)
            smtp.send_message(message)
    return True


def issue_verification_code(db, user):
    current = now()
    previous = db.execute("SELECT created_at FROM verification_tokens WHERE user_id=?", (user["id"],)).fetchone()
    if previous and previous["created_at"] > current - 60:
        return False
    code = f"{secrets.randbelow(1_000_000):06d}"
    db.execute("DELETE FROM verification_tokens WHERE user_id=?", (user["id"],))
    db.execute("INSERT INTO verification_tokens(token_hash,user_id,expires_at,attempts,created_at) VALUES(?,?,?,?,?)",
               (hashlib.sha256(code.encode()).hexdigest(), user["id"], current+600, 0, current))
    try:
        sent = send_email(user["email"], "Your Masaha verification code", f"Your verification code is {code}. It expires in 10 minutes.")
    except Exception as exc:
        print("Verification email failed:", repr(exc)); sent = False
    if not sent:
        print(f"Email verification code for {user['email']} (valid for 10 minutes): {code}")
    return True


def backup_database():
    """Create a consistent SQLite snapshot and retain only the newest backups."""
    BACKUP_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(BACKUP_DIR, 0o700)
    except OSError:
        pass
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    target = BACKUP_DIR / f"masaha-{stamp}.sqlite3"
    temporary = BACKUP_DIR / f".{target.name}.tmp"
    try:
        with sqlite3.connect(DB_PATH, timeout=30) as source:
            with sqlite3.connect(temporary, timeout=30) as destination:
                source.backup(destination)
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()
    copies = sorted(BACKUP_DIR.glob("masaha-*.sqlite3"), key=lambda item: item.stat().st_mtime, reverse=True)
    for old in copies[BACKUP_KEEP:]:
        old.unlink(missing_ok=True)
    print(f"Database backup saved: {target}")
    if BACKUP_BUCKET:
        gcloud = shutil.which("gcloud")
        if not gcloud:
            raise RuntimeError("MASAHA_BACKUP_BUCKET is set but the gcloud CLI is not installed")
        if not BACKUP_BUCKET.startswith("gs://"):
            raise ValueError("MASAHA_BACKUP_BUCKET must start with gs://")
        remote = f"{BACKUP_BUCKET}/{target.name}"
        subprocess.run([gcloud, "storage", "cp", str(target), remote], check=True, timeout=180, capture_output=True, text=True)
        print(f"Offsite database backup uploaded: {remote}")
    return target


def consume_rate_limit(db, user_id, action, maximum, window_seconds):
    current = now()
    cutoff = current - window_seconds
    db.execute("DELETE FROM rate_events WHERE created_at<?", (current - 86400,))
    count = db.execute("SELECT COUNT(*) FROM rate_events WHERE user_id=? AND action=? AND created_at>?", (user_id, action, cutoff)).fetchone()[0]
    if count >= maximum:
        first = db.execute("SELECT MIN(created_at) FROM rate_events WHERE user_id=? AND action=? AND created_at>?", (user_id, action, cutoff)).fetchone()[0]
        return max(1, window_seconds - (current - first))
    db.execute("INSERT INTO rate_events(user_id,action,created_at) VALUES(?,?,?)", (user_id, action, current))
    return 0


def backup_worker():
    while True:
        time.sleep(BACKUP_INTERVAL)
        try:
            backup_database()
        except Exception as exc:
            print("Scheduled database backup failed:", repr(exc))


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
          password_hash TEXT NOT NULL, bio TEXT NOT NULL DEFAULT '',
          role TEXT NOT NULL DEFAULT 'member', created_at INTEGER NOT NULL,
          avatar_url TEXT NOT NULL DEFAULT '', is_banned INTEGER NOT NULL DEFAULT 0,
          email_verified INTEGER NOT NULL DEFAULT 0
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
        CREATE TABLE IF NOT EXISTS likes (
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          topic_id INTEGER NOT NULL REFERENCES topics(id) ON DELETE CASCADE,
          created_at INTEGER NOT NULL, PRIMARY KEY(user_id,topic_id)
        );
        CREATE TABLE IF NOT EXISTS bookmarks (
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          topic_id INTEGER NOT NULL REFERENCES topics(id) ON DELETE CASCADE,
          created_at INTEGER NOT NULL, PRIMARY KEY(user_id,topic_id)
        );
        CREATE TABLE IF NOT EXISTS notifications (
          id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          actor_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          topic_id INTEGER NOT NULL REFERENCES topics(id) ON DELETE CASCADE,
          kind TEXT NOT NULL, created_at INTEGER NOT NULL, seen INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS reset_tokens (
          token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          expires_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS verification_tokens (
          token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          expires_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
          created_at INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS rate_events (
          id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          action TEXT NOT NULL, created_at INTEGER NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS users_username_nocase ON users(username COLLATE NOCASE);
        CREATE INDEX IF NOT EXISTS topics_created ON topics(created_at DESC);
        CREATE INDEX IF NOT EXISTS comments_topic ON comments(topic_id, created_at);
        CREATE INDEX IF NOT EXISTS reports_status ON reports(status, created_at);
        CREATE INDEX IF NOT EXISTS rate_events_user_action ON rate_events(user_id,action,created_at);
        """)
        # Add fields when opening a database created by an older version.
        for table, name, declaration in (
            ("users", "avatar_url", "TEXT NOT NULL DEFAULT ''"),
            ("users", "is_banned", "INTEGER NOT NULL DEFAULT 0"),
            ("users", "email_verified", "INTEGER NOT NULL DEFAULT 0"),
            ("topics", "image_url", "TEXT NOT NULL DEFAULT ''"),
        ):
            columns = {row[1] for row in db.execute(f"PRAGMA table_info({table})")}
            if name not in columns:
                db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")
        verify_columns = {row[1] for row in db.execute("PRAGMA table_info(verification_tokens)")}
        if "attempts" not in verify_columns:
            db.execute("ALTER TABLE verification_tokens ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0")
        if "created_at" not in verify_columns:
            db.execute("ALTER TABLE verification_tokens ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0")


def now():
    return int(time.time())


def public_user(row):
    if not row:
        return None
    return {"id": row["id"], "username": row["username"],
            "displayName": row["display_name"], "bio": row["bio"],
            "role": row["role"], "createdAt": row["created_at"],
            "avatarUrl": row["avatar_url"] if "avatar_url" in row.keys() else "",
            "is_banned": row["is_banned"] if "is_banned" in row.keys() else 0}


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
                          WHERE s.token_hash=? AND s.expires_at>? AND u.email_verified=1""", (digest, now())).fetchone()
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
            if path not in ("/", "/index.html", "/app.js", "/style.css"):
                return self.send_error(404)
            return super().do_GET()
        with connect() as db:
            if path == "/api/me":
                return self.send_json(200, {"user": public_user(self.session_user(db))})
            if path == "/api/bookmarks":
                user = self.require_user(db)
                if not user: return
                rows = db.execute("""SELECT t.*,u.username,u.display_name,u.avatar_url AS author_avatar,
                    (SELECT COUNT(*) FROM comments c WHERE c.topic_id=t.id) AS comment_count,
                    (SELECT COUNT(*) FROM likes l WHERE l.topic_id=t.id) AS like_count,
                    1 AS bookmarked_by_me, EXISTS(SELECT 1 FROM likes l WHERE l.topic_id=t.id AND l.user_id=?) AS liked_by_me
                    FROM bookmarks b JOIN topics t ON t.id=b.topic_id JOIN users u ON u.id=t.user_id
                    WHERE b.user_id=? AND t.deleted=0 ORDER BY b.created_at DESC""", (user["id"], user["id"])).fetchall()
                return self.send_json(200, {"topics": [self.topic_json(row) for row in rows]})
            if path == "/api/notifications":
                user = self.require_user(db)
                if not user: return
                query = parse_qs(parsed.query)
                if query.get("mark", ["0"])[0] == "1":
                    db.execute("UPDATE notifications SET seen=1 WHERE user_id=?", (user["id"],))
                rows = db.execute("""SELECT n.*,a.display_name AS actor,t.title FROM notifications n
                    JOIN users a ON a.id=n.actor_id JOIN topics t ON t.id=n.topic_id
                    WHERE n.user_id=? ORDER BY n.created_at DESC LIMIT 50""", (user["id"],)).fetchall()
                unread = db.execute("SELECT COUNT(*) FROM notifications WHERE user_id=? AND seen=0", (user["id"],)).fetchone()[0]
                return self.send_json(200, {"notifications": [dict(row) for row in rows], "unread": unread})
            if path == "/api/admin/users":
                user = self.require_user(db)
                if not user or not self.require_admin(user): return
                rows = db.execute("SELECT id,username,display_name,role,is_banned FROM users ORDER BY created_at DESC LIMIT 200").fetchall()
                return self.send_json(200, {"users": [dict(row) for row in rows]})
            if path == "/api/topics":
                query = parse_qs(parsed.query)
                search = query.get("q", [""])[0].strip()[:100]
                category = query.get("category", [""])[0]
                sort = query.get("sort", ["newest"])[0]
                try:
                    limit = max(1, min(50, int(query.get("limit", ["20"])[0])))
                    offset = max(0, int(query.get("offset", ["0"])[0]))
                except ValueError:
                    limit, offset = 20, 0
                viewer = self.session_user(db)
                select_sql = """SELECT t.*, u.username, u.display_name,u.avatar_url AS author_avatar,
                         (SELECT COUNT(*) FROM comments c WHERE c.topic_id=t.id) AS comment_count,
                         (SELECT COUNT(*) FROM likes l WHERE l.topic_id=t.id) AS like_count,
                         EXISTS(SELECT 1 FROM likes l WHERE l.topic_id=t.id AND l.user_id=?) AS liked_by_me,
                         EXISTS(SELECT 1 FROM bookmarks b WHERE b.topic_id=t.id AND b.user_id=?) AS bookmarked_by_me
                         FROM topics t JOIN users u ON u.id=t.user_id WHERE t.deleted=0"""
                filters = ""
                filter_values = []
                if search:
                    filters += " AND (t.title LIKE ? OR t.body LIKE ? OR u.display_name LIKE ?)"
                    needle = "%" + search + "%"
                    filter_values.extend([needle, needle, needle])
                if category in ("programming", "learning", "general"):
                    filters += " AND t.category=?"; filter_values.append(category)
                order = " ORDER BY t.created_at DESC"
                if sort == "popular":
                    order = " ORDER BY like_count DESC,t.created_at DESC"
                elif sort == "oldest":
                    order = " ORDER BY t.created_at ASC"
                total = db.execute("SELECT COUNT(*) FROM topics t JOIN users u ON u.id=t.user_id WHERE t.deleted=0" + filters, filter_values).fetchone()[0]
                sql = select_sql + filters + order + " LIMIT ? OFFSET ?"
                values = [viewer["id"] if viewer else -1, viewer["id"] if viewer else -1, *filter_values, limit, offset]
                rows = db.execute(sql, values).fetchall()
                return self.send_json(200, {"topics": [self.topic_json(row) for row in rows], "total": total})
            if path.startswith("/api/topics/") and path.count("/") == 3:
                try: topic_id = int(path.rsplit("/", 1)[1])
                except ValueError: return self.send_json(400, {"error": "Invalid topic id"})
                viewer = self.session_user(db)
                topic = db.execute("""SELECT t.*,u.username,u.display_name,u.avatar_url AS author_avatar,
                    (SELECT COUNT(*) FROM comments c WHERE c.topic_id=t.id) AS comment_count,
                    (SELECT COUNT(*) FROM likes l WHERE l.topic_id=t.id) AS like_count,
                    EXISTS(SELECT 1 FROM likes l WHERE l.topic_id=t.id AND l.user_id=?) AS liked_by_me,
                    EXISTS(SELECT 1 FROM bookmarks b WHERE b.topic_id=t.id AND b.user_id=?) AS bookmarked_by_me
                    FROM topics t JOIN users u ON u.id=t.user_id WHERE t.id=? AND t.deleted=0""", (viewer["id"] if viewer else -1, viewer["id"] if viewer else -1, topic_id)).fetchone()
                if not topic: return self.send_json(404, {"error": "Topic not found"})
                comments = db.execute("""SELECT c.*,u.username,u.display_name FROM comments c
                    JOIN users u ON u.id=c.user_id WHERE c.topic_id=? ORDER BY c.created_at""", (topic_id,)).fetchall()
                return self.send_json(200, {"topic": self.topic_json(topic), "comments": [self.comment_json(x) for x in comments]})
            if path.startswith("/api/users/"):
                try: user_id = int(path.rsplit("/", 1)[1])
                except ValueError: return self.send_json(400, {"error": "Invalid user id"})
                user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
                if not user: return self.send_json(404, {"error": "Profile not found"})
                posts = db.execute("""SELECT t.*,u.username,u.display_name,u.avatar_url AS author_avatar,
                    (SELECT COUNT(*) FROM comments c WHERE c.topic_id=t.id) AS comment_count,
                    (SELECT COUNT(*) FROM likes l WHERE l.topic_id=t.id) AS like_count,
                    0 AS liked_by_me, 0 AS bookmarked_by_me
                    FROM topics t JOIN users u ON u.id=t.user_id WHERE t.user_id=? AND t.deleted=0
                    ORDER BY t.created_at DESC LIMIT 50""", (user_id,)).fetchall()
                return self.send_json(200, {"user": public_user(user), "topics": [self.topic_json(x) for x in posts]})
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
                "commentCount": row["comment_count"], "likeCount": row["like_count"] if "like_count" in row.keys() else 0,
                "likedByMe": bool(row["liked_by_me"]) if "liked_by_me" in row.keys() else False,
                "bookmarkedByMe": bool(row["bookmarked_by_me"]) if "bookmarked_by_me" in row.keys() else False,
                "imageUrl": row["image_url"] if "image_url" in row.keys() else "",
                "user": {"id": row["user_id"], "username": row["username"],
                "displayName": row["display_name"], "avatarUrl": row["author_avatar"] if "author_avatar" in row.keys() else ""}}

    @staticmethod
    def comment_json(row):
        return {"id": row["id"], "body": row["body"], "createdAt": row["created_at"],
                "user": {"id": row["user_id"], "username": row["username"],
                         "displayName": row["display_name"]}}

    def do_POST(self):
        path = urlparse(self.path).path
        if not path.startswith("/api/"):
            return self.send_json(404, {"error": "API route not found"})
        try:
            data = self.read_json()
            with connect() as db:
                if path == "/api/verify":
                    email = str(data.get("email", "")).strip().lower()
                    code = str(data.get("code", "")).strip()
                    user = db.execute("SELECT * FROM users WHERE email=? AND email_verified=0", (email,)).fetchone()
                    row = db.execute("SELECT * FROM verification_tokens WHERE user_id=? AND expires_at>?", (user["id"], now())).fetchone() if user else None
                    if not row:
                        return self.send_json(400, {"error": "CODE_INVALID"})
                    if row["attempts"] >= 5:
                        db.execute("DELETE FROM verification_tokens WHERE user_id=?", (user["id"],))
                        return self.send_json(400, {"error": "CODE_EXPIRED"})
                    digest = hashlib.sha256(code.encode()).hexdigest()
                    if not hmac.compare_digest(digest, row["token_hash"]):
                        attempts = row["attempts"] + 1
                        if attempts >= 5:
                            db.execute("DELETE FROM verification_tokens WHERE user_id=?", (user["id"],))
                            return self.send_json(400, {"error": "CODE_EXPIRED"})
                        db.execute("UPDATE verification_tokens SET attempts=? WHERE user_id=?", (attempts, user["id"]))
                        return self.send_json(400, {"error": "CODE_INVALID"})
                    db.execute("UPDATE users SET email_verified=1 WHERE id=?", (user["id"],))
                    if ADMIN_EMAIL and email == ADMIN_EMAIL:
                        db.execute("UPDATE users SET role='admin' WHERE id=?", (user["id"],))
                    db.execute("DELETE FROM verification_tokens WHERE user_id=?", (user["id"],))
                    return self.send_json(200, {"ok": True})
                if path == "/api/verification-resend":
                    email = str(data.get("email", "")).strip().lower()
                    user = db.execute("SELECT * FROM users WHERE email=? AND email_verified=0", (email,)).fetchone()
                    if user: issue_verification_code(db, user)
                    return self.send_json(200, {"sent": True})
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
                    try:
                        cur = db.execute("INSERT INTO users(username,display_name,email,password_hash,role,created_at,email_verified) VALUES(?,?,?,?,?,?,0)",
                                         (username, name, email, encoded, "member", now()))
                    except sqlite3.IntegrityError:
                        if db.execute("SELECT 1 FROM users WHERE username=? COLLATE NOCASE", (username,)).fetchone():
                            return self.send_json(409, {"error": "USERNAME_TAKEN"})
                        return self.send_json(409, {"error": "That email is already registered"})
                    user = db.execute("SELECT * FROM users WHERE id=?", (cur.lastrowid,)).fetchone()
                    issue_verification_code(db, user)
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
                    if not user["email_verified"]:
                        issue_verification_code(db, user)
                        return self.send_json(403, {"error": "EMAIL_NOT_VERIFIED"})
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
                if path == "/api/forgot-password":
                    email = str(data.get("email", "")).strip().lower()
                    account = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
                    if account:
                        token = secrets.token_urlsafe(32)
                        db.execute("DELETE FROM reset_tokens WHERE user_id=?", (account["id"],))
                        db.execute("INSERT INTO reset_tokens(token_hash,user_id,expires_at) VALUES(?,?,?)", (hashlib.sha256(token.encode()).hexdigest(), account["id"], now()+3600))
                        base = SITE_URL or f"http://127.0.0.1:{PORT}"
                        link = f"{base}/?reset={token}"
                        try:
                            sent = send_email(email, "Reset your Masaha password", f"Open this link within one hour to reset your password:\n\n{link}")
                        except Exception as exc:
                            print("Password reset email failed:", repr(exc)); sent = False
                        if not sent: print(f"Password reset link (valid for 1 hour): {link}")
                    return self.send_json(200, {"ok": True})
                if path == "/api/reset-password":
                    token = str(data.get("token", ""))
                    password = str(data.get("password", ""))
                    if len(password) < 10: return self.send_json(400, {"error": "Password must be at least 10 characters"})
                    digest = hashlib.sha256(token.encode()).hexdigest()
                    reset = db.execute("SELECT user_id FROM reset_tokens WHERE token_hash=? AND expires_at>?", (digest, now())).fetchone()
                    if not reset: return self.send_json(400, {"error": "Reset link is invalid or expired"})
                    salt = secrets.token_bytes(16)
                    password_hash = "scrypt$" + salt.hex() + "$" + hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1).hex()
                    db.execute("UPDATE users SET password_hash=? WHERE id=?", (password_hash, reset["user_id"]))
                    db.execute("DELETE FROM reset_tokens WHERE user_id=?", (reset["user_id"],))
                    db.execute("DELETE FROM sessions WHERE user_id=?", (reset["user_id"],))
                    return self.send_json(200, {"ok": True}, self.cookie_headers("", 0))
                user = self.require_user(db)
                if not user: return
                if path.startswith("/api/topics/") and path.endswith("/like"):
                    try: topic_id = int(path.split("/")[3])
                    except (ValueError, IndexError): return self.send_json(400, {"error": "Invalid topic id"})
                    topic = db.execute("SELECT user_id FROM topics WHERE id=? AND deleted=0", (topic_id,)).fetchone()
                    if not topic: return self.send_json(404, {"error": "Topic not found"})
                    existing = db.execute("SELECT 1 FROM likes WHERE user_id=? AND topic_id=?", (user["id"], topic_id)).fetchone()
                    if existing:
                        db.execute("DELETE FROM likes WHERE user_id=? AND topic_id=?", (user["id"], topic_id))
                        liked = False
                    else:
                        db.execute("INSERT INTO likes(user_id,topic_id,created_at) VALUES(?,?,?)", (user["id"], topic_id, now()))
                        liked = True
                        if topic["user_id"] != user["id"]:
                            db.execute("INSERT INTO notifications(user_id,actor_id,topic_id,kind,created_at) VALUES(?,?,?,?,?)", (topic["user_id"], user["id"], topic_id, "like", now()))
                    return self.send_json(200, {"liked": liked})
                if path.startswith("/api/topics/") and path.endswith("/bookmark"):
                    try: topic_id = int(path.split("/")[3])
                    except (ValueError, IndexError): return self.send_json(400, {"error": "Invalid topic id"})
                    if not db.execute("SELECT 1 FROM topics WHERE id=? AND deleted=0", (topic_id,)).fetchone(): return self.send_json(404, {"error": "Topic not found"})
                    existing = db.execute("SELECT 1 FROM bookmarks WHERE user_id=? AND topic_id=?", (user["id"], topic_id)).fetchone()
                    if existing: db.execute("DELETE FROM bookmarks WHERE user_id=? AND topic_id=?", (user["id"], topic_id))
                    else: db.execute("INSERT INTO bookmarks(user_id,topic_id,created_at) VALUES(?,?,?)", (user["id"], topic_id, now()))
                    return self.send_json(200, {"saved": not bool(existing)})
                if path.startswith("/api/admin/users/") and path.endswith("/ban"):
                    if not self.require_admin(user): return
                    try: target_id = int(path.split("/")[4])
                    except (ValueError, IndexError): return self.send_json(400, {"error": "Invalid user id"})
                    target = db.execute("SELECT role FROM users WHERE id=?", (target_id,)).fetchone()
                    if not target: return self.send_json(404, {"error": "Member not found"})
                    if target["role"] == "admin" or target_id == user["id"]: return self.send_json(400, {"error": "This account cannot be suspended"})
                    db.execute("UPDATE users SET is_banned=1-is_banned WHERE id=?", (target_id,))
                    return self.send_json(200, {"ok": True})
                if path == "/api/me/avatar":
                    image = str(data.get("image", ""))
                    if len(image) > 2_800_000 or not re.fullmatch(r"data:image/(?:png|jpeg|webp);base64,[A-Za-z0-9+/]+={0,2}", image):
                        return self.send_json(400, {"error": "Image must be PNG, JPEG, or WebP and under 2 MB"})
                    db.execute("UPDATE users SET avatar_url=? WHERE id=?", (image, user["id"]))
                    return self.send_json(200, {"avatarUrl": image})
                if path == "/api/topics":
                    title = str(data.get("title", "")).strip()
                    body = str(data.get("body", "")).strip()
                    category = str(data.get("category", "general"))
                    if not title or len(title) > 120 or not body or len(body) > 5000 or category not in ("programming", "learning", "general"):
                        return self.send_json(400, {"error": "Check the title, message, and category"})
                    image = str(data.get("image", ""))
                    if image and (len(image) > 2_800_000 or not re.fullmatch(r"data:image/(?:png|jpeg|webp);base64,[A-Za-z0-9+/]+={0,2}", image)):
                        return self.send_json(400, {"error": "Image must be PNG, JPEG, or WebP and under 2 MB"})
                    duplicate = db.execute("SELECT 1 FROM topics WHERE user_id=? AND deleted=0 AND lower(title)=lower(?) AND lower(body)=lower(?) AND created_at>? LIMIT 1", (user["id"], title, body, now()-86400)).fetchone()
                    if duplicate:
                        return self.send_json(409, {"error": "DUPLICATE_TOPIC"})
                    retry = consume_rate_limit(db, user["id"], "topic", 5, 3600)
                    if retry:
                        return self.send_json(429, {"error": "RATE_LIMITED", "retryAfter": retry})
                    cur = db.execute("INSERT INTO topics(user_id,title,body,category,created_at,image_url) VALUES(?,?,?,?,?,?)",
                                     (user["id"], title, body, category, now(), image))
                    return self.send_json(201, {"id": cur.lastrowid})
                if path.startswith("/api/topics/") and path.endswith("/comments"):
                    try: topic_id = int(path.split("/")[3])
                    except (ValueError, IndexError): return self.send_json(400, {"error": "Invalid topic id"})
                    body = str(data.get("body", "")).strip()
                    topic = db.execute("SELECT id FROM topics WHERE id=? AND deleted=0", (topic_id,)).fetchone()
                    if not topic: return self.send_json(404, {"error": "Topic not found"})
                    if not body or len(body) > 3000: return self.send_json(400, {"error": "Comment must be 1–3000 characters"})
                    retry = consume_rate_limit(db, user["id"], "comment", 20, 3600)
                    if retry:
                        return self.send_json(429, {"error": "RATE_LIMITED", "retryAfter": retry})
                    cur = db.execute("INSERT INTO comments(topic_id,user_id,body,created_at) VALUES(?,?,?,?)",
                                     (topic_id, user["id"], body, now()))
                    owner = db.execute("SELECT user_id FROM topics WHERE id=?", (topic_id,)).fetchone()[0]
                    if owner != user["id"]:
                        db.execute("INSERT INTO notifications(user_id,actor_id,topic_id,kind,created_at) VALUES(?,?,?,?,?)", (owner, user["id"], topic_id, "reply", now()))
                    return self.send_json(201, {"id": cur.lastrowid})
                if path == "/api/reports":
                    kind = data.get("targetType")
                    try: target_id = int(data.get("targetId"))
                    except (ValueError, TypeError): return self.send_json(400, {"error": "Invalid report target"})
                    reason = str(data.get("reason", "")).strip()[:500]
                    if kind not in ("topic", "comment") or not reason:
                        return self.send_json(400, {"error": "Choose a reason for the report"})
                    retry = consume_rate_limit(db, user["id"], "report", 10, 3600)
                    if retry:
                        return self.send_json(429, {"error": "RATE_LIMITED", "retryAfter": retry})
                    exists = db.execute("SELECT id FROM topics WHERE id=? AND deleted=0", (target_id,)).fetchone() if kind == "topic" else db.execute("SELECT id FROM comments WHERE id=?", (target_id,)).fetchone()
                    if not exists: return self.send_json(404, {"error": "Content not found"})
                    db.execute("INSERT INTO reports(reporter_id,target_type,target_id,reason,created_at) VALUES(?,?,?,?,?)",
                               (user["id"], kind, target_id, reason, now()))
                    if ADMIN_EMAIL:
                        if kind == "topic":
                            item = db.execute("SELECT title FROM topics WHERE id=?", (target_id,)).fetchone()
                            target_label = f"Topic #{target_id}: {item['title']}"
                        else:
                            item = db.execute("SELECT c.topic_id,t.title FROM comments c JOIN topics t ON t.id=c.topic_id WHERE c.id=?", (target_id,)).fetchone()
                            target_label = f"Reply #{target_id} on topic #{item['topic_id']} ({item['title']})"
                        try:
                            send_email(ADMIN_EMAIL, "New report on Masaha", f"Reporter: {user['display_name']} (@{user['username']})\nTarget: {target_label}\nReason: {reason}\n")
                        except Exception as exc:
                            print("Report notification email failed:", repr(exc))
                    return self.send_json(201, {"ok": True})
                if path.startswith("/api/topics/") and path.endswith("/delete"):
                    try: topic_id = int(path.split("/")[3])
                    except (ValueError, IndexError): return self.send_json(400, {"error": "Invalid topic id"})
                    topic = db.execute("SELECT user_id FROM topics WHERE id=? AND deleted=0", (topic_id,)).fetchone()
                    if not topic: return self.send_json(404, {"error": "Topic not found"})
                    if user["role"] != "admin" and topic["user_id"] != user["id"]:
                        return self.send_json(403, {"error": "Only the author or an admin can remove this topic"})
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
        path = urlparse(self.path).path
        if path.startswith("/api/admin/topics/") or (path.startswith("/api/topics/") and path.count("/") == 3):
            try:
                topic_id = int(path.rsplit("/", 1)[1])
                data = self.read_json()
                with connect() as db:
                    user = self.require_user(db)
                    if not user: return
                    admin_route = path.startswith("/api/admin/")
                    topic = db.execute("SELECT user_id FROM topics WHERE id=? AND deleted=0", (topic_id,)).fetchone()
                    if not topic: return self.send_json(404, {"error": "Topic not found"})
                    if admin_route and not self.require_admin(user): return
                    if not admin_route and user["role"] != "admin" and topic["user_id"] != user["id"]:
                        return self.send_json(403, {"error": "Only the author or an admin can edit this topic"})
                    title = str(data.get("title", "")).strip()
                    body = str(data.get("body", "")).strip()
                    category = str(data.get("category", "general"))
                    if not title or len(title) > 120 or not body or len(body) > 5000 or category not in ("programming", "learning", "general"):
                        return self.send_json(400, {"error": "Check the title, message, and category"})
                    cur = db.execute("UPDATE topics SET title=?,body=?,category=? WHERE id=? AND deleted=0", (title, body, category, topic_id))
                    if not cur.rowcount: return self.send_json(404, {"error": "Topic not found"})
                    return self.send_json(200, {"ok": True})
            except ValueError as exc:
                return self.send_json(400, {"error": str(exc)})
            except Exception as exc:
                print("Request error:", repr(exc))
                return self.send_json(500, {"error": "Server error"})
        if path != "/api/me/profile":
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
    try:
        backup_database()
    except Exception as exc:
        print("Initial database backup failed:", repr(exc))
    threading.Thread(target=backup_worker, name="masaha-backups", daemon=True).start()
    print(f"Masaha forum running at http://{HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), ForumHandler).serve_forever()
