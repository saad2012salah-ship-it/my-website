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
DB_URL = os.environ.get("MASAHA_DB", os.environ.get("DATABASE_URL", "")).strip()
USE_POSTGRES = DB_URL.startswith(("postgres://", "postgresql://"))

if USE_POSTGRES:
    import psycopg2
    import psycopg2.extras
    from psycopg2.extensions import parse_dsn

    DB_INTEGRITY_ERROR = psycopg2.IntegrityError
    if DB_URL.startswith("postgres://"):
        DB_URL = "postgresql://" + DB_URL[len("postgres://"):]

    class PostgresCursor:
        def __init__(self, cursor, lastrowid=None):
            self.cursor = cursor
            self.lastrowid = lastrowid
            self.rowcount = cursor.rowcount

        def fetchone(self):
            return self.cursor.fetchone()

        def fetchall(self):
            return self.cursor.fetchall()

    class PostgresConnectionWrapper:
        def __init__(self, url):
            self.conn = psycopg2.connect(url, sslmode="require")
            self.conn.autocommit = False

        def execute(self, query, params=()):
            sql = query.replace("?", "%s")
            wants_id = bool(re.match(r"\s*INSERT\s+INTO\s+(users|topics|comments|direct_messages)\b", sql, re.I))
            if wants_id and " RETURNING " not in sql.upper():
                sql += " RETURNING id"
            cursor = self.conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
            cursor.execute(sql, params)
            lastrowid = cursor.fetchone()["id"] if wants_id else None
            return PostgresCursor(cursor, lastrowid)

        def executescript(self, script):
            script = re.sub(r"\bid\s+INTEGER\s+PRIMARY\s+KEY\b", "id SERIAL PRIMARY KEY", script, flags=re.I)
            for statement in script.split(";"):
                statement = statement.strip()
                if statement:
                    self.execute(statement)

        def columns(self, table):
            cursor = self.conn.cursor()
            cursor.execute("SELECT column_name FROM information_schema.columns WHERE table_schema=current_schema() AND table_name=%s", (table,))
            return {row[0] for row in cursor.fetchall()}
            
        def commit(self):
            self.conn.commit()

        def rollback(self):
            self.conn.rollback()
            
        def close(self):
            self.conn.close()
            
        def __enter__(self):
            return self
            
        def __exit__(self, exc_type, exc_val, exc_tb):
            self.close()

    def get_db():
        return PostgresConnectionWrapper(DB_URL)
else:
    _db_path = Path(DB_URL).expanduser() if DB_URL else Path("masaha.sqlite3")
    DB_PATH = (_db_path if _db_path.is_absolute() else ROOT / _db_path).resolve()
    DB_INTEGRITY_ERROR = sqlite3.IntegrityError
    
    def get_db():
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(DB_PATH, timeout=30)
        conn.row_factory = sqlite3.Row
        return conn
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "10000"))
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "").strip().lower()
SITE_URL = os.environ.get("SITE_URL", "").rstrip("/")
SESSION_SECONDS = 90 * 24 * 60 * 60
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
        return False, None
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
    return True, sent


def backup_database():
    """Create a consistent database snapshot and retain only the newest backups."""
    BACKUP_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(BACKUP_DIR, 0o700)
    except OSError:
        pass
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    suffix = ".dump" if USE_POSTGRES else ".sqlite3"
    target = BACKUP_DIR / f"masaha-{stamp}{suffix}"
    temporary = BACKUP_DIR / f".{target.name}.tmp"
    try:
        if USE_POSTGRES:
            dsn = parse_dsn(DB_URL)
            env = os.environ.copy()
            if dsn.get("password"):
                env["PGPASSWORD"] = dsn["password"]
            # The application connection requires TLS too.
            env["PGSSLMODE"] = "require"
            command = ["pg_dump", "--no-owner", "--format=custom", f"--file={temporary}"]
            for key, flag in (("host", "--host"), ("port", "--port"), ("user", "--username"), ("dbname", "--dbname")):
                if dsn.get(key): command.extend([flag, dsn[key]])
            subprocess.run(command, check=True, timeout=180, capture_output=True, text=True, env=env)
        else:
            with sqlite3.connect(DB_PATH, timeout=30) as source:
                with sqlite3.connect(temporary, timeout=30) as destination:
                    source.backup(destination)
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()
    copies = sorted(BACKUP_DIR.glob("masaha-*"), key=lambda item: item.stat().st_mtime, reverse=True)
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
    db = get_db()
    if not USE_POSTGRES:
        db.execute("PRAGMA busy_timeout = 30000")
        db.execute("PRAGMA foreign_keys = ON")
        db.execute("PRAGMA synchronous = FULL")
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
        if not USE_POSTGRES:
            db.execute("PRAGMA journal_mode = WAL")
        schema = """
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE,
          display_name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
          password_hash TEXT NOT NULL, bio TEXT NOT NULL DEFAULT '',
          role TEXT NOT NULL DEFAULT 'member', created_at INTEGER NOT NULL,
          avatar_url TEXT NOT NULL DEFAULT '', is_banned INTEGER NOT NULL DEFAULT 0,
          email_verified INTEGER NOT NULL DEFAULT 0, cover_url TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS sessions (
          token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          expires_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS topics (
          id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          title TEXT NOT NULL, body TEXT NOT NULL, category TEXT NOT NULL,
          created_at INTEGER NOT NULL, deleted INTEGER NOT NULL DEFAULT 0,
          image_url TEXT NOT NULL DEFAULT '', tags TEXT NOT NULL DEFAULT '[]',
          is_pinned INTEGER NOT NULL DEFAULT 0, poll_json TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS categories (
          slug TEXT PRIMARY KEY, name_ar TEXT NOT NULL, name_en TEXT NOT NULL,
          description TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS comments (
          id INTEGER PRIMARY KEY, topic_id INTEGER NOT NULL REFERENCES topics(id) ON DELETE CASCADE,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          body TEXT NOT NULL, created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS direct_messages (
          id INTEGER PRIMARY KEY, sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          body TEXT NOT NULL, created_at INTEGER NOT NULL, seen INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS moderation_log (
          id INTEGER PRIMARY KEY, admin_id INTEGER NOT NULL REFERENCES users(id),
          action TEXT NOT NULL, target_type TEXT NOT NULL, target_id INTEGER NOT NULL,
          details TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL
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
        CREATE TABLE IF NOT EXISTS user_follows (
          follower_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          followed_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          created_at INTEGER NOT NULL, PRIMARY KEY(follower_id,followed_id)
        );
        CREATE TABLE IF NOT EXISTS category_follows (
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          category_slug TEXT NOT NULL REFERENCES categories(slug) ON DELETE CASCADE,
          created_at INTEGER NOT NULL, PRIMARY KEY(user_id,category_slug)
        );
        CREATE TABLE IF NOT EXISTS poll_votes (
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          topic_id INTEGER NOT NULL REFERENCES topics(id) ON DELETE CASCADE,
          option_index INTEGER NOT NULL, created_at INTEGER NOT NULL,
          PRIMARY KEY(user_id,topic_id)
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
        CREATE INDEX IF NOT EXISTS topics_created ON topics(created_at DESC);
        CREATE INDEX IF NOT EXISTS comments_topic ON comments(topic_id, created_at);
        CREATE INDEX IF NOT EXISTS reports_status ON reports(status, created_at);
        CREATE INDEX IF NOT EXISTS rate_events_user_action ON rate_events(user_id,action,created_at);
        CREATE INDEX IF NOT EXISTS direct_messages_inbox ON direct_messages(recipient_id,seen,created_at);
        CREATE INDEX IF NOT EXISTS direct_messages_thread ON direct_messages(sender_id,recipient_id,created_at);
        """
        db.executescript(schema)
        for slug, name_ar, name_en, description in (
            ("programming", "البرمجة", "Programming", "أسئلة وتجارب ومشاريع برمجية."),
            ("learning", "التعلّم", "Learning", "مصادر وتجارب تساعدنا على التعلّم."),
            ("general", "نقاش عام", "General", "موضوعات وأفكار عامة."),
        ):
            db.execute("INSERT INTO categories(slug,name_ar,name_en,description,created_at) VALUES(?,?,?,?,?) ON CONFLICT(slug) DO NOTHING",
                       (slug, name_ar, name_en, description, now()))
        if USE_POSTGRES:
            db.execute("CREATE UNIQUE INDEX IF NOT EXISTS users_username_nocase ON users (LOWER(username))")
        else:
            db.execute("CREATE UNIQUE INDEX IF NOT EXISTS users_username_nocase ON users(username COLLATE NOCASE)")
        # Add fields when opening a database created by an older version.
        for table, name, declaration in (
            ("users", "avatar_url", "TEXT NOT NULL DEFAULT ''"),
            ("users", "is_banned", "INTEGER NOT NULL DEFAULT 0"),
            ("users", "email_verified", "INTEGER NOT NULL DEFAULT 0"),
            ("users", "cover_url", "TEXT NOT NULL DEFAULT ''"),
            ("topics", "image_url", "TEXT NOT NULL DEFAULT ''"),
            ("topics", "tags", "TEXT NOT NULL DEFAULT '[]'"),
            ("topics", "is_pinned", "INTEGER NOT NULL DEFAULT 0"),
            ("topics", "poll_json", "TEXT NOT NULL DEFAULT ''"),
            ("topics", "best_answer_id", "INTEGER"),
        ):
            columns = db.columns(table) if USE_POSTGRES else {row[1] for row in db.execute(f"PRAGMA table_info({table})")}
            if name not in columns:
                db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")
        verify_columns = db.columns("verification_tokens") if USE_POSTGRES else {row[1] for row in db.execute("PRAGMA table_info(verification_tokens)")}
        if "attempts" not in verify_columns:
            db.execute("ALTER TABLE verification_tokens ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0")
        if "created_at" not in verify_columns:
            db.execute("ALTER TABLE verification_tokens ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0")


def now():
    return int(time.time())


def member_metrics(db, user_id):
    topic_count = db.execute("SELECT COUNT(*) FROM topics WHERE user_id=? AND deleted=0", (user_id,)).fetchone()[0]
    reply_count = db.execute("SELECT COUNT(*) FROM comments WHERE user_id=?", (user_id,)).fetchone()[0]
    likes_received = db.execute("SELECT COUNT(*) FROM likes l JOIN topics t ON t.id=l.topic_id WHERE t.user_id=? AND t.deleted=0", (user_id,)).fetchone()[0]
    points = topic_count * 10 + reply_count * 3 + likes_received * 2
    badges = []
    if topic_count: badges.append("first_topic")
    if reply_count >= 5: badges.append("helpful_voice")
    if points >= 100: badges.append("active_member")
    if points >= 300: badges.append("community_star")
    return {"topicCount": topic_count, "replyCount": reply_count,
            "likesReceived": likes_received, "points": points, "badges": badges}


def poll_details(db, topic_id, viewer_id=None):
    row = db.execute("SELECT poll_json FROM topics WHERE id=?", (topic_id,)).fetchone()
    if not row or not row["poll_json"]: return None
    poll = json.loads(row["poll_json"])
    counts = [0] * len(poll["options"])
    for vote in db.execute("SELECT option_index,COUNT(*) AS total FROM poll_votes WHERE topic_id=? GROUP BY option_index", (topic_id,)).fetchall():
        if 0 <= vote["option_index"] < len(counts): counts[vote["option_index"]] = vote["total"]
    selected = None
    if viewer_id:
        vote = db.execute("SELECT option_index FROM poll_votes WHERE topic_id=? AND user_id=?", (topic_id, viewer_id)).fetchone()
        if vote: selected = vote["option_index"]
    return {"question": poll["question"], "options": poll["options"], "counts": counts, "total": sum(counts), "selected": selected}


def public_user(row):
    if not row:
        return None
    return {"id": row["id"], "username": row["username"],
            "displayName": row["display_name"], "bio": row["bio"],
            "role": row["role"], "createdAt": row["created_at"],
            "avatarUrl": row["avatar_url"] if "avatar_url" in row.keys() else "",
            "coverUrl": row["cover_url"] if "cover_url" in row.keys() else "",
            "is_banned": row["is_banned"] if "is_banned" in row.keys() else 0}


def normalize_tags(value):
    values = value if isinstance(value, list) else str(value or "").split(",")
    tags = []
    for item in values:
        tag = str(item).strip().lstrip("#")[:24]
        if tag and tag.casefold() not in {x.casefold() for x in tags}:
            tags.append(tag)
        if len(tags) == 8:
            break
    return tags


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
                   "/app.js": ROOT / "app.js", "/style.css": ROOT / "style.css",
                   "/manifest.json": ROOT / "manifest.json", "/sw.js": ROOT / "sw.js", "/icon.svg": ROOT / "icon.svg"}
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
        c["masaha_session"]["samesite"] = "Lax"
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
            if path not in ("/", "/index.html", "/app.js", "/style.css", "/manifest.json", "/sw.js", "/icon.svg"):
                return self.send_error(404)
            return super().do_GET()
        with connect() as db:
            if path == "/api/categories":
                viewer = self.session_user(db)
                rows = db.execute("""SELECT c.slug,c.name_ar,c.name_en,c.description,
                    COUNT(t.id) AS topic_count FROM categories c LEFT JOIN topics t
                    ON t.category=c.slug AND t.deleted=0 GROUP BY c.slug,c.name_ar,c.name_en,c.description
                    ORDER BY c.created_at,c.slug""").fetchall()
                categories = [dict(row) for row in rows]
                if viewer:
                    followed = {row[0] for row in db.execute("SELECT category_slug FROM category_follows WHERE user_id=?", (viewer["id"],)).fetchall()}
                    for category in categories: category["followed_by_me"] = category["slug"] in followed
                return self.send_json(200, {"categories": categories})
            if path == "/api/me":
                current = self.session_user(db)
                profile = public_user(current)
                if profile: profile["email"] = current["email"]
                return self.send_json(200, {"user": profile})
            if path == "/api/admin/moderation-log":
                user=self.require_user(db)
                if not user or not self.require_admin(user): return
                rows=db.execute("SELECT l.*,u.display_name AS admin_name FROM moderation_log l JOIN users u ON u.id=l.admin_id ORDER BY l.created_at DESC LIMIT 100").fetchall()
                return self.send_json(200,{"entries":[dict(r) for r in rows]})
            if path == "/api/inbox":
                user = self.require_user(db)
                if not user: return
                rows = db.execute("""SELECT u.id,u.username,u.display_name,u.avatar_url,
                    MAX(m.created_at) AS last_at,
                    (SELECT body FROM direct_messages x WHERE (x.sender_id=u.id AND x.recipient_id=?) OR (x.sender_id=? AND x.recipient_id=u.id) ORDER BY x.created_at DESC,x.id DESC LIMIT 1) AS last_body,
                    (SELECT COUNT(*) FROM direct_messages x WHERE x.sender_id=u.id AND x.recipient_id=? AND x.seen=0) AS unread
                    FROM users u JOIN direct_messages m ON (m.sender_id=u.id AND m.recipient_id=?) OR (m.recipient_id=u.id AND m.sender_id=?)
                    WHERE u.id<>? GROUP BY u.id,u.username,u.display_name,u.avatar_url ORDER BY last_at DESC LIMIT 100""",
                    (user["id"],user["id"],user["id"],user["id"],user["id"],user["id"])).fetchall()
                return self.send_json(200, {"conversations": [dict(r) for r in rows]})
            if path.startswith("/api/messages/"):
                user = self.require_user(db)
                if not user: return
                try: peer_id = int(path.rsplit("/", 1)[1])
                except ValueError: return self.send_json(400, {"error": "Invalid member"})
                peer = db.execute("SELECT id,username,display_name,avatar_url FROM users WHERE id=? AND is_banned=0", (peer_id,)).fetchone()
                if not peer: return self.send_json(404, {"error": "Member not found"})
                db.execute("UPDATE direct_messages SET seen=1 WHERE sender_id=? AND recipient_id=?", (peer_id,user["id"]))
                rows = db.execute("SELECT id,sender_id,recipient_id,body,created_at,seen FROM direct_messages WHERE (sender_id=? AND recipient_id=?) OR (sender_id=? AND recipient_id=?) ORDER BY created_at DESC,id DESC LIMIT 100", (user["id"],peer_id,peer_id,user["id"])).fetchall()
                return self.send_json(200, {"peer": dict(peer), "messages": [dict(r) for r in reversed(rows)]})
            if path == "/api/bookmarks":
                user = self.require_user(db)
                if not user: return
                query = parse_qs(parsed.query)
                search = query.get("q", [""])[0].strip()[:100]
                category = query.get("category", [""])[0]
                sort = query.get("sort", ["newest"])[0]
                filters = ""
                params = [user["id"], user["id"]]
                if search:
                    filters += " AND (t.title LIKE ? OR t.body LIKE ? OR t.tags LIKE ?)"
                    needle = "%" + search + "%"; params.extend([needle, needle, needle])
                if category and db.execute("SELECT 1 FROM categories WHERE slug=?", (category,)).fetchone():
                    filters += " AND t.category=?"; params.append(category)
                ordering = "t.is_pinned DESC,b.created_at DESC"
                if sort == "popular": ordering = "t.is_pinned DESC,like_count DESC,t.created_at DESC"
                elif sort == "oldest": ordering = "t.is_pinned DESC,t.created_at ASC"
                rows = db.execute("""SELECT t.*,u.username,u.display_name,u.avatar_url AS author_avatar,
                    (SELECT COUNT(*) FROM comments c WHERE c.topic_id=t.id) AS comment_count,
                    (SELECT COUNT(*) FROM likes l WHERE l.topic_id=t.id) AS like_count,
                    1 AS bookmarked_by_me, EXISTS(SELECT 1 FROM likes l WHERE l.topic_id=t.id AND l.user_id=?) AS liked_by_me
                    FROM bookmarks b JOIN topics t ON t.id=b.topic_id JOIN users u ON u.id=t.user_id
                    WHERE b.user_id=? AND t.deleted=0""" + filters + " ORDER BY " + ordering, params).fetchall()
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
            if path == "/api/following-feed":
                user = self.require_user(db)
                if not user: return
                viewer_id = user["id"]
                rows = db.execute("""SELECT t.*,u.username,u.display_name,u.avatar_url AS author_avatar,
                    (SELECT COUNT(*) FROM comments c WHERE c.topic_id=t.id) AS comment_count,
                    (SELECT COUNT(*) FROM likes l WHERE l.topic_id=t.id) AS like_count,
                    EXISTS(SELECT 1 FROM likes l WHERE l.topic_id=t.id AND l.user_id=?) AS liked_by_me,
                    EXISTS(SELECT 1 FROM bookmarks b WHERE b.topic_id=t.id AND b.user_id=?) AS bookmarked_by_me
                    FROM topics t JOIN users u ON u.id=t.user_id
                    WHERE t.deleted=0 AND (EXISTS(SELECT 1 FROM user_follows f WHERE f.follower_id=? AND f.followed_id=t.user_id)
                    OR EXISTS(SELECT 1 FROM category_follows cf WHERE cf.user_id=? AND cf.category_slug=t.category))
                    ORDER BY t.is_pinned DESC,t.created_at DESC LIMIT 100""",
                    (viewer_id, viewer_id, viewer_id, viewer_id)).fetchall()
                return self.send_json(200, {"topics": [self.topic_json(row) for row in rows]})
            if path == "/api/admin/users":
                user = self.require_user(db)
                if not user or not self.require_admin(user): return
                rows = db.execute("SELECT id,username,display_name,role,is_banned FROM users ORDER BY created_at DESC LIMIT 200").fetchall()
                return self.send_json(200, {"users": [dict(row) for row in rows]})
            if path == "/api/admin/stats":
                user = self.require_user(db)
                if not user or not self.require_admin(user): return
                stats = {
                    "members": db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
                    "topics": db.execute("SELECT COUNT(*) FROM topics WHERE deleted=0").fetchone()[0],
                    "replies": db.execute("SELECT COUNT(*) FROM comments").fetchone()[0],
                    "openReports": db.execute("SELECT COUNT(*) FROM reports WHERE status='open'").fetchone()[0],
                    "todayTopics": db.execute("SELECT COUNT(*) FROM topics WHERE created_at>=? AND deleted=0", (now()-86400,)).fetchone()[0],
                }
                return self.send_json(200, {"stats": stats})
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
                    filters += " AND (t.title LIKE ? OR t.body LIKE ? OR u.display_name LIKE ? OR t.tags LIKE ?)"
                    needle = "%" + search + "%"
                    filter_values.extend([needle, needle, needle, needle])
                if category and db.execute("SELECT 1 FROM categories WHERE slug=?", (category,)).fetchone():
                    filters += " AND t.category=?"; filter_values.append(category)
                order = " ORDER BY t.is_pinned DESC,t.created_at DESC"
                if sort == "popular":
                    order = " ORDER BY t.is_pinned DESC,like_count DESC,t.created_at DESC"
                elif sort == "oldest":
                    order = " ORDER BY t.is_pinned DESC,t.created_at ASC"
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
                return self.send_json(200, {"topic": self.topic_json(topic), "comments": [self.comment_json(x) for x in comments],
                                            "poll": poll_details(db, topic_id, viewer["id"] if viewer else None)})
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
                replies = db.execute("""SELECT c.id,c.body,c.created_at,t.id AS topic_id,t.title
                    FROM comments c JOIN topics t ON t.id=c.topic_id
                    WHERE c.user_id=? AND t.deleted=0 ORDER BY c.created_at DESC LIMIT 50""", (user_id,)).fetchall()
                profile = public_user(user)
                profile.update(member_metrics(db, user_id))
                profile["followerCount"] = db.execute("SELECT COUNT(*) FROM user_follows WHERE followed_id=?", (user_id,)).fetchone()[0]
                profile["followingCount"] = db.execute("SELECT COUNT(*) FROM user_follows WHERE follower_id=?", (user_id,)).fetchone()[0]
                viewer = self.session_user(db)
                profile["followedByMe"] = bool(viewer and db.execute("SELECT 1 FROM user_follows WHERE follower_id=? AND followed_id=?", (viewer["id"], user_id)).fetchone())
                return self.send_json(200, {"user": profile, "topics": [self.topic_json(x) for x in posts],
                    "replies": [dict(row) for row in replies]})
            if path == "/api/admin/reports":
                user = self.require_user(db)
                if not user or not self.require_admin(user): return
                status = parse_qs(parsed.query).get("status", ["open"])[0]
                if status not in ("open", "resolved"): status = "open"
                rows = db.execute("""SELECT r.*,u.username AS reporter,u.display_name AS reporter_name,
                    CASE WHEN r.target_type='topic' THEN (SELECT title FROM topics WHERE id=r.target_id)
                    ELSE (SELECT t.title FROM comments c JOIN topics t ON t.id=c.topic_id WHERE c.id=r.target_id) END AS topic_title
                    ,CASE WHEN r.target_type='topic' THEN r.target_id
                    ELSE (SELECT c.topic_id FROM comments c WHERE c.id=r.target_id) END AS target_topic_id
                    FROM reports r
                    JOIN users u ON u.id=r.reporter_id WHERE r.status=? ORDER BY r.created_at DESC LIMIT 200""", (status,)).fetchall()
                return self.send_json(200, {"reports": [dict(x) for x in rows]})
        return self.send_json(404, {"error": "API route not found"})

    @staticmethod
    def topic_json(row):
        return {"id": row["id"], "title": row["title"], "body": row["body"],
                "category": row["category"], "createdAt": row["created_at"],
                "commentCount": row["comment_count"], "likeCount": row["like_count"] if "like_count" in row.keys() else 0,
                "likedByMe": bool(row["liked_by_me"]) if "liked_by_me" in row.keys() else False,
                "bookmarkedByMe": bool(row["bookmarked_by_me"]) if "bookmarked_by_me" in row.keys() else False,
                "isPinned": bool(row["is_pinned"]) if "is_pinned" in row.keys() else False,
                "bestAnswerId": row["best_answer_id"] if "best_answer_id" in row.keys() else None,
                "hasPoll": bool(row["poll_json"]) if "poll_json" in row.keys() else False,
                "imageUrl": row["image_url"] if "image_url" in row.keys() else "",
                "tags": json.loads(row["tags"] or "[]") if "tags" in row.keys() else [],
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
                    created, email_sent = issue_verification_code(db, user) if user else (True, False)
                    if user and not created:
                        previous = db.execute("SELECT created_at FROM verification_tokens WHERE user_id=?", (user["id"],)).fetchone()
                        retry_after = max(1, 60 - (now() - previous["created_at"])) if previous else 60
                        return self.send_json(429, {"error": "RESEND_COOLDOWN", "retryAfter": retry_after})
                    return self.send_json(200, {"sent": True, "emailSent": email_sent})
                if path == "/api/register":
                    name = str(data.get("displayName", "")).strip()[:50]
                    username = str(data.get("username", "")).strip().lower()
                    email = str(data.get("email", "")).strip().lower()[:254]
                    password = str(data.get("password", ""))
                    if len(name) < 2 or "@" not in email or len(password) < 10:
                        return self.send_json(400, {"error": "Name, valid email, and password (10+ characters) required"})
                    if not re.fullmatch(r"[a-z0-9_]{3,24}", username):
                        return self.send_json(400, {"error": "USERNAME_INVALID"})
                    if db.execute("SELECT 1 FROM users WHERE lower(username)=lower(?)", (username,)).fetchone():
                        return self.send_json(409, {"error": "USERNAME_TAKEN"})
                    salt = secrets.token_bytes(16)
                    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
                    encoded = "scrypt$" + salt.hex() + "$" + digest.hex()
                    role = "admin" if ADMIN_EMAIL and email == ADMIN_EMAIL else "member"
                    try:
                        cur = db.execute("INSERT INTO users(username,display_name,email,password_hash,role,created_at,email_verified) VALUES(?,?,?,?,?,?,1)",
                                         (username, name, email, encoded, role, now()))
                    except DB_INTEGRITY_ERROR:
                        if db.execute("SELECT 1 FROM users WHERE lower(username)=lower(?)", (username,)).fetchone():
                            return self.send_json(409, {"error": "USERNAME_TAKEN"})
                        return self.send_json(409, {"error": "That email is already registered"})
                    user = db.execute("SELECT * FROM users WHERE id=?", (cur.lastrowid,)).fetchone()
                    token = secrets.token_urlsafe(32)
                    db.execute("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)",
                               (hashlib.sha256(token.encode()).hexdigest(), user["id"], now()+SESSION_SECONDS))
                    response_user = public_user(user); response_user["email"] = user["email"]
                    return self.send_json(201, {"user": response_user}, self.cookie_headers(token, SESSION_SECONDS))
                if path == "/api/login":
                    email = str(data.get("email", "")).strip().lower()
                    password = str(data.get("password", ""))
                    user = db.execute("SELECT * FROM users WHERE lower(email)=? OR lower(username)=?", (email, email)).fetchone()
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
                    if ADMIN_EMAIL and user["email"].lower() == ADMIN_EMAIL and user["role"] != "admin":
                        db.execute("UPDATE users SET role='admin' WHERE id=?", (user["id"],))
                        user = db.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
                    token = secrets.token_urlsafe(32)
                    db.execute("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)",
                               (hashlib.sha256(token.encode()).hexdigest(), user["id"], now()+SESSION_SECONDS))
                    response_user = public_user(user); response_user["email"] = user["email"]
                    return self.send_json(200, {"user": response_user}, self.cookie_headers(token, SESSION_SECONDS))
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
                if path == "/api/messages":
                    try: recipient_id = int(data.get("recipientId"))
                    except (TypeError, ValueError): return self.send_json(400, {"error": "Invalid member"})
                    body = str(data.get("body", "")).strip()
                    if recipient_id == user["id"] or not body or len(body) > 2000:
                        return self.send_json(400, {"error": "Message must be 1–2000 characters"})
                    recipient = db.execute("SELECT id FROM users WHERE id=? AND is_banned=0", (recipient_id,)).fetchone()
                    if not recipient: return self.send_json(404, {"error": "Member not found"})
                    retry = consume_rate_limit(db,user["id"],"message",60,3600)
                    if retry: return self.send_json(429,{"error":"RATE_LIMITED","retryAfter":retry})
                    cur = db.execute("INSERT INTO direct_messages(sender_id,recipient_id,body,created_at) VALUES(?,?,?,?)", (user["id"],recipient_id,body,now()))
                    return self.send_json(201,{"id":cur.lastrowid})
                if path.startswith("/api/topics/") and path.endswith("/best-answer"):
                    try: topic_id=int(path.split("/")[3]); comment_id=int(data.get("commentId"))
                    except (ValueError,TypeError,IndexError): return self.send_json(400,{"error":"Invalid answer"})
                    topic=db.execute("SELECT user_id,best_answer_id FROM topics WHERE id=? AND deleted=0",(topic_id,)).fetchone()
                    comment=db.execute("SELECT id FROM comments WHERE id=? AND topic_id=?",(comment_id,topic_id)).fetchone()
                    if not topic or not comment: return self.send_json(404,{"error":"Answer not found"})
                    if user["role"]!="admin" and topic["user_id"]!=user["id"]: return self.send_json(403,{"error":"Only the topic author can select the best answer"})
                    selected=None if topic["best_answer_id"]==comment_id else comment_id
                    db.execute("UPDATE topics SET best_answer_id=? WHERE id=?",(selected,topic_id))
                    return self.send_json(200,{"bestAnswerId":selected})
                if path == "/api/follow/user":
                    try: followed_id = int(data.get("userId"))
                    except (TypeError, ValueError): return self.send_json(400, {"error": "Invalid member"})
                    if followed_id == user["id"]: return self.send_json(400, {"error": "CANNOT_FOLLOW_SELF"})
                    if not db.execute("SELECT 1 FROM users WHERE id=?", (followed_id,)).fetchone():
                        return self.send_json(404, {"error": "Member not found"})
                    exists = db.execute("SELECT 1 FROM user_follows WHERE follower_id=? AND followed_id=?", (user["id"], followed_id)).fetchone()
                    if exists:
                        db.execute("DELETE FROM user_follows WHERE follower_id=? AND followed_id=?", (user["id"], followed_id)); following = False
                    else:
                        db.execute("INSERT INTO user_follows(follower_id,followed_id,created_at) VALUES(?,?,?)", (user["id"], followed_id, now())); following = True
                    return self.send_json(200, {"following": following})
                if path == "/api/follow/category":
                    slug = str(data.get("category", ""))
                    if not db.execute("SELECT 1 FROM categories WHERE slug=?", (slug,)).fetchone():
                        return self.send_json(404, {"error": "Category not found"})
                    exists = db.execute("SELECT 1 FROM category_follows WHERE user_id=? AND category_slug=?", (user["id"], slug)).fetchone()
                    if exists:
                        db.execute("DELETE FROM category_follows WHERE user_id=? AND category_slug=?", (user["id"], slug)); following = False
                    else:
                        db.execute("INSERT INTO category_follows(user_id,category_slug,created_at) VALUES(?,?,?)", (user["id"], slug, now())); following = True
                    return self.send_json(200, {"following": following})
                if path.startswith("/api/topics/") and path.endswith("/vote"):
                    try: topic_id = int(path.split("/")[3]); option_index = int(data.get("optionIndex"))
                    except (ValueError, TypeError, IndexError): return self.send_json(400, {"error": "Invalid vote"})
                    topic = db.execute("SELECT poll_json FROM topics WHERE id=? AND deleted=0", (topic_id,)).fetchone()
                    if not topic or not topic["poll_json"]: return self.send_json(404, {"error": "Poll not found"})
                    poll = json.loads(topic["poll_json"])
                    if option_index < 0 or option_index >= len(poll["options"]): return self.send_json(400, {"error": "Invalid option"})
                    db.execute("INSERT INTO poll_votes(user_id,topic_id,option_index,created_at) VALUES(?,?,?,?) ON CONFLICT(user_id,topic_id) DO UPDATE SET option_index=excluded.option_index,created_at=excluded.created_at", (user["id"], topic_id, option_index, now()))
                    return self.send_json(200, {"poll": poll_details(db, topic_id, user["id"])})
                if path.startswith("/api/admin/topics/") and path.endswith("/pin"):
                    if not self.require_admin(user): return
                    try: topic_id = int(path.split("/")[4])
                    except (ValueError, IndexError): return self.send_json(400, {"error": "Invalid topic id"})
                    topic = db.execute("SELECT is_pinned FROM topics WHERE id=? AND deleted=0", (topic_id,)).fetchone()
                    if not topic: return self.send_json(404, {"error": "Topic not found"})
                    pinned = not bool(topic["is_pinned"])
                    db.execute("UPDATE topics SET is_pinned=? WHERE id=?", (int(pinned), topic_id))
                    db.execute("INSERT INTO moderation_log(admin_id,action,target_type,target_id,details,created_at) VALUES(?,?,?,?,?,?)",(user["id"],"pin_topic","topic",topic_id,"Pinned status changed",now()))
                    return self.send_json(200, {"pinned": pinned})
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
                    db.execute("INSERT INTO moderation_log(admin_id,action,target_type,target_id,details,created_at) VALUES(?,?,?,?,?,?)",(user["id"],"toggle_ban","user",target_id,"Account suspension status changed",now()))
                    return self.send_json(200, {"ok": True})
                if path == "/api/me/avatar":
                    image = str(data.get("image", ""))
                    if len(image) > 2_800_000 or not re.fullmatch(r"data:image/(?:png|jpeg|webp);base64,[A-Za-z0-9+/]+={0,2}", image):
                        return self.send_json(400, {"error": "Image must be PNG, JPEG, or WebP and under 2 MB"})
                    db.execute("UPDATE users SET avatar_url=? WHERE id=?", (image, user["id"]))
                    return self.send_json(200, {"avatarUrl": image})
                if path == "/api/me/cover":
                    image = str(data.get("image", ""))
                    if len(image) > 2_800_000 or not re.fullmatch(r"data:image/(?:png|jpeg|webp);base64,[A-Za-z0-9+/]+={0,2}", image):
                        return self.send_json(400, {"error": "Image must be PNG, JPEG, or WebP and under 2 MB"})
                    db.execute("UPDATE users SET cover_url=? WHERE id=?", (image, user["id"]))
                    return self.send_json(200, {"coverUrl": image})
                if path == "/api/me/settings":
                    current_password = str(data.get("currentPassword", ""))
                    try:
                        _, salt_hex, hash_hex = user["password_hash"].split("$")
                        candidate = hashlib.scrypt(current_password.encode(), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1)
                        valid_password = hmac.compare_digest(candidate.hex(), hash_hex)
                    except (ValueError, TypeError):
                        valid_password = False
                    if not valid_password:
                        return self.send_json(403, {"error": "CURRENT_PASSWORD_INVALID"})
                    email = str(data.get("email", user["email"])).strip().lower()[:254]
                    password = str(data.get("newPassword", ""))
                    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
                        return self.send_json(400, {"error": "Enter a valid email address"})
                    if email != user["email"] and db.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
                        return self.send_json(409, {"error": "That email is already registered"})
                    if password and len(password) < 10:
                        return self.send_json(400, {"error": "Password must be at least 10 characters"})
                    if email != user["email"]:
                        db.execute("UPDATE users SET email=?,email_verified=1 WHERE id=?", (email, user["id"]))
                    if password:
                        salt = secrets.token_bytes(16)
                        encoded = "scrypt$" + salt.hex() + "$" + hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1).hex()
                        db.execute("UPDATE users SET password_hash=? WHERE id=?", (encoded, user["id"]))
                    raw_cookie = cookies.SimpleCookie(self.headers.get("Cookie", ""))
                    if "masaha_session" in raw_cookie:
                        current_hash = hashlib.sha256(raw_cookie["masaha_session"].value.encode()).hexdigest()
                        db.execute("DELETE FROM sessions WHERE user_id=? AND token_hash<>?", (user["id"], current_hash))
                    if email != user["email"]:
                        db.execute("DELETE FROM verification_tokens WHERE user_id=?", (user["id"],))
                    updated = db.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
                    response_user = public_user(updated); response_user["email"] = updated["email"]
                    response = {"ok": True, "user": response_user}
                    return self.send_json(200, response)
                if path == "/api/topics":
                    title = str(data.get("title", "")).strip()
                    body = str(data.get("body", "")).strip()
                    category = str(data.get("category", "general"))
                    tags = normalize_tags(data.get("tags", []))
                    if not title or len(title) > 120 or not body or len(body) > 5000 or not db.execute("SELECT 1 FROM categories WHERE slug=?", (category,)).fetchone():
                        return self.send_json(400, {"error": "Check the title, message, and category"})
                    image = str(data.get("image", ""))
                    if image and (len(image) > 2_800_000 or not re.fullmatch(r"data:image/(?:png|jpeg|webp);base64,[A-Za-z0-9+/]+={0,2}", image)):
                        return self.send_json(400, {"error": "Image must be PNG, JPEG, or WebP and under 2 MB"})
                    poll_question = str(data.get("pollQuestion", "")).strip()[:160]
                    raw_options = data.get("pollOptions", [])
                    if isinstance(raw_options, str): raw_options = raw_options.splitlines()
                    poll_options = list(dict.fromkeys(str(option).strip()[:80] for option in raw_options if str(option).strip()))[:6]
                    if poll_question and len(poll_options) < 2:
                        return self.send_json(400, {"error": "POLL_NEEDS_OPTIONS"})
                    if poll_options and (not poll_question or len(poll_options) < 2):
                        return self.send_json(400, {"error": "POLL_NEEDS_QUESTION"})
                    poll_json = json.dumps({"question": poll_question, "options": poll_options}, ensure_ascii=False) if poll_options else ""
                    duplicate = db.execute("SELECT 1 FROM topics WHERE user_id=? AND deleted=0 AND lower(title)=lower(?) AND lower(body)=lower(?) AND created_at>? LIMIT 1", (user["id"], title, body, now()-86400)).fetchone()
                    if duplicate:
                        return self.send_json(409, {"error": "DUPLICATE_TOPIC"})
                    retry = consume_rate_limit(db, user["id"], "topic", 5, 3600)
                    if retry:
                        return self.send_json(429, {"error": "RATE_LIMITED", "retryAfter": retry})
                    cur = db.execute("INSERT INTO topics(user_id,title,body,category,created_at,image_url,tags,poll_json) VALUES(?,?,?,?,?,?,?,?)",
                                     (user["id"], title, body, category, now(), image, json.dumps(tags, ensure_ascii=False), poll_json))
                    recipients = {row[0] for row in db.execute("SELECT follower_id FROM user_follows WHERE followed_id=?", (user["id"],)).fetchall()}
                    recipients.update(row[0] for row in db.execute("SELECT user_id FROM category_follows WHERE category_slug=?", (category,)).fetchall())
                    for recipient in recipients:
                        if recipient != user["id"]:
                            db.execute("INSERT INTO notifications(user_id,actor_id,topic_id,kind,created_at) VALUES(?,?,?,?,?)", (recipient, user["id"], cur.lastrowid, "followed_topic", now()))
                    return self.send_json(201, {"id": cur.lastrowid})
                if path == "/api/admin/categories":
                    if not self.require_admin(user): return
                    slug = str(data.get("slug", "")).strip().lower()
                    name_ar = str(data.get("nameAr", "")).strip()[:50]
                    name_en = str(data.get("nameEn", "")).strip()[:50]
                    description = str(data.get("description", "")).strip()[:240]
                    if not re.fullmatch(r"[a-z0-9-]{2,32}", slug) or not name_ar or not name_en:
                        return self.send_json(400, {"error": "CATEGORY_INVALID"})
                    try:
                        db.execute("INSERT INTO categories(slug,name_ar,name_en,description,created_at) VALUES(?,?,?,?,?)",
                                   (slug, name_ar, name_en, description, now()))
                    except DB_INTEGRITY_ERROR:
                        return self.send_json(409, {"error": "CATEGORY_EXISTS"})
                    return self.send_json(201, {"ok": True})
                if path == "/api/admin/categories/delete":
                    if not self.require_admin(user): return
                    slug = str(data.get("slug", ""))
                    if slug in ("programming", "learning", "general"):
                        return self.send_json(400, {"error": "DEFAULT_CATEGORY"})
                    used = db.execute("SELECT 1 FROM topics WHERE category=? LIMIT 1", (slug,)).fetchone()
                    if used: return self.send_json(409, {"error": "CATEGORY_IN_USE"})
                    db.execute("DELETE FROM category_follows WHERE category_slug=?", (slug,))
                    deleted = db.execute("DELETE FROM categories WHERE slug=?", (slug,))
                    return self.send_json(200 if deleted.rowcount else 404, {"ok": bool(deleted.rowcount)})
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
                    recipients = {owner}
                    recipients.update(row[0] for row in db.execute("SELECT DISTINCT user_id FROM comments WHERE topic_id=? AND user_id<>?", (topic_id, user["id"])).fetchall())
                    recipients.discard(user["id"])
                    for recipient in recipients:
                        db.execute("INSERT INTO notifications(user_id,actor_id,topic_id,kind,created_at) VALUES(?,?,?,?,?)", (recipient, user["id"], topic_id, "reply_comment" if recipient != owner else "reply", now()))
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
                    # Make repeat delete requests safe (for example, a double click
                    # or an old moderation report pointing at an already removed topic).
                    topic = db.execute("SELECT user_id,deleted FROM topics WHERE id=?", (topic_id,)).fetchone()
                    if not topic: return self.send_json(404, {"error": "Topic not found"})
                    if user["role"] != "admin" and topic["user_id"] != user["id"]:
                        return self.send_json(403, {"error": "Only the author or an admin can remove this topic"})
                    if topic["deleted"]:
                        return self.send_json(200, {"ok": True, "alreadyDeleted": True})
                    db.execute("UPDATE topics SET deleted=1 WHERE id=?", (topic_id,))
                    db.execute("UPDATE reports SET status='resolved' WHERE target_type='topic' AND target_id=?", (topic_id,))
                    if user["role"]=="admin": db.execute("INSERT INTO moderation_log(admin_id,action,target_type,target_id,details,created_at) VALUES(?,?,?,?,?,?)",(user["id"],"delete","topic",topic_id,"Topic removed",now()))
                    return self.send_json(200, {"ok": True})
                if path.startswith("/api/comments/") and path.endswith("/delete"):
                    try: comment_id = int(path.split("/")[3])
                    except (ValueError, IndexError): return self.send_json(400, {"error": "Invalid comment id"})
                    comment = db.execute("SELECT user_id FROM comments WHERE id=?", (comment_id,)).fetchone()
                    if not comment: return self.send_json(404, {"error": "Comment not found"})
                    if user["role"] != "admin" and comment["user_id"] != user["id"]:
                        return self.send_json(403, {"error": "Only the author or an admin can remove this reply"})
                    db.execute("DELETE FROM comments WHERE id=?", (comment_id,))
                    db.execute("UPDATE topics SET best_answer_id=NULL WHERE best_answer_id=?", (comment_id,))
                    db.execute("UPDATE reports SET status='resolved' WHERE target_type='comment' AND target_id=?", (comment_id,))
                    if user["role"]=="admin": db.execute("INSERT INTO moderation_log(admin_id,action,target_type,target_id,details,created_at) VALUES(?,?,?,?,?,?)",(user["id"],"delete","comment",comment_id,"Reply removed",now()))
                    return self.send_json(200, {"ok": True})
                if path.startswith("/api/reports/") and path.endswith("/resolve"):
                    if not self.require_admin(user): return
                    try: report_id = int(path.split("/")[3])
                    except (ValueError, IndexError): return self.send_json(400, {"error": "Invalid report id"})
                    db.execute("UPDATE reports SET status='resolved' WHERE id=?", (report_id,))
                    db.execute("INSERT INTO moderation_log(admin_id,action,target_type,target_id,details,created_at) VALUES(?,?,?,?,?,?)",(user["id"],"resolve_report","report",report_id,"Report resolved",now()))
                    return self.send_json(200, {"ok": True})
        except ValueError as exc:
            return self.send_json(400, {"error": str(exc)})
        except Exception as exc:
            print("Request error:", repr(exc))
            return self.send_json(500, {"error": "Server error"})
        return self.send_json(404, {"error": "API route not found"})

    def do_PUT(self):
        path = urlparse(self.path).path
        if path.startswith("/api/comments/") and path.count("/") == 3:
            try:
                comment_id = int(path.rsplit("/", 1)[1])
                data = self.read_json()
                body = str(data.get("body", "")).strip()
                if not body or len(body) > 3000:
                    return self.send_json(400, {"error": "Comment must be 1–3000 characters"})
                with connect() as db:
                    user = self.require_user(db)
                    if not user: return
                    comment = db.execute("SELECT user_id FROM comments WHERE id=?", (comment_id,)).fetchone()
                    if not comment: return self.send_json(404, {"error": "Comment not found"})
                    if user["role"] != "admin" and comment["user_id"] != user["id"]:
                        return self.send_json(403, {"error": "Only the author or an admin can edit this reply"})
                    db.execute("UPDATE comments SET body=? WHERE id=?", (body, comment_id))
                    return self.send_json(200, {"ok": True})
            except ValueError as exc:
                return self.send_json(400, {"error": str(exc)})
            except Exception as exc:
                print("Request error:", repr(exc))
                return self.send_json(500, {"error": "Server error"})
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
                    tags = normalize_tags(data.get("tags", []))
                    if not title or len(title) > 120 or not body or len(body) > 5000 or not db.execute("SELECT 1 FROM categories WHERE slug=?", (category,)).fetchone():
                        return self.send_json(400, {"error": "Check the title, message, and category"})
                    cur = db.execute("UPDATE topics SET title=?,body=?,category=?,tags=? WHERE id=? AND deleted=0", (title, body, category, json.dumps(tags, ensure_ascii=False), topic_id))
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
    print(f"Database backend: {'PostgreSQL' if USE_POSTGRES else f'SQLite ({DB_PATH})'}")
    print(f"Masaha forum running at http://{HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), ForumHandler).serve_forever()
