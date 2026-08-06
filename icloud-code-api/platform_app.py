"""Commercial multi-tenant iCloud Mail verification-code service MVP."""

from __future__ import annotations

import base64
import hashlib
import hmac
import imaplib
import os
import re
import secrets
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

from app import clean_text, extract_code, message_body_text


APP_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("PLATFORM_DATA_DIR", str(APP_DIR / "data" / "platform")))
DB_PATH = DATA_DIR / "platform.sqlite3"
KEY_PATH = DATA_DIR / "platform_master.key"
OPERATOR_KEY_PATH = DATA_DIR / "platform_admin.key"
OPERATOR_HTML_PATH = APP_DIR / "operator.html"
MAX_BODY = 1_048_576
SERVICE_VERSION = "0.1.0"
INVENTORY_TENANT_ID = "__platform_inventory__"
INVENTORY_TENANT_EMAIL = "platform-inventory@platform.invalid"
INVENTORY_TENANT_DISPLAY = "\u5e73\u53f0\u5e93\u5b58\uff08\u672a\u5206\u914d\u5ba2\u6237\uff09"


def env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError:
        value = default
    return max(minimum, min(maximum, value))


def env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def load_operator_html() -> str:
    try:
        return OPERATOR_HTML_PATH.read_text(encoding="utf-8")
    except OSError:
        return "<h1>Operator UI is not installed</h1>"


SESSION_TTL = env_int("PLATFORM_SESSION_TTL_SECONDS", 86400, 900, 30 * 86400)
CODE_MAX_AGE = env_int("PLATFORM_CODE_MAX_AGE_SECONDS", 3600, 0, 30 * 86400)
LOOKBACK_DAYS = env_int("PLATFORM_IMAP_LOOKBACK_DAYS", 3, 1, 365)
RECENT_LIMIT = env_int("PLATFORM_IMAP_RECENT_LIMIT", 200, 1, 500)
PUBLIC_ORIGIN = os.environ.get("PLATFORM_PUBLIC_ORIGIN", "http://127.0.0.1:8766").strip().rstrip("/")
R2_REQUIRED = env_bool("R2_REQUIRED", False)
R2_ARCHIVE_ENABLED = env_bool("R2_ARCHIVE_ENABLED", True)
R2_REGION = os.environ.get("R2_REGION", "auto").strip() or "auto"
R2_PREFIX = re.sub(r"[^A-Za-z0-9._/-]+", "-", os.environ.get("R2_PREFIX", "icloud-mail")).strip("/") or "icloud-mail"
R2_MONTHLY_MAX_PUTS = env_int("R2_MONTHLY_MAX_PUTS", 900_000, 0, 1_000_000)
R2_MONTHLY_MAX_BYTES = env_int("R2_MONTHLY_MAX_BYTES", 9_000_000_000, 0, 10_000_000_000)
R2_MAX_OBJECT_BYTES = env_int("R2_MAX_OBJECT_BYTES", 5 * 1024 * 1024, 0, 100 * 1024 * 1024)


class R2Storage:
    """Lazy S3-compatible R2 archive client; no network call happens at import time."""

    def __init__(self) -> None:
        self.endpoint = os.environ.get("R2_ENDPOINT", "").strip().rstrip("/")
        self.bucket = os.environ.get("R2_BUCKET", "").strip()
        self.access_key_id = os.environ.get("R2_ACCESS_KEY_ID", "").strip()
        self.secret_access_key = os.environ.get("R2_SECRET_ACCESS_KEY", "").strip()
        self._client: Any | None = None

    @property
    def configured(self) -> bool:
        return all((self.endpoint, self.bucket, self.access_key_id, self.secret_access_key))

    def _get_client(self) -> Any:
        if not self.configured:
            raise RuntimeError("R2 storage is not configured")
        if self._client is None:
            try:
                import boto3
                from botocore.config import Config
            except ImportError as exc:
                raise RuntimeError("boto3 is required when R2 storage is enabled") from exc
            self._client = boto3.client(
                "s3",
                endpoint_url=self.endpoint,
                aws_access_key_id=self.access_key_id,
                aws_secret_access_key=self.secret_access_key,
                region_name=R2_REGION,
                config=Config(
                    signature_version="s3v4",
                    connect_timeout=10,
                    read_timeout=30,
                    retries={"max_attempts": 3, "mode": "standard"},
                ),
            )
        return self._client

    @staticmethod
    def object_key(tenant_id: str, mailbox_id: str, imap_uid: str) -> str:
        uid_digest = hashlib.sha256(str(imap_uid).encode("utf-8", "ignore")).hexdigest()
        parts = [R2_PREFIX, str(tenant_id), str(mailbox_id), f"{uid_digest}.eml"]
        return "/".join(part.strip("/") for part in parts if part.strip("/"))

    def archive_message(self, tenant_id: str, mailbox_id: str, imap_uid: str, raw_email: bytes) -> str:
        key = self.object_key(tenant_id, mailbox_id, imap_uid)
        self._get_client().put_object(
            Bucket=self.bucket,
            Key=key,
            Body=raw_email,
            ContentType="message/rfc822",
        )
        return key


R2_STORAGE = R2Storage()


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def normalize_email(value: str | None) -> str:
    return str(value or "").strip().lower()


def valid_email(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_{}|~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", value))


def resolve_imap_login_email(mailbox_email: str, login_email: str | None = None) -> str:
    resolved = normalize_email(login_email or mailbox_email)
    if not valid_email(resolved):
        raise HTTPException(400, "invalid IMAP login email")
    return resolved


def friendly_sync_error(exc: Exception) -> str:
    raw = clean_text(str(exc))[:300]
    lowered = raw.lower()
    if "authenticationfailed" in lowered or "authentication failed" in lowered:
        return "iCloud 登录失败：请使用主 iCloud 邮箱作为 IMAP 登录账号，并确认 App 专用密码有效；隐藏邮箱别名不能直接登录 IMAP。"
    if "imap4" in lowered and "login" in lowered:
        return "iCloud 登录失败：请检查 IMAP 登录邮箱和 App 专用密码。"
    return raw or "mailbox sync failed"


def load_fernet() -> Fernet:
    configured = os.environ.get("PLATFORM_MASTER_KEY", "").strip()
    if configured:
        try:
            return Fernet(configured.encode("ascii"))
        except (ValueError, UnicodeEncodeError) as exc:
            raise RuntimeError("invalid PLATFORM_MASTER_KEY") from exc
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        key = KEY_PATH.read_bytes().strip()
    except FileNotFoundError:
        key = Fernet.generate_key()
        try:
            fd = os.open(KEY_PATH, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            key = KEY_PATH.read_bytes().strip()
        else:
            try:
                os.write(fd, key)
                os.fsync(fd)
            finally:
                os.close(fd)
    try:
        return Fernet(key)
    except (ValueError, TypeError) as exc:
        raise RuntimeError("invalid platform master key") from exc


FERNET = load_fernet()


def load_operator_key() -> str:
    """Load the owner-console key from an environment variable or local secret file."""
    configured = os.environ.get("PLATFORM_ADMIN_KEY", "").strip()
    if configured:
        return configured
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        value = OPERATOR_KEY_PATH.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        value = "adm_" + secrets.token_urlsafe(32)
        try:
            fd = os.open(OPERATOR_KEY_PATH, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            value = OPERATOR_KEY_PATH.read_text(encoding="utf-8").strip()
            fd = -1
        if fd >= 0:
            try:
                os.write(fd, value.encode("utf-8"))
                os.fsync(fd)
            finally:
                os.close(fd)
    if len(value) < 16:
        raise RuntimeError("PLATFORM_ADMIN_KEY must be at least 16 characters")
    return value


OPERATOR_KEY = load_operator_key()
OPERATOR_HTML = load_operator_html()


class ManagedConnection(sqlite3.Connection):
    """Close SQLite handles when the existing ``with db()`` blocks finish."""

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> bool:
        try:
            return bool(super().__exit__(exc_type, exc_value, traceback))
        finally:
            self.close()


def db() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False, factory=ManagedConnection)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db() -> None:
    with db() as conn:
        conn.executescript(
            """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS tenants(
              id TEXT PRIMARY KEY,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,
              active INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions(
              token_hash TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,expires_at TEXT NOT NULL,
              created_at TEXT NOT NULL,FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS operator_sessions(
              token_hash TEXT PRIMARY KEY,expires_at TEXT NOT NULL,created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS mailboxes(
              id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,email TEXT NOT NULL,imap_username TEXT NOT NULL DEFAULT '',label TEXT NOT NULL DEFAULT '',
              imap_host TEXT NOT NULL DEFAULT 'imap.mail.me.com',imap_port INTEGER NOT NULL DEFAULT 993,
              mailbox TEXT NOT NULL DEFAULT 'INBOX',credential_ciphertext TEXT NOT NULL,
              api_key_hash TEXT NOT NULL,api_key_prefix TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1,
              last_sync_at TEXT NOT NULL DEFAULT '',last_error TEXT NOT NULL DEFAULT '',
              created_at TEXT NOT NULL,updated_at TEXT NOT NULL,UNIQUE(tenant_id,email),
              FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS messages(
              id INTEGER PRIMARY KEY AUTOINCREMENT,tenant_id TEXT NOT NULL,mailbox_id TEXT NOT NULL,
              imap_uid TEXT NOT NULL,message_id TEXT NOT NULL DEFAULT '',from_addr TEXT NOT NULL DEFAULT '',
              to_addrs TEXT NOT NULL DEFAULT '',subject TEXT NOT NULL DEFAULT '',
              body_preview TEXT NOT NULL DEFAULT '',code TEXT NOT NULL DEFAULT '',
              r2_object_key TEXT NOT NULL DEFAULT '',r2_error TEXT NOT NULL DEFAULT '',
              received_at TEXT NOT NULL,created_at TEXT NOT NULL,UNIQUE(mailbox_id,imap_uid),
              FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
              FOREIGN KEY(mailbox_id) REFERENCES mailboxes(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS audit_events(
              id INTEGER PRIMARY KEY AUTOINCREMENT,tenant_id TEXT,mailbox_id TEXT,
              action TEXT NOT NULL,remote_ip TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS public_access(
              id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,mailbox_id TEXT NOT NULL UNIQUE,
              token_hash TEXT UNIQUE NOT NULL,token_prefix TEXT NOT NULL,
              active INTEGER NOT NULL DEFAULT 1,last_access_at TEXT NOT NULL DEFAULT '',
              created_at TEXT NOT NULL,updated_at TEXT NOT NULL,
              FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
              FOREIGN KEY(mailbox_id) REFERENCES mailboxes(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_sessions_tenant ON sessions(tenant_id);
            CREATE INDEX IF NOT EXISTS idx_operator_sessions_expiry ON operator_sessions(expires_at);
            CREATE INDEX IF NOT EXISTS idx_mailboxes_tenant ON mailboxes(tenant_id);
            CREATE INDEX IF NOT EXISTS idx_messages_mailbox_time ON messages(mailbox_id,received_at DESC);
            CREATE INDEX IF NOT EXISTS idx_public_access_token ON public_access(token_hash);
            CREATE TABLE IF NOT EXISTS r2_usage(
              month TEXT PRIMARY KEY,put_count INTEGER NOT NULL DEFAULT 0,
              put_bytes INTEGER NOT NULL DEFAULT 0,updated_at TEXT NOT NULL
            );
            """
        )
        if conn.execute("SELECT 1 FROM tenants WHERE id=?", (INVENTORY_TENANT_ID,)).fetchone() is None:
            conn.execute(
                "INSERT INTO tenants(id,email,password_hash,active,created_at) VALUES(?,?,?,?,?)",
                (INVENTORY_TENANT_ID, INVENTORY_TENANT_EMAIL, hash_password(secrets.token_urlsafe(48)), 1, now_iso()),
            )
        mailbox_columns = {row["name"] for row in conn.execute("PRAGMA table_info(mailboxes)").fetchall()}
        if "imap_username" not in mailbox_columns:
            conn.execute("ALTER TABLE mailboxes ADD COLUMN imap_username TEXT NOT NULL DEFAULT ''")
        message_columns = {row["name"] for row in conn.execute("PRAGMA table_info(messages)").fetchall()}
        if "r2_object_key" not in message_columns:
            conn.execute("ALTER TABLE messages ADD COLUMN r2_object_key TEXT NOT NULL DEFAULT ''")
        if "r2_error" not in message_columns:
            conn.execute("ALTER TABLE messages ADD COLUMN r2_error TEXT NOT NULL DEFAULT ''")


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    enc = lambda value: base64.urlsafe_b64encode(value).decode("ascii")
    return "scrypt$16384$8$1$" + enc(salt) + "$" + enc(digest)


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, n, r, p, salt_text, expected_text = encoded.split("$", 5)
        if scheme != "scrypt":
            return False
        salt = base64.urlsafe_b64decode(salt_text)
        expected = base64.urlsafe_b64decode(expected_text)
        actual = hashlib.scrypt(password.encode(), salt=salt, n=int(n), r=int(r), p=int(p), dklen=len(expected))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def token_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def issue_session(tenant_id: str) -> tuple[str, int]:
    """Create a bearer session and persist only its hash."""
    raw = "sess_" + secrets.token_urlsafe(32)
    created = now_iso()
    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=SESSION_TTL)).replace(microsecond=0).isoformat()
    with db() as conn:
        conn.execute(
            "INSERT INTO sessions(token_hash,tenant_id,expires_at,created_at) VALUES(?,?,?,?)",
            (token_hash(raw), tenant_id, expires_at, created),
        )
    return raw, SESSION_TTL


def audit(tenant_id: str | None, action: str, request: Request | None = None, mailbox_id: str | None = None) -> None:
    ip = str(request.client.host if request and request.client else "")[:64]
    with db() as conn:
        conn.execute(
            "INSERT INTO audit_events(tenant_id,mailbox_id,action,remote_ip,created_at) VALUES(?,?,?,?,?)",
            (tenant_id, mailbox_id, action[:80], ip, now_iso()),
        )


class Limiter:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.events: dict[str, list[float]] = {}

    def allow(self, key: str, limit: int) -> bool:
        current = time.monotonic()
        with self.lock:
            values = [x for x in self.events.get(key, []) if current - x < 60]
            if len(values) >= limit:
                self.events[key] = values
                return False
            values.append(current)
            self.events[key] = values
            return True


LIMITER = Limiter()
SYNC_LOCKS: dict[str, threading.Lock] = {}
SYNC_LOCKS_GUARD = threading.Lock()


def rate_limit(request: Request, bucket: str, limit: int, subject: str = "") -> None:
    ip = str(request.client.host if request.client else "")
    suffix = ":" + subject if subject else ""
    if not LIMITER.allow(bucket + ":" + ip + suffix, limit):
        raise HTTPException(429, "rate limit exceeded")


def sync_lock(mailbox_id: str) -> threading.Lock:
    with SYNC_LOCKS_GUARD:
        return SYNC_LOCKS.setdefault(mailbox_id, threading.Lock())


class AuthPayload(BaseModel):
    email: str = Field(..., min_length=3, max_length=254)
    password: str = Field(..., min_length=8, max_length=128)


class MailboxPayload(BaseModel):
    email: str = Field(..., min_length=3, max_length=254)
    app_password: str = Field(..., min_length=1, max_length=128)
    label: str = Field("", max_length=80)
    imap_username: str | None = Field(default=None, max_length=254)


class OperatorMailboxPayload(MailboxPayload):
    tenant_id: str | None = Field(default=None, max_length=64)


class OperatorMailboxCredentialsPayload(BaseModel):
    app_password: str = Field(..., min_length=1, max_length=128)
    imap_username: str | None = Field(default=None, max_length=254)
    label: str | None = Field(default=None, max_length=80)


class OperatorLoginPayload(BaseModel):
    key: str = Field(..., min_length=8, max_length=256)


class TenantStatusPayload(BaseModel):
    active: bool


def issue_operator_session() -> tuple[str, int]:
    raw = "op_" + secrets.token_urlsafe(32)
    created = now_iso()
    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=SESSION_TTL)).replace(microsecond=0).isoformat()
    with db() as conn:
        conn.execute(
            "INSERT INTO operator_sessions(token_hash,expires_at,created_at) VALUES(?,?,?)",
            (token_hash(raw), expires_at, created),
        )
    return raw, SESSION_TTL


def require_operator(request: Request) -> bool:
    header = request.headers.get("Authorization", "")
    if not header.lower().startswith("bearer "):
        raise HTTPException(401, "operator bearer token required")
    raw = header[7:].strip()
    with db() as conn:
        row = conn.execute(
            "SELECT token_hash FROM operator_sessions WHERE token_hash=? AND expires_at>?",
            (token_hash(raw), now_iso()),
        ).fetchone()
    if row is None:
        raise HTTPException(401, "invalid or expired operator session")
    return True


def require_session(request: Request) -> dict[str, Any]:
    header = request.headers.get("Authorization", "")
    if not header.lower().startswith("bearer "):
        raise HTTPException(401, "bearer token required")
    raw = header[7:].strip()
    with db() as conn:
        row = conn.execute(
            """
            SELECT t.* FROM sessions s JOIN tenants t ON t.id=s.tenant_id
            WHERE s.token_hash=? AND t.active=1 AND s.expires_at>?
            """,
            (token_hash(raw), now_iso()),
        ).fetchone()
    if row is None:
        raise HTTPException(401, "invalid or expired session")
    return dict(row)


def tenant_mailbox(tenant_id: str, mailbox_id: str) -> dict[str, Any]:
    with db() as conn:
        row = conn.execute(
            """
            SELECT m.*, CASE WHEN p.active=1 THEN 1 ELSE 0 END AS public_access_enabled
            FROM mailboxes m LEFT JOIN public_access p ON p.mailbox_id=m.id
            WHERE m.id=? AND m.tenant_id=? AND m.active=1
            """,
            (mailbox_id, tenant_id),
        ).fetchone()
    if row is None:
        raise HTTPException(404, "mailbox not found")
    return dict(row)


def public_mailbox(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"], "email": row["email"], "label": row["label"],
        "imap_host": row["imap_host"], "imap_port": row["imap_port"],
        "mailbox": row["mailbox"], "api_key_prefix": row["api_key_prefix"],
        "active": bool(row["active"]), "last_sync_at": row["last_sync_at"] or None,
        "last_error": row["last_error"] or None, "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "public_access_enabled": bool(row.get("public_access_enabled", False)),
    }


def parse_date(value: str) -> datetime:
    try:
        parsed = parsedate_to_datetime(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).replace(microsecond=0)
    except (TypeError, ValueError, OverflowError):
        return datetime.now(timezone.utc).replace(microsecond=0)


def r2_usage_snapshot() -> dict[str, Any]:
    month = datetime.now(timezone.utc).strftime("%Y-%m")
    with db() as conn:
        row = conn.execute("SELECT put_count,put_bytes FROM r2_usage WHERE month=?", (month,)).fetchone()
    return {
        "month": month,
        "put_count": int(row["put_count"]) if row else 0,
        "put_bytes": int(row["put_bytes"]) if row else 0,
        "max_puts": R2_MONTHLY_MAX_PUTS,
        "max_bytes": R2_MONTHLY_MAX_BYTES,
        "archive_enabled": R2_ARCHIVE_ENABLED,
    }


def reserve_r2_upload(byte_count: int) -> bool:
    """Reserve local safety budget before an R2 PUT.

    The limits are deliberately below the advertised free tier. Reservations
    are conservative: a process crash may leave unused budget reserved until
    the next month, but it can never make this service exceed its configured
    local ceiling through concurrent workers.
    """
    if not R2_STORAGE.configured or not R2_ARCHIVE_ENABLED:
        return False
    if byte_count < 0 or byte_count > R2_MAX_OBJECT_BYTES:
        return False
    month = datetime.now(timezone.utc).strftime("%Y-%m")
    stamp = now_iso()
    with db() as conn:
        conn.execute(
            "INSERT INTO r2_usage(month,put_count,put_bytes,updated_at) VALUES(?,?,?,?) ON CONFLICT(month) DO NOTHING",
            (month, 0, 0, stamp),
        )
        row = conn.execute("SELECT put_count,put_bytes FROM r2_usage WHERE month=?", (month,)).fetchone()
        if row is None:
            return False
        if int(row["put_count"]) >= R2_MONTHLY_MAX_PUTS:
            return False
        if int(row["put_bytes"]) + byte_count > R2_MONTHLY_MAX_BYTES:
            return False
        conn.execute(
            "UPDATE r2_usage SET put_count=put_count+1,put_bytes=put_bytes+?,updated_at=? WHERE month=?",
            (byte_count, stamp, month),
        )
    return True


def sync_mailbox(row: dict[str, Any]) -> dict[str, Any]:
    lock = sync_lock(row["id"])
    if not lock.acquire(blocking=False):
        return {"ok": True, "skipped": True, "reason": "sync already running"}
    client = None
    try:
        if R2_REQUIRED and not R2_STORAGE.configured:
            raise RuntimeError("R2 storage is required but not configured")
        if R2_REQUIRED and not R2_ARCHIVE_ENABLED:
            raise RuntimeError("R2 storage is required but archiving is disabled")
        try:
            password = FERNET.decrypt(row["credential_ciphertext"].encode()).decode()
        except (InvalidToken, UnicodeDecodeError) as exc:
            raise RuntimeError("mailbox credential cannot be decrypted") from exc
        login_email = resolve_imap_login_email(row["email"], row.get("imap_username"))
        target_email = normalize_email(row["email"])
        client = imaplib.IMAP4_SSL(row["imap_host"], int(row["imap_port"]), timeout=env_int("PLATFORM_IMAP_TIMEOUT_SECONDS", 30, 5, 300))
        client.login(login_email, password)
        status_code, _ = client.select(row["mailbox"], readonly=True)
        if status_code != "OK":
            raise RuntimeError("unable to open mailbox")
        since = (datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)).strftime("%d-%b-%Y")
        status_code, data = client.uid("search", None, f"(SINCE {since})")
        uids = (data[0] or b"").split()[-RECENT_LIMIT:] if status_code == "OK" and data and data[0] is not None else []
        inspected = inserted = archived = r2_errors = 0
        for uid_bytes in uids:
            uid = uid_bytes.decode("ascii", errors="ignore")
            if not uid:
                continue
            status_code, fetched = client.uid("fetch", uid, "(BODY.PEEK[] INTERNALDATE)")
            if status_code != "OK":
                continue
            raw_email = next((item[1] for item in fetched if isinstance(item, tuple) and len(item) > 1 and isinstance(item[1], bytes)), None)
            if not raw_email:
                continue
            message = BytesParser(policy=policy.default).parsebytes(raw_email)
            subject = clean_text(str(message.get("Subject") or ""))[:500]
            sender = clean_text(str(message.get("From") or ""))[:500]
            recipients = clean_text(" ".join(str(message.get_all(x, []) or "") for x in ("To", "Cc", "Delivered-To", "X-Original-To", "X-Envelope-To", "Apparently-To")))[:1000]
            if target_email != login_email and target_email not in recipients.lower():
                continue
            inspected += 1
            body = message_body_text(message)
            code = extract_code("\n".join((subject, sender, recipients, body)))
            received = parse_date(str(message.get("Date") or ""))
            message_id = clean_text(str(message.get("Message-ID") or ""))[:500]
            with db() as conn:
                before = conn.execute("SELECT id,r2_object_key FROM messages WHERE mailbox_id=? AND imap_uid=?", (row["id"], uid)).fetchone()
            r2_key = str(before["r2_object_key"] or "") if before is not None else ""
            r2_error = ""
            if R2_STORAGE.configured and R2_ARCHIVE_ENABLED and not r2_key:
                if not reserve_r2_upload(len(raw_email)):
                    r2_errors += 1
                    r2_error = "R2 monthly safety budget reached or message is too large"
                    if R2_REQUIRED:
                        raise RuntimeError(r2_error)
                else:
                    try:
                        r2_key = R2_STORAGE.archive_message(row["tenant_id"], row["id"], uid, raw_email)
                        archived += 1
                    except Exception as exc:
                        r2_errors += 1
                        r2_error = clean_text(str(exc))[:300] or "R2 archive failed"
                        if R2_REQUIRED:
                            raise RuntimeError(r2_error) from exc
            with db() as conn:
                conn.execute(
                    """
                    INSERT INTO messages(tenant_id,mailbox_id,imap_uid,message_id,from_addr,to_addrs,subject,body_preview,code,r2_object_key,r2_error,received_at,created_at)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(mailbox_id,imap_uid) DO UPDATE SET
                      message_id=excluded.message_id,from_addr=excluded.from_addr,to_addrs=excluded.to_addrs,
                      subject=excluded.subject,body_preview=excluded.body_preview,code=excluded.code,
                      r2_object_key=CASE WHEN excluded.r2_object_key!='' THEN excluded.r2_object_key ELSE messages.r2_object_key END,
                      r2_error=excluded.r2_error,received_at=excluded.received_at
                    """,
                    (row["tenant_id"], row["id"], uid, message_id, sender, recipients, subject, body[:280], code, r2_key, r2_error, received.isoformat(), now_iso()),
                )
                if before is None:
                    inserted += 1
        synced_at = now_iso()
        with db() as conn:
            conn.execute("UPDATE mailboxes SET last_sync_at=?,last_error='',updated_at=? WHERE id=?", (synced_at, synced_at, row["id"]))
        return {
            "ok": True, "skipped": False, "inspected": inspected, "inserted": inserted,
            "r2_archived": archived, "r2_errors": r2_errors, "synced_at": synced_at,
        }
    except Exception as exc:
        message = friendly_sync_error(exc)
        with db() as conn:
            conn.execute("UPDATE mailboxes SET last_error=?,updated_at=? WHERE id=?", (message, now_iso(), row["id"]))
        raise RuntimeError(message) from exc
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
            try:
                client.logout()
            except Exception:
                pass
        lock.release()


def get_latest_code(row: dict[str, Any], after: int = 0) -> dict[str, Any]:
    cutoff = None
    if CODE_MAX_AGE:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=CODE_MAX_AGE)
    if after:
        try:
            after_date = datetime.fromtimestamp(after, timezone.utc)
            if cutoff is None or after_date > cutoff:
                cutoff = after_date
        except (OverflowError, OSError, ValueError):
            pass
    with db() as conn:
        if cutoff is None:
            message = conn.execute(
                "SELECT id,subject,from_addr,to_addrs,code,received_at FROM messages WHERE mailbox_id=? AND code!='' ORDER BY datetime(received_at) DESC,id DESC LIMIT 1",
                (row["id"],),
            ).fetchone()
        else:
            message = conn.execute(
                "SELECT id,subject,from_addr,to_addrs,code,received_at FROM messages WHERE mailbox_id=? AND code!='' AND received_at>=? ORDER BY datetime(received_at) DESC,id DESC LIMIT 1",
                (row["id"], cutoff.isoformat()),
            ).fetchone()
    if message is None:
        return {"ok": True, "code": "", "mail": None}
    return {
        "ok": True,
        "code": message["code"],
        "mail": {
            "id": message["id"], "subject": message["subject"],
            "from": message["from_addr"], "to": message["to_addrs"],
            "received_at": message["received_at"],
        },
    }


def message_history(mailbox_id: str, limit: int = 50, before_id: int = 0) -> dict[str, Any]:
    """Return recent stored messages for a mailbox without exposing credentials."""
    page_size = max(1, min(int(limit or 50), 100))
    cursor = max(0, int(before_id or 0))
    with db() as conn:
        rows = conn.execute(
            """
            SELECT id,subject,from_addr,to_addrs,body_preview,code,received_at
            FROM messages
            WHERE mailbox_id=? AND (?=0 OR id<?)
            ORDER BY id DESC
            LIMIT ?
            """,
            (mailbox_id, cursor, cursor, page_size + 1),
        ).fetchall()
    has_more = len(rows) > page_size
    rows = rows[:page_size]
    messages = [
        {
            "id": row["id"],
            "subject": row["subject"] or "",
            "from": row["from_addr"] or "",
            "to": row["to_addrs"] or "",
            "preview": row["body_preview"] or "",
            "code": row["code"] or "",
            "received_at": row["received_at"] or "",
        }
        for row in rows
    ]
    return {
        "messages": messages,
        "has_more": has_more,
        "next_before": messages[-1]["id"] if has_more and messages else None,
    }


def mailbox_by_key(request: Request, mailbox_id: str) -> dict[str, Any]:
    rate_limit(request, "code", 60)
    key = (request.headers.get("X-Mailbox-Key") or request.headers.get("X-API-Key") or "").strip()
    if not key or len(key) > 256:
        raise HTTPException(401, "mailbox key required")
    with db() as conn:
        row = conn.execute("SELECT * FROM mailboxes WHERE id=? AND active=1", (mailbox_id,)).fetchone()
    if row is None or not hmac.compare_digest(row["api_key_hash"], token_hash(key)):
        raise HTTPException(401, "invalid mailbox key")
    result = dict(row)
    audit(result["tenant_id"], "code.read", request, mailbox_id)
    return result


def public_access_by_token(request: Request, access_token: str) -> dict[str, Any]:
    """Resolve an opaque public link without exposing an email or mailbox key in the URL."""
    token = str(access_token or "").strip()
    if not token or len(token) > 256:
        raise HTTPException(404, "public link not found")
    rate_limit(request, "public-code", 60, token_hash(token)[:16])
    with db() as conn:
        row = conn.execute(
            """
            SELECT p.*,m.id AS mailbox_id,m.email,m.label,m.active AS mailbox_active
            FROM public_access p JOIN mailboxes m ON m.id=p.mailbox_id
              JOIN tenants t ON t.id=p.tenant_id
            WHERE p.token_hash=? AND p.active=1 AND m.active=1 AND t.active=1
            """,
            (token_hash(token),),
        ).fetchone()
        if row is None:
            raise HTTPException(404, "public link not found")
        conn.execute("UPDATE public_access SET last_access_at=? WHERE id=?", (now_iso(), row["id"]))
    return dict(row)


def public_link_payload(token: str) -> dict[str, str]:
    return {
        "token": token,
        "api_url": f"{PUBLIC_ORIGIN}/api/v1/public/mail/{token}/latest",
        "viewer_url": f"{PUBLIC_ORIGIN}/public/mail/{token}",
    }


def delivery_payload(email: str, viewer_url: str) -> dict[str, str]:
    return {
        "mailbox_email": email,
        "code_url": viewer_url,
        "delivery_text": f"{email}\n{viewer_url}",
    }


def create_public_access_record(tenant_id: str, mailbox_id: str) -> tuple[str, dict[str, Any]]:
    token = "pub_" + secrets.token_urlsafe(32)
    access_id = uuid.uuid4().hex
    stamp = now_iso()
    with db() as conn:
        conn.execute(
            """
            INSERT INTO public_access(id,tenant_id,mailbox_id,token_hash,token_prefix,active,last_access_at,created_at,updated_at)
            VALUES(?,?,?,?,?,1,'',?,?)
            ON CONFLICT(mailbox_id) DO UPDATE SET
              tenant_id=excluded.tenant_id,token_hash=excluded.token_hash,token_prefix=excluded.token_prefix,
              active=1,last_access_at='',updated_at=excluded.updated_at
            """,
            (access_id, tenant_id, mailbox_id, token_hash(token), token[:12], stamp, stamp),
        )
        row = conn.execute(
            "SELECT * FROM mailboxes WHERE id=? AND tenant_id=? AND active=1",
            (mailbox_id, tenant_id),
        ).fetchone()
    if row is None:
        raise HTTPException(404, "mailbox not found")
    return token, dict(row)


init_db()
app = FastAPI(title="iCloud Code Platform", version=SERVICE_VERSION, docs_url="/docs", redoc_url=None)
origins = [x.strip() for x in os.environ.get("PLATFORM_CORS_ORIGINS", "").split(",") if x.strip() and x.strip() != "*"]
if origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Mailbox-Key", "X-API-Key"],
    )


@app.middleware("http")
async def security_headers(request: Request, call_next):
    length = request.headers.get("content-length")
    if length:
        try:
            if int(length) > MAX_BODY:
                return JSONResponse({"detail": "request body too large"}, status_code=413)
        except ValueError:
            return JSONResponse({"detail": "invalid content length"}, status_code=400)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "ok": True, "service": "icloud-code-platform", "version": SERVICE_VERSION,
        "r2_configured": R2_STORAGE.configured,
        "r2_required": R2_REQUIRED,
        "r2_usage": r2_usage_snapshot(),
    }


@app.post("/api/v1/auth/register")
def register(payload: AuthPayload, request: Request) -> dict[str, Any]:
    rate_limit(request, "auth", 10)
    email = normalize_email(payload.email)
    if not valid_email(email):
        raise HTTPException(400, "invalid email")
    if email == INVENTORY_TENANT_EMAIL:
        raise HTTPException(400, "reserved account email")
    tenant_id = uuid.uuid4().hex
    try:
        with db() as conn:
            conn.execute("INSERT INTO tenants(id,email,password_hash,created_at) VALUES(?,?,?,?)", (tenant_id, email, hash_password(payload.password), now_iso()))
    except sqlite3.IntegrityError as exc:
        raise HTTPException(409, "account already exists") from exc
    session, expires = issue_session(tenant_id)
    audit(tenant_id, "tenant.register", request)
    return {"ok": True, "tenant_id": tenant_id, "access_token": session, "token_type": "bearer", "expires_in": expires}


@app.post("/api/v1/auth/login")
def login(payload: AuthPayload, request: Request) -> dict[str, Any]:
    rate_limit(request, "auth", 10)
    email = normalize_email(payload.email)
    with db() as conn:
        row = conn.execute("SELECT * FROM tenants WHERE email=? AND active=1", (email,)).fetchone()
    if row is None or not verify_password(payload.password, row["password_hash"]):
        raise HTTPException(401, "invalid email or password")
    session, expires = issue_session(row["id"])
    audit(row["id"], "tenant.login", request)
    return {"ok": True, "tenant_id": row["id"], "access_token": session, "token_type": "bearer", "expires_in": expires}


@app.post("/api/v1/auth/logout")
def logout(request: Request, tenant: dict[str, Any] = Depends(require_session)) -> dict[str, Any]:
    raw = request.headers.get("Authorization", "")[7:].strip()
    with db() as conn:
        conn.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash(raw),))
    audit(tenant["id"], "tenant.logout", request)
    return {"ok": True}


@app.get("/api/v1/me")
def me(tenant: dict[str, Any] = Depends(require_session)) -> dict[str, Any]:
    return {"ok": True, "tenant": {"id": tenant["id"], "email": tenant["email"], "created_at": tenant["created_at"]}}


@app.post("/api/v1/operator/login")
def operator_login(payload: OperatorLoginPayload, request: Request) -> dict[str, Any]:
    rate_limit(request, "operator-auth", 8)
    if not hmac.compare_digest(OPERATOR_KEY, payload.key.strip()):
        raise HTTPException(401, "invalid operator key")
    session, expires = issue_operator_session()
    return {"ok": True, "access_token": session, "token_type": "bearer", "expires_in": expires}


@app.post("/api/v1/operator/logout")
def operator_logout(request: Request, _operator: bool = Depends(require_operator)) -> dict[str, Any]:
    raw = request.headers.get("Authorization", "")[7:].strip()
    with db() as conn:
        conn.execute("DELETE FROM operator_sessions WHERE token_hash=?", (token_hash(raw),))
    return {"ok": True}


@app.get("/api/v1/operator/overview")
def operator_overview(_operator: bool = Depends(require_operator)) -> dict[str, Any]:
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).replace(microsecond=0).isoformat()
    with db() as conn:
        counts = {
            "tenants": conn.execute("SELECT COUNT(*) FROM tenants WHERE id != ?", (INVENTORY_TENANT_ID,)).fetchone()[0],
            "active_tenants": conn.execute("SELECT COUNT(*) FROM tenants WHERE id != ? AND active=1", (INVENTORY_TENANT_ID,)).fetchone()[0],
            "mailboxes": conn.execute("SELECT COUNT(*) FROM mailboxes WHERE active=1").fetchone()[0],
            "messages": conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0],
            "codes_24h": conn.execute("SELECT COUNT(*) FROM messages WHERE code!='' AND received_at>=?", (cutoff,)).fetchone()[0],
            "sync_errors": conn.execute("SELECT COUNT(*) FROM mailboxes WHERE active=1 AND last_error!=''").fetchone()[0],
            "public_links": conn.execute("SELECT COUNT(*) FROM public_access WHERE active=1").fetchone()[0],
        }
    return {
        "ok": True,
        "counts": counts,
        "r2_configured": R2_STORAGE.configured,
        "r2_required": R2_REQUIRED,
        "r2_usage": r2_usage_snapshot(),
    }


@app.post("/api/v1/operator/tenants")
def operator_create_tenant(payload: AuthPayload, request: Request, _operator: bool = Depends(require_operator)) -> dict[str, Any]:
    rate_limit(request, "operator-tenant", 30)
    email = normalize_email(payload.email)
    if not valid_email(email):
        raise HTTPException(400, "invalid tenant email")
    if email == INVENTORY_TENANT_EMAIL:
        raise HTTPException(400, "reserved account email")
    tenant_id = uuid.uuid4().hex
    try:
        with db() as conn:
            conn.execute(
                "INSERT INTO tenants(id,email,password_hash,created_at) VALUES(?,?,?,?)",
                (tenant_id, email, hash_password(payload.password), now_iso()),
            )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(409, "account already exists") from exc
    audit(tenant_id, "operator.tenant.create", request)
    return {"ok": True, "tenant": {"id": tenant_id, "email": email, "active": True}}


@app.get("/api/v1/operator/tenants")
def operator_tenants(search: str = Query("", max_length=100), _operator: bool = Depends(require_operator)) -> dict[str, Any]:
    term = f"%{search.strip()}%"
    with db() as conn:
        rows = conn.execute(
            """
            SELECT t.id,t.email,t.active,t.created_at,
              (SELECT COUNT(*) FROM mailboxes m WHERE m.tenant_id=t.id AND m.active=1) AS mailbox_count,
              (SELECT COUNT(*) FROM messages x WHERE x.tenant_id=t.id) AS message_count,
              (SELECT MAX(m.last_sync_at) FROM mailboxes m WHERE m.tenant_id=t.id AND m.active=1) AS last_sync_at,
              (SELECT COUNT(*) FROM mailboxes m WHERE m.tenant_id=t.id AND m.active=1 AND m.last_error!='') AS error_count
            FROM tenants t
            WHERE t.id != ? AND (t.email LIKE ? OR t.id LIKE ?)
            ORDER BY t.created_at DESC
            LIMIT 200
            """,
            (INVENTORY_TENANT_ID, term, term),
        ).fetchall()
    return {
        "ok": True,
        "tenants": [
            {
                "id": row["id"], "email": row["email"], "active": bool(row["active"]),
                "created_at": row["created_at"], "mailbox_count": row["mailbox_count"],
                "message_count": row["message_count"], "last_sync_at": row["last_sync_at"] or None,
                "error_count": row["error_count"],
            }
            for row in rows
        ],
    }


@app.patch("/api/v1/operator/tenants/{tenant_id}")
def operator_update_tenant(tenant_id: str, payload: TenantStatusPayload, request: Request, _operator: bool = Depends(require_operator)) -> dict[str, Any]:
    if tenant_id == INVENTORY_TENANT_ID:
        raise HTTPException(400, "platform inventory cannot be changed as a customer")
    stamp = now_iso()
    with db() as conn:
        row = conn.execute("SELECT id,email FROM tenants WHERE id=?", (tenant_id,)).fetchone()
        if row is None:
            raise HTTPException(404, "tenant not found")
        conn.execute("UPDATE tenants SET active=? WHERE id=?", (1 if payload.active else 0, tenant_id))
        if not payload.active:
            conn.execute("DELETE FROM sessions WHERE tenant_id=?", (tenant_id,))
            conn.execute("UPDATE public_access SET active=0,updated_at=? WHERE tenant_id=?", (stamp, tenant_id))
    audit(tenant_id, "operator.tenant.activate" if payload.active else "operator.tenant.suspend", request)
    return {"ok": True, "tenant": {"id": row["id"], "email": row["email"], "active": payload.active}}


def operator_mailbox_row(mailbox_id: str, active_only: bool = True) -> dict[str, Any]:
    condition = " AND m.active=1" if active_only else ""
    with db() as conn:
        row = conn.execute(
            f"""
            SELECT m.*,t.email AS tenant_email,t.active AS tenant_active,
              CASE WHEN p.active=1 THEN 1 ELSE 0 END AS public_access_enabled,
              (SELECT x.code FROM messages x WHERE x.mailbox_id=m.id AND x.code!='' ORDER BY datetime(x.received_at) DESC,x.id DESC LIMIT 1) AS latest_code,
              (SELECT x.received_at FROM messages x WHERE x.mailbox_id=m.id AND x.code!='' ORDER BY datetime(x.received_at) DESC,x.id DESC LIMIT 1) AS latest_code_at,
              (SELECT COUNT(*) FROM messages x WHERE x.mailbox_id=m.id) AS message_count
            FROM mailboxes m JOIN tenants t ON t.id=m.tenant_id
              LEFT JOIN public_access p ON p.mailbox_id=m.id
            WHERE m.id=?{condition}
            """,
            (mailbox_id,),
        ).fetchone()
    if row is None:
        raise HTTPException(404, "mailbox not found")
    return dict(row)


@app.get("/api/v1/operator/mailboxes")
def operator_mailboxes(
    search: str = Query("", max_length=100),
    tenant_id: str = Query("", max_length=64),
    include_inactive: bool = Query(False),
    _operator: bool = Depends(require_operator),
) -> dict[str, Any]:
    term = f"%{search.strip()}%"
    active_clause = "" if include_inactive else " AND m.active=1"
    with db() as conn:
        rows = conn.execute(
            f"""
            SELECT m.id,m.tenant_id,m.email,m.imap_username,m.label,m.active,m.last_sync_at,m.last_error,m.created_at,m.updated_at,
              t.email AS tenant_email,t.active AS tenant_active,
              CASE WHEN p.active=1 THEN 1 ELSE 0 END AS public_access_enabled,
              (SELECT x.code FROM messages x WHERE x.mailbox_id=m.id AND x.code!='' ORDER BY datetime(x.received_at) DESC,x.id DESC LIMIT 1) AS latest_code,
              (SELECT x.received_at FROM messages x WHERE x.mailbox_id=m.id AND x.code!='' ORDER BY datetime(x.received_at) DESC,x.id DESC LIMIT 1) AS latest_code_at,
              (SELECT COUNT(*) FROM messages x WHERE x.mailbox_id=m.id) AS message_count
            FROM mailboxes m JOIN tenants t ON t.id=m.tenant_id
              LEFT JOIN public_access p ON p.mailbox_id=m.id
            WHERE (?='' OR m.tenant_id=?) AND (m.email LIKE ? OR m.label LIKE ? OR t.email LIKE ?){active_clause}
            ORDER BY m.created_at DESC LIMIT 500
            """,
            (tenant_id.strip(), tenant_id.strip(), term, term, term),
        ).fetchall()
    return {"ok": True, "mailboxes": [operator_public_mailbox(dict(row)) for row in rows]}


def operator_public_mailbox(row: dict[str, Any]) -> dict[str, Any]:
    unassigned = row.get("tenant_id") == INVENTORY_TENANT_ID
    return {
        "id": row["id"], "tenant_id": None if unassigned else row["tenant_id"],
        "tenant_email": INVENTORY_TENANT_DISPLAY if unassigned else row.get("tenant_email", ""),
        "tenant_unassigned": unassigned,
        "imap_username": row.get("imap_username") or "",
        "email": row["email"], "label": row["label"], "active": bool(row["active"]),
        "tenant_active": bool(row.get("tenant_active", True)),
        "last_sync_at": row["last_sync_at"] or None, "last_error": row["last_error"] or None,
        "created_at": row["created_at"], "updated_at": row["updated_at"],
        "public_access_enabled": bool(row["public_access_enabled"]),
        "latest_code": row["latest_code"] or "", "latest_code_at": row["latest_code_at"] or None,
        "message_count": row["message_count"],
    }


def resolve_operator_tenant(tenant_id: str | None) -> dict[str, Any]:
    requested = str(tenant_id or "").strip()
    resolved = requested or INVENTORY_TENANT_ID
    with db() as conn:
        tenant = conn.execute("SELECT id,active FROM tenants WHERE id=?", (resolved,)).fetchone()
    if tenant is None or not tenant["active"]:
        raise HTTPException(404, "active tenant not found")
    return dict(tenant)


def create_operator_mailbox_record(tenant_id: str, payload: MailboxPayload, request: Request) -> dict[str, Any]:
    email = normalize_email(payload.email)
    if not valid_email(email):
        raise HTTPException(400, "invalid mailbox email")
    mailbox_id = uuid.uuid4().hex
    api_key = "mb_" + secrets.token_urlsafe(32)
    stamp = now_iso()
    ciphertext = FERNET.encrypt(payload.app_password.encode()).decode("ascii")
    try:
        with db() as conn:
            conn.execute(
                "INSERT INTO mailboxes(id,tenant_id,email,imap_username,label,credential_ciphertext,api_key_hash,api_key_prefix,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (mailbox_id, tenant_id, email, resolve_imap_login_email(email, payload.imap_username), payload.label.strip(), ciphertext, token_hash(api_key), api_key[:12], stamp, stamp),
            )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(409, "mailbox already exists for this assignment") from exc
    token, _ = create_public_access_record(tenant_id, mailbox_id)
    links = public_link_payload(token)
    audit(tenant_id, "operator.mailbox.create", request, mailbox_id)
    return {
        "ok": True, "mailbox": operator_public_mailbox(operator_mailbox_row(mailbox_id)),
        "api_key": api_key, "api_key_notice": "copy this key now; it will not be shown again",
        **links, **delivery_payload(email, links["viewer_url"]),
    }


@app.post("/api/v1/operator/mailboxes")
def operator_create_mailbox(payload: OperatorMailboxPayload, request: Request, _operator: bool = Depends(require_operator)) -> dict[str, Any]:
    tenant = resolve_operator_tenant(payload.tenant_id)
    return create_operator_mailbox_record(tenant["id"], payload, request)


@app.post("/api/v1/operator/tenants/{tenant_id}/mailboxes")
def operator_create_mailbox_for_tenant(tenant_id: str, payload: MailboxPayload, request: Request, _operator: bool = Depends(require_operator)) -> dict[str, Any]:
    tenant = resolve_operator_tenant(tenant_id)
    return create_operator_mailbox_record(tenant["id"], payload, request)


@app.patch("/api/v1/operator/mailboxes/{mailbox_id}/credentials")
def operator_update_mailbox_credentials(
    mailbox_id: str,
    payload: OperatorMailboxCredentialsPayload,
    request: Request,
    _operator: bool = Depends(require_operator),
) -> dict[str, Any]:
    row = operator_mailbox_row(mailbox_id, active_only=False)
    login_email = resolve_imap_login_email(row["email"], payload.imap_username)
    label = row["label"] if payload.label is None else payload.label.strip()
    ciphertext = FERNET.encrypt(payload.app_password.encode()).decode("ascii")
    stamp = now_iso()
    with db() as conn:
        conn.execute(
            "UPDATE mailboxes SET imap_username=?,label=?,credential_ciphertext=?,last_error='',updated_at=? WHERE id=?",
            (login_email, label, ciphertext, stamp, mailbox_id),
        )
    audit(row["tenant_id"], "operator.mailbox.credentials.update", request, mailbox_id)
    return {"ok": True, "mailbox": operator_public_mailbox(operator_mailbox_row(mailbox_id, active_only=False))}


@app.post("/api/v1/operator/mailboxes/{mailbox_id}/public-access")
def operator_create_public_access(mailbox_id: str, request: Request, _operator: bool = Depends(require_operator)) -> dict[str, Any]:
    row = operator_mailbox_row(mailbox_id)
    if not row["tenant_active"]:
        raise HTTPException(409, "tenant is inactive")
    token, stored = create_public_access_record(row["tenant_id"], mailbox_id)
    links = public_link_payload(token)
    audit(row["tenant_id"], "operator.mailbox.public_access.create", request, mailbox_id)
    return {"ok": True, "mailbox": operator_public_mailbox(operator_mailbox_row(mailbox_id)), **links, **delivery_payload(stored["email"], links["viewer_url"])}


@app.delete("/api/v1/operator/mailboxes/{mailbox_id}/public-access")
def operator_revoke_public_access(mailbox_id: str, request: Request, _operator: bool = Depends(require_operator)) -> dict[str, Any]:
    row = operator_mailbox_row(mailbox_id, active_only=False)
    with db() as conn:
        conn.execute("UPDATE public_access SET active=0,updated_at=? WHERE mailbox_id=?", (now_iso(), mailbox_id))
    audit(row["tenant_id"], "operator.mailbox.public_access.revoke", request, mailbox_id)
    return {"ok": True}


@app.patch("/api/v1/operator/mailboxes/{mailbox_id}")
def operator_update_mailbox(mailbox_id: str, payload: TenantStatusPayload, request: Request, _operator: bool = Depends(require_operator)) -> dict[str, Any]:
    row = operator_mailbox_row(mailbox_id, active_only=False)
    stamp = now_iso()
    with db() as conn:
        conn.execute("UPDATE mailboxes SET active=?,updated_at=? WHERE id=?", (1 if payload.active else 0, stamp, mailbox_id))
        if not payload.active:
            conn.execute("UPDATE public_access SET active=0,updated_at=? WHERE mailbox_id=?", (stamp, mailbox_id))
    audit(row["tenant_id"], "operator.mailbox.activate" if payload.active else "operator.mailbox.suspend", request, mailbox_id)
    return {"ok": True, "mailbox": operator_public_mailbox(operator_mailbox_row(mailbox_id, active_only=False))}


@app.post("/api/v1/operator/mailboxes/{mailbox_id}/sync")
def operator_sync_mailbox(mailbox_id: str, request: Request, _operator: bool = Depends(require_operator)) -> dict[str, Any]:
    row = operator_mailbox_row(mailbox_id)
    if not row["tenant_active"]:
        raise HTTPException(409, "tenant is inactive")
    try:
        result = sync_mailbox(row)
    except RuntimeError as exc:
        raise HTTPException(502, str(exc)) from exc
    audit(row["tenant_id"], "operator.mailbox.sync", request, mailbox_id)
    return result


@app.get("/api/v1/operator/mailboxes/{mailbox_id}/code")
def operator_mailbox_code(mailbox_id: str, request: Request, after: int = Query(0, ge=0), _operator: bool = Depends(require_operator)) -> dict[str, Any]:
    row = operator_mailbox_row(mailbox_id, active_only=False)
    rate_limit(request, "operator-code", 120)
    result = get_latest_code(row, after)
    return {"ok": True, "mailbox": row["email"], **result}


@app.get("/api/v1/operator/mailboxes/{mailbox_id}/messages")
def operator_mailbox_messages(
    mailbox_id: str,
    limit: int = Query(50, ge=1, le=100),
    before: int = Query(0, ge=0),
    _operator: bool = Depends(require_operator),
) -> dict[str, Any]:
    row = operator_mailbox_row(mailbox_id, active_only=False)
    return {"ok": True, "mailbox": row["email"], **message_history(mailbox_id, limit, before)}


@app.delete("/api/v1/operator/mailboxes/{mailbox_id}")
def operator_delete_mailbox(mailbox_id: str, request: Request, _operator: bool = Depends(require_operator)) -> dict[str, Any]:
    row = operator_mailbox_row(mailbox_id, active_only=False)
    stamp = now_iso()
    with db() as conn:
        conn.execute("UPDATE mailboxes SET active=0,updated_at=? WHERE id=?", (stamp, mailbox_id))
        conn.execute("UPDATE public_access SET active=0,updated_at=? WHERE mailbox_id=?", (stamp, mailbox_id))
    audit(row["tenant_id"], "operator.mailbox.delete", request, mailbox_id)
    return {"ok": True}


@app.get("/api/v1/mailboxes")
def list_mailboxes(tenant: dict[str, Any] = Depends(require_session)) -> dict[str, Any]:
    with db() as conn:
        rows = conn.execute(
            """
            SELECT m.*, CASE WHEN p.active=1 THEN 1 ELSE 0 END AS public_access_enabled
            FROM mailboxes m LEFT JOIN public_access p ON p.mailbox_id=m.id
            WHERE m.tenant_id=? AND m.active=1 ORDER BY m.created_at
            """,
            (tenant["id"],),
        ).fetchall()
    return {"ok": True, "mailboxes": [public_mailbox(dict(row)) for row in rows]}


@app.post("/api/v1/mailboxes")
def create_mailbox(payload: MailboxPayload, request: Request, tenant: dict[str, Any] = Depends(require_session)) -> dict[str, Any]:
    email = normalize_email(payload.email)
    if not valid_email(email):
        raise HTTPException(400, "invalid mailbox email")
    mailbox_id = uuid.uuid4().hex
    api_key = "mb_" + secrets.token_urlsafe(32)
    stamp = now_iso()
    ciphertext = FERNET.encrypt(payload.app_password.encode()).decode("ascii")
    try:
        with db() as conn:
            conn.execute(
                "INSERT INTO mailboxes(id,tenant_id,email,imap_username,label,credential_ciphertext,api_key_hash,api_key_prefix,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (mailbox_id, tenant["id"], email, resolve_imap_login_email(email, payload.imap_username), payload.label.strip(), ciphertext, token_hash(api_key), api_key[:12], stamp, stamp),
            )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(409, "mailbox already exists for this account") from exc
    audit(tenant["id"], "mailbox.create", request, mailbox_id)
    row = {"id": mailbox_id, "email": email, "label": payload.label.strip(), "imap_host": "imap.mail.me.com", "imap_port": 993, "mailbox": "INBOX", "api_key_prefix": api_key[:12], "active": 1, "last_sync_at": "", "last_error": "", "created_at": stamp, "updated_at": stamp}
    return {"ok": True, "mailbox": public_mailbox(row), "api_key": api_key, "api_key_notice": "copy this key now; it will not be shown again"}


@app.post("/api/v1/mailboxes/{mailbox_id}/rotate-key")
def rotate_key(mailbox_id: str, request: Request, tenant: dict[str, Any] = Depends(require_session)) -> dict[str, Any]:
    row = tenant_mailbox(tenant["id"], mailbox_id)
    key = "mb_" + secrets.token_urlsafe(32)
    with db() as conn:
        conn.execute("UPDATE mailboxes SET api_key_hash=?,api_key_prefix=?,updated_at=? WHERE id=? AND tenant_id=?", (token_hash(key), key[:12], now_iso(), mailbox_id, tenant["id"]))
    row["api_key_prefix"] = key[:12]
    audit(tenant["id"], "mailbox.rotate_key", request, mailbox_id)
    return {"ok": True, "mailbox": public_mailbox(row), "api_key": key, "api_key_notice": "copy this key now; it will not be shown again"}


@app.post("/api/v1/mailboxes/{mailbox_id}/public-access")
def create_public_access(mailbox_id: str, request: Request, tenant: dict[str, Any] = Depends(require_session)) -> dict[str, Any]:
    row = tenant_mailbox(tenant["id"], mailbox_id)
    token, stored = create_public_access_record(tenant["id"], mailbox_id)
    row["public_access_enabled"] = 1
    audit(tenant["id"], "mailbox.public_access.create", request, mailbox_id)
    links = public_link_payload(token)
    return {
        "ok": True,
        "mailbox": public_mailbox(row),
        **links,
        **delivery_payload(stored["email"], links["viewer_url"]),
        "token_notice": "copy this token now; it will not be shown again",
    }


@app.delete("/api/v1/mailboxes/{mailbox_id}/public-access")
def revoke_public_access(mailbox_id: str, request: Request, tenant: dict[str, Any] = Depends(require_session)) -> dict[str, Any]:
    row = tenant_mailbox(tenant["id"], mailbox_id)
    stamp = now_iso()
    with db() as conn:
        conn.execute(
            "UPDATE public_access SET active=0,updated_at=? WHERE mailbox_id=? AND tenant_id=?",
            (stamp, mailbox_id, tenant["id"]),
        )
    row["public_access_enabled"] = 0
    audit(tenant["id"], "mailbox.public_access.revoke", request, mailbox_id)
    return {"ok": True, "mailbox": public_mailbox(row)}


@app.delete("/api/v1/mailboxes/{mailbox_id}")
def delete_mailbox(mailbox_id: str, request: Request, tenant: dict[str, Any] = Depends(require_session)) -> dict[str, Any]:
    tenant_mailbox(tenant["id"], mailbox_id)
    with db() as conn:
        conn.execute("UPDATE mailboxes SET active=0,updated_at=? WHERE id=? AND tenant_id=?", (now_iso(), mailbox_id, tenant["id"]))
        conn.execute("UPDATE public_access SET active=0,updated_at=? WHERE mailbox_id=? AND tenant_id=?", (now_iso(), mailbox_id, tenant["id"]))
    audit(tenant["id"], "mailbox.delete", request, mailbox_id)
    return {"ok": True}


@app.post("/api/v1/mailboxes/{mailbox_id}/sync")
def manual_sync(mailbox_id: str, request: Request, tenant: dict[str, Any] = Depends(require_session)) -> dict[str, Any]:
    row = tenant_mailbox(tenant["id"], mailbox_id)
    try:
        result = sync_mailbox(row)
    except RuntimeError as exc:
        raise HTTPException(502, str(exc)) from exc
    audit(tenant["id"], "mailbox.sync", request, mailbox_id)
    return result


@app.get("/api/v1/mailboxes/{mailbox_id}/code")
def management_code(mailbox_id: str, request: Request, after: int = Query(0, ge=0), tenant: dict[str, Any] = Depends(require_session)) -> dict[str, Any]:
    row = tenant_mailbox(tenant["id"], mailbox_id)
    rate_limit(request, "management-code", 60)
    return get_latest_code(row, after)


@app.get("/api/v1/mailboxes/{mailbox_id}/messages")
def management_messages(
    mailbox_id: str,
    limit: int = Query(50, ge=1, le=100),
    before: int = Query(0, ge=0),
    tenant: dict[str, Any] = Depends(require_session),
) -> dict[str, Any]:
    row = tenant_mailbox(tenant["id"], mailbox_id)
    return {"ok": True, "mailbox": row["email"], **message_history(mailbox_id, limit, before)}


@app.get("/api/v1/code")
def customer_code(request: Request, mailbox_id: str = Query(..., min_length=8, max_length=64), after: int = Query(0, ge=0)) -> dict[str, Any]:
    return get_latest_code(mailbox_by_key(request, mailbox_id), after)


@app.get("/api/v1/public/mail/{access_token}/latest")
def public_customer_code(request: Request, access_token: str) -> dict[str, Any]:
    access = public_access_by_token(request, access_token)
    mailbox = dict(access)
    mailbox["id"] = access["mailbox_id"]
    result = get_latest_code(mailbox, 0)
    history = message_history(access["mailbox_id"])
    return {
        "ok": True,
        "email": access["email"],
        "label": access["label"],
        "mail": result["mail"],
        "code": result["code"],
        **history,
    }


@app.get("/api/v1/public/mail/{access_token}/messages")
def public_customer_messages(
    request: Request,
    access_token: str,
    limit: int = Query(50, ge=1, le=100),
    before: int = Query(0, ge=0),
) -> dict[str, Any]:
    access = public_access_by_token(request, access_token)
    return {
        "ok": True,
        "email": access["email"],
        "label": access["label"],
        **message_history(access["mailbox_id"], limit, before),
    }


@app.get("/public/mail/{access_token}", response_class=HTMLResponse)
def public_mail_viewer(access_token: str) -> str:
    if not access_token or len(access_token) > 256:
        raise HTTPException(404, "public link not found")
    return PUBLIC_VIEWER_HTML


@app.get("/platform/admin", response_class=HTMLResponse)
def platform_admin() -> str:
    return ADMIN_HTML


@app.get("/platform/operator", response_class=HTMLResponse)
def platform_operator() -> str:
    return OPERATOR_HTML


PUBLIC_VIEWER_HTML = r"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><title>验证码邮箱</title><style>
*{box-sizing:border-box}body{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:0;background:#f5f7fb;color:#172033}main{max-width:760px;margin:0 auto;padding:28px 16px}.card{background:#fff;border:1px solid #dfe4ef;border-radius:16px;padding:24px;box-shadow:0 8px 30px #1d35570d}.muted{color:#667085}.code{font-size:42px;letter-spacing:.18em;font-weight:750;color:#155eef;word-break:break-all}.mail{margin-top:20px;border-top:1px solid #edf0f5;padding-top:18px}.row{display:flex;gap:12px;justify-content:space-between;align-items:baseline;flex-wrap:wrap}.error{color:#b42318;background:#fef3f2;padding:12px;border-radius:8px}button{border:1px solid #b8c4d8;border-radius:8px;padding:9px 14px;background:#fff;cursor:pointer}button:hover{background:#f2f4f7}</style></head><body><main><div class="card"><div id="state" class="muted">正在加载最新邮件…</div><div id="content" hidden><div class="row"><h1 id="email"></h1><button id="refresh">刷新</button></div><p class="muted">页面每 15 秒自动刷新；仅显示最新一封邮件。</p><section id="codeBox" hidden><div style="display:flex;justify-content:space-between;align-items:center;gap:10px"><div class="muted">验证码</div><button id="copyCode">复制验证码</button></div><div id="code" class="code"></div></section><div class="mail"><div><b id="subject"></b></div><div class="muted" id="from"></div><div class="muted" id="received"></div></div></div></div></main><script>
const $=id=>document.getElementById(id);const token=decodeURIComponent(location.pathname.split("/").filter(Boolean).pop()||"");const endpoint="/api/v1/public/mail/"+encodeURIComponent(token)+"/latest";const fmt=x=>x?new Date(x).toLocaleString("zh-CN",{timeZone:"Asia/Shanghai"}):"";async function load(){try{const r=await fetch(endpoint,{cache:"no-store"});const x=await r.json().catch(()=>({}));if(!r.ok)throw Error(x.detail||x.error||"公开链接无效");$("state").hidden=true;$("content").hidden=false;$("email").textContent=x.email||"验证码邮箱";const m=x.mail;if(!m){$("codeBox").hidden=true;$("subject").textContent="暂无邮件";$("from").textContent="";$("received").textContent="";return}$("codeBox").hidden=!x.code;$("code").textContent=x.code||"";$("copyCode").disabled=!x.code;$("subject").textContent=m.subject||"无主题";$("from").textContent=m.from?"发件人："+m.from:"";$("received").textContent=m.received_at?"时间："+fmt(m.received_at):""}catch(e){$("state").hidden=false;$("state").className="error";$("state").textContent=e.message||"公开链接无效"}}$("refresh").onclick=load;$("copyCode").onclick=async()=>{const value=$("code").textContent;if(!value)return;try{if(navigator.clipboard&&navigator.clipboard.writeText){await navigator.clipboard.writeText(value)}else{const area=document.createElement("textarea");area.value=value;area.style.position="fixed";area.style.opacity="0";document.body.append(area);area.select();document.execCommand("copy");area.remove()}$("copyCode").textContent="\u5df2\u590d\u5236";setTimeout(()=>$("copyCode").textContent="\u590d\u5236\u9a8c\u8bc1\u7801",1200)}catch(_){$("copyCode").textContent="\u8bf7\u624b\u52a8\u590d\u5236";setTimeout(()=>$("copyCode").textContent="\u590d\u5236\u9a8c\u8bc1\u7801",1800)}};load();setInterval(load,15000);
</script></body></html>"""


ADMIN_HTML = r"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>iCloud Code Platform</title><style>
*{box-sizing:border-box}body{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:0 auto;max-width:1120px;padding:24px 16px;background:#f5f7fb;color:#172033}section{background:#fff;border:1px solid #dfe4ef;border-radius:14px;padding:18px;margin:14px 0;box-shadow:0 5px 20px #1d35570a}input,button{font:inherit;padding:9px 11px;margin:4px 4px 4px 0;border-radius:8px;border:1px solid #cbd3e3}button{background:#155eef;color:#fff;cursor:pointer}button.secondary{background:#fff;color:#172033}button.danger{background:#b42318}.muted{color:#667085}.notice{padding:12px;background:#fff4d6;border-radius:8px;white-space:pre-wrap;word-break:break-word}.table-scroll{overflow-x:auto}table{width:100%;border-collapse:collapse;min-width:760px}td,th{padding:10px;text-align:left;border-bottom:1px solid #edf0f5;vertical-align:top}th{color:#667085;font-weight:600}.status-error{color:#b42318}.status-ok{color:#067647}</style></head><body>
<h1>iCloud Code Platform</h1><p><a href="/platform/operator">管理员后台入口</a>（需管理员密钥）</p><p class="muted">多租户邮箱取码工作台：每个客户、每个邮箱独立隔离。只接受 iCloud App 专用密码，不保存 Apple ID 主密码或 Cookie。</p><div id="message" class="muted"></div>
<section><h2>注册 / 登录</h2><input id="email" type="email" autocomplete="username" placeholder="客户账号邮箱"><input id="password" type="password" autocomplete="current-password" placeholder="至少 8 位密码"><button id="register">注册</button><button id="login">登录</button><button id="logout" class="secondary">退出</button></section>
<section><h2>添加 iCloud 邮箱</h2><input id="mailbox" type="email" placeholder="your-mail@icloud.com"><input id="appPassword" type="password" autocomplete="new-password" placeholder="App 专用密码"><input id="label" placeholder="标签"><button id="add">添加并生成邮箱 Key</button><div id="newKey" class="notice" hidden></div></section>
<section><div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap"><h2 style="margin:0">邮箱库存</h2><button id="refresh" class="secondary">刷新</button></div><p class="muted">开放链接使用独立的不透明访问令牌，不把邮箱地址或邮箱 API Key 放进 URL；轮换或撤销后旧链接立即失效。</p><div class="table-scroll"><table><thead><tr><th>邮箱</th><th>同步状态</th><th>公开访问</th><th>操作</th></tr></thead><tbody id="rows"></tbody></table></div></section>
<script>
const $=x=>document.getElementById(x);let token=localStorage.getItem("platformSession")||"";
const show=(x,b=false)=>{$("message").textContent=x;$("message").className=b?"notice":"muted"};
const api=async(p,o={})=>{const h={...(o.body?{"Content-Type":"application/json"}:{}),...(o.headers||{})};if(token)h.Authorization="Bearer "+token;const r=await fetch(p,{...o,headers:h,cache:"no-store"});const x=await r.json().catch(()=>({}));if(!r.ok)throw Error(x.detail||"请求失败");return x};
const button=(label,klass="secondary")=>{const b=document.createElement("button");b.textContent=label;b.className=klass;return b};
const load=async()=>{if(!token){show("请先登录");return}const x=await api("/api/v1/mailboxes");$("rows").textContent="";for(const m of x.mailboxes){const tr=document.createElement("tr"),a=document.createElement("td"),b=document.createElement("td"),d=document.createElement("td"),c=document.createElement("td");a.textContent=m.email+(m.label?"（"+m.label+"）":"");b.textContent=m.last_error?"错误："+m.last_error:(m.last_sync_at?"最近同步："+m.last_sync_at:"尚未同步");b.className=m.last_error?"status-error":"status-ok";d.textContent=m.public_access_enabled?"已开放":"未开放";if(m.public_access_enabled)d.className="status-ok";const s=button("同步");s.onclick=async()=>{try{await api("/api/v1/mailboxes/"+m.id+"/sync",{method:"POST",body:"{}"});await load();show("同步完成")}catch(e){show(e.message,true)}};const q=button("取码");q.onclick=async()=>{try{const r=await api("/api/v1/mailboxes/"+m.id+"/code");show(r.code?"验证码："+r.code:"暂无有效验证码")}catch(e){show(e.message,true)}};const k=button("轮换邮箱 Key");k.onclick=async()=>{if(!confirm("轮换后旧邮箱 Key 会立即失效，继续吗？"))return;try{const r=await api("/api/v1/mailboxes/"+m.id+"/rotate-key",{method:"POST",body:"{}"});$("newKey").hidden=false;$("newKey").textContent="邮箱 API Key（只显示一次）：\n"+r.api_key;show("邮箱 Key 已轮换")}catch(e){show(e.message,true)}};const p=button(m.public_access_enabled?"重置开放链接":"生成开放链接");p.onclick=async()=>{try{const r=await api("/api/v1/mailboxes/"+m.id+"/public-access",{method:"POST",body:"{}"});$("newKey").hidden=false;$("newKey").textContent="发货信息（复制这两行给客户）：\n"+r.delivery_text+"\n\n公开查看页：\n"+r.viewer_url+"\n\nJSON 接口：\n"+r.api_url+"\n\n访问令牌（只显示一次）：\n"+r.token;await load();show("开放链接已生成，请立即复制")}catch(e){show(e.message,true)}};c.append(s,q,k,p);if(m.public_access_enabled){const v=button("撤销开放链接","danger");v.onclick=async()=>{if(!confirm("撤销后旧公开链接立即失效，继续吗？"))return;try{await api("/api/v1/mailboxes/"+m.id+"/public-access",{method:"DELETE"});await load();show("开放链接已撤销")}catch(e){show(e.message,true)}};c.append(v)}tr.append(a,b,d,c);$("rows").append(tr)}};
$("register").onclick=async()=>{try{const x=await api("/api/v1/auth/register",{method:"POST",body:JSON.stringify({email:$("email").value,password:$("password").value})});token=x.access_token;localStorage.setItem("platformSession",token);await load();show("注册成功")}catch(e){show(e.message,true)}};
$("login").onclick=async()=>{try{const x=await api("/api/v1/auth/login",{method:"POST",body:JSON.stringify({email:$("email").value,password:$("password").value})});token=x.access_token;localStorage.setItem("platformSession",token);await load();show("登录成功")}catch(e){show(e.message,true)}};
$("logout").onclick=async()=>{try{await api("/api/v1/auth/logout",{method:"POST",body:"{}"})}catch(_){ }token="";localStorage.removeItem("platformSession");$("rows").textContent="";show("已退出")};
$("add").onclick=async()=>{try{const x=await api("/api/v1/mailboxes",{method:"POST",body:JSON.stringify({email:$("mailbox").value,app_password:$("appPassword").value,label:$("label").value})});$("newKey").hidden=false;$("newKey").textContent="邮箱 API Key（只显示一次）：\n"+x.api_key;$("appPassword").value="";await load();show("邮箱已添加，请立即复制 Key")}catch(e){show(e.message,true)}};
$("refresh").onclick=()=>load().catch(e=>show(e.message,true));if(token)load().catch(()=>{token="";localStorage.removeItem("platformSession")});
</script></body></html>"""


# Keep the UI in separate UTF-8 files so the browser-facing copy can evolve
# without turning this service module into one giant escaped string. The
# inline versions above remain as a fallback for portable deployments.
def _load_ui_override(filename: str, fallback: str) -> str:
    try:
        return (APP_DIR / filename).read_text(encoding="utf-8")
    except OSError:
        return fallback


PUBLIC_VIEWER_HTML = _load_ui_override("platform_viewer.html", PUBLIC_VIEWER_HTML)
ADMIN_HTML = _load_ui_override("platform_admin.html", ADMIN_HTML)


def sync_all_mailboxes() -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute(
            "SELECT m.* FROM mailboxes m JOIN tenants t ON t.id=m.tenant_id WHERE m.active=1 AND t.active=1 ORDER BY m.created_at"
        ).fetchall()
    result = []
    for raw in rows:
        row = dict(raw)
        try:
            value = sync_mailbox(row)
        except Exception as exc:
            value = {"ok": False, "error": clean_text(str(exc))[:300]}
        result.append({"mailbox_id": row["id"], **value})
    return result


@app.get("/")
def root() -> RedirectResponse:
    return RedirectResponse("/platform/admin")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=os.environ.get("PLATFORM_HOST", "127.0.0.1"), port=env_int("PLATFORM_PORT", 8766, 1, 65535))
