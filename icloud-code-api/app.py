#!/usr/bin/env python3
"""
Private iCloud Hide My Email inbox splitter.

This service reads one iCloud mailbox through IMAP, classifies forwarded
messages by Hide My Email alias, and exposes a small authenticated API plus a
local admin page.
"""

from __future__ import annotations

import email.utils
import hashlib
import hmac
import html
import imaplib
import json
import os
import re
import secrets
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from email import policy
from email.parser import BytesParser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse


APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "data"
CONFIG_PATH = APP_DIR / "config.json"
SECRETS_PATH = DATA_DIR / "secrets.json"
DB_PATH = DATA_DIR / "icloud_code_api.sqlite3"
SCHEDULE_TASK_NAME = "iCloud Hide My Email - 30min"
SCHEDULE_STATE_PATH = DATA_DIR / "hme_schedule_state.json"
SCHEDULE_LOG_PATH = DATA_DIR / "hme_schedule.log"
GENERATOR_DATA_DIR = APP_DIR.parent / "hidemyemail-generator" / "data"
BROWSER_SESSION_STATUS_PATH = GENERATOR_DATA_DIR / "browser-session-status.json"
BROWSER_SESSION_LOG_PATH = GENERATOR_DATA_DIR / "browser-session.log"
SCHEDULE_INTERVAL_MINUTES = 30
SCHEDULE_INITIAL_COUNT = 4
SCHEDULE_RECURRING_COUNT = 5
MAX_REQUEST_BODY_BYTES = 1_048_576

DEFAULT_CONFIG: dict[str, Any] = {
    "host": "127.0.0.1",
    "port": 8765,
    "admin_key": "",
    # Empty by default: same-origin/local clients do not need CORS.
    "cors_origin": "",
    "imap": {
        "host": "imap.mail.me.com",
        "port": 993,
        "username": "",
        "app_password": "",
        "mailbox": "INBOX",
        "timeout_seconds": 30,
    },
    "sync": {
        "lookback_days": 3,
        "recent_limit": 200,
        "code_max_age_seconds": 3600,
        "request_sync_cooldown_seconds": 8,
        "scan_body_for_alias": False,
    },
}

CONFIG: dict[str, Any] = {}
CONFIG_LOCK = threading.RLock()
SYNC_LOCK = threading.Lock()
LAST_SYNC_AT = 0.0


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = json.loads(json.dumps(base))
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def ensure_data_dir() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def load_json_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def write_json_file(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    tmp.replace(path)


def get_or_create_generated_admin_key() -> str:
    ensure_data_dir()
    secrets_data = load_json_file(SECRETS_PATH)
    existing = str(secrets_data.get("admin_key") or "").strip()
    if existing:
        return existing
    key = f"adm_{secrets.token_urlsafe(32)}"
    secrets_data["admin_key"] = key
    write_json_file(SECRETS_PATH, secrets_data)
    return key


def load_config() -> dict[str, Any]:
    config = deep_merge(DEFAULT_CONFIG, load_json_file(CONFIG_PATH))

    env_overrides: dict[str, Any] = {}
    if os.environ.get("ICLOUD_CODE_API_HOST"):
        env_overrides["host"] = os.environ["ICLOUD_CODE_API_HOST"]
    if os.environ.get("ICLOUD_CODE_API_PORT"):
        env_overrides["port"] = int(os.environ["ICLOUD_CODE_API_PORT"])
    if os.environ.get("ICLOUD_CODE_ADMIN_KEY"):
        env_overrides["admin_key"] = os.environ["ICLOUD_CODE_ADMIN_KEY"]
    if os.environ.get("ICLOUD_CODE_API_CORS_ORIGIN"):
        env_overrides["cors_origin"] = os.environ["ICLOUD_CODE_API_CORS_ORIGIN"].strip()

    imap_override: dict[str, Any] = {}
    if os.environ.get("ICLOUD_IMAP_HOST"):
        imap_override["host"] = os.environ["ICLOUD_IMAP_HOST"]
    if os.environ.get("ICLOUD_IMAP_PORT"):
        imap_override["port"] = int(os.environ["ICLOUD_IMAP_PORT"])
    if os.environ.get("ICLOUD_EMAIL"):
        imap_override["username"] = os.environ["ICLOUD_EMAIL"]
    if os.environ.get("ICLOUD_APP_PASSWORD"):
        imap_override["app_password"] = os.environ["ICLOUD_APP_PASSWORD"]
    if os.environ.get("ICLOUD_MAILBOX"):
        imap_override["mailbox"] = os.environ["ICLOUD_MAILBOX"]
    if imap_override:
        env_overrides["imap"] = imap_override

    config = deep_merge(config, env_overrides)
    # Never enable wildcard CORS for an API protected by bearer-style keys.
    if str(config.get("cors_origin") or "").strip() == "*":
        config["cors_origin"] = ""
    if not str(config.get("admin_key") or "").strip():
        config["admin_key"] = get_or_create_generated_admin_key()
    return config


def reload_config() -> dict[str, Any]:
    global CONFIG
    with CONFIG_LOCK:
        CONFIG = load_config()
        return CONFIG


def current_config() -> dict[str, Any]:
    with CONFIG_LOCK:
        return json.loads(json.dumps(CONFIG))


def save_config_updates(updates: dict[str, Any]) -> dict[str, Any]:
    with CONFIG_LOCK:
        existing = deep_merge(DEFAULT_CONFIG, load_json_file(CONFIG_PATH))
        merged = deep_merge(existing, updates)
        if not str(merged.get("admin_key") or "").strip():
            merged["admin_key"] = current_config().get("admin_key") or get_or_create_generated_admin_key()
        write_json_file(CONFIG_PATH, merged)
        return reload_config()


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    try:
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def parse_email_date(value: str | None) -> datetime:
    if value:
        try:
            dt = email.utils.parsedate_to_datetime(value)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            pass
    return datetime.now(timezone.utc)


def normalize_email(value: str | None) -> str:
    return str(value or "").strip().lower()


def sanitize_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        number = int(value)
    except Exception:
        number = default
    return max(minimum, min(maximum, number))


def secret_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:10]


def generate_api_key(prefix: str = "alias") -> str:
    return f"{prefix}_{secrets.token_urlsafe(24)}"


def constant_time_equal(left: str, right: str) -> bool:
    left_bytes = str(left or "").encode("utf-8")
    right_bytes = str(right or "").encode("utf-8")
    return hmac.compare_digest(left_bytes, right_bytes)


def db_connect() -> sqlite3.Connection:
    ensure_data_dir()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    ensure_data_dir()
    with db_connect() as conn:
        conn.executescript(
            """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS aliases (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              email TEXT NOT NULL UNIQUE,
              label TEXT NOT NULL DEFAULT '',
              note TEXT NOT NULL DEFAULT '',
              api_key TEXT NOT NULL,
              active INTEGER NOT NULL DEFAULT 1,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS messages (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              alias_id INTEGER,
              alias_email TEXT NOT NULL DEFAULT '',
              imap_uid TEXT NOT NULL UNIQUE,
              message_id TEXT NOT NULL DEFAULT '',
              from_addr TEXT NOT NULL DEFAULT '',
              to_addrs TEXT NOT NULL DEFAULT '',
              subject TEXT NOT NULL DEFAULT '',
              body_text TEXT NOT NULL DEFAULT '',
              body_preview TEXT NOT NULL DEFAULT '',
              code TEXT NOT NULL DEFAULT '',
              raw_headers TEXT NOT NULL DEFAULT '',
              received_at TEXT NOT NULL,
              created_at TEXT NOT NULL,
              FOREIGN KEY(alias_id) REFERENCES aliases(id)
            );

            CREATE INDEX IF NOT EXISTS idx_aliases_email ON aliases(email);
            CREATE INDEX IF NOT EXISTS idx_messages_alias_id ON messages(alias_id);
            CREATE INDEX IF NOT EXISTS idx_messages_alias_email ON messages(alias_email);
            CREATE INDEX IF NOT EXISTS idx_messages_received_at ON messages(received_at);
            """
        )
        alias_columns = {row["name"] for row in conn.execute("PRAGMA table_info(aliases)").fetchall()}
        if "group_name" not in alias_columns:
            conn.execute("ALTER TABLE aliases ADD COLUMN group_name TEXT NOT NULL DEFAULT ''")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_aliases_group_name ON aliases(group_name)")


def row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


def list_alias_rows(active_only: bool = False) -> list[dict[str, Any]]:
    query = "SELECT * FROM aliases"
    args: list[Any] = []
    if active_only:
        query += " WHERE active = 1"
    query += " ORDER BY datetime(created_at) ASC, id ASC"
    with db_connect() as conn:
        return [dict(row) for row in conn.execute(query, args).fetchall()]


def get_alias_by_email(alias_email: str) -> dict[str, Any] | None:
    with db_connect() as conn:
        row = conn.execute(
            "SELECT * FROM aliases WHERE email = ?",
            (normalize_email(alias_email),),
        ).fetchone()
    return row_to_dict(row)


def get_alias_by_id(alias_id: int) -> dict[str, Any] | None:
    with db_connect() as conn:
        row = conn.execute("SELECT * FROM aliases WHERE id = ?", (alias_id,)).fetchone()
    return row_to_dict(row)


def upsert_alias(email_addr: str, label: str = "", note: str = "", api_key: str = "", group_name: str = "") -> dict[str, Any]:
    email_addr = normalize_email(email_addr)
    if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email_addr):
        raise ValueError("邮箱地址格式不正确")
    label = str(label or "").strip()
    note = str(note or "").strip()
    group_name = str(group_name or "").strip()
    api_key = str(api_key or "").strip() or generate_api_key("alias")
    stamp = now_iso()
    with db_connect() as conn:
        existing = conn.execute("SELECT * FROM aliases WHERE email = ?", (email_addr,)).fetchone()
        if existing:
            conn.execute(
                """
                UPDATE aliases
                   SET label = COALESCE(NULLIF(?, ''), label),
                       note = COALESCE(NULLIF(?, ''), note),
                       group_name = COALESCE(NULLIF(?, ''), group_name),
                       api_key = COALESCE(NULLIF(?, ''), api_key),
                       active = 1,
                       updated_at = ?
                 WHERE email = ?
                """,
                (label, note, group_name, api_key, stamp, email_addr),
            )
        else:
            conn.execute(
                """
                INSERT INTO aliases (email, label, note, group_name, api_key, active, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (email_addr, label, note, group_name, api_key, stamp, stamp),
            )
        row = conn.execute("SELECT * FROM aliases WHERE email = ?", (email_addr,)).fetchone()
    reclassify_messages_for_alias(email_addr)
    return dict(row)


def parse_alias_import_line(line: str) -> tuple[str, str, str, str, str] | None:
    raw = str(line or "").strip()
    if not raw or raw.startswith("#"):
        return None
    parts = [part.strip() for part in raw.split("----")]
    email_addr = normalize_email(parts[0] if parts else "")
    if not email_addr:
        return None
    api_key = parts[1] if len(parts) > 1 else ""
    label = parts[2] if len(parts) > 2 else ""
    note = parts[3] if len(parts) > 3 else ""
    group_name = parts[4] if len(parts) > 4 else ""
    return email_addr, api_key, label, note, group_name


def update_alias_group(alias_ids: list[int], group_name: str) -> int:
    clean_ids = [int(alias_id) for alias_id in alias_ids if int(alias_id) > 0]
    group_name = str(group_name or "").strip()
    if not clean_ids:
        return 0
    placeholders = ",".join("?" for _ in clean_ids)
    stamp = now_iso()
    with db_connect() as conn:
        cursor = conn.execute(
            f"UPDATE aliases SET group_name = ?, updated_at = ? WHERE id IN ({placeholders})",
            [group_name, stamp, *clean_ids],
        )
        return int(cursor.rowcount or 0)


def rename_alias_group(old_name: str, new_name: str) -> int:
    old_name = str(old_name or "").strip()
    new_name = str(new_name or "").strip()
    stamp = now_iso()
    with db_connect() as conn:
        cursor = conn.execute(
            "UPDATE aliases SET group_name = ?, updated_at = ? WHERE group_name = ?",
            (new_name, stamp, old_name),
        )
        return int(cursor.rowcount or 0)


def auto_group_aliases(size: int = 100, prefix: str = "分组") -> dict[str, Any]:
    size = sanitize_int(size, 1, 1, 1000)
    prefix = str(prefix or "分组").strip() or "分组"
    aliases = list_alias_rows(active_only=False)
    stamp = now_iso()
    changed = 0
    groups: dict[str, int] = {}
    with db_connect() as conn:
        for index, alias in enumerate(aliases, start=1):
            group_index = ((index - 1) // size) + 1
            group_name = f"{prefix}{group_index:03d}"
            groups[group_name] = groups.get(group_name, 0) + 1
            if str(alias.get("group_name") or "") == group_name:
                continue
            conn.execute(
                "UPDATE aliases SET group_name = ?, updated_at = ? WHERE id = ?",
                (group_name, stamp, alias["id"]),
            )
            changed += 1
    return {"changed": changed, "groups": groups}


def parse_credential(value: str) -> tuple[str, str]:
    parts = str(value or "").strip().split("----")
    email_addr = normalize_email(parts[0] if parts else "")
    api_key = parts[1].strip() if len(parts) > 1 else ""
    return email_addr, api_key


def is_admin_key(candidate: str) -> bool:
    admin_key = str(current_config().get("admin_key") or "")
    return bool(admin_key) and constant_time_equal(candidate, admin_key)


def is_alias_key(alias: dict[str, Any] | None, candidate: str) -> bool:
    if not alias:
        return False
    api_key = str(alias.get("api_key") or "")
    return bool(api_key) and constant_time_equal(candidate, api_key)


def email_addresses_from_text(text: str) -> set[str]:
    return {
        match.group(0).lower()
        for match in re.finditer(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", str(text or ""))
    }


def clean_text(value: str) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def strip_html(value: str) -> str:
    text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", value or "")
    text = re.sub(r"(?s)<br\s*/?>", "\n", text)
    text = re.sub(r"(?s)</p\s*>", "\n", text)
    text = re.sub(r"(?s)<.*?>", " ", text)
    return html.unescape(text)


def message_body_text(msg: email.message.EmailMessage) -> str:
    plain_chunks: list[str] = []
    html_chunks: list[str] = []

    if msg.is_multipart():
        parts = msg.walk()
    else:
        parts = [msg]

    for part in parts:
        if part.is_multipart():
            continue
        if part.get_content_disposition() == "attachment":
            continue
        content_type = (part.get_content_type() or "").lower()
        try:
            content = part.get_content()
        except Exception:
            payload = part.get_payload(decode=True) or b""
            charset = part.get_content_charset() or "utf-8"
            content = payload.decode(charset, errors="replace")
        if not isinstance(content, str):
            continue
        if content_type == "text/plain":
            plain_chunks.append(content)
        elif content_type == "text/html":
            html_chunks.append(strip_html(content))

    text = "\n".join(plain_chunks or html_chunks)
    return clean_text(text)


def decode_header_value(value: str | None) -> str:
    if not value:
        return ""
    try:
        return str(email.headerregistry.AddressHeader) and str(value)
    except Exception:
        return str(value)


def raw_headers_text(msg: email.message.EmailMessage) -> str:
    return "\n".join(f"{key}: {value}" for key, value in msg.raw_items())


def recipient_header_text(msg: email.message.EmailMessage) -> str:
    header_names = [
        "To",
        "Cc",
        "Bcc",
        "Delivered-To",
        "X-Original-To",
        "Original-Recipient",
        "X-Forwarded-To",
        "Envelope-To",
        "Apparently-To",
        "Resent-To",
        "X-Envelope-To",
        "X-Rcpt-To",
        "X-Receiver",
        "X-Delivered-To",
    ]
    lines = []
    for name in header_names:
        values = msg.get_all(name, [])
        for value in values:
            lines.append(f"{name}: {value}")
    return "\n".join(lines)


def match_alias_for_message(
    aliases: list[dict[str, Any]],
    msg: email.message.EmailMessage,
    body_text: str,
) -> dict[str, Any] | None:
    cfg = current_config()
    header_text = raw_headers_text(msg).lower()
    recipient_text = recipient_header_text(msg).lower()
    body_lookup = body_text.lower() if cfg.get("sync", {}).get("scan_body_for_alias") else ""
    candidates = email_addresses_from_text(recipient_text + "\n" + header_text)
    for alias in aliases:
        email_addr = normalize_email(alias.get("email"))
        if not email_addr:
            continue
        if email_addr in candidates or email_addr in recipient_text or email_addr in header_text:
            return alias
        if body_lookup and email_addr in body_lookup:
            return alias
    return None


def normalize_code_candidate(value: str) -> str:
    digits = re.sub(r"\D+", "", value or "")
    return digits if 4 <= len(digits) <= 8 else ""


def compile_pattern(pattern: dict[str, Any] | str) -> re.Pattern[str] | None:
    try:
        if isinstance(pattern, dict):
            source = str(pattern.get("source") or "").strip()
            flags_raw = str(pattern.get("flags") or "")
        else:
            source = str(pattern or "").strip()
            flags_raw = ""
        if not source:
            return None
        flags = re.IGNORECASE if "i" in flags_raw.lower() else 0
        if "m" in flags_raw.lower():
            flags |= re.MULTILINE
        if "s" in flags_raw.lower():
            flags |= re.DOTALL
        return re.compile(source, flags)
    except Exception:
        return None


def extract_code(text: str, code_patterns: list[Any] | None = None, exclude_codes: set[str] | None = None) -> str:
    full_text = str(text or "")
    rejected = exclude_codes or set()

    for pattern in code_patterns or []:
        compiled = compile_pattern(pattern)
        if not compiled:
            continue
        match = compiled.search(full_text)
        if not match:
            continue
        groups = [group for group in match.groups() if group] or [match.group(0)]
        for group in groups:
            candidate = normalize_code_candidate(group)
            if candidate and candidate not in rejected:
                return candidate

    generic_patterns = [
        r"(?:verification\s+code|security\s+code|one[-\s]?time\s+(?:passcode|code)|passcode|otp|login\s+code|code|验证码|驗證碼|代码|代碼|安全码|安全碼)[^\d]{0,40}(\d[\d\s-]{2,10}\d)",
        r"(\d[\d\s-]{2,10}\d)[^\d]{0,40}(?:verification\s+code|security\s+code|one[-\s]?time\s+(?:passcode|code)|passcode|otp|login\s+code|code|验证码|驗證碼|代码|代碼|安全码|安全碼)",
        r"\b(\d{4,8})\b",
    ]
    for source in generic_patterns:
        match = re.search(source, full_text, re.IGNORECASE)
        if not match:
            continue
        candidate = normalize_code_candidate(match.group(1))
        if candidate and candidate not in rejected:
            return candidate
    return ""


def parse_imap_internal_date(fetch_data: list[Any]) -> datetime | None:
    for item in fetch_data:
        if not isinstance(item, tuple) or not item:
            continue
        try:
            parsed = imaplib.Internaldate2tuple(item[0])
            if parsed:
                return datetime.fromtimestamp(time.mktime(parsed), timezone.utc)
        except Exception:
            continue
    return None


def imap_since_date(days: int) -> str:
    since = datetime.now(timezone.utc) - timedelta(days=max(0, days))
    return since.strftime("%d-%b-%Y")


def connect_imap() -> imaplib.IMAP4_SSL:
    cfg = current_config()
    imap_cfg = cfg.get("imap", {})
    host = str(imap_cfg.get("host") or "imap.mail.me.com")
    port = sanitize_int(imap_cfg.get("port"), 993, 1, 65535)
    username = str(imap_cfg.get("username") or "").strip()
    password = str(imap_cfg.get("app_password") or "")
    mailbox = str(imap_cfg.get("mailbox") or "INBOX").strip() or "INBOX"
    if not username or not password:
        raise RuntimeError("请先在设置里填写 iCloud 邮箱和 App 专用密码")

    timeout_seconds = sanitize_int(imap_cfg.get("timeout_seconds"), 30, 5, 300)
    client = imaplib.IMAP4_SSL(host, port, timeout=timeout_seconds)
    client.login(username, password)
    status, _ = client.select(mailbox, readonly=True)
    if status != "OK":
        raise RuntimeError(f"无法打开邮箱目录：{mailbox}")
    return client


def save_message(
    uid: str,
    msg: email.message.EmailMessage,
    aliases: list[dict[str, Any]],
    internal_date: datetime | None = None,
) -> bool:
    body_text = message_body_text(msg)
    alias = match_alias_for_message(aliases, msg, body_text)
    subject = clean_text(str(msg.get("Subject") or ""))
    from_addr = clean_text(str(msg.get("From") or ""))
    to_addrs = clean_text(" ".join(str(msg.get_all(name, []) or "") for name in ("To", "Cc", "Delivered-To", "X-Original-To")))
    headers = raw_headers_text(msg)
    received_dt = parse_email_date(msg.get("Date")) if msg.get("Date") else (internal_date or datetime.now(timezone.utc))
    combined_text = "\n".join([subject, from_addr, to_addrs, body_text])
    code = extract_code(combined_text)
    stamp = now_iso()
    alias_id = int(alias["id"]) if alias else None
    alias_email = normalize_email(alias.get("email")) if alias else ""
    preview = body_text[:240]
    message_id = clean_text(str(msg.get("Message-ID") or ""))

    with db_connect() as conn:
        existing = conn.execute("SELECT id FROM messages WHERE imap_uid = ?", (uid,)).fetchone()
        if existing:
            conn.execute(
                """
                UPDATE messages
                   SET alias_id = COALESCE(?, alias_id),
                       alias_email = COALESCE(NULLIF(?, ''), alias_email),
                       code = COALESCE(NULLIF(?, ''), code)
                 WHERE imap_uid = ?
                """,
                (alias_id, alias_email, code, uid),
            )
            return False
        conn.execute(
            """
            INSERT INTO messages (
              alias_id, alias_email, imap_uid, message_id, from_addr, to_addrs,
              subject, body_text, body_preview, code, raw_headers, received_at, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alias_id,
                alias_email,
                uid,
                message_id,
                from_addr,
                to_addrs,
                subject,
                body_text,
                preview,
                code,
                headers,
                received_dt.replace(microsecond=0).isoformat(),
                stamp,
            ),
        )
        return True


def reclassify_messages_for_alias(alias_email: str) -> int:
    alias = get_alias_by_email(alias_email)
    if not alias:
        return 0
    email_addr = normalize_email(alias_email)
    changed = 0
    with db_connect() as conn:
        rows = conn.execute(
            """
            SELECT id, raw_headers, body_text
              FROM messages
             WHERE (alias_id IS NULL OR alias_email = '')
               AND (LOWER(raw_headers) LIKE ? OR LOWER(body_text) LIKE ?)
            """,
            (f"%{email_addr}%", f"%{email_addr}%"),
        ).fetchall()
        for row in rows:
            conn.execute(
                "UPDATE messages SET alias_id = ?, alias_email = ? WHERE id = ?",
                (alias["id"], email_addr, row["id"]),
            )
            changed += 1
    return changed


def sync_mailbox(force: bool = False) -> dict[str, Any]:
    global LAST_SYNC_AT
    cfg = current_config()
    sync_cfg = cfg.get("sync", {})
    cooldown = sanitize_int(sync_cfg.get("request_sync_cooldown_seconds"), 8, 0, 300)

    if not force and cooldown > 0 and time.time() - LAST_SYNC_AT < cooldown:
        return {"ok": True, "skipped": True, "reason": "cooldown", "synced_at": LAST_SYNC_AT}

    if not SYNC_LOCK.acquire(blocking=False):
        return {"ok": True, "skipped": True, "reason": "sync already running", "synced_at": LAST_SYNC_AT}

    try:
        aliases = list_alias_rows(active_only=True)
        recent_limit = sanitize_int(sync_cfg.get("recent_limit"), 200, 1, 2000)
        lookback_days = sanitize_int(sync_cfg.get("lookback_days"), 3, 0, 365)
        client = connect_imap()
        try:
            since = imap_since_date(lookback_days)
            status, data = client.uid("search", None, f"(SINCE {since})")
            if status != "OK" or not data or data[0] is None:
                status, data = client.uid("search", None, "ALL")
            uid_values = (data[0] or b"").split()
            selected_uids = [uid.decode("ascii", errors="ignore") for uid in uid_values[-recent_limit:]]
            inserted = 0
            inspected = 0
            for uid in selected_uids:
                if not uid:
                    continue
                inspected += 1
                raw_email = None
                fetch_data: list[Any] = []
                # iCloud's IMAP endpoint may acknowledge RFC822 but omit the
                # message body. BODY.PEEK[] reliably returns the RFC822 bytes
                # while leaving the message's read/unread state unchanged.
                for fetch_query in ("(BODY.PEEK[] INTERNALDATE)", "(RFC822 INTERNALDATE)"):
                    status, candidate_data = client.uid("fetch", uid, fetch_query)
                    if status != "OK" or not candidate_data:
                        continue
                    fetch_data = candidate_data
                    for item in candidate_data:
                        if isinstance(item, tuple) and len(item) >= 2 and isinstance(item[1], bytes):
                            raw_email = item[1]
                            break
                    if raw_email:
                        break
                if not raw_email:
                    continue
                msg = BytesParser(policy=policy.default).parsebytes(raw_email)
                internal_date = parse_imap_internal_date(fetch_data)
                if save_message(uid, msg, aliases, internal_date):
                    inserted += 1
            LAST_SYNC_AT = time.time()
            return {
                "ok": True,
                "skipped": False,
                "inspected": inspected,
                "inserted": inserted,
                "synced_at": LAST_SYNC_AT,
            }
        finally:
            try:
                client.close()
            except Exception:
                pass
            try:
                client.logout()
            except Exception:
                pass
    finally:
        SYNC_LOCK.release()


def parse_epoch(value: Any) -> datetime | None:
    try:
        number = float(value)
    except Exception:
        return None
    if number <= 0:
        return None
    if number > 10_000_000_000:
        number = number / 1000.0
    return datetime.fromtimestamp(number, timezone.utc)


def latest_code_for_alias(
    alias_email: str,
    *,
    code_patterns: list[Any] | None = None,
    exclude_codes: set[str] | None = None,
    after: datetime | None = None,
    max_age_seconds: int | None = None,
    sync_first: bool = True,
) -> dict[str, Any]:
    alias = get_alias_by_email(alias_email)
    if not alias:
        raise ValueError("未找到这个隐藏邮箱，请先在后台导入")
    if sync_first:
        sync_mailbox(force=False)

    cfg = current_config()
    max_age = max_age_seconds
    if max_age is None:
        max_age = sanitize_int(cfg.get("sync", {}).get("code_max_age_seconds"), 3600, 0, 30 * 24 * 3600)
    cutoff = None
    if max_age > 0:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=max_age)
    if after and cutoff:
        cutoff = max(cutoff, after)
    elif after:
        cutoff = after

    with db_connect() as conn:
        rows = conn.execute(
            """
            SELECT *
              FROM messages
             WHERE alias_id = ? OR alias_email = ?
             ORDER BY received_at DESC, id DESC
             LIMIT 50
            """,
            (alias["id"], normalize_email(alias_email)),
        ).fetchall()

    for row in rows:
        message = dict(row)
        received_at = parse_datetime(message.get("received_at"))
        if cutoff and received_at and received_at < cutoff:
            continue
        text = "\n".join(
            [
                str(message.get("subject") or ""),
                str(message.get("from_addr") or ""),
                str(message.get("to_addrs") or ""),
                str(message.get("body_text") or ""),
            ]
        )
        code = extract_code(text, code_patterns=code_patterns, exclude_codes=exclude_codes)
        if not code:
            code = str(message.get("code") or "")
            if code in (exclude_codes or set()):
                code = ""
        if code:
            return {
                "ok": True,
                "code": code,
                "mail": public_message(message),
            }
    return {"ok": True, "code": "", "mail": None}


def public_alias(alias: dict[str, Any], include_key: bool = True) -> dict[str, Any]:
    result = {
        "id": alias.get("id"),
        "email": alias.get("email"),
        "label": alias.get("label") or "",
        "note": alias.get("note") or "",
        "group_name": alias.get("group_name") or "",
        "active": bool(alias.get("active")),
        "created_at": alias.get("created_at"),
        "updated_at": alias.get("updated_at"),
    }
    if include_key:
        result["api_key"] = alias.get("api_key")
        result["credential"] = f"{alias.get('email')}----{alias.get('api_key')}"
    else:
        result["api_key_digest"] = secret_digest(str(alias.get("api_key") or ""))
    return result


def public_message(message: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": message.get("id"),
        "alias_email": message.get("alias_email") or "",
        "from": message.get("from_addr") or "",
        "to": message.get("to_addrs") or "",
        "subject": message.get("subject") or "",
        "preview": message.get("body_preview") or "",
        "code": message.get("code") or "",
        "received_at": message.get("received_at") or "",
        "imap_uid": message.get("imap_uid") or "",
    }


def _parse_task_list_output(output: str) -> dict[str, str]:
    """Parse ``schtasks /FO LIST`` output without depending on the UI language."""
    # ``schtasks.exe`` can emit UTF-16-looking output when the API is running
    # without an attached console.  Removing NULs keeps the parser compatible
    # with both redirected and interactive output.
    output = output.replace("\x00", "").lstrip("\ufeff")
    field_names = {
        "TaskName": "task_name",
        "任务名称": "task_name",
        "任务名": "task_name",
        "Next Run Time": "next_run",
        "下次运行时间": "next_run",
        "Status": "state",
        "状态": "state",
        "模式": "state",
        "Last Run Time": "last_run",
        "上次运行时间": "last_run",
        "Last Result": "last_result",
        "上次结果": "last_result",
        "Scheduled Task State": "enabled_state",
        "计划任务状态": "enabled_state",
    }
    fields: dict[str, str] = {}
    for raw_line in output.splitlines():
        if ":" not in raw_line:
            continue
        key, value = raw_line.split(":", 1)
        normalized_key = key.strip()
        field = field_names.get(normalized_key)
        if field:
            fields[field] = value.strip()
    return fields


def schedule_status_payload() -> dict[str, Any]:
    """Return scheduler state for the admin dashboard, excluding secrets."""
    state = load_json_file(SCHEDULE_STATE_PATH)
    try:
        completed_runs = max(0, int(state.get("completed_runs", 0)))
    except (TypeError, ValueError):
        completed_runs = 0
    try:
        last_count = max(0, int(state.get("last_count", 0)))
    except (TypeError, ValueError):
        last_count = 0

    task_fields: dict[str, str] = {}
    query_error = ""
    try:
        completed = subprocess.run(
            [
                "schtasks",
                "/Query",
                "/TN",
                SCHEDULE_TASK_NAME,
                "/FO",
                "LIST",
                "/V",
            ],
            capture_output=True,
            timeout=5,
            check=False,
        )
        raw_stdout = completed.stdout or b""
        raw_stderr = completed.stderr or b""
        candidates: list[str] = []
        for encoding in ("utf-8", "mbcs", "utf-16", "utf-16le"):
            try:
                candidates.append(raw_stdout.decode(encoding, errors="replace"))
            except (LookupError, UnicodeError):
                continue
        task_output = max(
            candidates,
            key=lambda value: sum(
                token in value
                for token in ("TaskName", "Next Run Time", "任务名称", "下次运行时间")
            ),
            default="",
        )
        task_fields = _parse_task_list_output(task_output)
        if completed.returncode != 0:
            query_error = raw_stderr.decode("utf-8", errors="replace").strip() or "任务查询失败"
    except FileNotFoundError:
        query_error = "当前系统不支持 schtasks"
    except (OSError, subprocess.SubprocessError) as err:
        query_error = str(err)

    registered = bool(task_fields.get("task_name")) and not query_error
    task_state = task_fields.get("state") or task_fields.get("enabled_state") or ("Ready" if registered else "")
    next_count = SCHEDULE_INITIAL_COUNT if completed_runs == 0 else SCHEDULE_RECURRING_COUNT
    normalized_state = task_fields.get("state", "").lower()
    normalized_enabled_state = task_fields.get("enabled_state", "").lower()
    disabled = normalized_enabled_state in {"disabled", "已禁用", "已停用"} or normalized_state in {"disabled", "已禁用", "已停用"}
    enabled = registered and (
        not disabled
        and (
            normalized_enabled_state in {"enabled", "已启用"}
            or normalized_state in {"ready", "就绪", "running", "运行中"}
        )
    )
    return {
        "registered": registered,
        "enabled": enabled,
        "task_name": SCHEDULE_TASK_NAME,
        "state": task_state,
        "enabled_state": task_fields.get("enabled_state", ""),
        "next_run": task_fields.get("next_run", ""),
        "last_run": task_fields.get("last_run", ""),
        "last_result": task_fields.get("last_result", ""),
        "last_success_at": str(state.get("last_success_at") or ""),
        "completed_runs": completed_runs,
        "last_count": last_count,
        "next_count": next_count,
        "initial_count": SCHEDULE_INITIAL_COUNT,
        "recurring_count": SCHEDULE_RECURRING_COUNT,
        "interval_minutes": SCHEDULE_INTERVAL_MINUTES,
        "state_path": str(SCHEDULE_STATE_PATH),
        "log_path": str(SCHEDULE_LOG_PATH),
        "query_error": query_error if not registered else "",
        "recent_log": schedule_log_summary(),
    }


def browser_session_status_payload() -> dict[str, Any]:
    """Expose the independent iCloud browser-session health without secrets."""
    state = load_json_file(BROWSER_SESSION_STATUS_PATH)
    allowed = {
        "state",
        "message",
        "browser",
        "profile",
        "keep_alive",
        "interval_seconds",
        "auth_cookie_count",
        "updated_at",
        "last_success_at",
        "last_error",
    }
    payload = {key: state[key] for key in allowed if key in state}
    payload.update(
        {
            "available": bool(state),
            "status_file": str(BROWSER_SESSION_STATUS_PATH),
            "log_file": str(BROWSER_SESSION_LOG_PATH),
        }
    )
    if not payload.get("state"):
        payload["state"] = "unknown"
    if not payload.get("message"):
        payload["message"] = "尚未运行独立 iCloud 浏览器会话保活"
    return payload


SCHEDULE_ACTIONS: dict[str, tuple[list[str], str]] = {
    "start": (
        ["/Change", "/TN", SCHEDULE_TASK_NAME, "/ENABLE"],
        "定时任务已启用，将按计划时间运行",
    ),
    "stop": (
        ["/Change", "/TN", SCHEDULE_TASK_NAME, "/DISABLE"],
        "定时任务已停用，不会再按计划自动运行",
    ),
    "run": (
        ["/Run", "/TN", SCHEDULE_TASK_NAME],
        "已请求立即运行一轮",
    ),
}


def run_schedule_action(action: str) -> dict[str, Any]:
    """Enable, disable, or trigger the Windows scheduled task."""
    action_key = str(action or "").strip().lower()
    command_args = SCHEDULE_ACTIONS.get(action_key)
    if not command_args:
        raise ValueError("不支持的定时任务操作")
    args, message = command_args
    try:
        completed = subprocess.run(
            ["schtasks", *args],
            capture_output=True,
            timeout=10,
            check=False,
        )
    except FileNotFoundError as err:
        raise RuntimeError("当前系统不支持 schtasks") from err
    except (OSError, subprocess.SubprocessError) as err:
        raise RuntimeError(str(err)) from err

    if completed.returncode != 0:
        raw_error = completed.stderr or completed.stdout or b""
        detail = ""
        for encoding in ("utf-8", "mbcs", "gb18030", "utf-16"):
            try:
                detail = raw_error.decode(encoding, errors="replace").replace("\x00", "").strip()
            except (LookupError, UnicodeError):
                continue
            if detail and "�" not in detail:
                break
        raise RuntimeError(detail or f"定时任务操作失败（退出码 {completed.returncode}）")

    return {
        "action": action_key,
        "message": message,
        "schedule": schedule_status_payload(),
    }


def schedule_log_summary() -> dict[str, Any]:
    """Expose a short, secret-free execution summary for the admin panel."""
    empty = {
        "available": False,
        "status": "unknown",
        "message": "暂无定时任务执行日志",
        "at": "",
        "entries": [],
        "log_path": str(SCHEDULE_LOG_PATH),
    }
    try:
        raw = SCHEDULE_LOG_PATH.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return empty
    if not raw.strip():
        return empty

    events: list[dict[str, Any]] = []
    for position, raw_line in enumerate(raw.splitlines()):
        line = raw_line.strip()
        match = re.match(r"^\[([^\]]+)\]\s*(.*)$", line)
        if not match:
            continue
        timestamp, message = match.groups()
        lowered = message.lower()
        event: dict[str, Any] | None = None
        if lowered.startswith("starting run:"):
            count_match = re.search(r"count=(\d+)", message, re.IGNORECASE)
            count_text = count_match.group(1) if count_match else "-"
            event = {
                "at": timestamp,
                "status": "running",
                "message": f"开始执行：尝试创建 {count_text} 个",
            }
        elif "run completed successfully" in lowered:
            event = {"at": timestamp, "status": "success", "message": "执行成功"}
        elif "run failed:" in lowered:
            result_match = re.search(r"exit=(\d+)", message, re.IGNORECASE)
            result_text = f"（退出码 {result_match.group(1)}）" if result_match else ""
            event = {"at": timestamp, "status": "failed", "message": f"执行失败{result_text}"}
        elif "timed out after" in lowered:
            event = {"at": timestamp, "status": "failed", "message": "执行超时"}
        elif lowered.startswith("skipped:"):
            event = {"at": timestamp, "status": "skipped", "message": "已有任务运行，本次跳过"}
        if event:
            event["_position"] = position
            events.append(event)

    if not events:
        return {
            **empty,
            "available": True,
            "message": "日志存在，但暂无完整执行结果",
        }

    latest_start_position = max(
        (event["_position"] for event in events if event["status"] == "running"),
        default=-1,
    )
    latest_segment = raw.splitlines()[latest_start_position:] if latest_start_position >= 0 else raw.splitlines()
    latest_segment_text = "\n".join(latest_segment)
    cookie_refresh_failed = bool(
        re.search(
            r"cookie refresh failed|no authenticated iCloud cookies found|session validation failed|no valid iCloud login was found|previous cookie\.txt was kept unchanged",
            latest_segment_text,
            re.IGNORECASE,
        )
    )
    cookie_expired = bool(
        re.search(
            r"invalid global\s+session|session is invalid or expired|expired.*cookie|cookie.*expired|capture a fresh.*cookie",
            latest_segment_text,
            re.IGNORECASE,
        )
    )
    if cookie_refresh_failed:
        latest_event = events[-1]
        latest_event["status"] = "action_required"
        latest_event["message"] = "无法自动获取有效 iCloud Cookie，请在浏览器中完成登录/验证"
    elif cookie_expired:
        latest_event = events[-1]
        latest_event["status"] = "action_required"
        latest_event["message"] = "iCloud Cookie/会话已过期，请更新 cookie.txt"

    public_events = [
        {
            "at": event["at"],
            "status": event["status"],
            "message": event["message"],
        }
        for event in events[-6:]
    ]
    latest = public_events[-1]
    return {
        "available": True,
        "status": latest["status"],
        "message": latest["message"],
        "at": latest["at"],
        "entries": public_events,
        "log_path": str(SCHEDULE_LOG_PATH),
    }


def dashboard_payload() -> dict[str, Any]:
    aliases = list_alias_rows(active_only=False)
    with db_connect() as conn:
        message_count = conn.execute("SELECT COUNT(*) AS c FROM messages").fetchone()["c"]
        unmatched_count = conn.execute("SELECT COUNT(*) AS c FROM messages WHERE alias_id IS NULL OR alias_email = ''").fetchone()["c"]
        counts = {
            row["alias_id"]: row["c"]
            for row in conn.execute(
                "SELECT alias_id, COUNT(*) AS c FROM messages WHERE alias_id IS NOT NULL GROUP BY alias_id"
            ).fetchall()
        }
        latest_codes = {
            row["alias_id"]: dict(row)
            for row in conn.execute(
                """
                WITH ranked AS (
                    SELECT
                        alias_id,
                        code,
                        subject,
                        received_at,
                        ROW_NUMBER() OVER (
                            PARTITION BY alias_id
                            ORDER BY datetime(received_at) DESC, id DESC
                        ) AS row_number
                      FROM messages
                     WHERE alias_id IS NOT NULL AND code != ''
                )
                SELECT alias_id, code, subject, received_at
                  FROM ranked
                 WHERE row_number = 1
                """
            ).fetchall()
        }
    public_aliases = []
    for alias in aliases:
        item = public_alias(alias, include_key=True)
        item["message_count"] = int(counts.get(alias["id"], 0))
        item["latest_code"] = latest_codes.get(alias["id"], {})
        public_aliases.append(item)

    cfg = current_config()
    imap_cfg = cfg.get("imap", {})
    return {
        "ok": True,
        "aliases": public_aliases,
        "summary": {
            "alias_count": len(aliases),
            "message_count": int(message_count),
            "unmatched_count": int(unmatched_count),
            "imap_configured": bool(str(imap_cfg.get("username") or "").strip() and str(imap_cfg.get("app_password") or "")),
            "last_sync_at": LAST_SYNC_AT,
            "admin_key_digest": secret_digest(str(cfg.get("admin_key") or "")),
        },
        "schedule": schedule_status_payload(),
        "browser_session": browser_session_status_payload(),
    }


def list_messages(alias_email: str = "", limit: int = 50) -> list[dict[str, Any]]:
    limit = sanitize_int(limit, 50, 1, 500)
    args: list[Any] = []
    where = ""
    if alias_email:
        where = "WHERE alias_email = ?"
        args.append(normalize_email(alias_email))
    args.append(limit)
    with db_connect() as conn:
        rows = conn.execute(
            f"""
            SELECT *
              FROM messages
              {where}
             ORDER BY received_at DESC, id DESC
             LIMIT ?
            """,
            args,
        ).fetchall()
    return [public_message(dict(row)) for row in rows]


ADMIN_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>iCloud Code API</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f6f7f9;
      --panel: #ffffff;
      --line: #d9dee7;
      --text: #18212f;
      --muted: #637083;
      --accent: #0f766e;
      --accent-2: #2563eb;
      --danger: #b42318;
      --ok: #137333;
      --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    * { box-sizing: border-box; }
    body { margin: 0; background: var(--bg); color: var(--text); }
    header {
      position: sticky; top: 0; z-index: 2; background: rgba(255,255,255,.95);
      border-bottom: 1px solid var(--line); backdrop-filter: blur(10px);
    }
    .wrap { max-width: 1180px; margin: 0 auto; padding: 18px; }
    .top { display: flex; gap: 12px; align-items: center; justify-content: space-between; flex-wrap: wrap; }
    h1 { margin: 0; font-size: 20px; letter-spacing: 0; }
    h2 { margin: 0 0 12px; font-size: 15px; letter-spacing: 0; }
    .grid { display: grid; grid-template-columns: 360px minmax(0,1fr); gap: 14px; align-items: start; }
    .panel { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 14px; }
    .row { display: grid; gap: 6px; margin-bottom: 10px; }
    .inline { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
    .toolbar { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin: 8px 0 10px; }
    .checkline { display: inline-flex; gap: 6px; align-items: center; color: var(--text); font-size: 13px; }
    input[type="checkbox"] { width: auto; }
    label { color: var(--muted); font-size: 12px; }
    input, textarea, select {
      width: 100%; border: 1px solid var(--line); border-radius: 6px; padding: 8px 9px;
      font: inherit; background: #fff; color: var(--text);
    }
    textarea { min-height: 86px; resize: vertical; font-family: var(--mono); font-size: 12px; }
    button {
      border: 1px solid var(--line); border-radius: 6px; background: #fff; color: var(--text);
      padding: 8px 11px; cursor: pointer; font-weight: 600; white-space: nowrap;
    }
    button.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
    button.blue { background: var(--accent-2); border-color: var(--accent-2); color: #fff; }
    button.danger { color: var(--danger); }
    button:disabled { opacity: .55; cursor: default; }
    .stats { display: grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap: 10px; margin-bottom: 14px; }
    .stat { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 12px; }
    .stat b { display: block; font-size: 20px; }
    .stat span { color: var(--muted); font-size: 12px; }
    .mono { font-family: var(--mono); font-size: 12px; }
    .muted { color: var(--muted); }
    .ok { color: var(--ok); }
    .bad { color: var(--danger); }
    .table-wrap { overflow: auto; border: 1px solid var(--line); border-radius: 8px; }
    table { width: 100%; border-collapse: collapse; min-width: 980px; background: #fff; }
    th, td { padding: 9px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }
    th { color: var(--muted); font-size: 12px; background: #fbfcfe; position: sticky; top: 0; }
    th.tight, td.tight { width: 34px; }
    .select-small { width: auto; min-width: 170px; }
    .input-small { width: 170px; }
    tr:last-child td { border-bottom: 0; }
    .pill { display: inline-flex; border: 1px solid var(--line); border-radius: 999px; padding: 2px 7px; font-size: 12px; }
    .toast { min-height: 22px; color: var(--muted); font-size: 13px; }
    .schedule-grid { display: grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap: 10px; margin-top: 12px; }
    .schedule-item { border: 1px solid var(--line); border-radius: 6px; padding: 9px; min-height: 58px; }
    .schedule-item label { display: block; margin-bottom: 4px; }
    .schedule-item b { display: block; font-size: 14px; overflow-wrap: anywhere; }
    .schedule-paths { margin-top: 12px; overflow-wrap: anywhere; }
    .schedule-log { margin-top: 12px; padding: 10px; border: 1px solid var(--line); border-radius: 6px; background: #fbfcfe; }
    .schedule-log-message { margin-top: 6px; font-weight: 600; overflow-wrap: anywhere; }
    .schedule-log-time { margin-top: 4px; }
    .schedule-log-list { display: grid; gap: 4px; margin-top: 8px; }
    .schedule-log-entry { display: flex; gap: 8px; flex-wrap: wrap; font-size: 12px; }
    @media (max-width: 900px) {
      .grid { grid-template-columns: 1fr; }
      .stats { grid-template-columns: repeat(2, minmax(0,1fr)); }
      .schedule-grid { grid-template-columns: repeat(2, minmax(0,1fr)); }
    }
    @media (max-width: 520px) {
      .schedule-grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <header>
    <div class="wrap top">
      <h1>iCloud Code API</h1>
      <div class="inline">
        <input id="adminKey" class="mono" type="password" placeholder="Admin API Key" style="width:260px" />
        <button id="saveKey">保存 Key</button>
        <button id="refresh" class="blue">刷新</button>
        <button id="sync" class="primary">同步邮件</button>
      </div>
    </div>
  </header>

  <main class="wrap">
    <div class="stats">
      <div class="stat"><b id="statAliases">0</b><span>隐藏邮箱</span></div>
      <div class="stat"><b id="statMessages">0</b><span>邮件</span></div>
      <div class="stat"><b id="statUnmatched">0</b><span>未归类</span></div>
      <div class="stat"><b id="statImap">-</b><span>IMAP</span></div>
    </div>

    <section class="panel" style="margin-bottom:14px">
      <div class="inline" style="justify-content:space-between">
        <div>
          <h2>定时创建隐藏邮箱</h2>
          <div class="muted" id="scheduleSummary">正在读取任务状态...</div>
        </div>
        <div class="inline">
          <span class="pill" id="scheduleBadge">读取中</span>
          <button id="scheduleStart" class="primary" type="button">启动定时</button>
          <button id="scheduleStop" class="danger" type="button">停止定时</button>
          <button id="scheduleRunNow" type="button">立即运行一轮</button>
          <button id="refreshSchedule" class="blue" type="button">刷新状态</button>
        </div>
      </div>
      <div class="muted" style="margin-top:8px">启动/停止控制后续自动运行；“立即运行一轮”会按当前周期数量马上启动任务。</div>
      <div class="schedule-grid">
        <div class="schedule-item"><label>任务状态</label><b id="scheduleStatus">-</b></div>
        <div class="schedule-item"><label>下一轮创建</label><b id="scheduleNextCount">-</b></div>
        <div class="schedule-item"><label>下次运行</label><b id="scheduleNextRun">-</b></div>
        <div class="schedule-item"><label>已完成周期</label><b id="scheduleCompleted">-</b></div>
        <div class="schedule-item"><label>上次运行</label><b id="scheduleLastRun">-</b></div>
        <div class="schedule-item"><label>上次成功</label><b id="scheduleLastSuccess">-</b></div>
        <div class="schedule-item"><label>上次创建数量</label><b id="scheduleLastCount">-</b></div>
        <div class="schedule-item"><label>上次结果</label><b id="scheduleLastResult">-</b></div>
      </div>
      <div class="muted mono schedule-paths" id="schedulePaths"></div>
      <div class="schedule-log">
        <div class="inline" style="justify-content:space-between">
          <b>最近执行状态日志</b>
          <span class="pill" id="scheduleLogBadge">读取中</span>
        </div>
        <div class="schedule-log-message" id="scheduleLogMessage">正在读取日志...</div>
        <div class="muted mono schedule-log-time" id="scheduleLogTime"></div>
        <div class="schedule-log-list" id="scheduleLogEntries"></div>
      </div>
      <div class="schedule-log" id="browserSessionPanel">
        <div class="inline" style="justify-content:space-between">
          <b>iCloud 独立浏览器登录会话</b>
          <span class="pill" id="browserSessionBadge">读取中</span>
        </div>
        <div class="schedule-log-message" id="browserSessionMessage">正在读取会话状态...</div>
        <div class="muted mono schedule-log-time" id="browserSessionTime"></div>
        <div class="muted mono schedule-paths" id="browserSessionPaths"></div>
      </div>
      <div class="toast" id="scheduleToast"></div>
    </section>

    <div class="grid">
      <section class="panel">
        <h2>设置</h2>
        <div class="row"><label>iCloud 邮箱</label><input id="imapUser" autocomplete="off" /></div>
        <div class="row"><label>App 专用密码</label><input id="imapPass" type="password" autocomplete="new-password" placeholder="留空则保持原密码" /></div>
        <div class="inline">
          <div class="row" style="flex:1"><label>IMAP 主机</label><input id="imapHost" /></div>
          <div class="row" style="width:90px"><label>端口</label><input id="imapPort" type="number" /></div>
        </div>
        <div class="inline">
          <div class="row" style="flex:1"><label>邮箱目录</label><input id="mailbox" /></div>
          <div class="row" style="width:130px"><label>验证码有效秒数</label><input id="codeAge" type="number" /></div>
        </div>
        <button id="saveSettings" class="primary">保存设置</button>
        <div class="toast" id="settingsToast"></div>
      </section>

      <section class="panel">
        <h2>新增 / 导入</h2>
        <div class="inline">
          <div class="row" style="flex:1"><label>隐藏邮箱</label><input id="aliasEmail" placeholder="xxxx@icloud.com" /></div>
          <div class="row" style="width:180px"><label>标签</label><input id="aliasLabel" /></div>
        </div>
        <div class="row"><label>备注</label><input id="aliasNote" /></div>
        <button id="addAlias" class="primary">添加邮箱</button>
        <div class="row" style="margin-top:14px">
          <label>批量导入：email 或 email----apiKey----标签----备注----分组</label>
          <textarea id="bulkAliases"></textarea>
        </div>
        <button id="importAliases">导入</button>
        <div class="toast" id="aliasToast"></div>
      </section>
    </div>

    <section class="panel" style="margin-top:14px">
      <div class="inline" style="justify-content:space-between">
        <h2>邮箱 API</h2>
        <span class="muted mono" id="adminDigest"></span>
      </div>
      <div class="toolbar">
        <select id="groupFilter" class="select-small"></select>
        <input id="groupName" class="input-small" placeholder="分组名" />
        <button id="autoGroup100" type="button">每100个自动分组</button>
        <button id="setSelectedGroup" type="button">所选设为分组</button>
        <button id="renameCurrentGroup" type="button">重命名当前分组</button>
        <label class="checkline"><input type="checkbox" id="selectAllAliases" /> 全选</label>
        <button id="invertAliasSelection" type="button">反选</button>
        <button id="exportSelectedCredentials" type="button">导出所选凭据</button>
        <button id="exportSelectedEndpoints" type="button">导出所选 API 地址</button>
        <button id="exportGroupCredentials" type="button">导出当前分组凭据</button>
        <button id="exportGroupEndpoints" type="button">导出当前分组 API</button>
        <button id="exportAllCredentials" type="button">导出全部凭据</button>
        <button id="exportAllEndpoints" type="button">导出全部 API 地址</button>
        <button id="exportSelectedEmails" type="button">导出所选邮箱</button>
        <button id="exportGroupEmails" type="button">导出当前分组邮箱</button>
        <button id="exportAllEmails" type="button">导出全部邮箱</button>
        <span class="muted" id="aliasSelectionSummary">已选 0 个</span>
      </div>
      <div class="toast" id="aliasExportToast"></div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th class="tight"></th><th>邮箱</th><th>分组</th><th>标签</th><th>API Key / 凭据</th><th>最新验证码</th><th>邮件</th><th>操作</th>
            </tr>
          </thead>
          <tbody id="aliasRows"></tbody>
        </table>
      </div>
    </section>

    <section class="panel" style="margin-top:14px">
      <div class="inline" style="justify-content:space-between">
        <h2>最近邮件</h2>
        <select id="messageAlias" style="width:280px"></select>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>时间</th><th>邮箱</th><th>发件人</th><th>主题</th><th>验证码</th></tr></thead>
          <tbody id="messageRows"></tbody>
        </table>
      </div>
    </section>
  </main>

  <script>
    const $ = (id) => document.getElementById(id);
    const api = async (path, options = {}) => {
      const headers = Object.assign({
        "Content-Type": "application/json",
        "X-API-Key": $("adminKey").value.trim(),
      }, options.headers || {});
      const response = await fetch(path, Object.assign({}, options, { headers }));
      const text = await response.text();
      let payload = {};
      try { payload = text ? JSON.parse(text) : {}; } catch { payload = { error: text }; }
      if (!response.ok) throw new Error(payload.error || `HTTP ${response.status}`);
      return payload;
    };
    const esc = (value) => String(value || "").replace(/[&<>"']/g, c => ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;" }[c]));
    const toast = (id, text, good = true) => { const el = $(id); el.textContent = text; el.className = `toast ${good ? "ok" : "bad"}`; };
    const copy = async (text) => { await navigator.clipboard.writeText(text); };
    const aliasState = { aliases: [], visibleAliases: [], selectedIds: new Set() };
    const endpointForAlias = (a) => `${location.origin}/api/v1/code?email=${encodeURIComponent(a.email)}&key=${encodeURIComponent(a.api_key)}`;
    const currentGroup = () => $("groupFilter").value || "";
    const selectedAliases = () => aliasState.visibleAliases.filter(a => aliasState.selectedIds.has(String(a.id)));
    const currentGroupAliases = () => aliasState.visibleAliases;
    const aliasLines = (aliases, kind) => aliases.map(a => {
      if (kind === "endpoint") return `${a.email}---${endpointForAlias(a)}`;
      if (kind === "email") return a.email;
      return a.credential || `${a.email}----${a.api_key}`;
    });
    const updateAliasSelectionSummary = () => {
      const selected = aliasState.selectedIds.size;
      const visible = aliasState.visibleAliases.length;
      const total = aliasState.aliases.length;
      $("aliasSelectionSummary").textContent = `已选 ${selected} / 当前 ${visible} / 全部 ${total} 个`;
      $("selectAllAliases").checked = visible > 0 && selected === visible;
      $("selectAllAliases").indeterminate = selected > 0 && selected < visible;
    };
    const downloadText = (filename, text) => {
      const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    };
    const exportAliases = async (scope, kind) => {
      const rows = scope === "all" ? aliasState.aliases : scope === "group" ? currentGroupAliases() : selectedAliases();
      if (!rows.length) {
        toast("aliasExportToast", scope === "all" ? "没有可导出的邮箱" : scope === "group" ? "当前分组没有可导出的邮箱" : "请先选择要导出的邮箱", false);
        return;
      }
      const text = aliasLines(rows, kind).join("\n");
      await copy(text);
      const name = kind === "endpoint" ? "api-urls" : kind === "email" ? "emails" : "credentials";
      downloadText(`icloud-${name}-${scope}.txt`, text + "\n");
      toast("aliasExportToast", `已导出 ${rows.length} 条，并复制到剪贴板`);
    };
    const groupNameForIndex = (index) => `分组${String(Math.floor(index / 100) + 1).padStart(3, "0")}`;
    const renderGroupFilter = () => {
      const previous = $("groupFilter").value || "";
      const groups = [];
      const counts = {};
      aliasState.aliases.forEach((a, index) => {
        const name = a.group_name || "未分组";
        if (!counts[name]) groups.push(name);
        counts[name] = (counts[name] || 0) + 1;
      });
      $("groupFilter").innerHTML = `<option value="">全部分组 (${aliasState.aliases.length})</option>` + groups.map(name => {
        const value = name === "未分组" ? "__ungrouped__" : name;
        return `<option value="${esc(value)}">${esc(name)} (${counts[name]})</option>`;
      }).join("");
      if ([...$("groupFilter").options].some(option => option.value === previous)) $("groupFilter").value = previous;
    };
    const applyGroupFilter = () => {
      const group = currentGroup();
      aliasState.visibleAliases = aliasState.aliases.filter(a => {
        if (!group) return true;
        if (group === "__ungrouped__") return !(a.group_name || "");
        return (a.group_name || "") === group;
      });
      const visibleIds = new Set(aliasState.visibleAliases.map(a => String(a.id)));
      aliasState.selectedIds = new Set([...aliasState.selectedIds].filter(id => visibleIds.has(id)));
      renderAliasRows();
    };
    const groupPayloadIds = () => [...aliasState.selectedIds].map(id => Number(id)).filter(Boolean);
    const resolveGroupName = (value) => value === "__ungrouped__" ? "" : value;
    const bindAliasCheckboxes = () => {
      document.querySelectorAll(".aliasSelect").forEach(box => {
        box.onchange = () => {
          const id = String(box.dataset.id || "");
          if (!id) return;
          if (box.checked) aliasState.selectedIds.add(id);
          else aliasState.selectedIds.delete(id);
          updateAliasSelectionSummary();
        };
      });
      updateAliasSelectionSummary();
    };

    async function loadSettings() {
      const payload = await api("/api/settings");
      const s = payload.settings;
      $("imapUser").value = s.imap.username || "";
      $("imapHost").value = s.imap.host || "imap.mail.me.com";
      $("imapPort").value = s.imap.port || 993;
      $("mailbox").value = s.imap.mailbox || "INBOX";
      $("codeAge").value = s.sync.code_max_age_seconds || 3600;
      $("imapPass").placeholder = s.imap.password_set ? "已保存，留空则保持原密码" : "Apple App 专用密码";
    }

    const formatScheduleTime = (value) => {
      if (!value || value === "N/A" || value === "不适用") return "-";
      const parsed = new Date(value);
      return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toLocaleString();
    };
    const renderSchedule = (schedule = {}) => {
      const registered = Boolean(schedule.registered);
      const enabled = registered && schedule.enabled !== false;
      const statusText = registered ? (enabled ? "已启用" : "已停用") : "未注册";
      const nextCount = Number(schedule.next_count || 0);
      const completedRuns = Number(schedule.completed_runs || 0);
      const lastCount = Number(schedule.last_count || 0);
      $("scheduleStatus").textContent = statusText;
      $("scheduleStatus").className = enabled ? "ok" : "bad";
      $("scheduleBadge").textContent = statusText;
      $("scheduleBadge").className = `pill ${enabled ? "ok" : "bad"}`;
      $("scheduleNextCount").textContent = nextCount ? `${nextCount} 个（${completedRuns === 0 ? "首轮" : "后续"}）` : "-";
      $("scheduleNextRun").textContent = formatScheduleTime(schedule.next_run);
      $("scheduleCompleted").textContent = `${completedRuns} 个周期`;
      $("scheduleLastRun").textContent = formatScheduleTime(schedule.last_run);
      $("scheduleLastSuccess").textContent = formatScheduleTime(schedule.last_success_at);
      $("scheduleLastCount").textContent = lastCount ? `${lastCount} 个` : "-";
      $("scheduleLastResult").textContent = schedule.last_result || "-";
      $("scheduleSummary").textContent = registered
        ? `每 ${schedule.interval_minutes || 30} 分钟运行；首轮 ${schedule.initial_count || 4} 个，后续 ${schedule.recurring_count || 5} 个`
        : (schedule.query_error || "没有找到 Windows 定时任务，请先运行安装脚本");
      $("schedulePaths").textContent = `任务：${schedule.task_name || "-"}　状态文件：${schedule.state_path || "-"}　日志：${schedule.log_path || "-"}`;
      renderScheduleLog(schedule.recent_log);
    };
    const renderScheduleLog = (log = {}) => {
      const statusLabels = {
        success: "成功",
        running: "执行中",
        failed: "失败",
        action_required: "需要处理",
        skipped: "已跳过",
        unknown: "未知",
      };
      const status = log.status || "unknown";
      const statusClass = status === "success" ? "ok" : ["failed", "action_required"].includes(status) ? "bad" : "";
      $("scheduleLogBadge").textContent = statusLabels[status] || status;
      $("scheduleLogBadge").className = `pill ${statusClass}`;
      $("scheduleLogMessage").textContent = log.message || "暂无定时任务执行日志";
      $("scheduleLogMessage").className = `schedule-log-message ${statusClass}`;
      $("scheduleLogTime").textContent = log.at ? `时间：${formatScheduleTime(log.at)}` : "";
      const entries = Array.isArray(log.entries) ? log.entries : [];
      $("scheduleLogEntries").innerHTML = entries.map(entry => {
        const entryLabel = statusLabels[entry.status] || entry.status || "状态";
        return `<div class="schedule-log-entry"><span class="muted mono">${esc(formatScheduleTime(entry.at))}</span><span class="pill">${esc(entryLabel)}</span><span>${esc(entry.message || "")}</span></div>`;
      }).join("");
    };
    const renderBrowserSession = (session = {}) => {
      const state = session.state || "unknown";
      const labels = {
        authenticated: "已登录",
        starting: "启动中",
        login_required: "需要登录",
        browser_closed: "浏览器已关闭",
        unknown: "未知",
      };
      const needsAction = ["login_required", "browser_closed"].includes(state);
      const statusClass = state === "authenticated" ? "ok" : needsAction ? "bad" : "";
      $("browserSessionBadge").textContent = labels[state] || state;
      $("browserSessionBadge").className = `pill ${statusClass}`;
      $("browserSessionMessage").textContent = session.message || "暂无会话状态";
      $("browserSessionMessage").className = `schedule-log-message ${statusClass}`;
      $("browserSessionTime").textContent = session.updated_at
        ? `更新时间：${formatScheduleTime(session.updated_at)}`
        : "";
      $("browserSessionPaths").textContent =
        `状态文件：${session.status_file || "-"}　日志：${session.log_file || "-"}`;
    };
    const scheduleActionButtons = ["scheduleStart", "scheduleStop", "scheduleRunNow"];
    const scheduleAction = async (action) => {
      try {
        scheduleActionButtons.forEach(id => { $(id).disabled = true; });
        const payload = await api("/api/schedule/action", {
          method: "POST",
          body: JSON.stringify({ action }),
        });
        renderSchedule(payload.schedule);
        toast("scheduleToast", payload.message || "操作已完成");
      } catch (err) {
        toast("scheduleToast", err.message, false);
      } finally {
        scheduleActionButtons.forEach(id => { $(id).disabled = false; });
      }
    };

    async function loadDashboard() {
      const payload = await api("/api/dashboard");
      const { summary, aliases, schedule, browser_session } = payload;
      aliasState.aliases = aliases;
      $("statAliases").textContent = summary.alias_count;
      $("statMessages").textContent = summary.message_count;
      $("statUnmatched").textContent = summary.unmatched_count;
      $("statImap").textContent = summary.imap_configured ? "已配置" : "未配置";
      $("statImap").className = summary.imap_configured ? "ok" : "bad";
      $("adminDigest").textContent = `Admin Key 指纹：${summary.admin_key_digest}`;
      renderSchedule(schedule);
      renderBrowserSession(browser_session);

      $("messageAlias").innerHTML = `<option value="">全部邮箱</option>` + aliases.map(a => `<option value="${esc(a.email)}">${esc(a.email)}</option>`).join("");
      renderGroupFilter();
      applyGroupFilter();
    }

    function renderAliasRows() {
      $("aliasRows").innerHTML = aliasState.visibleAliases.map(a => {
        const id = String(a.id);
        const checked = aliasState.selectedIds.has(id) ? "checked" : "";
        const endpoint = endpointForAlias(a);
        const credential = a.credential || [a.email, a.api_key].join("----");
        const latest = a.latest_code && a.latest_code.code ? `${esc(a.latest_code.code)} <span class="muted mono">${esc(a.latest_code.received_at || "")}</span>` : "-";
        return `<tr>
          <td class="tight"><input class="aliasSelect" type="checkbox" data-id="${esc(id)}" ${checked} /></td>
          <td class="mono">${esc(a.email)}<br><span class="muted">${esc(a.note || "")}</span></td>
          <td>${esc(a.group_name || "未分组")}</td>
          <td>${esc(a.label || "")}</td>
          <td class="mono">
            <span>${esc(a.api_key)}</span><br>
            <button data-copy-value="${esc(credential)}">复制凭据</button>
            <button data-copy-value="${esc(endpoint)}">复制接口</button>
          </td>
          <td class="mono">${latest}</td>
          <td><span class="pill">${a.message_count || 0}</span></td>
          <td>
            <button data-rotate-id="${esc(id)}">换 Key</button>
            <button class="danger" data-delete-id="${esc(id)}">删除</button>
          </td>
        </tr>`;
      }).join("");
      bindAliasCheckboxes();
      bindAliasActions();
    }

    const bindAliasActions = () => {
      document.querySelectorAll("[data-copy-value]").forEach((button) => {
        button.onclick = () => copy(button.dataset.copyValue || "").catch((error) => {
          toast("aliasExportToast", error.message || "copy failed", false);
        });
      });
      document.querySelectorAll("[data-rotate-id]").forEach((button) => {
        button.onclick = () => rotateAlias(Number(button.dataset.rotateId)).catch((error) => {
          toast("aliasExportToast", error.message || "key update failed", false);
        });
      });
      document.querySelectorAll("[data-delete-id]").forEach((button) => {
        button.onclick = () => deleteAlias(Number(button.dataset.deleteId)).catch((error) => {
          toast("aliasExportToast", error.message || "delete failed", false);
        });
      });
    };

    async function loadMessages() {
      const alias = $("messageAlias").value;
      const query = alias ? `?alias=${encodeURIComponent(alias)}&limit=80` : "?limit=80";
      const payload = await api(`/api/messages${query}`);
      $("messageRows").innerHTML = payload.messages.map(m => `<tr>
        <td class="mono">${esc(m.received_at)}</td>
        <td class="mono">${esc(m.alias_email || "-")}</td>
        <td>${esc(m.from)}</td>
        <td>${esc(m.subject)}<br><span class="muted">${esc(m.preview)}</span></td>
        <td class="mono">${esc(m.code || "")}</td>
      </tr>`).join("");
    }

    async function refreshAll() {
      await loadSettings();
      await loadDashboard();
      await loadMessages();
    }

    async function rotateAlias(id) {
      await api(`/api/aliases/${id}/rotate-key`, { method: "POST", body: "{}" });
      await loadDashboard();
    }

    async function deleteAlias(id) {
      if (!confirm("删除这个邮箱？历史邮件不会删除，只会取消关联。")) return;
      await api(`/api/aliases/${id}`, { method: "DELETE" });
      await loadDashboard();
    }

    $("adminKey").value = localStorage.getItem("icloudCodeAdminKey") || "";
    $("saveKey").onclick = () => { localStorage.setItem("icloudCodeAdminKey", $("adminKey").value.trim()); refreshAll().catch(err => toast("settingsToast", err.message, false)); };
    $("refresh").onclick = () => refreshAll().catch(err => toast("settingsToast", err.message, false));
    $("refreshSchedule").onclick = () => loadDashboard().catch(err => toast("scheduleToast", err.message, false));
    $("scheduleStart").onclick = () => scheduleAction("start");
    $("scheduleStop").onclick = () => scheduleAction("stop");
    $("scheduleRunNow").onclick = () => scheduleAction("run");
    $("sync").onclick = async () => {
      try {
        $("sync").disabled = true;
        const result = await api("/api/sync", { method: "POST", body: JSON.stringify({ force: true }) });
        toast("settingsToast", `同步完成：检查 ${result.inspected || 0} 封，新增 ${result.inserted || 0} 封`);
        await loadDashboard(); await loadMessages();
      } catch (err) { toast("settingsToast", err.message, false); }
      finally { $("sync").disabled = false; }
    };
    $("saveSettings").onclick = async () => {
      try {
        await api("/api/settings", { method: "POST", body: JSON.stringify({
          imap: {
            username: $("imapUser").value.trim(),
            app_password: $("imapPass").value,
            host: $("imapHost").value.trim(),
            port: Number($("imapPort").value || 993),
            mailbox: $("mailbox").value.trim() || "INBOX",
          },
          sync: { code_max_age_seconds: Number($("codeAge").value || 3600) },
        }) });
        $("imapPass").value = "";
        toast("settingsToast", "设置已保存");
        await refreshAll();
      } catch (err) { toast("settingsToast", err.message, false); }
    };
    $("addAlias").onclick = async () => {
      try {
        await api("/api/aliases", { method: "POST", body: JSON.stringify({
          email: $("aliasEmail").value.trim(),
          label: $("aliasLabel").value.trim(),
          note: $("aliasNote").value.trim(),
        }) });
        $("aliasEmail").value = ""; $("aliasLabel").value = ""; $("aliasNote").value = "";
        toast("aliasToast", "邮箱已添加");
        await loadDashboard();
      } catch (err) { toast("aliasToast", err.message, false); }
    };
    $("importAliases").onclick = async () => {
      try {
        const payload = await api("/api/aliases/import", { method: "POST", body: JSON.stringify({ text: $("bulkAliases").value }) });
        toast("aliasToast", `导入完成：${payload.imported} 个`);
        $("bulkAliases").value = "";
        await loadDashboard();
      } catch (err) { toast("aliasToast", err.message, false); }
    };
    $("selectAllAliases").onchange = () => {
      if ($("selectAllAliases").checked) aliasState.visibleAliases.forEach(a => aliasState.selectedIds.add(String(a.id)));
      else aliasState.selectedIds.clear();
      document.querySelectorAll(".aliasSelect").forEach(box => { box.checked = $("selectAllAliases").checked; });
      updateAliasSelectionSummary();
    };
    $("invertAliasSelection").onclick = () => {
      aliasState.visibleAliases.forEach(a => {
        const id = String(a.id);
        if (aliasState.selectedIds.has(id)) aliasState.selectedIds.delete(id);
        else aliasState.selectedIds.add(id);
      });
      document.querySelectorAll(".aliasSelect").forEach(box => { box.checked = aliasState.selectedIds.has(String(box.dataset.id || "")); });
      updateAliasSelectionSummary();
    };
    $("groupFilter").onchange = () => applyGroupFilter();
    $("autoGroup100").onclick = async () => {
      try {
        const payload = await api("/api/aliases/auto-group", { method: "POST", body: JSON.stringify({ size: 100, prefix: "分组" }) });
        toast("aliasExportToast", `自动分组完成：更新 ${payload.changed || 0} 个邮箱`);
        await loadDashboard();
      } catch (err) { toast("aliasExportToast", err.message, false); }
    };
    $("setSelectedGroup").onclick = async () => {
      try {
        const ids = groupPayloadIds();
        if (!ids.length) { toast("aliasExportToast", "请先选择要设置分组的邮箱", false); return; }
        const groupName = $("groupName").value.trim();
        if (!groupName) { toast("aliasExportToast", "请先填写分组名", false); return; }
        const payload = await api("/api/aliases/group", { method: "POST", body: JSON.stringify({ ids, group_name: groupName }) });
        toast("aliasExportToast", `已设置 ${payload.updated || 0} 个邮箱到 ${groupName}`);
        await loadDashboard();
      } catch (err) { toast("aliasExportToast", err.message, false); }
    };
    $("renameCurrentGroup").onclick = async () => {
      try {
        const oldName = resolveGroupName(currentGroup());
        const newName = $("groupName").value.trim();
        if (!currentGroup()) { toast("aliasExportToast", "请先在左侧选择一个分组", false); return; }
        if (!newName) { toast("aliasExportToast", "请先填写新的分组名", false); return; }
        const payload = await api("/api/aliases/group/rename", { method: "POST", body: JSON.stringify({ old_name: oldName, new_name: newName }) });
        toast("aliasExportToast", `已重命名 ${payload.updated || 0} 个邮箱`);
        await loadDashboard();
      } catch (err) { toast("aliasExportToast", err.message, false); }
    };
    $("exportSelectedCredentials").onclick = () => exportAliases("selected", "credential");
    $("exportSelectedEndpoints").onclick = () => exportAliases("selected", "endpoint");
    $("exportGroupCredentials").onclick = () => exportAliases("group", "credential");
    $("exportGroupEndpoints").onclick = () => exportAliases("group", "endpoint");
    $("exportAllCredentials").onclick = () => exportAliases("all", "credential");
    $("exportAllEndpoints").onclick = () => exportAliases("all", "endpoint");
    $("exportSelectedEmails").onclick = () => exportAliases("selected", "email");
    $("exportGroupEmails").onclick = () => exportAliases("group", "email");
    $("exportAllEmails").onclick = () => exportAliases("all", "email");
    $("messageAlias").onchange = () => loadMessages().catch(err => toast("settingsToast", err.message, false));
    refreshAll().catch(err => toast("settingsToast", err.message, false));
  </script>
</body>
</html>"""


class RequestBodyError(ValueError):
    def __init__(self, message: str, status: int) -> None:
        super().__init__(message)
        self.status = status


class ApiHandler(BaseHTTPRequestHandler):
    server_version = "IcloudCodeApi/0.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("%s - - [%s] %s\n" % (self.address_string(), self.log_date_time_string(), fmt % args))

    def end_headers(self) -> None:
        # CORS is opt-in. The previous wildcard policy allowed any web page
        # that obtained an API key to read protected responses.
        origin = self.headers.get("Origin", "").strip()
        allowed_origin = str(current_config().get("cors_origin") or "").strip()
        if allowed_origin and origin == allowed_origin:
            self.send_header("Access-Control-Allow-Origin", allowed_origin)
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
            self.send_header("Vary", "Origin")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def send_json(self, payload: dict[str, Any], status: int = 200) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def send_html(self, text: str, status: int = 200) -> None:
        raw = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def read_json(self) -> dict[str, Any]:
        raw_length = self.headers.get("Content-Length")
        if not raw_length:
            return {}
        try:
            length = int(raw_length)
        except (TypeError, ValueError) as error:
            raise RequestBodyError("invalid Content-Length", HTTPStatus.BAD_REQUEST) from error
        if length < 0:
            raise RequestBodyError("invalid Content-Length", HTTPStatus.BAD_REQUEST)
        if length > MAX_REQUEST_BODY_BYTES:
            raise RequestBodyError(
                f"request body exceeds {MAX_REQUEST_BODY_BYTES} bytes",
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            )
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def path_parts(self) -> tuple[str, dict[str, list[str]]]:
        parsed = urlparse(self.path)
        return parsed.path.rstrip("/") or "/", parse_qs(parsed.query)

    def request_key(self, query: dict[str, list[str]], body: dict[str, Any] | None = None) -> str:
        header_key = self.headers.get("X-API-Key") or ""
        auth = self.headers.get("Authorization") or ""
        if auth.lower().startswith("bearer "):
            header_key = auth[7:].strip()
        if header_key:
            return header_key.strip()
        for name in ("key", "api_key", "adminKey", "admin_key"):
            if query.get(name):
                return str(query[name][0]).strip()
        if body:
            return str(body.get("adminKey") or body.get("admin_key") or body.get("api_key") or body.get("key") or "").strip()
        return ""

    def require_admin(self, query: dict[str, list[str]], body: dict[str, Any] | None = None) -> bool:
        key = self.request_key(query, body)
        if is_admin_key(key):
            return True
        self.send_json({"ok": False, "error": "Admin API Key 不正确"}, HTTPStatus.UNAUTHORIZED)
        return False

    def send_internal_error(self, error: Exception) -> None:
        self.log_message("internal error: %s", error)
        self.send_json({"ok": False, "error": "Internal server error"}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self) -> None:
        """Respond to health checks without logging a spurious 501."""
        path, _ = self.path_parts()
        if path == "/admin":
            raw = ADMIN_HTML.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            return
        if path == "/api/health":
            cfg = current_config()
            imap_cfg = cfg.get("imap", {})
            raw = json.dumps(
                {
                    "ok": True,
                    "configured": bool(
                        imap_cfg.get("username") and imap_cfg.get("app_password")
                    ),
                    "admin_key_digest": secret_digest(
                        str(cfg.get("admin_key") or "")
                    ),
                },
                ensure_ascii=False,
            ).encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            return
        self.send_response(HTTPStatus.NOT_FOUND)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        path, query = self.path_parts()
        try:
            if path == "/":
                self.send_response(HTTPStatus.FOUND)
                self.send_header("Location", "/admin")
                self.end_headers()
                return
            if path == "/admin":
                self.send_html(ADMIN_HTML)
                return
            if path == "/api/health":
                cfg = current_config()
                imap_cfg = cfg.get("imap", {})
                self.send_json(
                    {
                        "ok": True,
                        "configured": bool(imap_cfg.get("username") and imap_cfg.get("app_password")),
                        "admin_key_digest": secret_digest(str(cfg.get("admin_key") or "")),
                    }
                )
                return
            if path == "/api/settings":
                if not self.require_admin(query):
                    return
                cfg = current_config()
                imap_cfg = cfg.get("imap", {})
                self.send_json(
                    {
                        "ok": True,
                        "settings": {
                            "imap": {
                                "host": imap_cfg.get("host"),
                                "port": imap_cfg.get("port"),
                                "username": imap_cfg.get("username"),
                                "mailbox": imap_cfg.get("mailbox"),
                                "password_set": bool(imap_cfg.get("app_password")),
                            },
                            "sync": cfg.get("sync", {}),
                        },
                    }
                )
                return
            if path == "/api/dashboard":
                if not self.require_admin(query):
                    return
                self.send_json(dashboard_payload())
                return
            if path == "/api/aliases":
                if not self.require_admin(query):
                    return
                aliases = [public_alias(alias, include_key=True) for alias in list_alias_rows(active_only=False)]
                self.send_json({"ok": True, "aliases": aliases})
                return
            if path == "/api/messages":
                if not self.require_admin(query):
                    return
                alias_email = normalize_email(query.get("alias", [""])[0])
                limit = sanitize_int(query.get("limit", ["50"])[0], 50, 1, 500)
                self.send_json({"ok": True, "messages": list_messages(alias_email, limit)})
                return
            if path in ("/api/v1/code", "/api/latest-code"):
                email_addr = normalize_email(query.get("email", [""])[0])
                key = self.request_key(query)
                alias = get_alias_by_email(email_addr)
                if not (is_admin_key(key) or is_alias_key(alias, key)):
                    self.send_json({"ok": False, "error": "API Key 不正确"}, HTTPStatus.UNAUTHORIZED)
                    return
                after = parse_epoch(query.get("after", ["0"])[0])
                result = latest_code_for_alias(email_addr, after=after, sync_first=True)
                self.send_json(result)
                return
            if path in ("/api/v1/messages",):
                email_addr = normalize_email(query.get("email", [""])[0])
                key = self.request_key(query)
                alias = get_alias_by_email(email_addr)
                if not (is_admin_key(key) or is_alias_key(alias, key)):
                    self.send_json({"ok": False, "error": "API Key 不正确"}, HTTPStatus.UNAUTHORIZED)
                    return
                limit = sanitize_int(query.get("limit", ["20"])[0], 20, 1, 100)
                self.send_json({"ok": True, "messages": list_messages(email_addr, limit)})
                return
            self.send_json({"ok": False, "error": "Not found"}, HTTPStatus.NOT_FOUND)
        except Exception as err:
            self.send_internal_error(err)

    def do_POST(self) -> None:
        path, query = self.path_parts()
        try:
            body = self.read_json()
        except RequestBodyError as error:
            self.send_json({"ok": False, "error": str(error)}, error.status)
            return
        try:
            if path == "/api/schedule/action":
                if not self.require_admin(query, body):
                    return
                action = str(body.get("action") or "").strip().lower()
                if action not in SCHEDULE_ACTIONS:
                    self.send_json(
                        {"ok": False, "error": "不支持的定时任务操作"},
                        HTTPStatus.BAD_REQUEST,
                    )
                    return
                self.send_json({"ok": True, **run_schedule_action(action)})
                return
            if path == "/api/settings":
                if not self.require_admin(query, body):
                    return
                current = current_config()
                imap_updates = body.get("imap") if isinstance(body.get("imap"), dict) else {}
                sync_updates = body.get("sync") if isinstance(body.get("sync"), dict) else {}
                updates = {
                    "imap": {
                        "host": str(imap_updates.get("host") or "imap.mail.me.com").strip(),
                        "port": sanitize_int(imap_updates.get("port"), 993, 1, 65535),
                        "username": str(imap_updates.get("username") or "").strip(),
                        "mailbox": str(imap_updates.get("mailbox") or "INBOX").strip() or "INBOX",
                        "app_password": str(imap_updates.get("app_password") or ""),
                    },
                    "sync": {
                        **(current.get("sync", {}) if isinstance(current.get("sync"), dict) else {}),
                        **sync_updates,
                    },
                    "admin_key": current.get("admin_key") or "",
                }
                if not updates["imap"]["app_password"]:
                    updates["imap"]["app_password"] = str(current.get("imap", {}).get("app_password") or "")
                cfg = save_config_updates(updates)
                self.send_json({"ok": True, "admin_key_digest": secret_digest(str(cfg.get("admin_key") or ""))})
                return
            if path == "/api/aliases":
                if not self.require_admin(query, body):
                    return
                alias = upsert_alias(
                    body.get("email") or "",
                    label=body.get("label") or "",
                    note=body.get("note") or "",
                    api_key=body.get("api_key") or "",
                )
                self.send_json({"ok": True, "alias": public_alias(alias, include_key=True)})
                return
            if path == "/api/aliases/import":
                if not self.require_admin(query, body):
                    return
                lines = str(body.get("text") or "").splitlines()
                imported = []
                errors = []
                for index, line in enumerate(lines, start=1):
                    parsed = parse_alias_import_line(line)
                    if not parsed:
                        continue
                    email_addr, api_key, label, note, group_name = parsed
                    try:
                        imported.append(public_alias(upsert_alias(email_addr, label, note, api_key, group_name), include_key=True))
                    except Exception as err:
                        errors.append({"line": index, "error": str(err)})
                self.send_json({"ok": True, "imported": len(imported), "aliases": imported, "errors": errors})
                return
            if path == "/api/aliases/auto-group":
                if not self.require_admin(query, body):
                    return
                result = auto_group_aliases(
                    size=sanitize_int(body.get("size"), 100, 1, 1000),
                    prefix=str(body.get("prefix") or "分组"),
                )
                self.send_json({"ok": True, **result})
                return
            if path == "/api/aliases/group":
                if not self.require_admin(query, body):
                    return
                raw_ids = body.get("ids") if isinstance(body.get("ids"), list) else []
                alias_ids = []
                for raw_id in raw_ids:
                    try:
                        alias_ids.append(int(raw_id))
                    except Exception:
                        continue
                updated = update_alias_group(alias_ids, str(body.get("group_name") or ""))
                self.send_json({"ok": True, "updated": updated})
                return
            if path == "/api/aliases/group/rename":
                if not self.require_admin(query, body):
                    return
                updated = rename_alias_group(
                    str(body.get("old_name") or ""),
                    str(body.get("new_name") or ""),
                )
                self.send_json({"ok": True, "updated": updated})
                return
            rotate_match = re.match(r"^/api/aliases/(\d+)/rotate-key$", path)
            if rotate_match:
                if not self.require_admin(query, body):
                    return
                alias_id = int(rotate_match.group(1))
                api_key = generate_api_key("alias")
                stamp = now_iso()
                with db_connect() as conn:
                    conn.execute(
                        "UPDATE aliases SET api_key = ?, updated_at = ? WHERE id = ?",
                        (api_key, stamp, alias_id),
                    )
                alias = get_alias_by_id(alias_id)
                if not alias:
                    self.send_json({"ok": False, "error": "邮箱不存在"}, HTTPStatus.NOT_FOUND)
                    return
                self.send_json({"ok": True, "alias": public_alias(alias, include_key=True)})
                return
            if path == "/api/sync":
                if not self.require_admin(query, body):
                    return
                result = sync_mailbox(force=bool(body.get("force", True)))
                self.send_json(result)
                return
            if path == "/api/verification-code":
                credential = str(body.get("credential") or "")
                email_addr, alias_key = parse_credential(credential)
                admin_key = str(body.get("adminKey") or body.get("admin_key") or "")
                alias = get_alias_by_email(email_addr)
                if not email_addr:
                    self.send_json({"ok": False, "error": "缺少 credential 邮箱"}, HTTPStatus.BAD_REQUEST)
                    return
                if not (is_admin_key(admin_key) or is_alias_key(alias, alias_key)):
                    self.send_json({"ok": False, "error": "API Key 不正确"}, HTTPStatus.UNAUTHORIZED)
                    return
                exclude = {normalize_code_candidate(x) for x in body.get("excludeCodes", []) if normalize_code_candidate(str(x))}
                after = parse_epoch(body.get("filterAfterTimestamp") or body.get("afterTimestamp") or 0)
                result = latest_code_for_alias(
                    email_addr,
                    code_patterns=body.get("codePatterns") if isinstance(body.get("codePatterns"), list) else [],
                    exclude_codes=exclude,
                    after=after,
                    sync_first=True,
                )
                self.send_json(result)
                return
            self.send_json({"ok": False, "error": "Not found"}, HTTPStatus.NOT_FOUND)
        except Exception as err:
            self.send_internal_error(err)

    def do_DELETE(self) -> None:
        path, query = self.path_parts()
        try:
            match = re.match(r"^/api/aliases/(\d+)$", path)
            if match:
                if not self.require_admin(query):
                    return
                alias_id = int(match.group(1))
                alias = get_alias_by_id(alias_id)
                if not alias:
                    self.send_json({"ok": False, "error": "邮箱不存在"}, HTTPStatus.NOT_FOUND)
                    return
                with db_connect() as conn:
                    conn.execute("UPDATE messages SET alias_id = NULL, alias_email = '' WHERE alias_id = ?", (alias_id,))
                    conn.execute("DELETE FROM aliases WHERE id = ?", (alias_id,))
                self.send_json({"ok": True})
                return
            self.send_json({"ok": False, "error": "Not found"}, HTTPStatus.NOT_FOUND)
        except Exception as err:
            self.send_internal_error(err)


def main() -> None:
    reload_config()
    init_db()
    cfg = current_config()
    host = str(cfg.get("host") or "127.0.0.1")
    port = sanitize_int(cfg.get("port"), 8765, 1, 65535)
    print(f"iCloud Code API listening on http://{host}:{port}/admin", flush=True)
    print(f"Admin key digest: {secret_digest(str(cfg.get('admin_key') or ''))}", flush=True)
    print(f"Secret file: {SECRETS_PATH}", flush=True)
    ThreadingHTTPServer((host, port), ApiHandler).serve_forever()


if __name__ == "__main__":
    main()
