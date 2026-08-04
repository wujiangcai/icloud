#!/usr/bin/env python3
"""List active iCloud Hide My Email aliases and import them into iCloud Code API."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from urllib import request


ROOT = Path(__file__).resolve().parents[1]
API_DIR = Path(__file__).resolve().parent
GENERATOR_DIR = ROOT / "hidemyemail-generator"


def read_admin_key() -> str:
    secrets_path = API_DIR / "data" / "secrets.json"
    if not secrets_path.exists():
        return ""
    data = json.loads(secrets_path.read_text(encoding="utf-8"))
    return str(data.get("admin_key") or "").strip()


def post_json(url: str, admin_key: str, payload: dict) -> dict:
    raw = json.dumps(payload).encode("utf-8")
    req = request.Request(
        url,
        data=raw,
        headers={
            "User-Agent": "icloud-code-api-importer/1.0",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-API-Key": admin_key,
        },
        method="POST",
    )
    with request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8") or "{}")


async def list_active_emails() -> list[str]:
    sys.path.insert(0, str(GENERATOR_DIR))
    from main import RichHideMyEmail  # type: ignore

    async with RichHideMyEmail() as hme:
        payload = await hme.list_email()
    if not payload or not payload.get("success"):
        error = payload.get("error") if isinstance(payload, dict) else {}
        reason = payload.get("reason") if isinstance(payload, dict) else ""
        if isinstance(error, dict):
            reason = error.get("errorMessage") or reason
        raise RuntimeError(reason or "Failed to list iCloud Hide My Email aliases")

    rows = payload.get("result", {}).get("hmeEmails", [])
    emails: list[str] = []
    seen: set[str] = set()
    for row in rows:
        if not row.get("isActive", True):
            continue
        email = str(row.get("hme") or "").strip().lower()
        if not email or "@" not in email or email in seen:
            continue
        seen.add(email)
        emails.append(email)
    return emails


def main() -> int:
    parser = argparse.ArgumentParser(description="Import active iCloud Hide My Email aliases into iCloud Code API.")
    parser.add_argument("--api-url", default="http://127.0.0.1:8765", help="iCloud Code API base URL")
    parser.add_argument("--admin-key", default="", help="Admin API key. Defaults to data/secrets.json")
    args = parser.parse_args()

    admin_key = args.admin_key.strip() or read_admin_key()
    if not admin_key:
        print("Missing admin key. Pass --admin-key.", file=sys.stderr)
        return 2

    emails = asyncio.run(list_active_emails())
    if not emails:
        print("No active iCloud Hide My Email aliases found.", file=sys.stderr)
        return 1

    payload = post_json(
        args.api_url.rstrip("/") + "/api/aliases/import",
        admin_key,
        {"text": "\n".join(emails)},
    )
    print(json.dumps({"listed": len(emails), **payload}, ensure_ascii=False, indent=2))
    return 0 if payload.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
