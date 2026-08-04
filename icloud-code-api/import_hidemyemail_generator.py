#!/usr/bin/env python3
"""Import hidemyemail-generator emails.txt into iCloud Code API."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib import request


def read_admin_key(api_dir: Path) -> str:
    secrets_path = api_dir / "data" / "secrets.json"
    config_path = api_dir / "config.json"
    for path in (secrets_path, config_path):
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        key = str(data.get("admin_key") or "").strip()
        if key:
            return key
    return ""


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
        text = resp.read().decode("utf-8")
    return json.loads(text or "{}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Import hidemyemail-generator emails.txt into iCloud Code API.")
    parser.add_argument(
        "--emails-file",
        default=str(Path(__file__).resolve().parents[1] / "hidemyemail-generator" / "emails.txt"),
        help="Path to hidemyemail-generator emails.txt",
    )
    parser.add_argument("--api-url", default="http://127.0.0.1:8765", help="iCloud Code API base URL")
    parser.add_argument("--admin-key", default="", help="Admin API key. Defaults to data/secrets.json")
    args = parser.parse_args()

    api_dir = Path(__file__).resolve().parent
    admin_key = args.admin_key.strip() or read_admin_key(api_dir)
    if not admin_key:
        print("Missing admin key. Start app.py once or pass --admin-key.", file=sys.stderr)
        return 2

    emails_path = Path(args.emails_file).resolve()
    if not emails_path.exists():
        print(f"emails.txt not found: {emails_path}", file=sys.stderr)
        return 2

    lines = [
        line.strip()
        for line in emails_path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    payload = post_json(
        args.api_url.rstrip("/") + "/api/aliases/import",
        admin_key,
        {"text": "\n".join(lines)},
    )
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if payload.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
