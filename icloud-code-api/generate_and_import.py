#!/usr/bin/env python3
"""Generate Hide My Email aliases, then import them into iCloud Code API."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from urllib import request


ROOT = Path(__file__).resolve().parents[1]
API_DIR = Path(__file__).resolve().parent
GENERATOR_DIR = ROOT / "hidemyemail-generator"


def read_admin_key() -> str:
    secrets_path = API_DIR / "data" / "secrets.json"
    config_path = API_DIR / "config.json"
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
        return json.loads(resp.read().decode("utf-8") or "{}")


def read_emails(path: Path) -> list[str]:
    if not path.exists():
        return []
    emails: list[str] = []
    seen: set[str] = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        email = line.strip().lower()
        if not email or "@" not in email or email in seen:
            continue
        seen.add(email)
        emails.append(email)
    return emails


def env_flag(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def refresh_cookie_before_generate(
    *,
    generator_python: str,
    cookie_file: Path,
    wait_seconds: int,
) -> int:
    """Refresh the browser session before starting any alias operation.

    Interactive runs open a visible browser so the user can complete Apple
    login/2FA.  Scheduler/API runs use headless mode and reuse the dedicated
    persistent profile that was initialized once by the user.
    """
    refresh_script = GENERATOR_DIR / "refresh_cookie.py"
    if not refresh_script.exists():
        print(f"Cookie refresh script not found: {refresh_script}", file=sys.stderr)
        return 2

    command = [
        generator_python,
        str(refresh_script),
        "--cookie-file",
        str(cookie_file),
        "--wait-seconds",
        str(max(0, wait_seconds)),
    ]
    # When stdout is connected to a terminal, show the browser and allow a
    # first-time login.  The scheduler captures stdout, so it defaults to
    # headless and never steals focus every 30 minutes.
    force_headless = "HME_COOKIE_REFRESH_HEADLESS" in os.environ
    headless = (
        env_flag("HME_COOKIE_REFRESH_HEADLESS")
        if force_headless
        else not sys.stdout.isatty()
    )
    if env_flag("HME_COOKIE_REFRESH_HEADED"):
        headless = False
    command.append("--headless" if headless else "--headed")

    print("Refreshing iCloud browser session before generation...")
    completed = subprocess.run(
        command,
        cwd=str(GENERATOR_DIR),
        env=os.environ.copy(),
        check=False,
    )
    if completed.returncode != 0:
        print(
            "Cookie refresh failed. Run refresh_cookie.py --headed, complete "
            "iCloud login in the opened browser, and retry.",
            file=sys.stderr,
        )
    return completed.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate Hide My Email aliases and import them into iCloud Code API.")
    parser.add_argument("--count", type=int, default=1, help="How many aliases to successfully generate")
    parser.add_argument("--success-delay", type=int, default=100, help="Seconds to wait after each successful alias")
    parser.add_argument("--failure-delay", type=int, default=120, help="Seconds to wait after each failed attempt")
    parser.add_argument("--api-url", default="http://127.0.0.1:8765", help="iCloud Code API base URL")
    parser.add_argument("--admin-key", default="", help="Admin API key. Defaults to data/secrets.json")
    parser.add_argument(
        "--no-cookie-refresh",
        action="store_true",
        help="Skip automatic browser Cookie refresh (not recommended)",
    )
    parser.add_argument(
        "--cookie-refresh-wait",
        type=int,
        default=int(os.environ.get("HME_COOKIE_REFRESH_WAIT_SECONDS", "90")),
        help="Seconds to wait for browser login when refreshing Cookie",
    )
    args = parser.parse_args()

    admin_key = args.admin_key.strip() or read_admin_key()
    if not admin_key:
        print("Missing admin key. Start app.py once or pass --admin-key.", file=sys.stderr)
        return 2

    cli_path = GENERATOR_DIR / "cli.py"
    if not cli_path.exists():
        print(f"hidemyemail-generator not found: {GENERATOR_DIR}", file=sys.stderr)
        return 2

    emails_path = GENERATOR_DIR / "emails.txt"
    before = set(read_emails(emails_path))
    if args.count < 1:
        print("--count must be at least 1", file=sys.stderr)
        return 2

    venv_python = GENERATOR_DIR / ".venv" / "Scripts" / "python.exe"
    generator_python = str(venv_python if venv_python.exists() else Path(sys.executable))
    cmd = [generator_python, str(cli_path), "generate", "--count", str(args.count)]
    print("Running:", " ".join(cmd))
    env = {
        **dict(os.environ),
        "HME_SUCCESS_DELAY_SECONDS": str(max(0, args.success_delay)),
        "HME_FAILURE_DELAY_SECONDS": str(max(0, args.failure_delay)),
    }
    cookie_file = Path(
        os.environ.get("HME_COOKIE_FILE", str(GENERATOR_DIR / "cookie.txt"))
    ).expanduser().resolve()
    if not args.no_cookie_refresh and env_flag("HME_AUTO_REFRESH_COOKIE", True):
        refresh_result = refresh_cookie_before_generate(
            generator_python=generator_python,
            cookie_file=cookie_file,
            wait_seconds=args.cookie_refresh_wait,
        )
        if refresh_result != 0:
            return refresh_result
    completed = subprocess.run(cmd, cwd=str(GENERATOR_DIR), check=False, env=env)
    if completed.returncode != 0:
        return completed.returncode

    after = read_emails(emails_path)
    new_emails = [email for email in after if email not in before]
    created_count = len(new_emails)
    if not new_emails:
        print("No new emails found in emails.txt. Importing all emails as fallback.")
        new_emails = after
    if not new_emails:
        print("No emails to import.", file=sys.stderr)
        return 1

    payload = post_json(
        args.api_url.rstrip("/") + "/api/aliases/import",
        admin_key,
        {"text": "\n".join(new_emails)},
    )
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    if created_count < args.count:
        print(
            f"Only {created_count}/{args.count} requested email(s) were created; "
            "the created addresses were imported."
        )
        return 1
    return 0 if payload.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
