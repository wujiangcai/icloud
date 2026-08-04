#!/usr/bin/env python3
"""Refresh the iCloud web cookie used by the Hide My Email client.

The browser's encrypted cookie database is not portable and recent Edge
versions may reject direct database readers.  This helper therefore uses a
real browser profile instead: on the first run the user signs in once, and
subsequent runs reuse that profile and write a fresh, validated Cookie header
to ``cookie.txt``.

The script deliberately never prints cookie names/values or the generated
Cookie header.  A failed refresh never overwrites an existing cookie file.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


GENERATOR_DIR = Path(__file__).resolve().parent
DEFAULT_COOKIE_FILE = GENERATOR_DIR / "cookie.txt"
DEFAULT_BROWSER_PROFILE = GENERATOR_DIR / "data" / "browser-profile"
DEFAULT_PAGE_URL = "https://www.icloud.com/icloudplus/"
AUTH_COOKIE_NAMES = {
    "x-apple-webauth-token",
    "x-apple-ds-web-session-token",
    "x-apple-webauth-login",
    "x-apple-webauth-validate",
}


def env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def browser_origin(region: str) -> str:
    return "https://www.icloud.com.cn" if region == "china" else "https://www.icloud.com"


def login_url(region: str, page_url: str) -> str:
    if page_url.strip() and not (
        region == "china" and page_url.strip() == DEFAULT_PAGE_URL
    ):
        return page_url.strip()
    return f"{browser_origin(region)}/icloudplus/"


def normalize_browser_name(value: str) -> str:
    value = (value or "msedge").strip().lower()
    aliases = {
        "edge": "msedge",
        "microsoft-edge": "msedge",
        "google-chrome": "chrome",
    }
    value = aliases.get(value, value)
    if value not in {"msedge", "chrome", "chromium"}:
        raise ValueError("browser must be msedge, chrome, or chromium")
    return value


def default_profile_path(browser: str) -> Path:
    """Return the dedicated profile used by the automation.

    A dedicated profile avoids changing or locking the user's normal Edge
    profile.  ``--use-existing-profile`` is available for users who explicitly
    want to open the normal profile after closing the browser.
    """
    explicit = os.environ.get("HME_BROWSER_PROFILE", "").strip()
    if explicit:
        return Path(explicit).expanduser()
    return DEFAULT_BROWSER_PROFILE


def existing_browser_user_data(browser: str) -> Path:
    local_app_data = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local"))
    if browser == "chrome":
        return local_app_data / "Google" / "Chrome" / "User Data"
    return local_app_data / "Microsoft" / "Edge" / "User Data"


def is_icloud_domain(domain: str) -> bool:
    value = str(domain or "").lower().lstrip(".")
    return value == "icloud.com" or value.endswith(".icloud.com") or value == "icloud.com.cn" or value.endswith(".icloud.com.cn")


def cookie_header_from_items(items: list[dict[str, Any]]) -> str:
    """Build a browser Cookie header without exposing values in logs."""
    values: dict[str, str] = {}
    # context.cookies(url) returns cookies applicable to that URL.  Keep the
    # first value for a name so a host-only cookie from www.icloud.com wins
    # over an unrelated cookie with the same name from another subdomain.
    for item in items:
        name = str(item.get("name") or "").strip()
        if not name or name.lower() in {"__host-invalid", "__secure-invalid"}:
            continue
        if not is_icloud_domain(str(item.get("domain") or "")):
            continue
        if name not in values:
            values[name] = str(item.get("value") or "")

    return "; ".join(f"{name}={value}" for name, value in values.items() if value != "")


def auth_cookie_count(cookie_header: str) -> int:
    found: set[str] = set()
    for part in cookie_header.split(";"):
        if "=" not in part:
            continue
        name = part.split("=", 1)[0].strip().lower()
        if name in AUTH_COOKIE_NAMES:
            found.add(name)
    return len(found)


def cookie_fingerprint(cookie_header: str) -> str:
    """Return a non-secret change detector for the authentication cookies."""
    parts: list[str] = []
    for part in cookie_header.split(";"):
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        if name.strip().lower() in AUTH_COOKIE_NAMES:
            parts.append(f"{name.strip().lower()}={value.strip()}")
    digest = hashlib.sha256("|".join(sorted(parts)).encode("utf-8")).hexdigest()
    return digest if parts else ""


async def validate_cookie(cookie_header: str, region: str) -> dict[str, str | bool]:
    """Validate the cookie through Apple's setup session endpoint."""
    # Import lazily so ``refresh_cookie.py --help`` remains useful even when
    # the generator's runtime dependencies have not been installed yet.
    sys.path.insert(0, str(GENERATOR_DIR))
    try:
        from icloud import HideMyEmail
    except Exception as exc:  # pragma: no cover - installation error path
        return {"valid": False, "error": f"cannot import generator client: {exc}"}

    try:
        client = HideMyEmail(cookies=cookie_header, region=region)
        async with client:
            context_error = str(getattr(client, "_context_error", "") or "")
            if context_error:
                return {"valid": False, "error": context_error}
            host = str(getattr(client, "maildomain_host", "") or "")
            if "maildomainws.icloud." not in host:
                return {"valid": False, "error": "Apple did not return a maildomain service"}
            return {
                "valid": True,
                "error": "",
                "maildomain_host": host,
            }
    except Exception as exc:
        return {"valid": False, "error": str(exc)}


def write_cookie_file(
    path: Path,
    cookie_header: str,
    maildomain_host: str = "",
) -> None:
    """Atomically write the validated cookie in the loader's safe format."""
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = base64.b64encode(cookie_header.encode("utf-8")).decode("ascii")
    lines = [
        "# Generated by refresh_cookie.py. Do not share this file.",
        f"HIDEMYEMAIL_COOKIE_BASE64={encoded}",
    ]
    if maildomain_host:
        lines.append(f"HIDEMYEMAIL_MAILDOMAIN_HOST={maildomain_host}")
    lines.append("")

    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write("\n".join(lines))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except Exception:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise


def import_playwright():
    try:
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except Exception as exc:  # pragma: no cover - installation error path
        raise RuntimeError(
            "Playwright is not installed. Run: "
            "hidemyemail-generator\\.venv\\Scripts\\python.exe -m pip install -r requirements.txt"
        ) from exc
    return sync_playwright, PlaywrightTimeoutError


def collect_context_cookies(context: Any, urls: list[str]) -> str:
    items: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for url in urls:
        try:
            current = context.cookies(url)
        except Exception:
            continue
        for item in current:
            key = (
                str(item.get("name") or ""),
                str(item.get("domain") or ""),
                str(item.get("path") or ""),
            )
            if key not in seen:
                seen.add(key)
                items.append(item)
    return cookie_header_from_items(items)


def try_browser_cookie_database(browser: str) -> str:
    """Best-effort extraction from the installed browser cookie database.

    Windows may require an elevated process for Edge's current App-Bound
    Encryption.  Failure is intentionally silent here; the persistent
    Playwright profile below is the reliable fallback and does not need admin
    access.
    """
    try:
        import browser_cookie3
    except Exception:
        return ""

    loader_name = "edge" if browser == "msedge" else browser
    loader = getattr(browser_cookie3, loader_name, None)
    if loader is None:
        return ""
    try:
        jar = loader(domain_name="icloud.com")
    except Exception:
        return ""

    items: list[dict[str, Any]] = []
    try:
        for item in jar:
            items.append(
                {
                    "name": getattr(item, "name", ""),
                    "value": getattr(item, "value", ""),
                    "domain": getattr(item, "domain", ""),
                    "path": getattr(item, "path", "/"),
                }
            )
    except Exception:
        return ""
    return cookie_header_from_items(items)


def launch_browser_context(
    playwright: Any,
    *,
    browser: str,
    profile: Path,
    profile_directory: str,
    headless: bool,
) -> Any:
    browser_type = playwright.chromium
    kwargs: dict[str, Any] = {
        "user_data_dir": str(profile),
        "headless": headless,
        "accept_downloads": False,
        "viewport": {"width": 1440, "height": 1000},
    }
    if browser == "msedge":
        kwargs["channel"] = "msedge"
    elif browser == "chrome":
        kwargs["channel"] = "chrome"
    else:
        kwargs["channel"] = "chromium"
    if profile_directory:
        kwargs["args"] = [f"--profile-directory={profile_directory}"]
    return browser_type.launch_persistent_context(**kwargs)


def refresh_cookie(args: argparse.Namespace) -> int:
    sync_playwright, PlaywrightTimeoutError = import_playwright()
    browser = normalize_browser_name(args.browser)
    cookie_file = Path(args.cookie_file).expanduser()
    region = args.region
    page_url = login_url(region, args.page_url)

    profile = Path(args.profile).expanduser() if args.profile else default_profile_path(browser)
    if args.use_existing_profile:
        profile = existing_browser_user_data(browser)
        if not args.profile_directory:
            args.profile_directory = os.environ.get("HME_BROWSER_PROFILE_DIRECTORY", "Default")
    profile = profile.resolve()
    if profile == cookie_file.resolve():
        raise RuntimeError("browser profile and cookie file cannot be the same path")

    print(f"[cookie-refresh] browser={browser}; profile={profile}")
    print(f"[cookie-refresh] opening {page_url}")
    if args.use_existing_profile:
        print("[cookie-refresh] using the existing browser profile; close that browser first if launch fails")
    else:
        print("[cookie-refresh] dedicated profile: sign in once here if this is the first run")

    # This can immediately reuse the normal logged-in browser without opening
    # another window when the OS allows the cookie database to be decrypted.
    # Edge commonly rejects this call unless the process is elevated, so do
    # not treat failure as a fatal condition.
    browser_cookie = try_browser_cookie_database(browser)
    if auth_cookie_count(browser_cookie) > 0:
        validation = asyncio.run(validate_cookie(browser_cookie, region))
        if bool(validation.get("valid")):
            host = str(validation.get("maildomain_host") or "")
            write_cookie_file(cookie_file, browser_cookie, host)
            print(
                "[cookie-refresh] success: reused the logged-in browser cookie "
                f"and updated {cookie_file} (auth cookies found: {auth_cookie_count(browser_cookie)})"
            )
            return 0
        print("[cookie-refresh] browser cookie was found but did not validate; using persistent profile")
    else:
        print("[cookie-refresh] direct browser-cookie access unavailable; using persistent profile")

    profile.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + max(0, args.wait_seconds)
    last_fingerprint = ""
    last_validation: dict[str, str | bool] | None = None
    login_hint_printed = False
    context = None
    try:
        with sync_playwright() as playwright:
            try:
                context = launch_browser_context(
                    playwright,
                    browser=browser,
                    profile=profile,
                    profile_directory=args.profile_directory,
                    headless=args.headless,
                )
            except Exception as exc:
                if args.use_existing_profile:
                    raise RuntimeError(
                        "无法打开现有浏览器配置，通常是 Edge/Chrome 仍在使用该配置；"
                        "请先完全退出浏览器，或不使用 --use-existing-profile 改用独立 profile。"
                    ) from exc
                raise RuntimeError(f"无法启动浏览器：{exc}") from exc

            page = context.pages[0] if context.pages else context.new_page()
            page.set_default_timeout(8_000)
            try:
                page.goto(page_url, wait_until="domcontentloaded", timeout=20_000)
            except PlaywrightTimeoutError:
                # iCloud can keep subresources open; cookies may already be
                # usable after DOMContentLoaded, so continue polling.
                print("[cookie-refresh] page load is still settling; checking session cookies")
            except Exception as exc:
                print(f"[cookie-refresh] page navigation note: {exc}")

            urls = [page_url, f"{browser_origin(region)}/settings/"]
            while True:
                cookie_header = collect_context_cookies(context, urls)
                current_fingerprint = cookie_fingerprint(cookie_header)
                if auth_cookie_count(cookie_header) > 0 and current_fingerprint != last_fingerprint:
                    last_fingerprint = current_fingerprint
                    last_validation = asyncio.run(validate_cookie(cookie_header, region))
                    if bool(last_validation.get("valid")):
                        host = str(last_validation.get("maildomain_host") or "")
                        write_cookie_file(cookie_file, cookie_header, host)
                        print(
                            "[cookie-refresh] success: validated the iCloud session "
                            f"and updated {cookie_file} (auth cookies found: {auth_cookie_count(cookie_header)})"
                        )
                        return 0
                    error = str(last_validation.get("error") or "validation failed")
                    print(f"[cookie-refresh] session validation failed: {error}")

                if not login_hint_printed:
                    if auth_cookie_count(cookie_header) == 0:
                        print(
                            "[cookie-refresh] no authenticated iCloud cookies found. "
                            "Complete login/verification in the opened browser window."
                        )
                    elif last_validation and not bool(last_validation.get("valid")):
                        print(
                            "[cookie-refresh] the browser session is not accepted by Hide My Email. "
                            "Sign in again in the opened window, then wait for a retry."
                        )
                    login_hint_printed = True

                if time.monotonic() >= deadline:
                    break
                try:
                    page.wait_for_timeout(1_000)
                except Exception:
                    time.sleep(1)

        # Context is closed by the Playwright manager here.
    finally:
        if context is not None:
            try:
                context.close()
            except Exception:
                pass

    if last_validation and not bool(last_validation.get("valid")):
        print(
            "[cookie-refresh] failed: iCloud session could not be validated; "
            "the previous cookie.txt was kept unchanged."
        )
    else:
        print(
            "[cookie-refresh] failed: no valid iCloud login was found; "
            "the previous cookie.txt was kept unchanged."
        )
    return 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Refresh and validate the iCloud web cookie using a persistent browser profile."
    )
    parser.add_argument(
        "--cookie-file",
        default=os.environ.get("HME_COOKIE_FILE", str(DEFAULT_COOKIE_FILE)),
        help="Output cookie file (default: hidemyemail-generator/cookie.txt)",
    )
    parser.add_argument(
        "--profile",
        default=os.environ.get("HME_BROWSER_PROFILE", ""),
        help="Persistent Playwright profile directory",
    )
    parser.add_argument(
        "--browser",
        default=os.environ.get("HME_BROWSER", "msedge"),
        choices=("msedge", "edge", "chrome", "chromium"),
        help="Browser channel to launch",
    )
    parser.add_argument(
        "--profile-directory",
        default=os.environ.get("HME_BROWSER_PROFILE_DIRECTORY", ""),
        help="Profile name when --use-existing-profile is used (usually Default)",
    )
    parser.add_argument(
        "--use-existing-profile",
        action="store_true",
        default=env_bool("HME_USE_EXISTING_BROWSER_PROFILE"),
        help="Use the normal Edge/Chrome User Data directory instead of a dedicated profile",
    )
    parser.add_argument(
        "--region",
        choices=("global", "china"),
        default=os.environ.get("HME_REGION", "global"),
    )
    parser.add_argument(
        "--page-url",
        default=os.environ.get("HME_COOKIE_REFRESH_URL", DEFAULT_PAGE_URL),
        help="iCloud page to open before reading the session",
    )
    parser.add_argument(
        "--wait-seconds",
        type=int,
        default=int(os.environ.get("HME_COOKIE_REFRESH_WAIT_SECONDS", "90")),
        help="How long to wait for a first login or re-authentication",
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        default=env_bool("HME_COOKIE_REFRESH_HEADLESS"),
        help="Do not open a visible browser window",
    )
    parser.add_argument(
        "--headed",
        action="store_true",
        help="Force a visible browser window",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.headed:
        args.headless = False
    try:
        return refresh_cookie(args)
    except KeyboardInterrupt:
        print("[cookie-refresh] cancelled; existing cookie.txt was kept unchanged")
        return 130
    except Exception as exc:
        print(f"[cookie-refresh] error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
