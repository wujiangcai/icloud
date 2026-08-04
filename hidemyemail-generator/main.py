import asyncio
import base64
import datetime
import os
import re
from contextlib import nullcontext
from pathlib import Path
from typing import List, Optional, Union

from rich.console import Console
from rich.prompt import IntPrompt
from rich.table import Table
from rich.text import Text

from icloud import HideMyEmail


SUCCESS_DELAY_SECONDS = int(os.environ.get("HME_SUCCESS_DELAY_SECONDS", "100"))
FAILURE_DELAY_SECONDS = int(os.environ.get("HME_FAILURE_DELAY_SECONDS", "120"))
try:
    MAX_FAILURES = max(0, int(os.environ.get("HME_MAX_FAILURES", "0")))
except ValueError:
    MAX_FAILURES = 0
GENERATOR_DIR = Path(__file__).resolve().parent


def load_cookie_context(cookie_file: str | Path) -> tuple[str, str]:
    """Load a plain cookie, curl export, or captured cookie metadata file."""
    path = Path(cookie_file)
    if not path.exists():
        return "", ""

    content = "\n".join(
        line.strip()
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip()
        and not line.lstrip().startswith("//")
        and not line.lstrip().startswith("#")
    ).strip()
    if not content:
        return "", ""

    # Accept the escaping used by both PowerShell/curl and POSIX curl
    # exports. Raw EditThisCookie exports are handled unchanged.
    normalized = (
        content.replace("^\\^\"", '\"')
        .replace('^"', '"')
        .replace("^'", "'")
        .replace('\\"', '"')
    )
    maildomain_host = ""

    marker = re.search(
        r"(?m)^HIDEMYEMAIL_MAILDOMAIN_HOST=([A-Za-z0-9.-]+)\s*$", normalized
    )
    if marker:
        maildomain_host = marker.group(1)

    encoded = re.search(
        r"(?m)^HIDEMYEMAIL_COOKIE_BASE64=([A-Za-z0-9+/=]+)\s*$", normalized
    )
    if encoded:
        try:
            cookie = base64.b64decode(encoded.group(1)).decode("utf-8")
            return HideMyEmail.normalize_cookie(cookie), maildomain_host
        except Exception:
            pass

    # A captured request can reveal the account's current partition.
    shards = re.findall(
        r"https://p(\d+)-maildomainws\.icloud\.(com(?:\.cn)?)",
        normalized,
        re.IGNORECASE,
    )
    if shards:
        partition, suffix = shards[-1]
        maildomain_host = f"p{partition}-maildomainws.icloud.{suffix}"
    else:
        shard = re.search(
            r"https://(p\d+)-[^/\s'\"]+\.icloud\.com(?:\.cn)?",
            normalized,
            re.IGNORECASE,
        )
        if shard:
            suffix = "com.cn" if ".icloud.com.cn" in shard.group(0) else "com"
            maildomain_host = f"{shard.group(1)}-maildomainws.icloud.{suffix}"

    # Accept a copied curl command as well as a raw cookie line.
    cookie_matches = [
        match
        for match in re.finditer(
            r"(?:^|\s)(?:-b|--cookie)\s+(['\"])(.+?)\1(?=\s*(?:\\|&|$|-H|--header))",
            normalized,
            re.IGNORECASE | re.DOTALL,
        )
    ]
    if cookie_matches:
        # A DevTools export can contain many requests. Prefer the last
        # authenticated cookie block because Apple may rotate the web token
        # while the page is loading.
        cookie_match = max(
            enumerate(cookie_matches),
            key=lambda item: (
                sum(
                    name in item[1].group(2)
                    for name in (
                        "X-APPLE-WEBAUTH-TOKEN",
                        "X-APPLE-DS-WEB-SESSION-TOKEN",
                        "X-APPLE-WEBAUTH-USER",
                    )
                ),
                item[0],
            ),
        )[1]
        content = cookie_match.group(2)
    else:
        header_match = re.search(
            r"cookie\s*:\s*([^\r\n]+)", normalized, re.IGNORECASE
        )
        if header_match:
            content = header_match.group(1).strip().strip("'\"")

    return HideMyEmail.normalize_cookie(content), maildomain_host


def response_error(response: dict | None) -> str:
    if not response:
        return "空响应"
    error = response.get("error")
    if isinstance(error, dict):
        return str(
            error.get("errorMessage")
            or error.get("message")
            or response.get("reason")
            or "未知错误"
        )
    return str(response.get("reason") or error or "未知错误")


def is_session_error(message: str) -> bool:
    text = str(message or "").lower()
    return any(
        term in text
        for term in (
            "invalid global session",
            "invalid session",
            "unauthorized",
            "not authenticated",
            "authentication",
        )
    )


class RichHideMyEmail(HideMyEmail):
    _cookie_file = GENERATOR_DIR / "cookie.txt"
    _emails_file = GENERATOR_DIR / "emails.txt"

    def __init__(self):
        cookie_override = os.environ.get("HME_COOKIE_FILE", "").strip()
        emails_override = os.environ.get("HME_EMAILS_FILE", "").strip()
        cookie_file = Path(cookie_override or self._cookie_file).expanduser()
        emails_file = Path(emails_override or self._emails_file).expanduser()
        cookies, maildomain_host = load_cookie_context(cookie_file)
        super().__init__(cookies=cookies, maildomain_host=maildomain_host)
        self.cookie_file = cookie_file
        self.emails_file = emails_file
        # Disable Rich's legacy Windows renderer when the command is launched
        # from another process (for example generate_and_import.py).
        self.console = Console(
            force_terminal=False,
            no_color=True,
            legacy_windows=False,
        )
        self.table = Table()
        self.last_error = ""

        if not cookies:
            self.console.log(
                f'[bold yellow][WARN][/] No usable cookie found in "{cookie_file}". '
                "Generation may fail with an authentication error."
            )

    async def _generate_one(self) -> Union[str, None]:
        gen_res = await self.generate_email()
        if not gen_res or not gen_res.get("success"):
            self.last_error = response_error(gen_res)
            self.console.log(
                f"[bold red][ERR][/] - Failed to generate email. Reason: {self.last_error}"
            )
            return None

        result = gen_res.get("result") or {}
        email = result.get("hme")
        if not email:
            self.last_error = "iCloud response did not include an address"
            self.console.log(f"[bold red][ERR][/] - {self.last_error}")
            return None
        self.console.log(f'[50%] "{email}" - Successfully generated')

        reserve_res = await self.reserve_email(email)
        if not reserve_res or not reserve_res.get("success"):
            self.last_error = response_error(reserve_res)
            self.console.log(
                f'[bold red][ERR][/] "{email}" - Failed to reserve email. Reason: {self.last_error}'
            )
            return None

        self.console.log(f'[100%] "{email}" - Successfully reserved')
        return email

    async def generate(self, count: Optional[int]) -> List[str]:
        try:
            emails: List[str] = []
            self.last_error = ""
            self.console.rule()
            if count is None:
                count = int(
                    IntPrompt.ask(
                        Text.assemble(("How many iCloud emails you want to generate?")),
                        console=self.console,
                    )
                )
            if count < 1:
                self.console.log("[bold red][ERR][/] count must be at least 1")
                return emails

            self.console.log(f"Generating {count} email(s)...")
            self.console.log(
                f"Slow mode: wait {SUCCESS_DELAY_SECONDS}s after each success, "
                f"{FAILURE_DELAY_SECONDS}s after each failure."
            )
            self.console.rule()

            status_context = (
                self.console.status("[bold green]Generating iCloud email(s)...")
                if self.console.is_terminal
                else nullcontext()
            )
            with status_context:
                failures = 0
                while len(emails) < count:
                    email = await self._generate_one()
                    if email:
                        emails.append(email)
                        self.emails_file.parent.mkdir(parents=True, exist_ok=True)
                        with self.emails_file.open("a+", encoding="utf-8") as file:
                            file.write(email + os.linesep)
                        failures = 0
                        remaining = count - len(emails)
                        if remaining > 0 and SUCCESS_DELAY_SECONDS > 0:
                            self.console.log(
                                f"Created {len(emails)}/{count}. Waiting {SUCCESS_DELAY_SECONDS}s before next email..."
                            )
                            await asyncio.sleep(SUCCESS_DELAY_SECONDS)
                        continue

                    failures += 1
                    # Never retry an expired/invalid session forever.
                    if is_session_error(self.last_error):
                        self.console.log(
                            "[bold yellow][STOP][/] iCloud session is invalid or expired. "
                            "Please capture a fresh Hide My Email request into cookie.txt."
                        )
                        break
                    if MAX_FAILURES and failures >= MAX_FAILURES:
                        self.console.log(
                            f"[bold yellow][STOP][/] Reached the maximum of {MAX_FAILURES} failed attempts."
                        )
                        break
                    if FAILURE_DELAY_SECONDS > 0:
                        self.console.log(
                            f"Failed attempt #{failures}. Waiting {FAILURE_DELAY_SECONDS}s before retry..."
                        )
                        await asyncio.sleep(FAILURE_DELAY_SECONDS)

            if emails:
                self.console.rule()
                self.console.log(
                    f'[bold green]Emails have been saved into "{self.emails_file}"[/]'
                )
                self.console.log(
                    f"[bold green]All done![/] Successfully generated {len(emails)} email(s)"
                )
            return emails
        except KeyboardInterrupt:
            return []

    async def list(self, active: bool, search: str | None) -> bool:
        gen_res = await self.list_email()
        if not gen_res or not gen_res.get("success"):
            err_msg = response_error(gen_res)
            self.console.log(
                f"[bold red][ERR][/] - Failed to list emails. Reason: {err_msg}"
            )
            return False

        self.table.add_column("Label")
        self.table.add_column("Hide my email")
        self.table.add_column("Created Date Time")
        self.table.add_column("IsActive")

        for row in (gen_res.get("result") or {}).get("hmeEmails") or []:
            if row.get("isActive") != active:
                continue
            if search is not None and not re.search(search, row.get("label", "")):
                continue
            timestamp = row.get("createTimestamp") or 0
            created = datetime.datetime.fromtimestamp(timestamp / 1000)
            self.table.add_row(
                str(row.get("label", "")),
                str(row.get("hme", "")),
                str(created),
                str(row.get("isActive")),
            )
        self.console.print(self.table)
        return True


async def generate(count: Optional[int]) -> List[str]:
    async with RichHideMyEmail() as hme:
        return await hme.generate(count)


async def list(active: bool, search: str | None) -> bool:
    async with RichHideMyEmail() as hme:
        return await hme.list(active, search)


if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(generate(None))
    except KeyboardInterrupt:
        pass
