"""Small client for iCloud Hide My Email.

The iCloud web client uses a partitioned maildomain service (for example
``p188-maildomainws``).  Older versions of this project hard-coded an old
partition and old build numbers, which causes ``Invalid global session`` even
when the browser session is still valid.  This module validates the session
first and discovers the current partition when possible.
"""

from __future__ import annotations

import asyncio
import os
import re
import ssl
import uuid

import aiohttp
import certifi


REQUEST_TIMEOUT_SECONDS = int(os.environ.get("HME_REQUEST_TIMEOUT_SECONDS", "30"))
REQUEST_RETRIES = max(1, int(os.environ.get("HME_REQUEST_RETRIES", "2")))


def _is_limit_error(value: object) -> bool:
    text = str(value or "").lower()
    return any(
        marker in text
        for marker in (
            "rate limit",
            "too many request",
            "quota",
            "limit exceeded",
            "throttl",
            "429",
        )
    )


class HideMyEmail:
    REGION_CONFIG = {
        "global": {
            "maildomain_host": "p68-maildomainws.icloud.com",
            "setup_url": "https://setup.icloud.com/setup/ws/1/validate",
            "web_origin": "https://www.icloud.com",
            "accept_language": "en-US,en-GB;q=0.9,en;q=0.8",
            "lang_code": "en-us",
        },
        "china": {
            "maildomain_host": "p217-maildomainws.icloud.com.cn",
            "setup_url": "https://setup.icloud.com.cn/setup/ws/1/validate",
            "web_origin": "https://www.icloud.com.cn",
            "accept_language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
            "lang_code": "zh-cn",
        },
    }

    def __init__(
        self,
        cookies: str = "",
        region: str = "global",
        maildomain_host: str = "",
    ):
        if region not in self.REGION_CONFIG:
            raise ValueError(f'Unsupported iCloud region "{region}"')

        config = self.REGION_CONFIG[region]
        self.region = region
        self.web_origin = config["web_origin"]
        self.lang_code = config["lang_code"]
        self.setup_url = config["setup_url"]
        self.cookies = cookies
        self._maildomain_host_override = self._clean_host(maildomain_host)
        self._context_error = ""
        self._context_resolved = False

        # The old project used 2536Project32/2536B20 and an empty clientId.
        # Current iCloud web traffic uses the 2626 build family.  Keep these
        # configurable so a future web build can be selected without a code
        # change.
        build_from_env = os.environ.get("HME_CLIENT_BUILD_NUMBER")
        build = build_from_env or "2626Build21"
        mastering_from_env = os.environ.get("HME_CLIENT_MASTERING_NUMBER")
        mastering = mastering_from_env or build
        self._build_from_env = bool(build_from_env)
        self._mastering_from_env = bool(mastering_from_env)
        self.params = {
            "clientBuildNumber": build,
            "clientMasteringNumber": mastering,
            "clientId": str(uuid.uuid4()),
            "dsid": "",
        }

        self._set_maildomain_host(
            self._maildomain_host_override or config["maildomain_host"]
        )

    @staticmethod
    def _clean_host(value: str) -> str:
        host = str(value or "").strip()
        host = re.sub(r"^https?://", "", host, flags=re.IGNORECASE)
        return host.split("/", 1)[0]

    @staticmethod
    def _cookie_value(cookie: str, name: str) -> str:
        """Read one value from a semicolon-separated browser cookie string."""
        wanted = name.lower()
        for part in str(cookie or "").split(";"):
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            if key.strip().lower() != wanted:
                continue
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            return value
        return ""

    @classmethod
    def normalize_cookie(cls, cookies: str) -> str:
        """Normalize EditThisCookie/curl exports before sending a Cookie header."""
        raw = str(cookies or "").strip()
        if ";" in raw and raw.lower().startswith("semicolon separated"):
            raw = raw.split(";", 1)[1].strip()

        parts: list[str] = []
        for part in raw.split(";"):
            part = part.strip()
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            key = key.strip()
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            if key:
                parts.append(f"{key}={value}")
        return "; ".join(parts)

    @classmethod
    def browser_headers(cls, region: str, cookies: str = "") -> dict[str, str]:
        config = cls.REGION_CONFIG[region]
        return {
            "Connection": "keep-alive",
            "Pragma": "no-cache",
            "Cache-Control": "no-cache",
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/151.0.0.0 Safari/537.36 Edg/151.0.0.0"
            ),
            "Content-Type": "text/plain;charset=UTF-8",
            "Accept": "*/*",
            "Origin": config["web_origin"],
            "Referer": f"{config['web_origin']}/",
            "Accept-Language": config["accept_language"],
            "sec-ch-ua": '"Not=A?Brand";v="99", "Microsoft Edge";v="151", "Chromium";v="151"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "Cookie": cls.normalize_cookie(cookies),
        }

    def _set_maildomain_host(self, host: str) -> None:
        host = self._clean_host(host)
        self.maildomain_host = host
        self.base_url_v1 = f"https://{host}/v1/hme"
        self.base_url_v2 = f"https://{host}/v2/hme"

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(
            ssl_context=ssl.create_default_context(cafile=certifi.where())
        )
        self.s = aiohttp.ClientSession(
            headers=self.browser_headers(self.region, self.__cookies),
            timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS),
            connector=connector,
        )
        await self._resolve_session_context()
        return self

    async def __aexit__(self, exc_t, exc_v, exc_tb):
        if getattr(self, "s", None) is not None:
            await self.s.close()

    @property
    def cookies(self) -> str:
        return self.__cookies

    @cookies.setter
    def cookies(self, cookies: str):
        self.__cookies = self.normalize_cookie(cookies)

    async def _discover_web_build(self) -> None:
        """Read the build embedded in the current iCloud shell page.

        Apple changes the web build frequently.  The environment variables
        remain an escape hatch for testing, but normal runs should follow the
        build advertised by the page instead of using a stale hard-coded one.
        """
        if self._build_from_env and self._mastering_from_env:
            return
        try:
            async with self.s.get(
                f"{self.web_origin}/settings/",
                headers={"Accept": "text/html,application/xhtml+xml"},
            ) as resp:
                if resp.status != 200:
                    return
                html = await resp.text(errors="replace")
        except Exception:
            return

        if not self._build_from_env:
            match = re.search(
                r'data-cw-private-build-number=["\']([^"\']+)', html
            )
            if match:
                self.params["clientBuildNumber"] = match.group(1)
        if not self._mastering_from_env:
            match = re.search(
                r'data-cw-private-mastering-number=["\']([^"\']+)', html
            )
            self.params["clientMasteringNumber"] = (
                match.group(1)
                if match
                else self.params["clientBuildNumber"]
            )

    async def _resolve_session_context(self) -> None:
        """Discover DSID/partition from the authenticated iCloud session."""
        if self._context_resolved:
            return
        self._context_resolved = True

        await self._discover_web_build()

        user_cookie = self._cookie_value(self.__cookies, "X-APPLE-WEBAUTH-USER")
        dsid_match = re.search(r"(?:^|:)d=(\d+)(?:$|\s)", user_cookie)
        if dsid_match:
            self.params["dsid"] = dsid_match.group(1)

        # A captured request may include the exact partition in a marker.  If
        # so, it is safer than guessing; otherwise ask setup for userPartition.
        if self._maildomain_host_override:
            return

        query = {
            "clientBuildNumber": self.params["clientBuildNumber"],
            "clientMasteringNumber": self.params["clientMasteringNumber"],
            "clientId": self.params["clientId"],
            "requestId": str(uuid.uuid4()),
        }
        attempts = (("POST", query), ("GET", query))
        last_error = ""
        for method, params in attempts:
            try:
                async with self.s.request(method, self.setup_url, params=params, data=b"") as resp:
                    data = await resp.json(content_type=None)
            except Exception as exc:
                last_error = str(exc)
                continue

            if (
                resp.status != 200
                or not isinstance(data, dict)
                or not data.get("success", True)
            ):
                raw_error = data.get("reason") or data.get("error")
                if raw_error == 1:
                    raw_error = "Apple rejected the iCloud session (error=1)"
                last_error = str(raw_error or f"HTTP {resp.status}")
                # Do not fall back from POST to GET after Apple has applied a
                # quota/rate limit; another request only extends the block.
                if resp.status == 429 or _is_limit_error(last_error):
                    self._context_error = last_error
                    return
                continue

            ds_info = data.get("dsInfo") or {}
            if ds_info.get("dsid") is not None:
                self.params["dsid"] = str(ds_info["dsid"])

            host = ""
            webservices = data.get("webservices") or {}
            maildomain = webservices.get("maildomainws") or {}
            if isinstance(maildomain, dict):
                host = self._clean_host(maildomain.get("url", ""))
            partition = data.get("userPartition")
            if not host and partition:
                suffix = "com.cn" if self.region == "china" else "com"
                host = f"p{partition}-maildomainws.icloud.{suffix}"
            if host:
                self._set_maildomain_host(host)
            return

        self._context_error = last_error or "Unable to validate iCloud session"

    async def _request_json(self, method: str, url: str, **kwargs) -> dict:
        method = method.upper()
        # POST creates or reserves an alias.  Retrying it after a timeout can
        # create a second alias because the server may have committed the
        # first request before the client lost its connection.
        attempts = 1 if method in {"POST", "PUT", "PATCH", "DELETE"} else REQUEST_RETRIES
        for attempt in range(attempts):
            try:
                async with self.s.request(method, url, **kwargs) as resp:
                    data = await resp.json(content_type=None)
                    if isinstance(data, dict):
                        if resp.status >= 400 and not data.get("reason"):
                            data = {**data, "reason": f"HTTP {resp.status}"}
                        # Apple rate-limit responses are terminal for this
                        # operation; never retry them as if they were transient.
                        if resp.status == 429 or _is_limit_error(data.get("reason") or data.get("error")):
                            return data
                        return data
                    return {"error": 1, "reason": f"Unexpected response ({resp.status})"}
            except asyncio.TimeoutError:
                if attempt == attempts - 1:
                    return {"error": 1, "reason": f"Request timed out after {REQUEST_TIMEOUT_SECONDS}s"}
            except Exception as exc:
                if attempt == attempts - 1:
                    return {"error": 1, "reason": str(exc)}
        return {"error": 1, "reason": "Request failed"}

    async def generate_email(self) -> dict:
        await self._resolve_session_context()
        return await self._request_json(
            "POST",
            f"{self.base_url_v1}/generate",
            params=self.params,
            json={"langCode": self.lang_code},
        )

    async def reserve_email(
        self,
        email: str,
        label: str | None = None,
        note: str | None = None,
    ) -> dict:
        await self._resolve_session_context()
        payload = {
            "hme": email,
            "label": label or "rtuna's gen",
            "note": note or "Generated by rtuna's iCloud email generator",
        }
        return await self._request_json(
            "POST", f"{self.base_url_v1}/reserve", params=self.params, json=payload
        )

    async def list_email(self) -> dict:
        await self._resolve_session_context()
        return await self._request_json(
            "GET", f"{self.base_url_v2}/list", params=self.params
        )
