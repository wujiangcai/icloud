import asyncio
import aiohttp
import json
import os
import ssl
import certifi
import uuid


REQUEST_TIMEOUT_SECONDS = 30
REQUEST_RETRIES = 2


def _decode_json_response(text: str) -> dict:
    """Decode normal JSON and the anti-XSSI-wrapped JSON used by some Apple edges."""
    payload = str(text or "").lstrip("\ufeff\r\n\t ")
    for prefix in (")]}'", "while(1);", "for(;;);"):
        if payload.startswith(prefix):
            payload = payload[len(prefix):].lstrip("\r\n\t ")
            break
    try:
        value = json.loads(payload)
        return value if isinstance(value, dict) else {"result": value}
    except json.JSONDecodeError as first_error:
        # A proxy may prepend a short JavaScript guard. Recover only when a
        # complete JSON object/array follows; never attempt to evaluate code.
        starts = [index for index in (payload.find("{"), payload.find("[")) if index >= 0]
        if starts:
            value, end = json.JSONDecoder().raw_decode(payload[min(starts):])
            trailing = payload[min(starts) + end:].strip()
            if not trailing or trailing == ";":
                return value if isinstance(value, dict) else {"result": value}
        raise first_error


class HideMyEmail:
    REGION_CONFIG = {
        "global": {
            "maildomain_host": "p68-maildomainws.icloud.com",
            "web_origin": "https://www.icloud.com",
        },
        "china": {
            "maildomain_host": "p217-maildomainws.icloud.com.cn",
            "web_origin": "https://www.icloud.com.cn",
        },
    }
    params = {
        # Keep these overridable because Apple changes the web build periodically.
        "clientBuildNumber": os.environ.get("HIDEMYEMAIL_CLIENT_BUILD_NUMBER", "2628Build27"),
        "clientMasteringNumber": os.environ.get(
            "HIDEMYEMAIL_CLIENT_MASTERING_NUMBER",
            os.environ.get("HIDEMYEMAIL_CLIENT_BUILD_NUMBER", "2628Build27"),
        ),
        "clientId": "",
        "dsid": "",  # Directory Services Identifier (DSID) is a method of identifying AppleID accounts
    }

    def __init__(
        self,
        cookies: str = "",
        region: str = "global",
        maildomain_host: str = "",
        dsid: str = "",
        client_id: str = "",
        client_build_number: str = "",
        client_mastering_number: str = "",
    ):
        """Initializes the HideMyEmail class.

        Args:
            cookies (str) Cookie string to be used with requests. Required for authorization.
            region (str)  iCloud region to target. Either "global" or "china".
        """
        if region not in self.REGION_CONFIG:
            raise ValueError(f'Unsupported iCloud region "{region}"')

        config = self.REGION_CONFIG[region]
        resolved_maildomain_host = maildomain_host or config["maildomain_host"]
        self.base_url_v1 = f"https://{resolved_maildomain_host}/v1/hme"
        self.base_url_v2 = f"https://{resolved_maildomain_host}/v2/hme"
        self.web_origin = config["web_origin"]
        self.cookies = cookies
        self.params = dict(type(self).params)
        self.params["clientId"] = str(client_id or uuid.uuid4())
        self.params["dsid"] = str(dsid or "")
        if client_build_number:
            self.params["clientBuildNumber"] = str(client_build_number)
        if client_mastering_number:
            self.params["clientMasteringNumber"] = str(client_mastering_number)

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(
            ssl_context=ssl.create_default_context(cafile=certifi.where())
        )
        self.s = aiohttp.ClientSession(
            headers={
                "Connection": "keep-alive",
                "Pragma": "no-cache",
                "Cache-Control": "no-cache",
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
                "Content-Type": "text/plain",
                "Accept": "*/*",
                "Sec-GPC": "1",
                "Origin": self.web_origin,
                "Sec-Fetch-Site": "same-site",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Dest": "empty",
                "Referer": f"{self.web_origin}/",
                "Accept-Language": "en-US,en-GB;q=0.9,en;q=0.8,cs;q=0.7",
                "sec-ch-ua": '"Brave";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"macOS"',
                "Cookie": self.__cookies.strip(),
            },
            timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS),
            connector=connector,
        )

        return self

    async def __aexit__(self, exc_t, exc_v, exc_tb):
        await self.s.close()

    @property
    def cookies(self) -> str:
        return self.__cookies

    @cookies.setter
    def cookies(self, cookies: str):
        # remove new lines/whitespace for security reasons
        self.__cookies = cookies.strip()

    async def _request_json(self, method: str, url: str, **kwargs) -> dict:
        response_status = 0
        response_size = 0
        for attempt in range(REQUEST_RETRIES):
            try:
                async with self.s.request(method, url, **kwargs) as resp:
                    response_status = resp.status
                    body = await resp.text()
                    response_size = len(body)
                    return _decode_json_response(body)
            except asyncio.TimeoutError:
                if attempt == REQUEST_RETRIES - 1:
                    return {
                        "error": 1,
                        "reason": f"Request timed out after {REQUEST_TIMEOUT_SECONDS}s",
                    }
            except json.JSONDecodeError as exc:
                if attempt == REQUEST_RETRIES - 1:
                    return {
                        "error": 1,
                        "reason": (
                            "Apple returned invalid JSON "
                            f"(HTTP {response_status}, {response_size} bytes, response position {exc.pos})"
                        ),
                    }
            except Exception as e:
                if attempt == REQUEST_RETRIES - 1:
                    return {"error": 1, "reason": str(e)}

        return {"error": 1, "reason": "Request failed"}

    async def generate_email(self) -> dict:
        """Generates an email"""
        return await self._request_json(
            "POST",
            f"{self.base_url_v1}/generate",
            params=self.params,
            json={"langCode": "en-us"},
        )

    async def reserve_email(self, email: str, label: str, note: str) -> dict:
        """Reserves an email and registers it for forwarding"""
        payload = {
            "hme": email,
            "label": label,
            "note": note,
        }
        return await self._request_json(
            "POST", f"{self.base_url_v1}/reserve", params=self.params, json=payload
        )

    async def list_email(self) -> dict:
        """List all HME"""
        return await self._request_json(
            "GET", f"{self.base_url_v2}/list", params=self.params
        )
