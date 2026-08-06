"""JSON bridge between the platform and the vendored Hide My Email client."""

import asyncio
import base64
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENDOR_SRC = ROOT / "vendor" / "hidemyemail-generator" / "src"
sys.path.insert(0, str(VENDOR_SRC))

from hidemyemail_generator.hidemyemail import HideMyEmail  # noqa: E402
from hidemyemail_generator.main import fetch_account_info_from_cookie  # noqa: E402


MAILDOMAIN_HOST_RE = re.compile(
    r"(?i)(?<![a-z0-9-])(p\d+-maildomainws\.icloud\.com(?:\.cn)?)(?![a-z0-9.-])"
)
MAILDOMAIN_HOST_FULL_RE = re.compile(
    r"(?i)^p\d+-maildomainws\.icloud\.com(?:\.cn)?$"
)


def _normalize_maildomain_host(value: str) -> str:
    host = str(value or "").strip().strip("'\"").lower()
    if host.startswith("https://"):
        host = host[8:]
    elif host.startswith("http://"):
        host = host[7:]
    host = host.split("/", 1)[0].split("?", 1)[0].strip()
    return host if MAILDOMAIN_HOST_FULL_RE.fullmatch(host) else ""


def _region_for_maildomain_host(host: str) -> str:
    return "china" if str(host or "").lower().endswith(".icloud.com.cn") else "global"


def _host_for_partition(user_partition: str, region: str) -> str:
    partition = re.fullmatch(r"\d+", str(user_partition or "").strip())
    if not partition or region not in {"global", "china"}:
        return ""
    suffix = "com.cn" if region == "china" else "com"
    return f"p{partition.group(0)}-maildomainws.icloud.{suffix}"


def _host_matches_region(host: str, region: str) -> bool:
    return bool(host and region in {"global", "china"} and _region_for_maildomain_host(host) == region)


def _normalize_curl_text(text: str) -> str:
    return re.sub(r"(?:\\|\^)\s*\r?\n", " ", text).replace("^\"", '\"').replace("^'", "'")


def _curl_blocks(normalized: str) -> list[str]:
    blocks = re.split(r"(?i)(?=\bcurl(?:\.exe)?\s)", normalized)
    return [block for block in blocks if block.strip()] or [normalized]


def _read_shell_argument(text: str, start: int) -> str:
    value = text[start:].lstrip()
    if value.startswith("^") and len(value) > 1 and value[1] in "'\"":
        value = value[1:]
    if not value:
        return ""
    quote = value[0] if value[0] in "'\"" else ""
    if not quote:
        return value.split(None, 1)[0].rstrip(";")
    escaped = False
    for index in range(1, len(value)):
        char = value[index]
        if quote == '"' and char == "\\" and not escaped:
            escaped = True
            continue
        if char == quote and not escaped:
            raw = value[1:index]
            return raw.replace('^\\^"', '"').replace('\\"', '"').replace('^"', '"').strip()
        escaped = False
    return ""


def _extract_cookie_from_block(block: str) -> str:
    option = re.search(r"(?i)(?:^|\s)(?:-b|--cookie)\s+", block)
    if option:
        cookie = _read_shell_argument(block, option.end())
        if cookie:
            return cookie
    header = re.search(
        r"(?is)(?:^|\s)(?:-H|--header)\s+(['\"])\s*cookie\s*:\s*(.*?)\1",
        block,
    )
    if header:
        return header.group(2).strip()
    header = re.search(r"(?im)^\s*cookie\s*:\s*(.+?)\s*$", block)
    return header.group(1).strip().strip("'\"") if header else ""


def _extract_maildomain_host(text: str) -> str:
    explicit = re.search(
        r"(?im)^\s*HIDEMYEMAIL_MAILDOMAIN_HOST\s*=\s*([^\s#]+)", text
    )
    if explicit:
        host = _normalize_maildomain_host(explicit.group(1))
        if host:
            return host
    matches = [_normalize_maildomain_host(match.group(1)) for match in MAILDOMAIN_HOST_RE.finditer(text)]
    return next((host for host in matches if host), "")


def _select_cookie_and_host(text: str, normalized: str) -> tuple[str, str]:
    preferred: list[tuple[str, str]] = []
    fallback: list[tuple[str, str]] = []
    for block in _curl_blocks(normalized):
        cookie = _extract_cookie_from_block(block)
        if not cookie:
            continue
        host = _extract_maildomain_host(block)
        item = (cookie, host)
        if host:
            preferred.append(item)
        else:
            fallback.append(item)
    if preferred:
        return preferred[-1]
    if fallback:
        return fallback[0]
    return "", ""


def _extract_request_params(content: str, preferred_host: str = "") -> dict[str, str]:
    normalized = _normalize_curl_text(str(content or ""))
    blocks = _curl_blocks(normalized)
    preferred_blocks = [
        block
        for block in blocks
        if preferred_host and preferred_host in block and re.search(r"(?i)/(?:v[12]/)?hme/", block)
    ]
    candidates = preferred_blocks or blocks
    keys = ("clientBuildNumber", "clientMasteringNumber", "clientId", "requestId", "dsid")
    result: dict[str, str] = {}
    for block in reversed(candidates):
        for key in keys:
            if key in result:
                continue
            match = re.search(
                rf"(?i)(?:[?&\s\"']|\b){re.escape(key)}(?:=|\"\s*:\s*\")([A-Za-z0-9_.:-]+)",
                block,
            )
            if match:
                result[key] = match.group(1)
    return result


def parse_cookie_context(content: str, requested_region: str = "auto") -> tuple[str, str, str]:
    """Parse a raw cookie, a copied cURL capture, or a generated cookie file."""
    text = str(content or "").strip()
    normalized = _normalize_curl_text(text)
    requested = str(requested_region or "auto").strip().lower()
    if requested not in {"auto", "global", "china"}:
        requested = "auto"
    region_match = re.search(r"(?im)^\s*HIDEMYEMAIL_REGION\s*=\s*(global|china)\s*$", text)
    region = region_match.group(1).lower() if region_match else requested
    maildomain_host = _extract_maildomain_host(text)

    encoded = re.search(
        r"(?im)^\s*HIDEMYEMAIL_COOKIE_BASE64\s*=\s*([A-Za-z0-9+/=]+)\s*$",
        text,
    )
    if encoded:
        cookie = base64.b64decode(encoded.group(1)).decode("utf-8").strip()
    else:
        cookie, block_host = _select_cookie_and_host(text, normalized)
        maildomain_host = block_host or maildomain_host
        if not cookie:
            cookie = text
    if region == "auto" and maildomain_host:
        region = _region_for_maildomain_host(maildomain_host)
    return cookie.strip(), region, maildomain_host


async def validate_cookie(payload: dict) -> dict:
    """Validate CK and return the account identity plus its HME shard."""
    source = str(payload.get("cookie", "") or "")
    cookie, requested_region, maildomain_host = parse_cookie_context(source, payload.get("region", "auto"))
    if "X-APPLE" not in cookie.upper():
        raise ValueError("CK does not contain an X-APPLE authorization field; paste a logged-in iCloud Cookie or cURL")

    if requested_region in {"global", "china"}:
        regions = [requested_region]
    elif maildomain_host:
        regions = [_region_for_maildomain_host(maildomain_host)]
    else:
        regions = ["global", "china"]
    request_params = _extract_request_params(source, maildomain_host)
    errors: list[str] = []
    for region in regions:
        attempt_host = maildomain_host if _host_matches_region(maildomain_host, region) else ""
        account = await fetch_account_info_from_cookie(cookie, region, attempt_host, request_params)
        if "error" in account:
            errors.append(f"{region}/{attempt_host or 'automatic shard'}: {account['error']}")
            continue
        ds_info = account.get("dsInfo", {}) or {}
        full_name = ds_info.get("fullName") or " ".join(
            filter(None, [ds_info.get("firstName"), ds_info.get("lastName")])
        )
        user_partition = str(account.get("userPartition") or "")
        detected_host = _normalize_maildomain_host(str(account.get("detectedMaildomainHost") or ""))
        resolved_host = (
            attempt_host
            or detected_host
            or _host_for_partition(user_partition, region)
            or HideMyEmail.REGION_CONFIG[region]["maildomain_host"]
        )
        return {
            "ok": True,
            "cookie": cookie,
            "region": region,
            "appleId": ds_info.get("appleId") or "",
            "dsid": str(ds_info.get("dsid") or ""),
            "displayName": full_name or "",
            "featureAvailable": bool(ds_info.get("isHideMyEmailFeatureAvailable")),
            "userPartition": user_partition,
            "maildomainHost": resolved_host,
        }
    detail = "; ".join(errors) if errors else "unknown error"
    raise ValueError(f"CK validation failed: {detail}")


def response_error(data: dict, fallback: str) -> str:
    """Extract a readable error without ever including the CK."""
    error = data.get("error") if isinstance(data, dict) else None
    if isinstance(error, dict):
        return str(error.get("errorMessage") or error.get("message") or fallback)
    return str(
        data.get("reason")
        or data.get("errorMessage")
        or error
        or fallback
    ) if isinstance(data, dict) else fallback


def _candidate_maildomain_hosts(region: str, preferred_host: str, user_partition: str) -> list[str]:
    default_host = HideMyEmail.REGION_CONFIG[region]["maildomain_host"]
    preferred = _normalize_maildomain_host(preferred_host)
    derived = _host_for_partition(user_partition, region)
    candidates: list[str] = []
    ordered = [preferred, derived, default_host]
    if preferred == default_host and derived and derived != default_host:
        ordered = [derived, preferred, default_host]
    for host in ordered:
        normalized = _normalize_maildomain_host(host)
        if normalized and _host_matches_region(normalized, region) and normalized not in candidates:
            candidates.append(normalized)
    return candidates


async def resolve_maildomain(
    cookie: str,
    region: str,
    preferred_host: str = "",
    user_partition: str = "",
    dsid: str = "",
    client_id: str = "",
    client_build_number: str = "",
    client_mastering_number: str = "",
) -> tuple[str, dict]:
    """Validate the HME shard, recovering from a stale/default shard when possible."""
    if region not in {"global", "china"}:
        raise ValueError("Cannot determine the iCloud region; choose global or china when importing")
    candidates = _candidate_maildomain_hosts(region, preferred_host, user_partition)
    errors: list[str] = []
    for host in candidates:
        try:
            async with HideMyEmail(
                cookies=cookie,
                region=region,
                maildomain_host=host,
                dsid=dsid,
                client_id=client_id,
                client_build_number=client_build_number,
                client_mastering_number=client_mastering_number,
            ) as client:
                response = await client.list_email()
        except Exception as exc:
            errors.append(f"{host}: network error {str(exc)[:180]}")
            continue
        if response.get("success"):
            return host, response
        errors.append(f"{host}: {response_error(response, 'Apple HME endpoint returned an error')}")
    tried = ", ".join(candidates) if candidates else "no valid maildomain host"
    detail = "; ".join(errors) if errors else "no Apple response"
    raise ValueError(f"HME sync failed (tried {tried}): {detail}")


def _operation_context(payload: dict) -> tuple[str, str, str, dict[str, str]]:
    source = str(payload.get("cookie", "") or "")
    cookie, region, parsed_host = parse_cookie_context(source, payload.get("region", "global"))
    payload_host = _normalize_maildomain_host(str(payload.get("maildomainHost") or ""))
    host = parsed_host or payload_host
    if region not in {"global", "china"}:
        region = _region_for_maildomain_host(host) if host else "global"
    params = _extract_request_params(source, host)
    return cookie, region, host, params


async def generate_addresses(payload: dict) -> dict:
    """Generate and reserve hidden addresses in label order."""
    cookie, region, maildomain_host, request_params = _operation_context(payload)
    user_partition = str(payload.get("userPartition") or "")
    dsid = str(payload.get("dsid") or request_params.get("dsid") or "")
    client_id = str(payload.get("clientId") or request_params.get("clientId") or "")
    build_number = str(payload.get("clientBuildNumber") or request_params.get("clientBuildNumber") or "")
    mastering_number = str(payload.get("clientMasteringNumber") or request_params.get("clientMasteringNumber") or "")
    labels = [str(item).strip() for item in payload.get("labels", []) if str(item).strip()]
    generated = []
    errors = []
    maildomain_host, _ = await resolve_maildomain(
        cookie,
        region,
        maildomain_host,
        user_partition,
        dsid,
        client_id,
        build_number,
        mastering_number,
    )
    async with HideMyEmail(
        cookies=cookie,
        region=region,
        maildomain_host=maildomain_host,
        dsid=dsid,
        client_id=client_id,
        client_build_number=build_number,
        client_mastering_number=mastering_number,
    ) as client:
        for index, label in enumerate(labels):
            generated_response = await client.generate_email()
            if not generated_response.get("success"):
                errors.append({"label": label, "error": response_error(generated_response, "generation failed")})
                errors.extend({"label": skipped, "error": "not run because a previous operation failed"} for skipped in labels[index + 1 :])
                break
            email = generated_response.get("result", {}).get("hme")
            reserved_response = await client.reserve_email(email, label, "Generated by iCloud Create Workbench")
            if not reserved_response.get("success"):
                errors.append({"label": label, "error": response_error(reserved_response, "reserve failed")})
                errors.extend({"label": skipped, "error": "not run because a previous operation failed"} for skipped in labels[index + 1 :])
                break
            generated.append({"email": email, "label": label, "createdAt": datetime.now(timezone.utc).isoformat()})
    return {"ok": True, "generated": generated, "errors": errors, "maildomainHost": maildomain_host}


async def list_addresses(payload: dict) -> dict:
    """Read the account's HME list and return a normalized address set."""
    cookie, region, maildomain_host, request_params = _operation_context(payload)
    user_partition = str(payload.get("userPartition") or "")
    dsid = str(payload.get("dsid") or request_params.get("dsid") or "")
    client_id = str(payload.get("clientId") or request_params.get("clientId") or "")
    build_number = str(payload.get("clientBuildNumber") or request_params.get("clientBuildNumber") or "")
    mastering_number = str(payload.get("clientMasteringNumber") or request_params.get("clientMasteringNumber") or "")
    maildomain_host, response = await resolve_maildomain(
        cookie,
        region,
        maildomain_host,
        user_partition,
        dsid,
        client_id,
        build_number,
        mastering_number,
    )
    rows = []
    for item in response.get("result", {}).get("hmeEmails", []):
        if item.get("hme"):
            rows.append({
                "email": item.get("hme"),
                "label": item.get("label") or "",
                "active": item.get("isActive") is not False,
                "createdAt": datetime.fromtimestamp(item.get("createTimestamp", 0) / 1000, timezone.utc).isoformat()
                if item.get("createTimestamp") else datetime.now(timezone.utc).isoformat(),
            })
    return {"ok": True, "addresses": rows, "maildomainHost": maildomain_host}


async def dispatch(command: str, payload: dict) -> dict:
    if command == "validate":
        return await validate_cookie(payload)
    if command == "generate":
        return await generate_addresses(payload)
    if command == "list":
        return await list_addresses(payload)
    raise ValueError("Unsupported Python bridge command")


def main() -> None:
    try:
        command = sys.argv[1] if len(sys.argv) > 1 else ""
        payload = json.loads(sys.stdin.read() or "{}")
        result = asyncio.run(dispatch(command, payload))
        print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    except Exception as error:
        print(json.dumps({"ok": False, "error": str(error)}, ensure_ascii=False, separators=(",", ":")))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
