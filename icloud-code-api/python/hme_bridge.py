"""Node.js 与 hidemyemail-generator 之间的 JSON 标准输入桥接层。"""

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


def parse_cookie_context(content: str, requested_region: str = "auto") -> tuple[str, str, str]:
    """在内存中解析原始 Cookie、cURL 或上游 Cookie 文件。"""
    text = str(content or "").strip()
    normalized = re.sub(r"(?:\\|\^)\s*\r?\n", " ", text)
    region_match = re.search(r"(?m)^HIDEMYEMAIL_REGION=(global|china)\s*$", text)
    region = region_match.group(1) if region_match else requested_region
    host_match = re.search(r"(?m)^HIDEMYEMAIL_MAILDOMAIN_HOST=([^\s]+)\s*$", text)
    maildomain_host = host_match.group(1).strip() if host_match else ""
    encoded = re.search(r"(?m)^HIDEMYEMAIL_COOKIE_BASE64=([A-Za-z0-9+/=]+)\s*$", text)
    if encoded:
        return base64.b64decode(encoded.group(1)).decode("utf-8").strip(), region, maildomain_host
    cookie_arg = re.search(r"(?:^|\s)(?:-b|--cookie)\s+(?:\^?\"|')(.+?)(?:\^?\"|')(?=\s+-|\s*$)", normalized, re.I | re.S)
    if cookie_arg:
        return cookie_arg.group(1).replace('^\"', '"').replace('\\"', '"').strip(), region, maildomain_host
    header_arg = re.search(r"(?:-H|--header)\s+\^?(['\"])\s*cookie\s*:\s*(.*?)\^?\1", normalized, re.I | re.S)
    if header_arg:
        return header_arg.group(2).strip(), region, maildomain_host
    header = re.search(r"^\s*cookie\s*:\s*(.+?)\s*$", normalized, re.I | re.S)
    if header:
        return header.group(1).strip().strip("'\""), region, maildomain_host
    return text, region, maildomain_host


async def validate_cookie(payload: dict) -> dict:
    """验证 CK 并返回经过筛选的账号信息。"""
    cookie, requested_region, maildomain_host = parse_cookie_context(payload.get("cookie", ""), payload.get("region", "auto"))
    if "X-APPLE" not in cookie:
        raise ValueError("CK 中未找到必要的 X-APPLE 字段")
    regions = [requested_region] if requested_region in {"global", "china"} else ["global", "china"]
    last_error = "CK 校验失败"
    for region in regions:
        resolved_host = maildomain_host or HideMyEmail.REGION_CONFIG[region]["maildomain_host"]
        account = await fetch_account_info_from_cookie(cookie, region, resolved_host)
        if "error" in account:
            last_error = str(account["error"])
            continue
        ds_info = account.get("dsInfo", {})
        full_name = ds_info.get("fullName") or " ".join(filter(None, [ds_info.get("firstName"), ds_info.get("lastName")]))
        return {
            "ok": True,
            "cookie": cookie,
            "region": region,
            "appleId": ds_info.get("appleId") or "",
            "dsid": str(ds_info.get("dsid") or ""),
            "displayName": full_name or "",
            "featureAvailable": bool(ds_info.get("isHideMyEmailFeatureAvailable")),
            "userPartition": str(account.get("userPartition") or ""),
            "maildomainHost": resolved_host,
        }
    raise ValueError(last_error)


def response_error(data: dict, fallback: str) -> str:
    """从 Apple API 响应中提取可读错误。"""
    error = data.get("error") if isinstance(data, dict) else None
    if isinstance(error, dict):
        return str(error.get("errorMessage") or fallback)
    return str(data.get("reason") or error or fallback) if isinstance(data, dict) else fallback


async def resolve_maildomain(cookie: str, region: str, preferred_host: str = "") -> tuple[str, dict]:
    """通过列表接口验证分片，错误分片自动回退到上游区域默认节点。"""
    default_host = HideMyEmail.REGION_CONFIG[region]["maildomain_host"]
    candidates = list(dict.fromkeys(host for host in [preferred_host, default_host] if host))
    last_error = "无法连接 iCloud maildomain 服务"
    for host in candidates:
        async with HideMyEmail(cookies=cookie, region=region, maildomain_host=host) as client:
            response = await client.list_email()
        if response.get("success"):
            return host, response
        last_error = response_error(response, last_error)
    raise ValueError(last_error)


async def generate_addresses(payload: dict) -> dict:
    """按标签顺序串行生成并保留隐藏邮箱。"""
    cookie, region, maildomain_host = parse_cookie_context(payload.get("cookie", ""), payload.get("region", "global"))
    maildomain_host = maildomain_host or str(payload.get("maildomainHost") or "")
    labels = [str(item).strip() for item in payload.get("labels", []) if str(item).strip()]
    generated = []
    errors = []
    maildomain_host, _ = await resolve_maildomain(cookie, region, maildomain_host)
    async with HideMyEmail(cookies=cookie, region=region, maildomain_host=maildomain_host) as client:
        for index, label in enumerate(labels):
            generated_response = await client.generate_email()
            if not generated_response.get("success"):
                errors.append({"label": label, "error": response_error(generated_response, "生成失败")})
                errors.extend({"label": skipped, "error": "前序操作失败，未继续执行"} for skipped in labels[index + 1 :])
                break
            email = generated_response.get("result", {}).get("hme")
            reserved_response = await client.reserve_email(email, label, "Generated by iCloud Create Workbench")
            if not reserved_response.get("success"):
                errors.append({"label": label, "error": response_error(reserved_response, "保留失败")})
                errors.extend({"label": skipped, "error": "前序操作失败，未继续执行"} for skipped in labels[index + 1 :])
                break
            generated.append({"email": email, "label": label, "createdAt": datetime.now(timezone.utc).isoformat()})
    return {"ok": True, "generated": generated, "errors": errors, "maildomainHost": maildomain_host}


async def list_addresses(payload: dict) -> dict:
    """读取 Apple 账号下的隐藏邮箱列表。"""
    cookie, region, maildomain_host = parse_cookie_context(payload.get("cookie", ""), payload.get("region", "global"))
    maildomain_host = maildomain_host or str(payload.get("maildomainHost") or "")
    maildomain_host, response = await resolve_maildomain(cookie, region, maildomain_host)
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
    """将命令分派到对应的桥接操作。"""
    if command == "validate":
        return await validate_cookie(payload)
    if command == "generate":
        return await generate_addresses(payload)
    if command == "list":
        return await list_addresses(payload)
    raise ValueError("不支持的 Python 桥接命令")


def main() -> None:
    """读取标准输入并保证标准输出只包含一行 JSON。"""
    try:
        command = sys.argv[1] if len(sys.argv) > 1 else ""
        payload = json.loads(sys.stdin.read() or "{}")
        result = asyncio.run(dispatch(command, payload))
        print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    except Exception as error:  # 桥接边界需要统一转换所有异常
        print(json.dumps({"ok": False, "error": str(error)}, ensure_ascii=False, separators=(",", ":")))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
