from __future__ import annotations

import os
from typing import Any, Callable

import httpx

SCANNER_V2_BASE_URL = os.getenv("SCANNER_V2_BASE_URL", "http://scanner-v2:8090").rstrip("/")
SCANNER_V2_TIMEOUT = float(os.getenv("SCANNER_V2_TIMEOUT", "30"))
SCANNER_PUBLIC_BASE_URL = os.getenv("SCANNER_PUBLIC_BASE_URL", "").rstrip("/")


class ScannerV2Client:
    async def request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = f"{SCANNER_V2_BASE_URL}/{path.lstrip('/')}"
        timeout = httpx.Timeout(SCANNER_V2_TIMEOUT, connect=min(SCANNER_V2_TIMEOUT, 10.0))
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
                response = await client.request(method, url, json=json_body)
        except httpx.HTTPError as exc:
            raise RuntimeError(f"连接 Scanner V2 失败: {exc}") from exc
        try:
            data = response.json()
        except ValueError as exc:
            raise RuntimeError(
                f"Scanner V2 返回非 JSON: HTTP {response.status_code}, body={response.text[:300]!r}"
            ) from exc
        if not isinstance(data, dict):
            raise RuntimeError(f"Scanner V2 返回格式异常: {type(data).__name__}")
        if response.status_code >= 400:
            raise RuntimeError(
                f"Scanner V2 请求失败: HTTP {response.status_code}, "
                f"error={data.get('error')}, message={data.get('message')}"
            )
        return data


scanner = ScannerV2Client()


def with_public_urls(payload: dict[str, Any]) -> dict[str, Any]:
    if not SCANNER_PUBLIC_BASE_URL:
        return payload
    urls = payload.get("report_urls")
    if isinstance(urls, dict):
        payload["public_report_urls"] = {
            key: value if str(value).startswith(("http://", "https://")) else f"{SCANNER_PUBLIC_BASE_URL}{value}"
            for key, value in urls.items()
        }
    return payload


def register(mcp: Any, require_write: Callable[[str], None], tool_error: type[Exception]) -> None:
    @mcp.tool()
    async def arl_scan_capabilities() -> dict[str, Any]:
        """读取 Scanner V2 能力、工具可用性和真实增强扫描链。"""
        try:
            data = await scanner.request("GET", "/capabilities")
        except Exception as exc:
            raise tool_error(str(exc)) from exc
        data.update(
            {
                "native_arl_restart": {
                    "operation": "legacy_native_restart",
                    "quality_upgrade": False,
                    "scanner_v2_used": False,
                },
                "enhanced_scan": {
                    "tool": "arl_submit_enhanced_scan",
                    "quality_upgrade": True,
                    "scanner_v2_used": True,
                },
            }
        )
        return data

    @mcp.tool()
    async def arl_submit_enhanced_scan(
        name: str,
        target: str,
        mode: str = "standard",
    ) -> dict[str, Any]:
        """提交真正的 Scanner V2 增强扫描，而不是原样重启旧 ARL 任务。"""
        require_write("提交 Scanner V2 增强扫描")
        name = name.strip()
        target = target.strip()
        mode = mode.strip().lower()
        if not name:
            raise tool_error("name 不能为空")
        if not target:
            raise tool_error("target 不能为空")
        if mode not in {"fast", "standard", "deep"}:
            raise tool_error("mode 仅允许 fast、standard 或 deep")
        if len(target.encode("utf-8")) > 200_000:
            raise tool_error("target 内容过大，最多 200000 字节")
        try:
            data = await scanner.request(
                "POST",
                "/scans",
                json_body={"name": name, "targets": target, "mode": mode},
            )
        except Exception as exc:
            raise tool_error(str(exc)) from exc
        data["operation"] = "scanner_v2_enhanced_scan"
        data["quality_upgrade"] = True
        return with_public_urls(data)

    @mcp.tool()
    async def arl_get_enhanced_scan(scan_id: str) -> dict[str, Any]:
        """读取 Scanner V2 增强扫描的排队、执行、完成或失败状态。"""
        scan_id = scan_id.strip()
        if not scan_id:
            raise tool_error("scan_id 不能为空")
        try:
            data = await scanner.request("GET", f"/scans/{scan_id}")
        except Exception as exc:
            raise tool_error(str(exc)) from exc
        return with_public_urls(data)

    @mcp.tool()
    async def arl_get_enhanced_scan_summary(scan_id: str) -> dict[str, Any]:
        """读取增强扫描的结构化汇总、覆盖面、Nuclei 状态和报告入口。"""
        scan_id = scan_id.strip()
        if not scan_id:
            raise tool_error("scan_id 不能为空")
        try:
            data = await scanner.request("GET", f"/scans/{scan_id}/summary")
        except Exception as exc:
            raise tool_error(str(exc)) from exc
        return with_public_urls(data)
