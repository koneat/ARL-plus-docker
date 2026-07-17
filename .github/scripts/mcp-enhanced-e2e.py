#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import json
from typing import Any

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client


def decode_result(result: Any) -> dict[str, Any]:
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        return structured
    structured = getattr(result, "structured_content", None)
    if isinstance(structured, dict):
        return structured
    text = "".join(getattr(item, "text", "") for item in result.content)
    value = json.loads(text)
    if not isinstance(value, dict):
        raise AssertionError(f"tool returned non-object: {value!r}")
    return value


async def call(session: ClientSession, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    result = await session.call_tool(name, arguments)
    if result.isError:
        raise AssertionError(f"{name} failed: {result}")
    return decode_result(result)


async def main() -> None:
    async with streamablehttp_client("http://127.0.0.1:5013/mcp") as streams:
        async with ClientSession(streams[0], streams[1]) as session:
            await session.initialize()

            capabilities = await call(session, "arl_scan_capabilities", {})
            assert capabilities["enhanced_submit_quality_upgrade"] is True
            assert capabilities["native_restart_quality_upgrade"] is False

            submitted = await call(
                session,
                "arl_submit_enhanced_scan",
                {
                    "name": "mcp-full-regression",
                    "target": "http://fixture.test:8080",
                    "mode": "fast",
                },
            )
            assert submitted["quality_upgrade"] is True
            assert submitted["operation"] == "scanner_v2_enhanced_scan"
            scan_id = submitted["scan_id"]

            state: dict[str, Any] = {}
            for _ in range(600):
                state = await call(session, "arl_get_enhanced_scan", {"scan_id": scan_id})
                if state.get("status") in {"completed", "failed", "interrupted"}:
                    break
                await asyncio.sleep(1)
            assert state.get("status") == "completed", state
            assert state.get("quality_upgrade") is True

            summary = await call(
                session,
                "arl_get_enhanced_scan_summary",
                {"scan_id": scan_id},
            )
            assert summary["scan_id"] == scan_id
            assert summary["quality"]["scanner_v2"] is True
            assert summary["quality"]["quality_upgrade"] is True
            assert summary["report_urls"]["report"].endswith(f"/{scan_id}/report.html")
            assert summary["artifact_counts"]["live_urls"] >= 1
            print(json.dumps({"scan_id": scan_id, "state": state, "summary": summary}, ensure_ascii=False))


if __name__ == "__main__":
    asyncio.run(main())
