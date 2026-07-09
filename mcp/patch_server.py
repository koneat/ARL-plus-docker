#!/usr/bin/env python3
from pathlib import Path

path = Path('/app/server.py')
text = path.read_text(encoding='utf-8')

anchor = 'ARL_PASSWORD = os.getenv("ARL_PASSWORD", "")\n'
addition = 'SCANNER_V2_BASE_URL = os.getenv("SCANNER_V2_BASE_URL", "http://scanner-v2:8090").rstrip("/")\n'
if addition not in text:
    if anchor not in text:
        raise SystemExit('ARL_PASSWORD anchor not found')
    text = text.replace(anchor, anchor + addition, 1)

old_health = '''    except Exception as exc:
        result["error"] = str(exc)
    return result
'''
new_health = '''    except Exception as exc:
        result["error"] = str(exc)
    result["scanner_v2_base_url"] = SCANNER_V2_BASE_URL
    result["scanner_v2_reachable"] = False
    try:
        async with httpx.AsyncClient(timeout=8, follow_redirects=False) as client:
            scanner_response = await client.get(f"{SCANNER_V2_BASE_URL}/healthz")
        scanner_data = scanner_response.json()
        result["scanner_v2_reachable"] = (
            scanner_response.status_code < 400
            and isinstance(scanner_data, dict)
            and scanner_data.get("status") == "ok"
        )
        if isinstance(scanner_data, dict):
            result["scanner_v2_queue_depth"] = scanner_data.get("queue_depth")
    except Exception as exc:
        result["scanner_v2_error"] = str(exc)
    return result
'''
if 'result["scanner_v2_reachable"]' not in text:
    if old_health not in text:
        raise SystemExit('arl_health return block not found')
    text = text.replace(old_health, new_health, 1)

old_submit_tail = '''    logger.warning("audit action=submit_task name=%r target=%r", name, target[:300])
    return await arl.request("POST", "/task/", json_body=payload)
'''
new_submit_tail = '''    logger.warning("audit action=submit_task name=%r target=%r", name, target[:300])
    response = await arl.request("POST", "/task/", json_body=payload)
    requested_but_not_guaranteed = []
    if github_search_domain:
        requested_but_not_guaranteed.append("github_search_domain")
    if fetch_api_path:
        requested_but_not_guaranteed.append("fetch_api_path")
    return {
        "operation": "native_arl_task",
        "quality_upgrade": False,
        "scanner_v2_used": False,
        "requested_but_not_guaranteed": requested_but_not_guaranteed,
        "warning": (
            "原生 ARL 任务不会调用 Scanner V2；github_search_domain 与 fetch_api_path "
            "可能被旧后端忽略。需要 Uncover、历史 URL、Katana、Sourcemap、增强 FFUF、"
            "失败闭合 Nuclei 和 Afrog 时，请使用 arl_submit_enhanced_scan。"
        ),
        "arl_response": response,
    }
'''
if 'operation": "native_arl_task"' not in text:
    if old_submit_tail not in text:
        raise SystemExit('arl_submit_task return block not found')
    text = text.replace(old_submit_tail, new_submit_tail, 1)

old_restart = '''@mcp.tool()
async def arl_restart_task(task_ids: list[str]) -> dict[str, Any]:
    """重新下发一个或多个已结束、已停止或失败的 ARL 任务。该操作有副作用。"""
    require_write("重启任务")
    clean = [item.strip() for item in task_ids if item and item.strip()]
    if not clean:
        raise ToolError("task_ids 不能为空")
    if len(clean) > 100:
        raise ToolError("单次最多重启 100 个任务")
    logger.warning("audit action=restart_task task_ids=%s", clean)
    return await arl.request("POST", "/task/restart/", json_body={"task_id": clean})
'''
new_restart = '''@mcp.tool()
async def arl_restart_task(task_ids: list[str]) -> dict[str, Any]:
    """原生 ARL 旧任务重启；只继承旧配置，不调用 Scanner V2，不代表质量升级。"""
    require_write("重启原生旧任务")
    clean = [item.strip() for item in task_ids if item and item.strip()]
    if not clean:
        raise ToolError("task_ids 不能为空")
    if len(clean) > 100:
        raise ToolError("单次最多重启 100 个任务")
    logger.warning("audit action=legacy_restart_task task_ids=%s", clean)
    response = await arl.request("POST", "/task/restart/", json_body={"task_id": clean})
    return {
        "operation": "legacy_native_restart",
        "quality_upgrade": False,
        "scanner_v2_used": False,
        "warning": "该操作仅原样继承旧 ARL 任务配置；需要提升扫描质量时使用 arl_submit_enhanced_scan。",
        "task_ids": clean,
        "arl_response": response,
    }
'''
if 'operation": "legacy_native_restart"' not in text:
    if old_restart not in text:
        raise SystemExit('arl_restart_task block not found')
    text = text.replace(old_restart, new_restart, 1)

text = text.replace(
    '"提交、停止、重启任务属于有副作用操作，并受 MCP_READ_ONLY 控制。"',
    '"提交、停止、重启任务属于有副作用操作，并受 MCP_READ_ONLY 控制；真正质量升级使用 Scanner V2 增强扫描。"',
)

path.write_text(text, encoding='utf-8')
