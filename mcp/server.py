from __future__ import annotations

import asyncio
import logging
import os
import secrets
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import httpx
import uvicorn
import yaml
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} 必须是整数") from exc
    return max(minimum, min(value, maximum))


LOG_LEVEL = os.getenv("MCP_LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("arl-mcp")

MCP_HOST = os.getenv("MCP_HOST", "0.0.0.0")
MCP_PORT = env_int("MCP_PORT", 5013, 1, 65535)
MCP_READ_ONLY = env_bool("MCP_READ_ONLY", True)
MCP_ALLOW_UNAUTHENTICATED = env_bool("MCP_ALLOW_UNAUTHENTICATED", False)
MCP_TOKEN_FILE = Path(os.getenv("MCP_TOKEN_FILE", "/data/token"))
MCP_MAX_PAGE_SIZE = env_int("MCP_MAX_PAGE_SIZE", 200, 1, 1000)

ARL_BASE_URL = os.getenv("ARL_BASE_URL", "https://web").rstrip("/")
ARL_API_PREFIX = "/" + os.getenv("ARL_API_PREFIX", "/api").strip("/")
ARL_CONFIG_PATH = Path(os.getenv("ARL_CONFIG_PATH", "/config/config-docker.yaml"))
ARL_VERIFY_TLS = env_bool("ARL_VERIFY_TLS", False)
ARL_TIMEOUT = float(os.getenv("ARL_TIMEOUT", "30"))
ARL_TOKEN = os.getenv("ARL_TOKEN", "").strip()
ARL_API_KEY = os.getenv("ARL_API_KEY", "").strip()
ARL_USERNAME = os.getenv("ARL_USERNAME", "").strip()
ARL_PASSWORD = os.getenv("ARL_PASSWORD", "")


def load_arl_yaml() -> tuple[bool, str]:
    if not ARL_CONFIG_PATH.exists():
        return True, ""
    try:
        with ARL_CONFIG_PATH.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
    except Exception as exc:
        raise RuntimeError(f"读取 ARL 配置失败: {ARL_CONFIG_PATH}: {exc}") from exc

    arl = data.get("ARL") or {}
    auth_enabled = bool(arl.get("AUTH", True))
    api_key = str(arl.get("API_KEY") or "").strip()
    return auth_enabled, api_key


ARL_AUTH_ENABLED, YAML_ARL_API_KEY = load_arl_yaml()


def load_or_create_mcp_token() -> str:
    configured = os.getenv("MCP_TOKEN", "").strip()
    if configured:
        return configured
    if MCP_ALLOW_UNAUTHENTICATED:
        return ""

    try:
        if MCP_TOKEN_FILE.exists():
            token = MCP_TOKEN_FILE.read_text(encoding="utf-8").strip()
            if token:
                return token

        MCP_TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
        token = secrets.token_urlsafe(32)
        MCP_TOKEN_FILE.write_text(token + "\n", encoding="utf-8")
        MCP_TOKEN_FILE.chmod(0o600)
        logger.warning(
            "未设置 MCP_TOKEN，已生成并保存到 %s；可用 docker-compose exec mcp cat %s 查看",
            MCP_TOKEN_FILE,
            MCP_TOKEN_FILE,
        )
        return token
    except OSError as exc:
        raise RuntimeError(
            f"无法读取或创建 MCP token 文件 {MCP_TOKEN_FILE}: {exc}。"
            "请设置 MCP_TOKEN，或修复 /data 卷权限。"
        ) from exc


MCP_TOKEN = load_or_create_mcp_token()


class ARLClient:
    def __init__(self) -> None:
        self._login_token = ""
        self._login_lock = asyncio.Lock()

    @property
    def configured_auth_source(self) -> str:
        if ARL_TOKEN:
            return "ARL_TOKEN"
        if ARL_API_KEY:
            return "ARL_API_KEY"
        if YAML_ARL_API_KEY:
            return "config-docker.yaml:ARL.API_KEY"
        if ARL_USERNAME and ARL_PASSWORD:
            return "ARL_USERNAME/ARL_PASSWORD"
        if not ARL_AUTH_ENABLED:
            return "ARL.AUTH=false"
        return "none"

    def _url(self, path: str) -> str:
        suffix = path if path.startswith("/") else f"/{path}"
        base = f"{ARL_BASE_URL}{ARL_API_PREFIX}/"
        return urljoin(base, suffix.lstrip("/"))

    async def _login(self, force: bool = False) -> str:
        if self._login_token and not force:
            return self._login_token
        if not ARL_USERNAME or not ARL_PASSWORD:
            return ""

        async with self._login_lock:
            if self._login_token and not force:
                return self._login_token
            async with httpx.AsyncClient(
                verify=ARL_VERIFY_TLS,
                timeout=ARL_TIMEOUT,
                follow_redirects=True,
            ) as client:
                try:
                    response = await client.post(
                        self._url("/user/login"),
                        json={"username": ARL_USERNAME, "password": ARL_PASSWORD},
                    )
                except httpx.HTTPError as exc:
                    raise ToolError(f"连接 ARL 登录接口失败: {exc}") from exc

            data = self._decode(response)
            if response.status_code >= 400 or data.get("code") != 200:
                raise ToolError(
                    f"ARL 登录失败: HTTP {response.status_code}, "
                    f"message={data.get('message', 'unknown')}"
                )
            token = str((data.get("data") or {}).get("token") or "").strip()
            if not token:
                raise ToolError("ARL 登录响应没有 token")
            self._login_token = token
            return token

    async def _auth_token(self) -> str:
        if ARL_TOKEN:
            return ARL_TOKEN
        if ARL_API_KEY:
            return ARL_API_KEY
        if YAML_ARL_API_KEY:
            return YAML_ARL_API_KEY
        if ARL_USERNAME and ARL_PASSWORD:
            return await self._login()
        if not ARL_AUTH_ENABLED:
            return ""
        raise ToolError(
            "ARL 已开启认证，但 MCP 未取得凭据。请配置 ARL.API_KEY、ARL_API_KEY、"
            "ARL_TOKEN，或 ARL_USERNAME/ARL_PASSWORD。"
        )

    @staticmethod
    def _decode(response: httpx.Response) -> dict[str, Any]:
        try:
            data = response.json()
        except ValueError as exc:
            body = response.text[:500]
            raise ToolError(
                f"ARL 返回非 JSON 响应: HTTP {response.status_code}, body={body!r}"
            ) from exc
        if not isinstance(data, dict):
            raise ToolError(f"ARL 返回格式异常: {type(data).__name__}")
        return data

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        retry_login: bool = True,
    ) -> dict[str, Any]:
        token = await self._auth_token()
        headers = {"Accept": "application/json"}
        if token:
            headers["Token"] = token

        async with httpx.AsyncClient(
            verify=ARL_VERIFY_TLS,
            timeout=ARL_TIMEOUT,
            follow_redirects=True,
        ) as client:
            try:
                response = await client.request(
                    method,
                    self._url(path),
                    params=params,
                    json=json_body,
                    headers=headers,
                )
            except httpx.HTTPError as exc:
                raise ToolError(f"连接 ARL 失败: {exc}") from exc

        data = self._decode(response)
        unauthorized = response.status_code == 401 or data.get("code") == 401
        if unauthorized and retry_login and ARL_USERNAME and ARL_PASSWORD:
            self._login_token = ""
            await self._login(force=True)
            return await self.request(
                method,
                path,
                params=params,
                json_body=json_body,
                retry_login=False,
            )

        if response.status_code >= 400:
            raise ToolError(
                f"ARL API 请求失败: HTTP {response.status_code}, "
                f"message={data.get('message', 'unknown')}"
            )
        if data.get("code") not in (None, 200):
            details = data.get("data") or data.get("items") or {}
            raise ToolError(
                f"ARL API 返回错误: code={data.get('code')}, "
                f"message={data.get('message', 'unknown')}, details={details}"
            )
        return data


arl = ARLClient()

mcp = FastMCP(
    name="ARL Lighthouse",
    instructions=(
        "连接并操作 ARL 资产侦察灯塔。优先使用查询工具查看任务和结果；"
        "提交、停止、重启任务属于有副作用操作，并受 MCP_READ_ONLY 控制。"
    ),
    host=MCP_HOST,
    port=MCP_PORT,
    streamable_http_path="/mcp",
    json_response=True,
    stateless_http=True,
)


def clamp_page(page: int, size: int) -> tuple[int, int]:
    page = max(1, page)
    size = max(1, min(size, MCP_MAX_PAGE_SIZE))
    return page, size


def require_write(action: str) -> None:
    if MCP_READ_ONLY:
        raise ToolError(
            f"MCP 当前为只读模式，禁止执行 {action}。"
            "确认环境安全后设置 MCP_READ_ONLY=false 并重启 mcp 容器。"
        )


@mcp.tool()
async def arl_health() -> dict[str, Any]:
    """检查 MCP 配置、ARL 连通性和认证是否有效，不泄露任何密钥。"""
    result: dict[str, Any] = {
        "mcp": "ok",
        "read_only": MCP_READ_ONLY,
        "mcp_auth_required": not MCP_ALLOW_UNAUTHENTICATED,
        "arl_base_url": ARL_BASE_URL,
        "arl_auth_enabled": ARL_AUTH_ENABLED,
        "arl_auth_source": arl.configured_auth_source,
        "arl_reachable": False,
    }
    try:
        data = await arl.request("GET", "/task/", params={"page": 1, "size": 1})
        result["arl_reachable"] = True
        result["task_total"] = data.get("total")
    except Exception as exc:
        result["error"] = str(exc)
    return result


@mcp.tool()
async def arl_list_tasks(
    page: int = 1,
    size: int = 20,
    status: str | None = None,
    name: str | None = None,
    target: str | None = None,
    task_tag: str | None = None,
    order: str = "-_id",
) -> dict[str, Any]:
    """分页查询 ARL 任务，可按状态、名称、目标和任务标签过滤。"""
    page, size = clamp_page(page, size)
    params: dict[str, Any] = {"page": page, "size": size, "order": order}
    for key, value in {
        "status": status,
        "name": name,
        "target": target,
        "task_tag": task_tag,
    }.items():
        if value not in (None, ""):
            params[key] = value
    return await arl.request("GET", "/task/", params=params)


@mcp.tool()
async def arl_get_task(task_id: str) -> dict[str, Any]:
    """根据 ARL 任务对象 ID 读取任务详情。"""
    if not task_id.strip():
        raise ToolError("task_id 不能为空")
    return await arl.request(
        "GET",
        "/task/",
        params={"_id": task_id.strip(), "page": 1, "size": 1},
    )


DATASETS: dict[str, tuple[str, str | None]] = {
    "domain": ("/domain/", "domain"),
    "ip": ("/ip/", "ip"),
    "site": ("/site/", "site"),
    "url": ("/url/", "url"),
    "service": ("/service/", None),
    "cert": ("/cert/", None),
    "fileleak": ("/fileleak/", None),
    "vuln": ("/vuln/", None),
    "nuclei_result": ("/nuclei_result/", None),
    "npoc_service": ("/npoc_service/", None),
    "wih": ("/wih/", None),
    "cip": ("/cip/", None),
    "stat_finger": ("/stat_finger/", None),
}


@mcp.tool()
async def arl_query_assets(
    dataset: str,
    task_id: str | None = None,
    query: str | None = None,
    page: int = 1,
    size: int = 50,
    order: str = "-_id",
    extra_filters: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """查询任务产出的资产或漏洞结果。dataset 仅允许白名单中的 ARL 数据集。"""
    dataset = dataset.strip().lower()
    if dataset not in DATASETS:
        raise ToolError(f"不支持的数据集 {dataset!r}，可选: {', '.join(DATASETS)}")
    page, size = clamp_page(page, size)
    path, primary_field = DATASETS[dataset]
    params: dict[str, Any] = {"page": page, "size": size, "order": order}
    if task_id:
        params["task_id"] = task_id.strip()
    if query:
        if not primary_field:
            raise ToolError(
                f"数据集 {dataset} 没有统一的 query 字段，请改用 extra_filters 指定字段。"
            )
        params[primary_field] = query
    if extra_filters:
        for key, value in extra_filters.items():
            if not isinstance(key, str) or not key or key.startswith("$"):
                raise ToolError(f"非法过滤字段: {key!r}")
            if value is not None:
                params[key] = value
    return await arl.request("GET", path, params=params)


@mcp.tool()
async def arl_task_summary(task_id: str) -> dict[str, Any]:
    """汇总指定任务的域名、IP、站点、URL、泄露、漏洞和扫描结果数量。"""
    if not task_id.strip():
        raise ToolError("task_id 不能为空")
    task_id = task_id.strip()
    summary_sets = [
        "domain",
        "ip",
        "site",
        "url",
        "service",
        "cert",
        "fileleak",
        "vuln",
        "nuclei_result",
        "npoc_service",
        "wih",
        "cip",
    ]

    async def total_for(dataset: str) -> tuple[str, Any]:
        path = DATASETS[dataset][0]
        try:
            data = await arl.request(
                "GET", path, params={"task_id": task_id, "page": 1, "size": 1}
            )
            return dataset, data.get("total", len(data.get("items") or []))
        except Exception as exc:
            return dataset, {"error": str(exc)}

    pairs = await asyncio.gather(*(total_for(name) for name in summary_sets))
    task = await arl_get_task(task_id)
    return {
        "task_id": task_id,
        "task": (task.get("items") or [None])[0],
        "totals": dict(pairs),
    }


@mcp.tool()
async def arl_submit_task(
    name: str,
    target: str,
    domain_brute: bool = True,
    domain_brute_type: str = "big",
    port_scan: bool = True,
    port_scan_type: str = "top100",
    dns_query_plugin: bool = True,
    alt_dns: bool = True,
    arl_search: bool = True,
    skip_scan_cdn_ip: bool = True,
    service_detection: bool = False,
    service_brute: bool = False,
    os_detection: bool = False,
    ssl_cert: bool = False,
    site_identify: bool = False,
    site_capture: bool = False,
    search_engines: bool = False,
    site_spider: bool = False,
    file_leak: bool = False,
    nuclei_scan: bool = False,
    findvhost: bool = False,
    github_search_domain: bool = False,
    fetch_api_path: bool = False,
) -> dict[str, Any]:
    """向 ARL 提交资产侦察任务。该操作有副作用，默认只读模式下不可执行。"""
    require_write("提交任务")
    name = name.strip()
    target = target.strip()
    if not name:
        raise ToolError("name 不能为空")
    if not target:
        raise ToolError("target 不能为空")
    if len(target) > 200_000:
        raise ToolError("target 内容过大，最多 200000 字符")

    payload: dict[str, Any] = {
        "name": name,
        "target": target,
        "domain_brute": domain_brute,
        "domain_brute_type": domain_brute_type,
        "port_scan": port_scan,
        "port_scan_type": port_scan_type,
        "dns_query_plugin": dns_query_plugin,
        "alt_dns": alt_dns,
        "arl_search": arl_search,
        "skip_scan_cdn_ip": skip_scan_cdn_ip,
        "service_detection": service_detection,
        "service_brute": service_brute,
        "os_detection": os_detection,
        "ssl_cert": ssl_cert,
        "site_identify": site_identify,
        "site_capture": site_capture,
        "search_engines": search_engines,
        "site_spider": site_spider,
        "file_leak": file_leak,
        "nuclei_scan": nuclei_scan,
        "findvhost": findvhost,
        "github_search_domain": github_search_domain,
        "fetch_api_path": fetch_api_path,
    }
    logger.warning("audit action=submit_task name=%r target=%r", name, target[:300])
    return await arl.request("POST", "/task/", json_body=payload)


@mcp.tool()
async def arl_stop_task(task_id: str) -> dict[str, Any]:
    """停止一个正在运行的 ARL 任务。该操作有副作用。"""
    require_write("停止任务")
    task_id = task_id.strip()
    if not task_id:
        raise ToolError("task_id 不能为空")
    logger.warning("audit action=stop_task task_id=%s", task_id)
    return await arl.request("GET", f"/task/stop/{task_id}")


@mcp.tool()
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


@mcp.custom_route("/healthz", methods=["GET"])
async def healthz(_: Request) -> JSONResponse:
    return JSONResponse(
        {
            "status": "ok",
            "service": "arl-mcp",
            "read_only": MCP_READ_ONLY,
            "auth_required": not MCP_ALLOW_UNAUTHENTICATED,
        }
    )


class BearerTokenMiddleware:
    def __init__(self, app: ASGIApp, token: str, allow_unauthenticated: bool) -> None:
        self.app = app
        self.token = token
        self.allow_unauthenticated = allow_unauthenticated

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path == "/healthz" or self.allow_unauthenticated:
            await self.app(scope, receive, send)
            return

        headers = {
            key.decode("latin-1").lower(): value.decode("latin-1")
            for key, value in scope.get("headers", [])
        }
        provided = ""
        authorization = headers.get("authorization", "")
        if authorization.lower().startswith("bearer "):
            provided = authorization[7:].strip()
        if not provided:
            provided = headers.get("x-mcp-token", "").strip()

        if not provided or not secrets.compare_digest(provided, self.token):
            response = JSONResponse(
                {"error": "unauthorized", "message": "需要有效的 MCP Bearer token"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)


app = BearerTokenMiddleware(
    mcp.streamable_http_app(),
    token=MCP_TOKEN,
    allow_unauthenticated=MCP_ALLOW_UNAUTHENTICATED,
)


if __name__ == "__main__":
    logger.info(
        "启动 ARL MCP: http://%s:%s/mcp read_only=%s auth_required=%s arl=%s",
        MCP_HOST,
        MCP_PORT,
        MCP_READ_ONLY,
        not MCP_ALLOW_UNAUTHENTICATED,
        ARL_BASE_URL,
    )
    uvicorn.run(app, host=MCP_HOST, port=MCP_PORT, log_level=LOG_LEVEL.lower())
