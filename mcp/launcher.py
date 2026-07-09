from __future__ import annotations

import uvicorn

import server
from enhanced_tools import register

register(server.mcp, server.require_write, server.ToolError)

app = server.BearerTokenMiddleware(
    server.mcp.streamable_http_app(),
    token=server.MCP_TOKEN,
    allow_unauthenticated=server.MCP_ALLOW_UNAUTHENTICATED,
)

if __name__ == "__main__":
    server.logger.info(
        "启动 ARL MCP + Scanner V2: http://%s:%s/mcp read_only=%s auth_required=%s scanner=%s",
        server.MCP_HOST,
        server.MCP_PORT,
        server.MCP_READ_ONLY,
        not server.MCP_ALLOW_UNAUTHENTICATED,
        server.SCANNER_V2_BASE_URL,
    )
    uvicorn.run(
        app,
        host=server.MCP_HOST,
        port=server.MCP_PORT,
        log_level=server.LOG_LEVEL.lower(),
    )
