#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import json
import os
import queue
import re
import shutil
import subprocess
import threading
import traceback
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

HOST = os.getenv("SCANNER_V2_HOST", "0.0.0.0")
PORT = int(os.getenv("SCANNER_V2_PORT", "8090"))
RESULT_ROOT = Path(os.getenv("SCANNER_V2_RESULT_ROOT", "/work/results"))
STATE_ROOT = RESULT_ROOT / ".scanner-api"
INPUT_ROOT = Path(os.getenv("SCANNER_V2_INPUT_ROOT", "/work/input/api"))
RUNNER = Path(os.getenv("SCANNER_V2_RUNNER", "/opt/scanner/run-scan-v2.sh"))
WORKERS = max(1, min(int(os.getenv("SCANNER_V2_WORKERS", "1")), 4))
MAX_TARGET_BYTES = max(1024, int(os.getenv("SCANNER_V2_MAX_TARGET_BYTES", "200000")))
MAX_QUEUE = max(1, int(os.getenv("SCANNER_V2_MAX_QUEUE", "100")))
MODES = {"fast", "standard", "deep"}
SCAN_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,96}$")
PIPELINE = [
    "scope_normalization", "uncover", "subfinder", "dnsx", "naabu", "httpx",
    "passive_urls", "katana", "tls_san", "sourcemap", "ffuf", "content_audit",
    "nuclei_fail_closed", "afrog", "html_report",
]
TOOLS = [
    "uncover", "subfinder", "dnsx", "naabu", "httpx", "urlfinder", "gau",
    "katana", "tlsx", "alterx", "cdncheck", "ffuf", "nuclei", "afrog", "nmap",
]

_jobs: "queue.Queue[str]" = queue.Queue(maxsize=MAX_QUEUE)
_state_lock = threading.RLock()


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def atomic_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def state_path(scan_id: str) -> Path:
    return STATE_ROOT / f"{scan_id}.json"


def validate_scan_id(scan_id: str) -> str:
    scan_id = scan_id.strip()
    if not SCAN_ID_RE.fullmatch(scan_id):
        raise ValueError("invalid scan_id")
    return scan_id


def load_state(scan_id: str) -> dict[str, Any] | None:
    try:
        scan_id = validate_scan_id(scan_id)
    except ValueError:
        return None
    value = read_json(state_path(scan_id), None)
    return value if isinstance(value, dict) else None


def count_lines(path: Path) -> int:
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            return sum(1 for line in handle if line.strip())
    except OSError:
        return 0


def report_urls(scan_id: str) -> dict[str, str]:
    base = f"/report/scanner/{scan_id}"
    return {
        "report": f"{base}/report.html",
        "summary_json": f"{base}/summary.json",
        "summary_markdown": f"{base}/summary.md",
        "quality_status": f"{base}/quality-status.json",
        "nuclei_status": f"{base}/nuclei-status.json",
        "log": f"{base}/scanner-api.log",
    }


def artifact_summary(scan_id: str) -> dict[str, Any]:
    out = RESULT_ROOT / scan_id
    summary = read_json(out / "summary.json", {})
    quality = read_json(out / "quality-status.json", {})
    nuclei = read_json(out / "nuclei-status.json", {})
    return {
        "scan_id": scan_id,
        "summary": summary if isinstance(summary, dict) else {},
        "quality": quality if isinstance(quality, dict) else {},
        "nuclei": nuclei if isinstance(nuclei, dict) else {},
        "artifact_counts": {
            "domains": count_lines(out / "domains.all.txt"),
            "live_urls": count_lines(out / "live-urls.txt"),
            "priority_urls": count_lines(out / "urls-priority.txt"),
            "nuclei_findings": count_lines(out / "nuclei.jsonl"),
            "afrog_findings": count_lines(out / "afrog.json"),
            "content_findings": count_lines(out / "content-findings.jsonl"),
        },
        "report_urls": report_urls(scan_id),
    }


def write_index() -> None:
    RESULT_ROOT.mkdir(parents=True, exist_ok=True)
    rows: list[str] = []
    paths = sorted(STATE_ROOT.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True)
    for path in paths[:500]:
        state = read_json(path, {})
        if not isinstance(state, dict):
            continue
        scan_id = str(state.get("scan_id") or path.stem)
        name = str(state.get("name") or scan_id)
        mode = str(state.get("mode") or "-")
        status = str(state.get("status") or "unknown")
        updated = str(state.get("updated_at") or "-")
        report = f"{scan_id}/report.html" if (RESULT_ROOT / scan_id / "report.html").is_file() else ""
        report_link = f'<a href="{report}">打开报告</a>' if report else "-"
        safe_name = name.replace("&", "&amp;").replace("<", "&lt;")
        rows.append(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                safe_name, scan_id, mode, status, updated, report_link
            )
        )
    body = "".join(rows) or '<tr><td colspan="6">还没有 Scanner V2 增强扫描任务。</td></tr>'
    document = (
        '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<title>Scanner V2 增强扫描</title>'
        '<style>body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f5f7fa;color:#1f2937;margin:0}'
        'main{max-width:1400px;margin:auto;padding:24px}table{width:100%;border-collapse:collapse;background:#fff}'
        'th,td{padding:10px;border-bottom:1px solid #e5e7eb;text-align:left}a{color:#0969da}</style></head>'
        '<body><main><h1>Scanner V2 增强扫描</h1>'
        '<p>真实调用 Uncover、历史 URL、Katana、TLS SAN、Sourcemap、FFUF、Nuclei 与 Afrog。</p>'
        '<table><thead><tr><th>名称</th><th>扫描 ID</th><th>模式</th><th>状态</th><th>更新时间</th><th>报告</th></tr></thead>'
        f'<tbody>{body}</tbody></table></main></body></html>'
    )
    temporary = RESULT_ROOT / "index.html.tmp"
    temporary.write_text(document, encoding="utf-8")
    os.replace(temporary, RESULT_ROOT / "index.html")


def save_state(scan_id: str, **changes: Any) -> dict[str, Any]:
    with _state_lock:
        current = load_state(scan_id) or {"scan_id": scan_id}
        current.update(changes)
        current["updated_at"] = utc_now()
        atomic_json(state_path(scan_id), current)
        write_index()
        return current


def safe_name(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-._")
    return normalized[:48] or "enhanced"


def make_scan_id(name: str) -> str:
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"{safe_name(name)}-{stamp}-{uuid.uuid4().hex[:8]}"


def capabilities() -> dict[str, Any]:
    available = {tool: bool(shutil.which(tool)) for tool in TOOLS}
    version_file = Path("/opt/scanner/V2_VERSION")
    version = version_file.read_text(encoding="utf-8").strip() if version_file.exists() else "unknown"
    return {
        "service": "arl-scanner-v2",
        "version": version,
        "modes": sorted(MODES),
        "pipeline": PIPELINE,
        "tools": available,
        "all_required_tools_available": all(available.values()),
        "report_prefix": "/report/scanner/",
        "native_restart_quality_upgrade": False,
        "enhanced_submit_quality_upgrade": True,
    }


def recover_states() -> None:
    STATE_ROOT.mkdir(parents=True, exist_ok=True)
    for path in STATE_ROOT.glob("*.json"):
        state = read_json(path, {})
        if isinstance(state, dict) and state.get("status") in {"queued", "running"}:
            state.update(
                status="interrupted",
                quality_upgrade=True,
                error="scanner-api restarted before the scan completed",
                ended_at=utc_now(),
                updated_at=utc_now(),
            )
            atomic_json(path, state)
    write_index()


def execute_scan(scan_id: str) -> None:
    state = load_state(scan_id)
    if not state:
        return
    target_file = Path(str(state["target_file"]))
    out = RESULT_ROOT / scan_id
    out.mkdir(parents=True, exist_ok=True)
    log_path = out / "scanner-api.log"
    env = os.environ.copy()
    env["SCAN_ID"] = scan_id
    env["ENABLE_SCANNER_V2"] = "true"
    save_state(
        scan_id,
        status="running",
        started_at=utc_now(),
        command=[RUNNER.name, "<targets>", state["mode"]],
        report_urls=report_urls(scan_id),
    )
    try:
        with log_path.open("ab", buffering=0) as log_handle:
            process = subprocess.run(
                [str(RUNNER), str(target_file), str(state["mode"])],
                env=env,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                close_fds=True,
                check=False,
            )
        save_state(
            scan_id,
            status="completed" if process.returncode == 0 else "failed",
            exit_code=process.returncode,
            ended_at=utc_now(),
            report_exists=(out / "report.html").is_file(),
            summary_exists=(out / "summary.json").is_file(),
            quality=artifact_summary(scan_id).get("quality", {}),
        )
    except Exception as exc:
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write("\n[scanner-api] unhandled exception\n")
            handle.write(traceback.format_exc())
        save_state(scan_id, status="failed", exit_code=-1, ended_at=utc_now(), error=str(exc))


def worker_loop() -> None:
    while True:
        scan_id = _jobs.get()
        try:
            execute_scan(scan_id)
        finally:
            _jobs.task_done()


def start_workers() -> None:
    for index in range(WORKERS):
        threading.Thread(
            target=worker_loop,
            name=f"scanner-worker-{index + 1}",
            daemon=True,
        ).start()


class Handler(BaseHTTPRequestHandler):
    server_version = "ARLScannerV2/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[scanner-api] {self.address_string()} {fmt % args}", flush=True)

    def send_json(self, status: int, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def read_body(self) -> dict[str, Any]:
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("invalid content length") from exc
        if size <= 0 or size > MAX_TARGET_BYTES + 65536:
            raise ValueError("request body is empty or too large")
        try:
            data = json.loads(self.rfile.read(size).decode("utf-8"))
        except Exception as exc:
            raise ValueError("invalid JSON body") from exc
        if not isinstance(data, dict):
            raise ValueError("JSON body must be an object")
        return data

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path.rstrip("/") or "/"
        if path in {"/", "/healthz"}:
            self.send_json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "service": "arl-scanner-v2",
                    "scanner_v2_reachable": True,
                    "queue_depth": _jobs.qsize(),
                    "workers": WORKERS,
                    "runner_exists": RUNNER.is_file(),
                },
            )
            return
        if path == "/capabilities":
            self.send_json(HTTPStatus.OK, capabilities())
            return
        match = re.fullmatch(r"/scans/([A-Za-z0-9._-]+)(/summary)?", path)
        if match:
            scan_id = match.group(1)
            state = load_state(scan_id)
            if not state:
                self.send_json(HTTPStatus.NOT_FOUND, {"error": "scan_not_found", "scan_id": scan_id})
                return
            if match.group(2):
                payload = artifact_summary(scan_id)
                payload["state"] = state
            else:
                payload = state
                payload["report_urls"] = report_urls(scan_id)
            self.send_json(HTTPStatus.OK, payload)
            return
        self.send_json(HTTPStatus.NOT_FOUND, {"error": "not_found", "path": path})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path.rstrip("/") or "/"
        if path != "/scans":
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "not_found", "path": path})
            return
        try:
            data = self.read_body()
            name = str(data.get("name") or "enhanced-scan").strip()
            mode = str(data.get("mode") or "standard").strip().lower()
            if mode not in MODES:
                raise ValueError(f"mode must be one of {sorted(MODES)}")
            targets_value = data.get("targets", data.get("target", ""))
            if isinstance(targets_value, list):
                targets = "\n".join(str(item).strip() for item in targets_value if str(item).strip())
            else:
                targets = str(targets_value or "").strip()
            raw = targets.encode("utf-8")
            if not raw:
                raise ValueError("targets cannot be empty")
            if len(raw) > MAX_TARGET_BYTES:
                raise ValueError(f"targets exceed {MAX_TARGET_BYTES} bytes")
            if _jobs.full():
                self.send_json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "queue_full"})
                return
            scan_id = make_scan_id(name)
            INPUT_ROOT.mkdir(parents=True, exist_ok=True)
            target_file = INPUT_ROOT / f"{scan_id}.targets.txt"
            target_file.write_text(targets.rstrip() + "\n", encoding="utf-8")
            target_file.chmod(0o600)
            state = {
                "scan_id": scan_id,
                "name": name[:160],
                "mode": mode,
                "status": "queued",
                "quality_upgrade": True,
                "engine": "scanner_v2",
                "legacy_native_restart": False,
                "target_count": sum(1 for line in targets.splitlines() if line.strip()),
                "target_file": str(target_file),
                "created_at": utc_now(),
                "updated_at": utc_now(),
                "report_urls": report_urls(scan_id),
            }
            atomic_json(state_path(scan_id), state)
            write_index()
            _jobs.put_nowait(scan_id)
            self.send_json(HTTPStatus.ACCEPTED, state)
        except ValueError as exc:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request", "message": str(exc)})
        except Exception as exc:
            self.send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal_error", "message": str(exc)})


def main() -> None:
    RESULT_ROOT.mkdir(parents=True, exist_ok=True)
    STATE_ROOT.mkdir(parents=True, exist_ok=True)
    INPUT_ROOT.mkdir(parents=True, exist_ok=True)
    recover_states()
    start_workers()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"[scanner-api] listening on http://{HOST}:{PORT} workers={WORKERS}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
