"""Local web interface (Python standard library only).

Security properties of the tool itself:
  * binds to 127.0.0.1 by default and rejects unexpected Host headers (DNS-rebinding defence)
  * every API call needs a per-process random token (CSRF defence; custom header forces a CORS preflight
    that is never granted)
  * uploads are size-limited and extracted with zip-slip / zip-bomb / symlink guards
  * API keys supplied in the UI are kept in memory for that job only and never logged
"""
from __future__ import annotations

import json
import secrets
import threading
import time
import uuid
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict
from urllib.parse import parse_qs, urlparse

from . import __tool_name__, __version__
from .ai.providers import DEFAULT_MODELS, PROVIDERS, detect_provider, env_key
from .collector import InputError, load_target, load_zip_bytes
from .pipeline import ScanOptions, run_scan
from .report import to_json, to_markdown, to_sarif
from .report.html import to_html

WEB_DIR = Path(__file__).parent / "web"
MAX_UPLOAD = 100 * 1024 * 1024
MAX_RUNNING = 2
TOKEN = secrets.token_urlsafe(24)
JOBS: Dict[str, Dict] = {}
LOCK = threading.Lock()
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}
CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")


def _run_job(job_id: str, mode: str, payload, opts: ScanOptions, name: str) -> None:
    job = JOBS[job_id]

    def log(msg: str):
        with LOCK:
            job["log"].append(msg)

    try:
        if mode == "zip":
            pre = load_zip_bytes(payload, name or "uploaded-project", [])
        else:
            pre = load_target(payload, [])
        result = run_scan(options=opts, progress=log, preloaded=pre)
        job["reports"] = {"html": to_html(result), "md": to_markdown(result), "json": to_json(result),
                          "sarif": to_sarif(result)}
        job["result"] = json.loads(job["reports"]["json"])
        job["status"] = "done"
        log(f"Done: {len(result.findings)} finding(s), overall risk {result.summary.get('risk_rating')}.")
    except (InputError, ValueError) as exc:
        job["status"], job["error"] = "error", str(exc)
    except Exception as exc:  # noqa: BLE001
        job["status"], job["error"] = "error", f"{type(exc).__name__}: {exc}"
    finally:
        opts.api_key = None


class Handler(BaseHTTPRequestHandler):
    server_version = "CodeWarden"
    sys_version = ""

    def log_message(self, fmt, *args):  # quiet, and never log query strings (tokens)
        return

    # ------------------------------------------------------------ helpers
    def _send(self, code: int, body: bytes, ctype: str, extra: Dict = None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        self.send_header("Content-Security-Policy", CSP)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj):
        self._send(code, json.dumps(obj).encode("utf-8"), "application/json; charset=utf-8")

    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").lower()
        port = self.server.server_address[1]
        return host in (f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}")

    def _token_ok(self, q) -> bool:
        t = self.headers.get("X-CW-Token") or (q.get("token", [""])[0])
        return secrets.compare_digest(t or "", TOKEN)

    # ------------------------------------------------------------ routes
    def do_GET(self):
        if not self._host_ok():
            return self._json(HTTPStatus.FORBIDDEN, {"error": "unexpected Host header"})
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path in ("/", "/index.html"):
            page = (WEB_DIR / "index.html").read_text(encoding="utf-8")
            page = page.replace("__CW_TOKEN__", TOKEN).replace("__CW_VERSION__", __version__)
            return self._send(200, page.encode("utf-8"), "text/html; charset=utf-8")
        if not u.path.startswith("/api/"):
            return self._json(404, {"error": "not found"})
        if not self._token_ok(q):
            return self._json(HTTPStatus.FORBIDDEN, {"error": "missing or invalid token"})
        if u.path == "/api/config":
            return self._json(200, {
                "version": __version__, "default_provider": detect_provider() or "none",
                "providers": [{"id": p, "default_model": DEFAULT_MODELS[p],
                               "key_configured": bool(env_key(p)) or p == "ollama"} for p in PROVIDERS],
            })
        parts = u.path.strip("/").split("/")
        if len(parts) >= 3 and parts[1] == "jobs":
            job = JOBS.get(parts[2])
            if not job:
                return self._json(404, {"error": "unknown job"})
            if len(parts) == 3:
                since = int(q.get("since", ["0"])[0] or 0)
                with LOCK:
                    log = job["log"][since:]
                    n = len(job["log"])
                return self._json(200, {"status": job["status"], "log": log, "next": n, "error": job.get("error"),
                                        "result": job.get("result") if job["status"] == "done" else None})
            if len(parts) == 4 and parts[3].startswith("report."):
                fmt = parts[3].split(".", 1)[1]
                reports = job.get("reports") or {}
                if fmt not in reports:
                    return self._json(404, {"error": "report not ready"})
                ctype = {"html": "text/html", "md": "text/markdown", "json": "application/json",
                         "sarif": "application/sarif+json"}[fmt] + "; charset=utf-8"
                fname = f"{job['name']}.{fmt}"
                disp = "inline" if q.get("inline") and fmt == "html" else f"attachment; filename=\"{fname}\""
                return self._send(200, reports[fmt].encode("utf-8"), ctype, {"Content-Disposition": disp})
        return self._json(404, {"error": "not found"})

    def do_POST(self):
        if not self._host_ok():
            return self._json(HTTPStatus.FORBIDDEN, {"error": "unexpected Host header"})
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path != "/api/scan":
            return self._json(404, {"error": "not found"})
        if not self._token_ok(q):
            return self._json(HTTPStatus.FORBIDDEN, {"error": "missing or invalid token"})
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_UPLOAD:
            return self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE if length > MAX_UPLOAD else 400,
                              {"error": "upload must be between 1 byte and 100 MB"})
        with LOCK:
            running = sum(1 for j in JOBS.values() if j["status"] == "running")
        if running >= MAX_RUNNING:
            return self._json(429, {"error": "a scan is already running; wait for it to finish"})
        body = self.rfile.read(length)
        mode = q.get("mode", ["zip"])[0]
        provider = q.get("provider", ["auto"])[0]
        if provider == "auto":
            provider = detect_provider() or "none"
        if provider not in PROVIDERS + ["none"]:
            return self._json(400, {"error": "unknown provider"})
        name = (q.get("name", [""])[0] or "").strip()[:80]
        opts = ScanOptions(provider=provider, model=(q.get("model", [""])[0] or None),
                           api_key=(self.headers.get("X-AI-Key") or None),
                           max_files=min(150, int(q.get("max_files", ["60"])[0] or 60)),
                           workers=min(6, int(q.get("workers", ["3"])[0] or 3)),
                           project_name=name or None)
        if mode == "zip":
            payload = body
            if not body.startswith(b"PK"):
                return self._json(400, {"error": "the upload is not a ZIP file"})
        elif mode in ("path", "github"):
            try:
                payload = json.loads(body.decode("utf-8")).get("target", "").strip()
            except Exception:
                return self._json(400, {"error": "expected JSON body {\"target\": ...}"})
            if not payload:
                return self._json(400, {"error": "target is required"})
            if mode == "github" and not payload.startswith("https://github.com/"):
                return self._json(400, {"error": "GitHub URL must start with https://github.com/"})
        else:
            return self._json(400, {"error": "mode must be zip, path or github"})
        job_id = uuid.uuid4().hex
        safe_name = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in (name or "codewarden")).strip("-") or "codewarden"
        JOBS[job_id] = {"status": "running", "log": [], "created": time.time(), "name": f"{safe_name.lower()}-security-report"}
        threading.Thread(target=_run_job, args=(job_id, mode, payload, opts, name), daemon=True).start()
        return self._json(202, {"job_id": job_id})


def serve(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True) -> int:
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("Refusing to bind to a non-loopback address: the web UI is a local tool.")
        return 2
    httpd = ThreadingHTTPServer((host, port), Handler)
    url = f"http://127.0.0.1:{port}/"
    print(f"{__tool_name__} v{__version__} web UI running at {url}")
    print("Press Ctrl+C to stop.")
    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        httpd.server_close()
    return 0
