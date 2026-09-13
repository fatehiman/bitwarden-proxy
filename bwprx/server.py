"""Loopback-only HTTP API.

Bound to 127.0.0.1, so nothing off this machine can reach it. A random bearer
token in a file only this user can read keeps other local accounts out, and
requests carrying browser headers are refused outright so a web page cannot be
tricked into driving the vault.
"""

from __future__ import annotations

import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional

from . import audit
from .broker import Broker, Denied
from .clientinfo import identify
from .paths import restrict_to_current_user, runtime_path
from .protocol import API_VERSION, MAX_BODY, REQUIRED_HEADER
from .vault import Locked, NotFound, VaultError



class _Handler(BaseHTTPRequestHandler):
    server_version = "bwprx/" + API_VERSION
    protocol_version = "HTTP/1.1"

    broker: Broker
    token: str

    # -------------------------------------------------------------- plumbing

    def log_message(self, fmt: str, *args: Any) -> None:  # silence stderr spam
        pass

    def _send(self, code: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _error(self, code: int, message: str, kind: str = "error") -> None:
        self._send(code, {"success": False, "error": {"code": kind, "message": message}})

    def _authorised(self) -> bool:
        # A browser cannot set a custom header cross-origin without a preflight,
        # and we never answer preflights - so these two checks together keep
        # web pages out even if they learn the port.
        if self.headers.get("Origin") or self.headers.get("Referer"):
            return False
        if self.headers.get(REQUIRED_HEADER) != API_VERSION:
            return False
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return False
        return secrets.compare_digest(auth[7:].strip(), self.token)

    def _body(self) -> Dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return {}
        if length <= 0:
            return {}
        if length > MAX_BODY:
            raise ValueError("request body too large")
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise ValueError("body is not valid JSON")
        if not isinstance(data, dict):
            raise ValueError("body must be a JSON object")
        return data

    # --------------------------------------------------------------- routing

    def do_GET(self) -> None:  # noqa: N802
        if not self._authorised():
            return self._error(401, "unauthorised", "unauthorised")
        if self.path.rstrip("/") == "/v1/status":
            return self._send(200, {"success": True, **self.broker.status()})
        self._error(404, "no such endpoint", "not_found")

    def do_POST(self) -> None:  # noqa: N802
        if not self._authorised():
            return self._error(401, "unauthorised", "unauthorised")
        path = self.path.rstrip("/")
        try:
            body = self._body()
        except ValueError as exc:
            return self._error(400, str(exc), "bad_request")

        client = identify(self.client_address[1] if self.client_address else 0)

        try:
            if path == "/v1/credential":
                query = (body.get("query") or "").strip()
                if not query:
                    return self._error(400, "query is required", "bad_request")
                data = self.broker.read_credential(query, client, body.get("fields"))
                return self._send(200, {"success": True, "credential": data})

            if path == "/v1/list":
                data = self.broker.list_items(
                    client,
                    search=(body.get("search") or None),
                    include_folders=body.get("include_folders", True),
                    folder=body.get("folder"))
                return self._send(200, {"success": True, **data})

            if path == "/v1/folders":
                data = self.broker.list_folders(client)
                return self._send(200, {"success": True, **data})

            if path == "/v1/folder/create":
                name = (body.get("name") or "").strip()
                if not name:
                    return self._error(400, "name is required", "bad_request")
                data = self.broker.create_folder(client, name)
                return self._send(200, {"success": True, "folder": data})

            if path == "/v1/item/move":
                item_id = (body.get("id") or "").strip()
                if not item_id:
                    return self._error(400, "id is required", "bad_request")
                # `folder: ""` is meaningful - it means "out of every folder".
                data = self.broker.move_item(client, item_id,
                                             body.get("folder") or "")
                return self._send(200, {"success": True, "item": data})

            if path == "/v1/item/create":
                name = (body.get("name") or "").strip()
                if not name:
                    return self._error(400, "name is required", "bad_request")
                data = self.broker.create_login(
                    client, name=name, username=body.get("username"),
                    uri=body.get("uri"), password=body.get("password"),
                    notes=body.get("notes"), folder=body.get("folder"),
                    generate_length=body.get("generate_length"))
                return self._send(200, {"success": True, "item": data})

            if path == "/v1/item/edit":
                item_id = (body.get("id") or "").strip()
                if not item_id:
                    return self._error(400, "id is required", "bad_request")
                data = self.broker.edit_login(
                    client, item_id, name=body.get("name"),
                    username=body.get("username"), uri=body.get("uri"),
                    password=body.get("password"), notes=body.get("notes"),
                    folder=body.get("folder"), rotate=bool(body.get("rotate")),
                    generate_length=body.get("generate_length"))
                return self._send(200, {"success": True, "item": data})

            if path == "/v1/item/delete":
                item_id = (body.get("id") or "").strip()
                if not item_id:
                    return self._error(400, "id is required", "bad_request")
                data = self.broker.delete_item(
                    client, item_id, permanent=bool(body.get("permanent")))
                return self._send(200, {"success": True, "item": data})

            self._error(404, "no such endpoint", "not_found")

        except Denied as exc:
            self._error(403, str(exc), "denied")
        except Locked as exc:
            self._error(423, str(exc), "locked")
        except NotFound as exc:
            self._error(404, str(exc), "not_found")
        except ValueError as exc:
            self._error(400, str(exc), "bad_request")
        except VaultError as exc:
            self._error(500, str(exc), "vault_error")
        except Exception as exc:  # pragma: no cover
            audit.record("server_error", detail=type(exc).__name__)
            self._error(500, f"internal error: {exc}", "internal")


class ApiServer:
    def __init__(self, broker: Broker, port: int) -> None:
        self.token = secrets.token_urlsafe(32)
        handler = type("_BoundHandler", (_Handler,),
                       {"broker": broker, "token": self.token})
        self._httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
        self._httpd.daemon_threads = True
        self.port = self._httpd.server_address[1]
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._write_runtime()
        self._thread = threading.Thread(target=self._httpd.serve_forever,
                                        name="bwprx-api", daemon=True)
        self._thread.start()
        audit.record("api_started", port=self.port)

    def stop(self) -> None:
        try:
            self._httpd.shutdown()
            self._httpd.server_close()
        except Exception:
            pass
        runtime_path().unlink(missing_ok=True)
        audit.record("api_stopped")

    def _write_runtime(self) -> None:
        p = runtime_path()
        p.write_text(json.dumps({
            "version": API_VERSION,
            "port": self.port,
            "token": self.token,
            "url": f"http://127.0.0.1:{self.port}",
        }, indent=2), encoding="utf-8")
        restrict_to_current_user(p)
