"""Authenticated loopback HTTP service. Secrets are loaded only by this runtime."""
import os
import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastmcp import FastMCP
from mcp.types import ToolAnnotations
from starlette.responses import JSONResponse
from starlette.routing import Route

from atlas_monitor import AtlasMonitor
from owner_auth import AtlasOAuthProxy, OwnerVerifier
from server import runtime_credentials


def private_value(name):
    try:
        folder = os.environ["CREDENTIALS_DIRECTORY"]
        with (Path(folder) / name).open("rb") as source:
            raw = source.read(4097)
        value = raw.decode("ascii")
        if not value or len(raw) > 4096 or any(c in value for c in "\r\n\0"):
            raise ValueError()
        return value
    except (KeyError, OSError, ValueError, UnicodeError):
        raise RuntimeError("PRIVATE_CREDENTIAL_LOADING_UNAVAILABLE") from None


class RequestLimits:
    def __init__(self, app):
        self.app = app
        self.slots = asyncio.Semaphore(16)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path") == "/health":
            return await self.app(scope, receive, send)
        acquired = False
        try:
            try:
                await asyncio.wait_for(self.slots.acquire(), 0.05)
                acquired = True
                chunks = []
                size = 0
                async def read():
                    nonlocal size
                    while True:
                        message = await receive()
                        if message["type"] == "http.disconnect":
                            raise ValueError()
                        size += len(message.get("body", b""))
                        if size > 65536:
                            raise ValueError()
                        chunks.append(message)
                        if not message.get("more_body", False):
                            break
                await asyncio.wait_for(read(), 10)
            except asyncio.TimeoutError:
                return await JSONResponse({"error": "temporarily_unavailable"}, status_code=503)(scope, receive, send)
            except ValueError:
                return await JSONResponse({"error": "request_rejected"}, status_code=413)(scope, receive, send)
            async def bounded_receive():
                return chunks.pop(0) if chunks else await receive()
            await self.app(scope, bounded_receive, send)
        finally:
            if acquired:
                self.slots.release()


def create_http_app(monitor, proxy, verifier):
    @asynccontextmanager
    async def lifespan(_):
        try:
            yield {}
        finally:
            await monitor.close()
            await verifier.close()

    server = FastMCP("BatterySwap Atlas Connections", auth=proxy, lifespan=lifespan,
        instructions="Read-only Cluster0 CONNECTIONS for Battery swap. UTC windows <=24h. "
        "Keep node timelines separate; partial/missing samples do not prove recovery. "
        "Do not infer client identity or TLS causation from connection metrics.")

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False,
                                            idempotentHint=True, openWorldHint=True))
    async def atlas_connections(start_utc: str, end_utc: str, granularity: str = "PT1M") -> dict:
        """Read CONNECTIONS for the fixed project/cluster only; no writes or database queries."""
        return await monitor.connections(start_utc, end_utc, granularity)

    app = server.http_app(path="/mcp", stateless_http=True)

    async def health(_request):
        # Only runtime liveness; never performs Atlas or GitHub requests.
        return JSONResponse({"ok": True})

    app.routes.append(Route("/health", health, methods=["GET"]))
    app.add_middleware(RequestLimits)
    return app


def main():
    logging.disable(logging.CRITICAL)
    if os.environ.get("ATLAS_MONITOR_AUTH_MODE") != "api_key":
        raise RuntimeError("EXPLICIT_API_KEY_MODE_REQUIRED")
    monitor = AtlasMonitor(*runtime_credentials(), auth_mode="api_key")
    verifier = OwnerVerifier()
    proxy = AtlasOAuthProxy(private_value("github_client_id"),
        private_value("github_client_secret"), verifier, signing_key=None)
    app = create_http_app(monitor, proxy, verifier)
    # Reverse proxy owns public TLS. Loopback only; no request/query access logs.
    uvicorn.run(app, host="127.0.0.1", port=8017, access_log=False,
                proxy_headers=False, log_level="critical")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit("ATLAS_RUNTIME_STARTUP_UNAVAILABLE") from None
