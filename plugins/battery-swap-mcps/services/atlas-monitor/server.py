"""Stdio only until an authenticated server deployment is separately approved."""
import os
from pathlib import Path
from contextlib import asynccontextmanager

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from atlas_monitor import AtlasMonitor


def runtime_auth_mode(environ=None):
    environ = os.environ if environ is None else environ
    mode = environ.get("ATLAS_MONITOR_AUTH_MODE", "service_account")
    if mode not in ("service_account", "api_key"):
        raise RuntimeError("INVALID_AUTH_MODE")
    return mode


def runtime_credentials(environ=None):
    """Prefer systemd credential files; environment values are for local development."""
    environ = os.environ if environ is None else environ
    mode = runtime_auth_mode(environ)
    names = {"service_account": ("atlas_client_id", "atlas_client_secret"),
             "api_key": ("atlas_public_key", "atlas_private_key")}[mode]
    directory = environ.get("CREDENTIALS_DIRECTORY")
    if directory:
        values = []
        for name in names:
            try:
                with (Path(directory) / name).open("rb") as source:
                    raw = source.read(4097)
                value = raw.decode("utf-8")
                if not value or len(raw) > 4096 or any(c in value for c in "\r\n\0"):
                    raise ValueError()
                values.append(value)
            except (OSError, ValueError, UnicodeError):
                raise RuntimeError("PRIVATE_CREDENTIAL_LOADING_UNAVAILABLE") from None
        return tuple(values)
    if mode == "api_key":
        return environ.get("ATLAS_MONITOR_API_PUBLIC_KEY"), environ.get("ATLAS_MONITOR_API_PRIVATE_KEY")
    return environ.get("ATLAS_MONITOR_CLIENT_ID"), environ.get("ATLAS_MONITOR_CLIENT_SECRET")


def create_server(monitor):
    @asynccontextmanager
    async def lifespan(_server):
        try:
            yield {}
        finally:
            await monitor.close()

    server = FastMCP("BatterySwap Atlas Connections", lifespan=lifespan, log_level="WARNING")

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False,
                                            idempotentHint=True, openWorldHint=True))
    async def atlas_connections(start_utc: str, end_utc: str, granularity: str = "PT1M") -> dict:
        """Read Cluster0 CONNECTIONS only. UTC window <=24h; PT1M/PT5M/PT1H.
        No arbitrary project/host/URL, database queries, or mutation operations.
        Missing samples and unavailable M0 API access are not zero connections.
        """
        return await monitor.connections(start_utc, end_utc, granularity)

    return server


if __name__ == "__main__":
    monitor = AtlasMonitor(*runtime_credentials(), auth_mode=runtime_auth_mode())
    create_server(monitor).run(transport="stdio")
