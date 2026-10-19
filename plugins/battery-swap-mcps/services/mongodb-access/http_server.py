"""Owner-only read runtime. Startup requires explicit activation and private credentials."""
import json
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastmcp import FastMCP
from fastmcp.server.dependencies import get_access_token
from mcp.types import ToolAnnotations
from starlette.responses import JSONResponse
from starlette.routing import Route

from access import Denied, Namespace, Principal, ReadGateway, READ
from mongo_reader import MongoReader
from owner_auth import MongoReadOAuthProxy, OwnerVerifier, OWNER_ID, RESOURCE
from request_limits import RequestLimits


def private_value(name):
    try:
        path = Path(os.environ["CREDENTIALS_DIRECTORY"]) / name
        with path.open("rb") as source:
            raw = source.read(8193)
        if not 1 <= len(raw) <= 8192 or any(c in raw for c in (b"\r",b"\n",b"\0")):
            raise ValueError()
        return raw.decode("ascii")
    except Exception:
        raise RuntimeError("PRIVATE_CREDENTIAL_LOADING_UNAVAILABLE") from None


def create_http_app(reader, proxy, verifier):
    gateway = ReadGateway(Namespace("test"), reader)
    @asynccontextmanager
    async def lifespan(_):
        try:
            yield {}
        finally:
            reader.close()
            await verifier.close()
    server = FastMCP("BatterySwap MongoDB Read",auth=proxy,lifespan=lifespan,mask_error_details=True,
        instructions="Read approved fields/collections in test only. No mutation, proposals, commands or connection switching.")
    def caller():
        token = get_access_token()
        if token is None or token.claims.get("sub") != str(OWNER_ID) or token.scopes != [READ]:
            raise Denied("OWNER_READ_AUTHORIZATION_REQUIRED")
        return Principal(str(OWNER_ID), token.client_id, frozenset((READ,)))
    annotation = ToolAnnotations(readOnlyHint=True,destructiveHint=False,idempotentHint=True)
    @server.tool(annotations=annotation)
    def find(collection:str,query:dict|None=None,limit:int=50)->list:
        """Read only approved fields from approved collections in test; max100 documents."""
        return gateway.find(caller(),collection,query,limit)
    @server.tool(annotations=annotation)
    def count(collection:str,query:dict|None=None)->int:
        """Count approved collection queries within a3-second server deadline."""
        return gateway.count(caller(),collection,query)
    app = server.http_app(path="/mcp",stateless_http=True)
    # Proxy issuer is /mongodb/auth; resource is /mongodb/mcp. Keep metadata paths absolute.
    for route in app.routes:
        if isinstance(route,Route):
            if route.path == "/.well-known/oauth-authorization-server":
                path = route.path + "/mongodb/auth"
            elif route.path.startswith("/.well-known/"):
                continue
            else:
                path = "/mongodb/mcp" if route.path == "/mcp" else "/mongodb/auth" + route.path
            route.path = path
            from starlette.routing import compile_path
            route.path_regex, route.path_format, route.param_convertors = compile_path(path)
    async def health(_):
        return JSONResponse({"ok":True,"mode":"read-only"})
    app.routes.append(Route("/mongodb/health",health,methods=["GET"]))
    app.add_middleware(RequestLimits)
    return app


def main():
    logging.disable(logging.CRITICAL)
    if os.environ.get("MONGODB_READ_ACTIVATED") != "1":
        raise RuntimeError("ACTIVATION_DISABLED")
    policy = json.loads(Path(__file__).with_name("read-policy.json").read_text())
    reader = MongoReader(private_value("mongodb_uri"),policy)
    verifier = OwnerVerifier()
    # Separate GitHub app secret derives independent signing/storage keys, never Atlas credentials.
    proxy = MongoReadOAuthProxy(private_value("github_client_id"),private_value("github_client_secret"),
                                verifier,signing_key=None)
    app = create_http_app(reader,proxy,verifier)
    uvicorn.run(app,host="127.0.0.1",port=8018,workers=1,access_log=False,
                proxy_headers=False,log_level="critical")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit("MONGODB_READ_RUNTIME_UNAVAILABLE") from None
