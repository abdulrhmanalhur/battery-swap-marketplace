"""Owner-only GitHub identity and independently scoped MongoRead MCP OAuth."""
import asyncio
import hashlib
import json
import logging
import re
import secrets
import time
from urllib.parse import urlparse

import httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client
from fastmcp.server.auth import OAuthProxy
from fastmcp.server.auth.auth import TokenVerifier, AccessToken
from fastmcp.server.auth.oauth_proxy.models import JTIMapping, RefreshTokenMetadata, _hash_token
from mcp.server.auth.provider import AuthorizeError, TokenError
from mcp.shared.auth import OAuthToken
from starlette.responses import HTMLResponse

OWNER_ID = 108840765
SCOPE = "mongodb:read"
BASE_URL = "https://mcpgooads.batteryswap.cc/mongodb/auth"
RESOURCE = "https://mcpgooads.batteryswap.cc/mongodb/mcp"
ACCESS_SECONDS = 900
REFRESH_SECONDS = 30 * 86400
IDENTITY_LIMIT = 16384


class OwnerVerifier(TokenVerifier):
    def __init__(self, transport=None):
        super().__init__(required_scopes=[SCOPE])
        self.http = httpx.AsyncClient(transport=transport, timeout=8, trust_env=False,
                                      follow_redirects=False)
        self._cache = {}
        self._lock = asyncio.Lock()

    async def close(self):
        await self.http.aclose()
        self._cache.clear()

    async def verify_token(self, token):
        try:
            return await asyncio.wait_for(self._verify_owner(token), 8)
        except asyncio.TimeoutError:
            return None

    async def _verify_owner(self, token):
        if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_]{1,4096}", token):
            return None
        key = hashlib.sha256(token.encode()).hexdigest()
        async with self._lock:
            if self._cache.get(key, 0) > time.monotonic():
                return self._access(token)
            try:
                async def read():
                    async with self.http.stream("GET", "https://api.github.com/user", headers={
                        "Authorization": "Bearer " + token,
                        "Accept": "application/vnd.github+json", "Accept-Encoding": "identity",
                        "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "BatterySwap-MongoRead-Reader"
                    }) as response:
                        if response.status_code != 200 or response.headers.get("content-encoding", "identity").lower() != "identity":
                            return False
                        # A dedicated app must have no upstream repository/profile/email scopes.
                        if response.headers.get("x-oauth-scopes", "").strip():
                            return False
                        raw = bytearray()
                        async for chunk in response.aiter_bytes():
                            if len(raw) + len(chunk) > IDENTITY_LIMIT:
                                return False
                            raw.extend(chunk)
                        data = json.loads(raw)
                        return isinstance(data, dict) and type(data.get("id")) is int and data["id"] == OWNER_ID
                if not await asyncio.wait_for(read(), 8):
                    return None
            except (httpx.HTTPError, ValueError, UnicodeError, RecursionError, asyncio.TimeoutError):
                return None
            now = time.monotonic()
            self._cache = {k: expiry for k, expiry in self._cache.items() if expiry > now}
            if len(self._cache) >= 256:
                self._cache.clear()
            self._cache[key] = now + 30
            return self._access(token)

    @staticmethod
    def _access(token):
        return AccessToken(token=token, client_id=str(OWNER_ID), scopes=[SCOPE],
                           claims={"sub": str(OWNER_ID)})


class MongoReadOAuthProxy(OAuthProxy):
    def __init__(self, client_id, client_secret, verifier, signing_key, storage=None):
        # Library error/debug messages may contain callback parameters or IdP errors.
        # No auth/request logging is enabled for this service.
        logging.getLogger("fastmcp.server.auth").disabled = True
        for name in ("fastmcp.server.auth.oauth_proxy.proxy", "httpx", "httpcore", "authlib"):
            logging.getLogger(name).setLevel(logging.CRITICAL)
        super().__init__(
            upstream_authorization_endpoint="https://github.com/login/oauth/authorize",
            upstream_token_endpoint="https://github.com/login/oauth/access_token",
            upstream_client_id=client_id, upstream_client_secret=client_secret,
            token_verifier=verifier, base_url=BASE_URL, issuer_url=BASE_URL,
            resource_base_url="https://mcpgooads.batteryswap.cc/mongodb", redirect_path="/callback",
            valid_scopes=[SCOPE], jwt_signing_key=signing_key, client_storage=storage,
            allowed_client_redirect_uris=[
                "http://127.0.0.1:*/callback", "http://127.0.0.1:*/callback/*",
                "http://127.0.0.1/callback", "http://127.0.0.1/callback/*",
                "http://localhost:*/auth/callback", "http://127.0.0.1:*/auth/callback",
                "http://localhost:*/callback", "http://localhost:*/callback/*",
                "https://chatgpt.com/connector/oauth/*",
                "https://chatgpt.com/connector_platform_oauth_redirect",
                "https://claude.ai/api/mcp/auth_callback",
                "https://claude.com/api/mcp/auth_callback",
            ],
            extra_authorize_params={"scope": ""}, extra_token_params={"scope": ""},
            forward_resource=False, forward_pkce=True, enable_cimd=True,
            require_authorization_consent=True,
            fallback_access_token_expiry_seconds=ACCESS_SECONDS,
        )
        from quota_store import QuotaStore
        bounded = QuotaStore(self._client_storage)
        for attr in ("_client_store","_transaction_store","_code_store","_jti_mapping_store",
                     "_refresh_token_store","_upstream_token_store"):
            getattr(self,attr)._key_value = bounded
        self._client_storage = bounded
        self.owner_verifier = verifier
        self._exchange_lock = asyncio.Lock()

    def _create_upstream_oauth_client(self):
        return AsyncOAuth2Client(client_id=self._upstream_client_id,
            client_secret=self._upstream_client_secret.get_secret_value(),
            token_endpoint_auth_method="client_secret_post", timeout=8,
            trust_env=False, follow_redirects=False)

    def _prepare_scopes_for_token_exchange(self, scopes):
        return []

    def _prepare_scopes_for_upstream_refresh(self, scopes):
        return []

    async def get_client(self, client_id):
        if not isinstance(client_id,str) or len(client_id)>512:return None
        if client_id.startswith("https://"):
            parsed = urlparse(client_id)
            if (parsed.netloc != "chatgpt.com" or parsed.query or parsed.fragment
                    or not re.fullmatch(r"/oauth/(?:codex/)?(?:[A-Za-z0-9_-]+/)?client\.json", parsed.path)):
                return None
        elif not isinstance(client_id, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,256}", client_id):
            return None
        return await super().get_client(client_id)

    async def register_client(self, client_info):
        if client_info.scope not in (None, "", SCOPE):
            raise ValueError("MONGO_READ_CLIENT_SCOPE_REJECTED")
        from urllib.parse import urlsplit
        for uri in client_info.redirect_uris:
            parsed = urlsplit(str(uri))
            loopback = (parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "localhost")
                        and (parsed.path in ("/callback", "/auth/callback") or parsed.path.startswith("/callback/")))
            cloud = (parsed.scheme == "https" and parsed.netloc in ("chatgpt.com", "claude.ai", "claude.com")
                     and (str(uri) in ("https://chatgpt.com/connector_platform_oauth_redirect",
                                      "https://claude.ai/api/mcp/auth_callback", "https://claude.com/api/mcp/auth_callback")
                          or parsed.netloc == "chatgpt.com" and parsed.path.startswith("/connector/oauth/")))
            if parsed.username or parsed.password or parsed.fragment or parsed.query or not (loopback or cloud):
                raise ValueError("MONGO_READ_CLIENT_REDIRECT_REJECTED")
        if not client_info.redirect_uris or len(client_info.redirect_uris) > 8:
            raise ValueError("MONGO_READ_CLIENT_REDIRECT_REJECTED")
        return await super().register_client(client_info)

    async def authorize(self, client, params):
        resource = getattr(params,"resource",None)
        if ((resource is not None and str(resource) != RESOURCE)
                or params.scopes != [SCOPE]
                or not isinstance(params.code_challenge, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{43}", params.code_challenge)
                or getattr(params, "code_challenge_method", "S256") != "S256"):
            raise AuthorizeError(error="invalid_request", error_description="MongoRead authorization rejected")
        if resource is None:
            params = params.model_copy(update={"resource":RESOURCE})
        return await super().authorize(client, params)

    async def _handle_idp_callback(self, request):
        response = await super()._handle_idp_callback(request)
        if response.status_code >= 400:
            return HTMLResponse("OAuth authorization unavailable. Restart the connection.", status_code=400)
        return response

    async def _extract_upstream_claims(self, idp_tokens):
        if not await self.owner_verifier.verify_token(idp_tokens.get("access_token")):
            raise TokenError("access_denied", "Owner authorization required")
        return {"sub": str(OWNER_ID)}

    async def exchange_authorization_code(self, client, authorization_code):
        async with self._exchange_lock:
            model = await self._code_store.get(key=authorization_code.code)
            if (not model or model.client_id != client.client_id
                    or model.expires_at <= time.time() or model.scopes != [SCOPE]
                    or model.idp_tokens.get("scope", "") != ""
                    or not await self.owner_verifier.verify_token(model.idp_tokens.get("access_token"))):
                raise TokenError("access_denied", "Owner authorization required")
            # Map verified GitHub identity to a local permission; never request it upstream.
            model.idp_tokens = {**model.idp_tokens, "scope": SCOPE, "expires_in": ACCESS_SECONDS}
            await self._code_store.put(key=model.code, value=model, ttl=max(1, int(model.expires_at-time.time())))
            try:
                result = await super().exchange_authorization_code(client, authorization_code)
                payload = self.jwt_issuer.verify_token(result.access_token)
                mapping = await self._jti_mapping_store.get(key=payload["jti"])
                upstream = await self._upstream_token_store.get(key=mapping.upstream_token_id)
                await self._upstream_token_store.put(key=upstream.upstream_token_id, value=upstream, ttl=REFRESH_SECONDS)
                # GitHub traditional OAuth tokens need no upstream refresh. Issue a bounded,
                # rotating local refresh reference and recheck the owner at every refresh.
                if result.refresh_token:
                    old = self.jwt_issuer.verify_token(result.refresh_token, expected_token_use="refresh")
                    await self._refresh_token_store.delete(key=_hash_token(result.refresh_token))
                    await self._jti_mapping_store.delete(key=old["jti"])
                refresh = await self._new_refresh(client.client_id, mapping.upstream_token_id, REFRESH_SECONDS)
                return result.model_copy(update={"refresh_token": refresh})
            except Exception:
                raise TokenError("invalid_grant", "MongoRead token exchange unavailable") from None

    async def _new_refresh(self, client_id, upstream_id, seconds):
        jti = secrets.token_urlsafe(32)
        token = self.jwt_issuer.issue_refresh_token(client_id=client_id, scopes=[SCOPE],
            jti=jti, expires_in=seconds, upstream_claims={"sub": str(OWNER_ID)})
        await self._jti_mapping_store.put(key=jti,
            value=JTIMapping(jti=jti, upstream_token_id=upstream_id, created_at=time.time()), ttl=seconds)
        await self._refresh_token_store.put(key=_hash_token(token),
            value=RefreshTokenMetadata(client_id=client_id, scopes=[SCOPE],
                expires_at=int(time.time())+seconds, created_at=time.time()), ttl=seconds)
        return token

    async def load_access_token(self, token):
        try:
            payload = self.jwt_issuer.verify_token(token)
            if payload.get("scope") != SCOPE:
                return None
            result = await super().load_access_token(token)
            if not result or result.claims.get("sub") != str(OWNER_ID) or result.scopes != [SCOPE]:
                return None
            return result
        except Exception:
            return None

    async def exchange_refresh_token(self, client, refresh_token, scopes):
        async with self._exchange_lock:
            try:
                loaded = await self.load_refresh_token(client, refresh_token.token)
                payload = self.jwt_issuer.verify_token(refresh_token.token, expected_token_use="refresh")
                if (loaded is None or payload["client_id"] != client.client_id
                        or loaded.scopes != [SCOPE] or (scopes and scopes != [SCOPE])):
                    raise ValueError()
                remaining = int(loaded.expires_at-time.time())
                if remaining <= 0:
                    raise ValueError()
                mapping = await self._jti_mapping_store.get(key=payload["jti"])
                upstream = await self._upstream_token_store.get(key=mapping.upstream_token_id) if mapping else None
                if not upstream:
                    raise ValueError()
                verified = await self.owner_verifier.verify_token(upstream.access_token)
                if not verified and upstream.refresh_token and upstream.expires_at <= time.time():
                    upstream = await self._try_transparent_refresh(upstream)
                    verified = await self.owner_verifier.verify_token(upstream.access_token)
                if not verified:
                    raise ValueError()
                # Invalidate before issuing: fail closed on an interrupted rotation.
                await self._refresh_token_store.delete(key=_hash_token(refresh_token.token))
                await self._jti_mapping_store.delete(key=payload["jti"])
                seconds = min(ACCESS_SECONDS, remaining)
                jti = secrets.token_urlsafe(32)
                access = self.jwt_issuer.issue_access_token(client_id=client.client_id, scopes=[SCOPE],
                    jti=jti, expires_in=seconds, upstream_claims={"sub": str(OWNER_ID)})
                await self._jti_mapping_store.put(key=jti,
                    value=JTIMapping(jti=jti, upstream_token_id=upstream.upstream_token_id,
                                     created_at=time.time()), ttl=seconds)
                refresh = await self._new_refresh(client.client_id, upstream.upstream_token_id, remaining)
                return OAuthToken(access_token=access, token_type="Bearer", expires_in=seconds,
                                  refresh_token=refresh, scope=SCOPE)
            except Exception:
                raise TokenError("invalid_grant", "MongoRead refresh rejected") from None
