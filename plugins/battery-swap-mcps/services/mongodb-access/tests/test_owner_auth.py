import asyncio
import base64
import hashlib
import json
import sys
import time
import unittest
from pathlib import Path

import httpx
from key_value.aio.stores.memory import MemoryStore
from mcp.server.auth.provider import AuthorizationParams, AuthorizeError, TokenError
from mcp.shared.auth import OAuthClientInformationFull
from pydantic import AnyUrl

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from owner_auth import MongoReadOAuthProxy, OwnerVerifier, OWNER_ID, SCOPE, RESOURCE, ACCESS_SECONDS
from fastmcp.server.auth.oauth_proxy.models import ClientCode
from http_server import create_http_app

TOKEN = "fake_owner_token"
KEY = "fake_signing_material_not_a_real_secret_12345"
VERIFIER = "a" * 43
CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).decode().rstrip("=")


class MongoOwnerAuthTests(unittest.IsolatedAsyncioTestCase):
    def make(self, response=None):
        self.requests = []
        def handler(request):
            self.requests.append(request)
            if response:
                return response(request)
            return httpx.Response(200, json={"id": OWNER_ID})
        verifier = OwnerVerifier(httpx.MockTransport(handler))
        self.addAsyncCleanup(verifier.close)
        proxy = MongoReadOAuthProxy("fake_id", "fake_secret", verifier, KEY, MemoryStore())
        proxy.set_mcp_path("/mcp")
        return verifier, proxy

    async def prepare_client_code(self, proxy, token=TOKEN):
        client = OAuthClientInformationFull(client_id="fixture_client", client_secret=None,
            token_endpoint_auth_method="none", redirect_uris=[AnyUrl("http://127.0.0.1:12345/callback")],
            grant_types=["authorization_code", "refresh_token"], response_types=["code"], scope=SCOPE)
        await proxy.register_client(client)
        code = ClientCode(code="fixture_code", client_id=client.client_id,
            redirect_uri=str(client.redirect_uris[0]), code_challenge=CHALLENGE,
            code_challenge_method="S256", scopes=[SCOPE],
            idp_tokens={"access_token": token, "token_type": "Bearer", "scope": ""},
            expires_at=time.time()+120, created_at=time.time())
        await proxy._code_store.put(key=code.code, value=code, ttl=120)
        loaded = await proxy.load_authorization_code(client, code.code)
        return client, loaded

    async def test_identity_owner_only_and_no_profile_output(self):
        verifier, _ = self.make()
        result = await verifier.verify_token(TOKEN)
        self.assertEqual(result.claims, {"sub": str(OWNER_ID)})
        self.assertEqual(result.scopes, [SCOPE])
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(str(self.requests[0].url), "https://api.github.com/user")
        await verifier.verify_token(TOKEN)
        self.assertEqual(len(self.requests), 1)

    async def test_wrong_identity_redirect_scope_and_invalid_data_rejected(self):
        for response in (httpx.Response(200,json={"id":1}), httpx.Response(200,json={"id":str(OWNER_ID)}),
                         httpx.Response(200,json={"id":OWNER_ID},headers={"X-OAuth-Scopes":"repo"}),
                         httpx.Response(302,headers={"Location":"https://evil.invalid"}),
                         httpx.Response(403,content=b"fake_private_body"),
                         httpx.Response(200,content=b"x"*16385),
                         httpx.Response(200,content=b"invalid")):
            verifier,_=self.make(lambda _request:response)
            self.assertIsNone(await verifier.verify_token(TOKEN))
            self.assertEqual(len(self.requests),1)

    async def test_raw_upstream_token_and_cross_service_jwt_cannot_read(self):
        verifier,proxy=self.make()
        class Reader:
            def close(self):pass
            def find(self,*args):raise AssertionError("unauthorized database call")
        app=create_http_app(Reader(),proxy,verifier)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app),base_url="https://fixture.invalid") as c:
            headers={"Authorization":"Bearer "+TOKEN}
            result=await c.post("/mongodb/mcp",headers=headers,json={"jsonrpc":"2.0","id":1,"method":"tools/list"})
            self.assertEqual(result.status_code,401)
        self.assertFalse(self.requests)

    async def test_registration_rejects_untrusted_redirects_and_extra_scopes(self):
        _,proxy=self.make()
        client,_=await self.prepare_client_code(proxy)
        for uri in ("https://evil.invalid/callback","http://127.0.0.1:1234/evil",
                    "https://claude.ai.evil.invalid/api/mcp/auth_callback",
                    "https://claude.ai/api/mcp/auth_callback?leak=1"):
            with self.assertRaises(ValueError):
                await proxy.register_client(client.model_copy(update={"redirect_uris":[AnyUrl(uri)]}))
        with self.assertRaises(ValueError):
            await proxy.register_client(client.model_copy(update={"scope":"mongodb:write"}))

    async def test_discovery_uses_exact_auth_issuer_and_resource(self):
        verifier,proxy=self.make()
        class Reader:
            def close(self):pass
        app=create_http_app(Reader(),proxy,verifier)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app),base_url="https://fixture.invalid") as c:
            metadata=await c.get("/.well-known/oauth-authorization-server/mongodb/auth")
            self.assertEqual(metadata.status_code,200)
            data=metadata.json()
            self.assertEqual(data["issuer"],"https://mcpgooads.batteryswap.cc/mongodb/auth")
            self.assertEqual(data["authorization_endpoint"],data["issuer"]+"/authorize")
            self.assertEqual(data["token_endpoint"],data["issuer"]+"/token")
            self.assertEqual(data["registration_endpoint"],data["issuer"]+"/register")
            self.assertEqual((await c.get("/mongodb/auth/callback")).status_code,400)
        self.assertFalse(self.requests)

    async def test_invalid_token_no_request(self):
        verifier,_=self.make()
        for token in ("", "fake\r\nheader", None, "x"*4097):
            self.assertIsNone(await verifier.verify_token(token))
        self.assertFalse(self.requests)

    async def test_authorization_requires_exact_resource_scope_and_pkce(self):
        _,proxy=self.make()
        client,_=await self.prepare_client_code(proxy)
        kwargs=dict(state="fixture_state",scopes=[SCOPE],code_challenge=CHALLENGE,
            redirect_uri=client.redirect_uris[0],redirect_uri_provided_explicitly=True,
            resource=RESOURCE)
        for changed in ({"resource":"https://other.invalid/mcp"},
                        {"scopes":["repo"]}, {"scopes":[]}, {"code_challenge":""}):
            with self.assertRaises(AuthorizeError):
                await proxy.authorize(client,AuthorizationParams(**{**kwargs,**changed}))
        url=await proxy.authorize(client,AuthorizationParams(**kwargs))
        self.assertTrue(url.startswith("https://mcpgooads.batteryswap.cc/mongodb/auth/consent?"))
        absent=await proxy.authorize(client,AuthorizationParams(**{**kwargs,"resource":None}))
        self.assertTrue(absent.startswith("https://mcpgooads.batteryswap.cc/mongodb/auth/consent?"))
        self.assertFalse(self.requests)

    async def test_owner_exchange_scoped_jwt_and_refresh_rotation(self):
        _,proxy=self.make()
        client,code=await self.prepare_client_code(proxy)
        result=await proxy.exchange_authorization_code(client,code)
        payload=proxy.jwt_issuer.verify_token(result.access_token)
        self.assertEqual(payload["aud"],RESOURCE)
        self.assertEqual(payload["scope"],SCOPE)
        self.assertEqual(result.expires_in,ACCESS_SECONDS)
        self.assertIsNotNone(await proxy.load_access_token(result.access_token))
        refresh=await proxy.load_refresh_token(client,result.refresh_token)
        self.assertIsNotNone(refresh)
        rotated=await proxy.exchange_refresh_token(client,refresh,[SCOPE])
        self.assertNotEqual(rotated.refresh_token,result.refresh_token)
        self.assertIsNone(await proxy.load_refresh_token(client,result.refresh_token))
        with self.assertRaises(TokenError):await proxy.exchange_refresh_token(client,refresh,[SCOPE])
        with self.assertRaises(TokenError):await proxy.exchange_authorization_code(client,code)

    async def test_other_owner_cannot_obtain_local_tokens(self):
        _,proxy=self.make(lambda _:httpx.Response(200,json={"id":1}))
        client,code=await self.prepare_client_code(proxy)
        with self.assertRaises(TokenError):await proxy.exchange_authorization_code(client,code)

    async def test_wrong_scope_and_audience_jwt_rejected(self):
        _,proxy=self.make()
        for scope in ("repo", ""):
            token=proxy.jwt_issuer.issue_access_token(client_id="fixture_client",scopes=[scope],
                jti="fake_jti",expires_in=900)
            self.assertIsNone(await proxy.load_access_token(token))
        _,other=self.make()
        other.set_mcp_path("/other")
        token=other.jwt_issuer.issue_access_token(client_id="fixture_client",scopes=[SCOPE],
            jti="fake_jti",expires_in=900)
        self.assertIsNone(await proxy.load_access_token(token))
        self.assertFalse(self.requests)

    async def test_http_discovery_health_and_unauthenticated_rejection(self):
        verifier,proxy=self.make()
        class Monitor:
            def close(self):pass
            def find(self,*args):raise AssertionError("unauthorized database read")
        app=create_http_app(Monitor(),proxy,verifier)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app),base_url="https://test.invalid") as c:
            response=await c.post("/mongodb/mcp",json={"jsonrpc":"2.0","id":1,"method":"tools/list"})
            self.assertEqual(response.status_code,401)
            self.assertIn("oauth-protected-resource",response.headers["www-authenticate"])
            metadata=(await c.get("/.well-known/oauth-protected-resource/mongodb/mcp")).json()
            self.assertEqual(metadata["resource"],RESOURCE)
            self.assertEqual(metadata["scopes_supported"],[SCOPE])
            health=await c.get("/mongodb/health")
            self.assertEqual(health.json(),{"ok":True,"mode":"read-only"})
        self.assertFalse(self.requests)

    async def test_http_wrong_pkce_rejected_and_owner_catalog_available(self):
        verifier,proxy=self.make()
        client,code=await self.prepare_client_code(proxy)
        class Monitor:
            def close(self):pass
            def find(self,*args):return []
        app=create_http_app(Monitor(),proxy,verifier)
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app),base_url="https://test.invalid") as c:
                data={"grant_type":"authorization_code","code":code.code,"client_id":client.client_id,
                    "code_verifier":"b"*43,"redirect_uri":str(client.redirect_uris[0]),"resource":RESOURCE}
                bad=await c.post("/mongodb/auth/token",data=data)
                self.assertEqual(bad.status_code,401,bad.text)
                self.assertEqual(bad.json()["error"],"invalid_grant")
                good=await c.post("/mongodb/auth/token",data={**data,"code_verifier":VERIFIER})
                self.assertEqual(good.status_code,200,good.text)
                token=good.json()["access_token"]
                headers={"Authorization":"Bearer "+token,"Accept":"application/json, text/event-stream"}
                initialize=await c.post("/mongodb/mcp",headers=headers,json={"jsonrpc":"2.0","id":1,"method":"initialize",
                    "params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}})
                self.assertEqual(initialize.status_code,200,initialize.text)
                result=await c.post("/mongodb/mcp",headers=headers,json={"jsonrpc":"2.0","id":2,"method":"tools/list"})
                self.assertEqual(result.status_code,200,result.text)
                self.assertIn('"name":"find"',result.text)
                self.assertNotIn('"name":"propose_update"',result.text)
                self.assertNotIn(TOKEN,result.text)
                self.assertNotIn(KEY,result.text)

    async def test_untrusted_client_metadata_url_never_fetched(self):
        _,proxy=self.make()
        for client in ("https://evil.invalid/client.json", "https://chatgpt.com@evil.invalid/oauth/client.json",
                       "https://chatgpt.com/oauth/client.json?extra=1", "file:///private"):
            self.assertIsNone(await proxy.get_client(client))
        self.assertFalse(self.requests)

    async def test_upstream_authorization_scope_stays_empty(self):
        from fastmcp.server.auth.oauth_proxy.models import OAuthTransaction
        _,proxy=self.make()
        transaction=OAuthTransaction(txn_id="fixture",client_id="fixture_client",
            client_redirect_uri="http://127.0.0.1:12345/callback",client_state="state",
            code_challenge=CHALLENGE,code_challenge_method="S256",scopes=[SCOPE],
            created_at=time.time(),resource=RESOURCE,proxy_code_verifier=VERIFIER)
        # Consent uses this public URL builder; the local Atlas scope must not reach GitHub.
        from urllib.parse import urlparse,parse_qs
        url=proxy._build_upstream_authorize_url("fixture",transaction.model_dump())
        query=parse_qs(urlparse(url).query,keep_blank_values=True)
        self.assertEqual(query.get("scope"),[""])
        self.assertEqual(urlparse(url).netloc,"github.com")
        self.assertEqual(proxy._prepare_scopes_for_token_exchange([SCOPE]),[])

    async def test_http_body_limit_before_registration_or_tool_execution(self):
        verifier,proxy=self.make()
        class Monitor:
            def close(self):pass
            def find(self,*args):raise AssertionError("unexpected database read")
        app=create_http_app(Monitor(),proxy,verifier)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app),base_url="https://test.invalid") as c:
            result=await c.post("/mongodb/auth/register",content=b"x"*65537)
            self.assertEqual(result.status_code,413)
        self.assertFalse(self.requests)

    async def test_refresh_bound_to_original_client_and_scope(self):
        _,proxy=self.make()
        client,code=await self.prepare_client_code(proxy)
        result=await proxy.exchange_authorization_code(client,code)
        different=client.model_copy(update={"client_id":"different_client"})
        self.assertIsNone(await proxy.load_refresh_token(different,result.refresh_token))
        refresh=await proxy.load_refresh_token(client,result.refresh_token)
        with self.assertRaises(TokenError):await proxy.exchange_refresh_token(client,refresh,["repo"])
        self.assertIsNotNone(await proxy.load_refresh_token(client,result.refresh_token))

    async def test_refresh_can_renew_expired_upstream_token_without_extra_scopes(self):
        def response(request):
            if request.headers.get("authorization")=="Bearer expired_fixture":
                return httpx.Response(401)
            return httpx.Response(200,json={"id":OWNER_ID})
        _,proxy=self.make(response)
        client,code=await self.prepare_client_code(proxy)
        result=await proxy.exchange_authorization_code(client,code)
        refresh=await proxy.load_refresh_token(client,result.refresh_token)
        payload=proxy.jwt_issuer.verify_token(refresh.token,expected_token_use="refresh")
        mapping=await proxy._jti_mapping_store.get(key=payload["jti"])
        upstream=await proxy._upstream_token_store.get(key=mapping.upstream_token_id)
        upstream.access_token="expired_fixture"
        upstream.refresh_token="fake_upstream_refresh"
        upstream.expires_at=time.time()-1
        await proxy._upstream_token_store.put(key=upstream.upstream_token_id,value=upstream,ttl=600)
        called=[]
        async def renew(value):
            called.append(True)
            value.access_token=TOKEN
            return value
        proxy._try_transparent_refresh=renew
        rotated=await proxy.exchange_refresh_token(client,refresh,[SCOPE])
        self.assertEqual(rotated.scope,SCOPE)
        self.assertEqual(called,[True])


if __name__ == "__main__":unittest.main()
