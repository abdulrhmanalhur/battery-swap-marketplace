import hashlib
import json
import sys
import unittest
from pathlib import Path
from urllib.request import parse_http_list

import httpx

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from atlas_monitor import AtlasError, AtlasMonitor, PREFIX, PROJECT_ID
from server import runtime_credentials, runtime_auth_mode
from test_atlas_monitor import CLUSTER, PROCESS, HOST, START, END, SECRET

CHALLENGE='Digest realm="MMS Public API",nonce="fake-nonce",algorithm=MD5,qop="auth"'
PUBLIC='fake-pub'


def fields(header):
    return {k:v.strip('"') for k,v in (part.split('=',1) for part in parse_http_list(header[len('Digest '):]))}


class DigestTests(unittest.IsolatedAsyncioTestCase):
    def make(self,extra=None,**options):
        self.requests=[]
        def handler(req):
            self.requests.append(req)
            if extra:
                response=extra(req)
                if response is not None:return response
            if 'authorization' not in req.headers:
                return httpx.Response(401,headers={'WWW-Authenticate':CHALLENGE},json={'detail':SECRET})
            if req.url.path==PREFIX+'/clusters/Cluster0':return httpx.Response(200,json=CLUSTER)
            if req.url.path==PREFIX+'/processes':return httpx.Response(200,json={'results':[PROCESS]})
            if req.url.path.endswith('/measurements'):
                return httpx.Response(200,json={'groupId':PROJECT_ID,'processId':HOST,'measurements':[{'name':'CONNECTIONS','dataPoints':[{'timestamp':START,'value':499}]}]})
            raise AssertionError('Unexpected route')
        client=AtlasMonitor(PUBLIC,SECRET,transport=httpx.MockTransport(handler),auth_mode='api_key',**options)
        self.addAsyncCleanup(client.close)
        return client

    async def test_digest_correct_hash_get_only_and_no_secret_output(self):
        result=await self.make().connections(START,END)
        self.assertEqual(result['status'],'available')
        self.assertEqual(result['nodes'][0]['peak'],499)
        self.assertEqual(len(self.requests),4)
        self.assertTrue(all(r.method=='GET' for r in self.requests))
        for request in self.requests[1:]:
            header=request.headers['Authorization']
            self.assertTrue(header.startswith('Digest '))
            self.assertNotIn(SECRET,header)
            self.assertNotIn('Basic',header)
            self.assertNotIn('Bearer',header)
            f=fields(header)
            md5=lambda v:hashlib.md5(v.encode()).hexdigest()
            ha1=md5(PUBLIC+':MMS Public API:'+SECRET)
            ha2=md5('GET:'+request.url.raw_path.decode())
            expected=md5(':'.join((ha1,f['nonce'],f['nc'],f['cnonce'],'auth',ha2)))
            self.assertEqual(f['response'],expected)
            self.assertEqual(f['uri'],request.url.raw_path.decode())
            self.assertEqual(request.headers['accept-encoding'],'identity')
        self.assertNotIn(SECRET,json.dumps(result))

    async def test_auth_failure_bounded_without_oauth_fallback(self):
        result=await self.make(lambda req:httpx.Response(401,headers={'WWW-Authenticate':CHALLENGE},json={'detail':SECRET})).connections(START,END)
        self.assertEqual(result['code'],'UNAUTHORIZED')
        self.assertEqual(len(self.requests),2)
        self.assertTrue(all(r.method=='GET' for r in self.requests))
        self.assertNotIn(SECRET,json.dumps(result))

    async def test_basic_challenge_does_not_receive_credentials(self):
        result=await self.make(lambda req:httpx.Response(401,headers={'WWW-Authenticate':'Basic realm="fake"'})).connections(START,END)
        self.assertEqual(result['code'],'UNAUTHORIZED')
        self.assertEqual(len(self.requests),1)
        self.assertNotIn('authorization',self.requests[0].headers)

    async def test_redirect_never_receives_key_or_follows(self):
        result=await self.make(lambda req:httpx.Response(302,headers={'Location':'https://evil.invalid/'})).connections(START,END)
        self.assertEqual(result['http_status'],302)
        self.assertEqual(len(self.requests),1)
        self.assertTrue(str(self.requests[0].url).startswith('https://cloud.mongodb.com/'))

    async def test_malformed_and_unsupported_challenges_are_safe(self):
        for challenge in ('Digest nonce="fake"','Digest realm="fake",nonce="fake",algorithm=UNKNOWN,qop="auth"',
                          'Digest realm="fake",nonce="fake",qop="auth-int"'):
            result=await self.make(lambda req:httpx.Response(401,headers={'WWW-Authenticate':challenge})).connections(START,END)
            self.assertEqual(result['status'],'unavailable')
            self.assertIn(result['code'],('NETWORK_ERROR','INVALID_AUTH_CHALLENGE'))
            self.assertNotIn(challenge,json.dumps(result))
            self.assertEqual(len(self.requests),1)

    async def test_oversized_intermediate_digest_body_rejected(self):
        class Large(httpx.AsyncByteStream):
            async def __aiter__(self):
                for _ in range(33):yield b'x'*65536
        result=await self.make(lambda req:httpx.Response(401,headers={'WWW-Authenticate':CHALLENGE},stream=Large())).connections(START,END)
        self.assertEqual(result['code'],'RESPONSE_TOO_LARGE')
        self.assertEqual(len(self.requests),1)

    async def test_compressed_digest_body_rejected_before_decode(self):
        result=await self.make(lambda req:httpx.Response(401,headers={'WWW-Authenticate':CHALLENGE,'Content-Encoding':'gzip'},stream=httpx.ByteStream(b'unread'))).connections(START,END)
        self.assertEqual(result['code'],'UNEXPECTED_CONTENT_ENCODING')
        self.assertEqual(len(self.requests),1)

    async def test_digest_deadline_includes_challenge_body(self):
        import asyncio
        class Slow(httpx.AsyncByteStream):
            async def __aiter__(self):
                await asyncio.sleep(0.1)
                yield b'{}'
        result=await self.make(lambda req:httpx.Response(401,headers={'WWW-Authenticate':CHALLENGE},stream=Slow()),request_seconds=0.01).connections(START,END)
        self.assertEqual(result['code'],'REQUEST_TIMEOUT')
        self.assertEqual(len(self.requests),1)

    async def test_key_mode_missing_credentials_no_network(self):
        client=AtlasMonitor(auth_mode='api_key',transport=httpx.MockTransport(lambda req:self.fail('network')))
        self.addAsyncCleanup(client.close)
        self.assertEqual((await client.connections(START,END))['code'],'NOT_CONFIGURED')

    async def test_unknown_mode_no_automatic_selection(self):
        with self.assertRaises(AtlasError):AtlasMonitor(auth_mode='auto')
        with self.assertRaisesRegex(RuntimeError,'INVALID_AUTH_MODE'):runtime_auth_mode({'ATLAS_MONITOR_AUTH_MODE':'auto'})
        self.assertEqual(runtime_auth_mode({}),'service_account')

    async def test_digest_private_files_and_no_cross_mode_fallback(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory)/'atlas_public_key').write_text(PUBLIC,encoding='utf-8')
            (Path(directory)/'atlas_private_key').write_text(SECRET,encoding='utf-8')
            env={'ATLAS_MONITOR_AUTH_MODE':'api_key','CREDENTIALS_DIRECTORY':directory,'ATLAS_MONITOR_CLIENT_SECRET':'ignored-fake'}
            self.assertEqual(runtime_credentials(env),(PUBLIC,SECRET))
            with self.assertRaisesRegex(RuntimeError,'PRIVATE_CREDENTIAL_LOADING_UNAVAILABLE'):
                runtime_credentials({**env,'ATLAS_MONITOR_AUTH_MODE':'service_account'})

    async def test_public_key_header_injection_rejected(self):
        for key in ('fake"pub', 'fake'+chr(10)+'pub', 'fake'+chr(13)+'pub'):
            with self.assertRaises(AtlasError) as caught:
                AtlasMonitor(key,SECRET,auth_mode='api_key')
            self.assertEqual(caught.exception.code,'INVALID_CREDENTIAL_FORMAT')
            self.assertNotIn(key,str(caught.exception))
