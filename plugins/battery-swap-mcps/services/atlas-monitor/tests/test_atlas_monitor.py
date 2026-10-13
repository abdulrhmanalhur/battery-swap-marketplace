import asyncio
import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from atlas_monitor import AtlasError, AtlasMonitor, CLUSTER_NAME, PREFIX, PROJECT_ID, cluster_hosts, select_processes, cluster_summary, alert_summary
from server import create_server, runtime_credentials

START, END = "2026-10-13T05:10:00Z", "2026-10-13T05:45:00Z"
HOST = "cluster0-a.mongodb.net:27017"
CLUSTER = {"name": CLUSTER_NAME, "groupId": PROJECT_ID,
           "connectionStrings": {"standard": "mongodb://" + HOST + "/?replicaSet=fake"}}
PROCESS = {"id": HOST, "groupId": PROJECT_ID, "port": 27017}
SECRET = "fake-test-secret-never-real"
TOKEN = "fake-test-access-token"


class ReaderTests(unittest.IsolatedAsyncioTestCase):
    def make(self, extra=None, cluster=None, processes=None, **kwargs):
        self.requests = []
        def handler(req):
            self.requests.append(req)
            if extra:
                response = extra(req)
                if response is not None: return response
            path = req.url.path
            if path == "/api/oauth/token":
                return httpx.Response(200, json={"access_token": TOKEN, "expires_in": 3600, "token_type": "Bearer"})
            if path == PREFIX + "/clusters/Cluster0":
                return httpx.Response(200, json=cluster if cluster is not None else CLUSTER)
            if path == PREFIX + "/processes":
                return httpx.Response(200, json={"results": processes if processes is not None else [PROCESS]})
            if path.endswith("/measurements"):
                return httpx.Response(200, json={"groupId": PROJECT_ID, "processId": HOST,
                    "measurements": [{"name": "CONNECTIONS", "dataPoints": [
                        {"timestamp": START, "value": 501}, {"timestamp": END, "value": None}]}]})
            raise AssertionError("Unexpected route")
        client = AtlasMonitor("fake-client-id", SECRET, transport=httpx.MockTransport(handler), **kwargs)
        self.addAsyncCleanup(client.close)
        return client

    async def test_samples_null_latest_and_secret_free_output(self):
        result = await self.make().connections(START, END)
        self.assertEqual(result["nodes"][0]["peak"], 501)
        self.assertIsNone(result["nodes"][0]["latest"])
        output = json.dumps(result)
        for secret in (SECRET, TOKEN, "mongodb://"):
            self.assertNotIn(secret, output)
        metric = self.requests[-1]
        self.assertEqual(metric.url.params["m"], "CONNECTIONS")
        self.assertEqual(metric.method, "GET")
        self.assertTrue(all(str(r.url).startswith("https://cloud.mongodb.com/") for r in self.requests))
        self.assertEqual([r.method for r in self.requests], ["POST", "GET", "GET", "GET"])
        self.assertEqual(self.requests[0].content, b"grant_type=client_credentials")

    async def test_missing_credentials_no_network(self):
        client = AtlasMonitor(transport=httpx.MockTransport(lambda _: self.fail("network")))
        self.addAsyncCleanup(client.close)
        self.assertEqual((await client.connections(START, END))["code"], "NOT_CONFIGURED")

    async def test_invalid_inputs_before_network(self):
        client = self.make()
        for start, end, granularity in [("invalid", END, "PT1M"), (END, START, "PT1M"),
                                       ("2026-10-13T05:00:00", END, "PT1M"),
                                       ("2026-10-11T05:00:00Z", END, "PT1M"),
                                       (START, END, "PT1S")]:
            result = await client.connections(start, end, granularity)
            self.assertEqual(result["status"], "unavailable")
        self.assertFalse(self.requests)

    async def test_foreign_process_excluded(self):
        foreign = {"id": "foreign.mongodb.net:27017", "groupId": PROJECT_ID}
        result = await self.make(processes=[foreign, PROCESS]).connections(START, END)
        self.assertEqual(result["returned_nodes"], 1)
        self.assertNotIn("foreign", json.dumps(result))
        self.assertFalse(any("foreign" in str(r.url) for r in self.requests))

    async def test_wrong_project_same_host_excluded(self):
        row = {**PROCESS, "groupId": "0"*24}
        result = await self.make(processes=[row]).connections(START, END)
        self.assertEqual(result["code"], "CLUSTER_PROCESSES_UNAVAILABLE")
        self.assertFalse(any(r.url.path.endswith("/measurements") for r in self.requests))

    async def test_cluster_scope_fail_closed(self):
        result = await self.make(cluster={**CLUSTER, "name": "OtherCluster"}).connections(START, END)
        self.assertEqual(result["code"], "CLUSTER_SCOPE_MISMATCH")
        self.assertEqual(len(self.requests), 2)

    async def test_no_standard_hosts_no_guessing(self):
        for strings in ({"standardSrv": "mongodb+srv://fake.mongodb.net"}, None):
            result = await self.make(cluster={**CLUSTER, "connectionStrings": strings}).connections(START, END)
            self.assertEqual(result["code"], "CLUSTER_HOST_MAPPING_UNAVAILABLE")
            self.assertEqual(len(self.requests), 2)

    async def test_credential_uri_rejected_without_echo(self):
        cluster = {**CLUSTER, "connectionStrings": {"standard": "mongodb://user:"+SECRET+"@"+HOST}}
        result = await self.make(cluster=cluster).connections(START, END)
        self.assertEqual(result["code"], "CLUSTER_HOST_MAPPING_UNAVAILABLE")
        self.assertNotIn(SECRET, json.dumps(result))

    async def test_alias_mapping(self):
        row = {**PROCESS, "id": "internal.mongodb.net:27017", "userAlias": "cluster0-a.mongodb.net"}
        self.assertEqual(select_processes([row], cluster_hosts(CLUSTER)), [row["id"]])

    async def test_partial_mapping_reported(self):
        cluster = {**CLUSTER, "connectionStrings": {"standard": "mongodb://"+HOST+",missing.mongodb.net:27017/"}}
        result = await self.make(cluster=cluster).connections(START, END)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["expected_nodes"], 2)

    async def test_missing_metric_not_zero(self):
        def extra(req):
            if req.url.path.endswith("/measurements"):
                return httpx.Response(200, json={"groupId":PROJECT_ID,"processId":HOST,"measurements": []})
        result = await self.make(extra).connections(START, END)
        self.assertEqual(result["nodes"][0]["status"], "missing_data")
        self.assertIsNone(result["nodes"][0]["peak"])
        self.assertEqual(result["status"], "partial")

    async def test_403_and_404_do_not_expand_permissions(self):
        for status, code in [(403,"FORBIDDEN_ROLE_OR_API_ACCESS_LIST"),(404,"RESOURCE_OR_CAPABILITY_UNAVAILABLE")]:
            def extra(req):
                if req.url.path.endswith("/measurements"):
                    return httpx.Response(status, json={"detail": SECRET})
            result = await self.make(extra).connections(START, END)
            self.assertEqual(result["nodes"][0]["code"], code)
            self.assertEqual(result["nodes"][0]["http_status"], status)
            self.assertNotIn(SECRET, json.dumps(result))
            self.assertEqual(len(self.requests), 4)

    async def test_429_cooldown_no_immediate_retry(self):
        def extra(req):
            if req.url.path.endswith("/measurements"):
                return httpx.Response(429, headers={"Retry-After": "120"}, json={"detail": SECRET})
        client = self.make(extra)
        first = await client.connections(START, END)
        self.assertEqual(first["nodes"][0]["retry_after_seconds"], 120)
        count = len(self.requests)
        second = await client.connections(START, END)
        self.assertEqual(second["code"], "RATE_LIMITED")
        self.assertEqual(count, len(self.requests))

    async def test_429_http_date(self):
        from email.utils import format_datetime
        from datetime import timedelta
        def extra(req):
            if req.url.path.endswith("/measurements"):
                return httpx.Response(429, headers={"Retry-After": format_datetime(datetime.now(timezone.utc)+timedelta(seconds=90),usegmt=True)})
        result = await self.make(extra).connections(START, END)
        self.assertGreater(result["nodes"][0]["retry_after_seconds"], 85)

    async def test_token_cache_and_one_refresh(self):
        state = {"gets": 0}
        def extra(req):
            if req.method == "GET":
                state["gets"] += 1
                if state["gets"] == 1: return httpx.Response(401, json={"detail": SECRET})
        client = self.make(extra)
        await client.connections(START, END)
        await client.connections(START, END)
        self.assertEqual(sum(r.method == "POST" for r in self.requests), 2)

    async def test_repeated_401_bounded_and_redacted(self):
        def extra(req):
            if req.method == "GET": return httpx.Response(401, json={"detail": TOKEN+SECRET})
        result = await self.make(extra).connections(START, END)
        self.assertEqual(result["code"], "UNAUTHORIZED")
        self.assertEqual(len(self.requests), 4)
        self.assertNotIn(SECRET, json.dumps(result))

    async def test_redirect_not_followed(self):
        def extra(req):
            if req.method == "GET": return httpx.Response(302, headers={"Location":"https://evil.invalid/"})
        result = await self.make(extra).connections(START, END)
        self.assertEqual(result["http_status"], 302)
        self.assertEqual(len(self.requests), 2)

    async def test_transport_failure_redacted(self):
        def extra(req): raise httpx.ConnectError(SECRET+TOKEN)
        result = await self.make(extra).connections(START, END)
        self.assertEqual(result["code"], "NETWORK_ERROR")
        self.assertNotIn(SECRET, json.dumps(result))

    async def test_503_single_retry(self):
        attempts = {"n":0}
        def extra(req):
            if req.url.path.endswith("/measurements"):
                attempts["n"] += 1
                return httpx.Response(503)
        result = await self.make(extra).connections(START, END)
        self.assertEqual(attempts["n"], 2)
        self.assertEqual(result["nodes"][0]["http_status"], 503)

    async def test_pagination_cap_no_link_following(self):
        def extra(req):
            if req.url.path == PREFIX + "/processes":
                return httpx.Response(200, json={"results":[{}]*100,"links":[{"rel":"next","href":"https://evil.invalid/"}]})
        result = await self.make(extra).connections(START, END)
        self.assertEqual(result["code"], "PROCESS_PAGINATION_LIMIT")
        self.assertEqual(sum(r.url.path == PREFIX+"/processes" for r in self.requests), 5)

    async def test_invalid_numeric_metric_and_scope(self):
        for value in (-1, True, "501", float('nan')):
            def extra(req):
                if req.url.path.endswith("/measurements"):
                    return httpx.Response(200,content=json.dumps({"groupId":PROJECT_ID,"processId":HOST,"measurements":[{"name":"CONNECTIONS","dataPoints":[{"timestamp":START,"value":value}]}]}).encode())
            result = await self.make(extra).connections(START, END)
            self.assertEqual(result["nodes"][0]["code"], "INVALID_RESPONSE")

    async def test_wrong_measurement_process_rejected(self):
        def extra(req):
            if req.url.path.endswith("/measurements"): return httpx.Response(200,json={"processId":"other:27017","measurements":[]})
        result = await self.make(extra).connections(START,END)
        self.assertEqual(result["nodes"][0]["code"], "MEASUREMENT_SCOPE_MISMATCH")

    async def test_body_size_limit(self):
        def extra(req):
            return httpx.Response(200,content=b'x'*(2*1024*1024+1))
        result = await self.make(extra).connections(START,END)
        self.assertEqual(result["code"], "RESPONSE_TOO_LARGE")

    async def test_request_timeout_includes_body(self):
        class Slow(httpx.AsyncByteStream):
            async def __aiter__(self):
                await asyncio.sleep(0.1)
                yield b'{}'
        def extra(req): return httpx.Response(200,stream=Slow())
        result = await self.make(extra,request_seconds=0.01).connections(START,END)
        self.assertEqual(result["code"], "REQUEST_TIMEOUT")

    async def test_call_deadline_and_serialization(self):
        client = self.make(call_seconds=0.01)
        await client._call_lock.acquire()
        try:
            result = await client.connections(START,END)
            self.assertEqual(result["code"], "CALL_TIMEOUT")
            self.assertFalse(self.requests)
        finally: client._call_lock.release()

    async def test_arbitrary_path_rejected(self):
        client = self.make()
        for path in (PREFIX+"/alerts",PREFIX+"/clusters/Other",PREFIX+"/processes/foreign%3A27017/measurements","https://evil.invalid"):
            with self.assertRaises(AtlasError): await client._get(path,{"m":"CONNECTIONS"})
        self.assertFalse(self.requests)

    async def test_mcp_catalog_only_one_read_tool(self):
        server = create_server(self.make())
        tools = await server.list_tools()
        self.assertEqual([x.name for x in tools], ['atlas_connections'])
        schema = tools[0].inputSchema
        self.assertEqual(set(schema['properties']), {'start_utc','end_utc','granularity'})
        self.assertTrue(tools[0].annotations.readOnlyHint)
        self.assertFalse(tools[0].annotations.destructiveHint)


    async def test_duplicate_alias_mapping_rejected(self):
        rows = [{**PROCESS,"id":"internal-a.mongodb.net:27017","userAlias":"cluster0-a.mongodb.net"},
                {**PROCESS,"id":"internal-b.mongodb.net:27017","userAlias":"cluster0-a.mongodb.net"}]
        result = await self.make(processes=rows).connections(START,END)
        self.assertEqual(result['code'],'CLUSTER_PROCESS_MAPPING_AMBIGUOUS')
        self.assertFalse(any(r.url.path.endswith('/measurements') for r in self.requests))

    async def test_bad_json_and_token_metadata(self):
        for response in (httpx.Response(200,content=b'not-json'),
                         httpx.Response(200,json={'access_token':TOKEN,'expires_in':3600,'token_type':'Other'})):
            def extra(req): return response
            result = await self.make(extra).connections(START,END)
            self.assertIn(result['code'],('INVALID_RESPONSE','INVALID_TOKEN_RESPONSE'))
            self.assertNotIn(TOKEN,json.dumps(result))

    async def test_concurrent_calls_serialized(self):
        state={'active':0,'peak':0}
        async def handler(req):
            state['active']+=1
            state['peak']=max(state['peak'],state['active'])
            await asyncio.sleep(0.002)
            state['active']-=1
            if req.method=='POST': return httpx.Response(200,json={'access_token':TOKEN,'expires_in':3600,'token_type':'Bearer'})
            if req.url.path.endswith('/clusters/Cluster0'): return httpx.Response(200,json=CLUSTER)
            if req.url.path==PREFIX+'/processes': return httpx.Response(200,json={'results':[PROCESS]})
            return httpx.Response(200,json={'groupId':PROJECT_ID,'processId':HOST,'measurements':[{'name':'CONNECTIONS','dataPoints':[{'timestamp':START,'value':10}]}]})
        client=AtlasMonitor('fake-id',SECRET,transport=httpx.MockTransport(handler))
        self.addAsyncCleanup(client.close)
        results=await asyncio.gather(client.connections(START,END),client.connections(START,END))
        self.assertTrue(all(r['status']=='available' for r in results))
        self.assertEqual(state['peak'],1)

    async def test_stdio_handshake_catalog_and_missing_credentials(self):
        import os
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
        path=Path(__file__).resolve().parents[1]/'server.py'
        # Explicitly blank candidate credentials, never inherit real ones into the test server.
        params=StdioServerParameters(command=sys.executable,args=[str(path)],
                    env={'ATLAS_MONITOR_CLIENT_ID':'','ATLAS_MONITOR_CLIENT_SECRET':''})
        async with stdio_client(params) as (read,write):
            async with ClientSession(read,write) as session:
                await session.initialize()
                listed=await session.list_tools()
                self.assertEqual([t.name for t in listed.tools],['atlas_connections'])
                result=await session.call_tool('atlas_connections',{'start_utc':START,'end_utc':END})
                content=json.dumps(result.model_dump())
                self.assertIn('NOT_CONFIGURED',content)
                self.assertNotIn(SECRET,content)
                self.assertNotIn(TOKEN,content)


    async def test_existing_cluster_metadata_adapter_redacted(self):
        result=cluster_summary({**CLUSTER,'stateName':'IDLE','paused':False,'privateSecret':SECRET})
        self.assertEqual(result['state'],'IDLE')
        self.assertFalse(result['paused'])
        self.assertNotIn('mongodb://',json.dumps(result))
        self.assertNotIn(SECRET,json.dumps(result))
        with self.assertRaises(AtlasError): cluster_summary({**CLUSTER,'groupId':'0'*24})

    async def test_existing_alert_adapter_scoping_and_redaction(self):
        alert={'groupId':PROJECT_ID,'clusterName':CLUSTER_NAME,'metricName':'CONNECTIONS',
               'status':'OPEN','created':START,'notifications':[{'emailAddress':SECRET}],'detail':TOKEN}
        unrelated={**alert,'clusterName':'OtherCluster','groupId':'0'*24}
        ambiguous={**alert,'clusterName':'OtherCluster'}
        result=alert_summary([alert,unrelated,ambiguous],[HOST])
        self.assertEqual(len(result['alerts']),1)
        self.assertEqual(result['unattributed_connection_alerts'],1)
        self.assertFalse(result['source_complete'])
        self.assertNotIn(SECRET,json.dumps(result))
        self.assertNotIn(TOKEN,json.dumps(result))

    async def test_existing_alert_process_match_and_recovery(self):
        alert={'groupId':PROJECT_ID,'hostnameAndPort':HOST,'metricName':'CONNECTIONS','status':'CLOSED','resolved':END}
        result=alert_summary([alert],[HOST],complete=True)
        self.assertTrue(result['source_complete'])
        self.assertEqual(result['alerts'][0]['status'],'CLOSED')
        self.assertEqual(result['alerts'][0]['resolved'],'2026-10-13T05:45:00+00:00')

    async def test_unattributed_empty_alerts_not_full_recovery(self):
        alert={'groupId':PROJECT_ID,'metricName':'CONNECTIONS','status':'OPEN'}
        result=alert_summary([alert],[HOST],complete=True)
        self.assertFalse(result['alerts'])
        self.assertEqual(result['unattributed_connection_alerts'],1)


    async def test_missing_identity_fields_fail_closed(self):
        cluster={**CLUSTER};cluster.pop('groupId')
        result=await self.make(cluster=cluster).connections(START,END)
        self.assertEqual(result['code'],'CLUSTER_SCOPE_MISMATCH')
        def extra(req):
            if req.url.path.endswith('/measurements'):
                return httpx.Response(200,json={'measurements':[]})
        result=await self.make(extra).connections(START,END)
        self.assertEqual(result['nodes'][0]['code'],'MEASUREMENT_SCOPE_MISMATCH')

    async def test_oversized_process_page_rejected(self):
        def extra(req):
            if req.url.path==PREFIX+'/processes': return httpx.Response(200,json={'results':[PROCESS]*101})
        result=await self.make(extra).connections(START,END)
        self.assertEqual(result['code'],'INVALID_RESPONSE')
        self.assertEqual(len(self.requests),3)

    async def test_oversized_metric_points_rejected(self):
        def extra(req):
            if req.url.path.endswith('/measurements'):
                return httpx.Response(200,json={'groupId':PROJECT_ID,'processId':HOST,'measurements':[{'name':'CONNECTIONS','dataPoints':[{'timestamp':START,'value':1}]*1501}]})
        result=await self.make(extra).connections(START,END)
        self.assertEqual(result['nodes'][0]['code'],'INVALID_RESPONSE')

    async def test_duplicate_metric_and_timestamps_rejected(self):
        metric={'name':'CONNECTIONS','dataPoints':[{'timestamp':START,'value':1}]}
        for metrics in ([metric,metric],[{**metric,'dataPoints':[{'timestamp':START,'value':1},{'timestamp':START,'value':501}]}]):
            def extra(req):
                if req.url.path.endswith('/measurements'): return httpx.Response(200,json={'groupId':PROJECT_ID,'processId':HOST,'measurements':metrics})
            result=await self.make(extra).connections(START,END)
            self.assertEqual(result['nodes'][0]['code'],'INVALID_RESPONSE')

    async def test_huge_numeric_values_do_not_crash(self):
        def extra(req):
            if req.url.path.endswith('/measurements'):
                return httpx.Response(200,content=json.dumps({'groupId':PROJECT_ID,'processId':HOST,'measurements':[{'name':'CONNECTIONS','dataPoints':[{'timestamp':START,'value':10**1000}]}]}).encode())
        result=await self.make(extra).connections(START,END)
        self.assertEqual(result['nodes'][0]['code'],'INVALID_RESPONSE')

    async def test_deep_json_rejected_without_raw_content(self):
        def extra(req): return httpx.Response(200,content=b'['*1500+b'0'+b']'*1500)
        result=await self.make(extra).connections(START,END)
        self.assertEqual(result['code'],'INVALID_RESPONSE')

    async def test_503_retry_after_retains_actual_status(self):
        def extra(req):
            if req.url.path.endswith('/measurements'): return httpx.Response(503,headers={'Retry-After':'120'})
        client=self.make(extra)
        result=await client.connections(START,END)
        self.assertEqual(result['nodes'][0]['code'],'TEMPORARILY_UNAVAILABLE')
        self.assertEqual(result['nodes'][0]['http_status'],503)
        count=len(self.requests)
        result=await client.connections(START,END)
        self.assertEqual(result['http_status'],503)
        self.assertEqual(len(self.requests),count)

    async def test_other_cluster_alert_name_overrides_host_match(self):
        alert={'groupId':PROJECT_ID,'clusterName':'OtherCluster','hostnameAndPort':HOST,'metricName':'CONNECTIONS','status':'OPEN'}
        result=alert_summary([alert],[HOST])
        self.assertFalse(result['alerts'])
        self.assertEqual(result['unattributed_connection_alerts'],1)


    async def test_systemd_credentials_prefer_private_files(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory)/'atlas_client_id').write_text('fake-id',encoding='utf-8')
            (Path(directory)/'atlas_client_secret').write_text(SECRET,encoding='utf-8')
            result=runtime_credentials({'CREDENTIALS_DIRECTORY':directory,'ATLAS_MONITOR_CLIENT_SECRET':'ignored-fake'})
            self.assertEqual(result,('fake-id',SECRET))

    async def test_private_file_failure_does_not_fall_back_or_echo(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError,'PRIVATE_CREDENTIAL_LOADING_UNAVAILABLE'):
                runtime_credentials({'CREDENTIALS_DIRECTORY':directory,'ATLAS_MONITOR_CLIENT_SECRET':SECRET})
            (Path(directory)/'atlas_client_id').write_text('fake-id',encoding='utf-8')
            for invalid in ('',SECRET+'\n','x'*4097):
                (Path(directory)/'atlas_client_secret').write_text(invalid,encoding='utf-8')
                with self.assertRaises(RuntimeError) as caught:
                    runtime_credentials({'CREDENTIALS_DIRECTORY':directory})
                self.assertNotIn(SECRET,str(caught.exception))


    async def test_safe_api_error_enum_only(self):
        def extra(req):
            if req.method=='GET':return httpx.Response(403,json={'errorCode':'IP_ADDRESS_NOT_ON_ACCESS_LIST','detail':SECRET})
        result=await self.make(extra).connections(START,END)
        self.assertEqual(result['atlas_error_code'],'IP_ADDRESS_NOT_ON_ACCESS_LIST')
        self.assertNotIn(SECRET,json.dumps(result))

    async def test_access_denial_stops_other_node_queries(self):
        second='cluster0-b.mongodb.net:27017'
        cluster={**CLUSTER,'connectionStrings':{'standard':'mongodb://'+HOST+','+second+'/'}}
        rows=[PROCESS,{'id':second,'groupId':PROJECT_ID,'port':27017}]
        def extra(req):
            if req.url.path.endswith('/measurements'):return httpx.Response(403,json={'errorCode':'NOT_IN_GROUP'})
        result=await self.make(extra,cluster=cluster,processes=rows).connections(START,END)
        self.assertEqual(len(result['nodes']),1)
        self.assertEqual(result['status'],'partial')
        self.assertEqual(result['expected_nodes'],2)
        self.assertEqual(result['mapped_nodes'],2)
        self.assertEqual(result['returned_nodes'],1)
        self.assertEqual(sum(r.url.path.endswith('/measurements') for r in self.requests),1)


if __name__ == '__main__': unittest.main()
