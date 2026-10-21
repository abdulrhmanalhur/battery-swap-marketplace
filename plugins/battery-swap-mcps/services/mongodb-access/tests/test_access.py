import copy
import json
import sys
import threading
import time
import unittest
import uuid
from pathlib import Path

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from access import (Denied,Namespace,TokenVerifier,ReadGateway,ProposalAuthority,Principal,
                    READ,PROPOSE,APPROVAL_AUDIENCE,digest)
from mcp_gateway import create_server

OWNER="fixture-owner"
CLIENTS={"codex-fixture","claude-fixture"}
ISSUER="https://identity.fixture.invalid"
RESOURCE="https://gateway.fixture.invalid/mongodb/mcp"
APPROVER="https://approval.fixture.invalid"


def public(key):
    return key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)


class FixtureDatabase:
    """JSON fixtures only; no network or production adapter."""
    def __init__(self):
        self.docs={"products":{"one":{"_id":"one","name":"Fixture battery","quantity":10,"api_token":"fixture-not-real"}},
                   "invoices":{"two":{"_id":"two","total":50}}}
        self.writes=[];self.lock=threading.Lock()

    def find(self,database,collection,query,limit):
        if database!="fixture_store":raise AssertionError("cross-database request")
        docs=list(self.docs.get(collection,{}).values())
        return copy.deepcopy([doc for doc in docs if all(doc.get(k)==v for k,v in query.items())][:limit])

    def count(self,database,collection,query):return len(self.find(database,collection,query,100))

    def snapshot(self,database,collection,document_id):
        if database!="fixture_store":raise AssertionError("cross-database request")
        return copy.deepcopy(self.docs.get(collection,{}).get(document_id))

    def commit_if_unchanged(self,plan):
        with self.lock:
            if plan["database"]!="fixture_store" or plan["max_affected"]!=1:raise Denied("SCOPE")
            current=self.docs.get(plan["collection"],{}).get(plan["document_id"])
            if current is None or digest(current)!=plan["before_hash"]:raise Denied("STALE_PREVIEW")
            if plan["operation"]=="update_one":current.update(plan["changes"])
            elif plan["operation"]=="delete_one":del self.docs[plan["collection"]][plan["document_id"]]
            else:raise Denied("OPERATION")
            self.writes.append(plan["id"])
            return 1


class Setup:
    def prepare(self):
        # Ephemeral in-memory fixture keys only; no key files/credentials are created.
        self.read_key=Ed25519PrivateKey.generate();self.approval_key=Ed25519PrivateKey.generate()
        self.namespace=Namespace("fixture_store");self.database=FixtureDatabase()
        self.verifier=TokenVerifier(public(self.read_key),ISSUER,RESOURCE,OWNER,CLIENTS,self.namespace)
        self.reader=ReadGateway(self.namespace,self.database)
        self.authority=ProposalAuthority(self.namespace,self.database,public(self.approval_key),APPROVER,OWNER)
        self.caller=Principal(OWNER,"codex-fixture",frozenset((READ,PROPOSE)))

    def access_token(self,client="codex-fixture",**changes):
        now=int(time.time())
        claims={"iss":ISSUER,"aud":RESOURCE,"sub":OWNER,"client_id":client,
            "database":"fixture_store","scope":READ+" "+PROPOSE,"iat":now,"nbf":now-1,"exp":now+60,"jti":uuid.uuid4().hex}
        claims.update(changes)
        return jwt.encode(claims,self.read_key,algorithm="EdDSA")

    def proposal(self,operation="update_one",caller=None):
        return self.authority.propose(caller or self.caller,"products","one",operation,
            {"quantity":9} if operation=="update_one" else None)

    def approve(self,proposal,key=None,**changes):
        now=int(time.time())
        claims={"iss":APPROVER,"aud":APPROVAL_AUDIENCE,"sub":OWNER,"iat":now,"nbf":now-1,
            "exp":now+120,"jti":uuid.uuid4().hex,"purpose":"execute_exact_mongodb_plan",
            "plan_id":proposal["plan"]["id"],"plan_sha256":proposal["plan_sha256"],
            "requester_client":proposal["plan"]["requester_client"]}
        claims.update(changes)
        return jwt.encode(claims,key or self.approval_key,algorithm="EdDSA")


class AccessTests(Setup,unittest.TestCase):
    def setUp(self):self.prepare()

    def test_both_clients_valid_and_fixed_database(self):
        for client in CLIENTS:self.assertEqual(self.verifier.verify(self.access_token(client)).client,client)
        for claims in ({"database":"other"},{"sub":"other"},{"client_id":"unknown"},
                       {"aud":"https://other.invalid/mcp"},{"scope":"mongodb:write"},{"exp":1}):
            with self.assertRaises(Denied):self.verifier.verify(self.access_token(**claims))

    def test_missing_namespace_and_private_verifier_key_rejected(self):
        for value in (None,"","admin/other","a.b"):
            with self.assertRaises(Denied):Namespace(value)
        with self.assertRaises(Denied):TokenVerifier(b"PRIVATE KEY",ISSUER,RESOURCE,OWNER,CLIENTS,self.namespace)

    def test_all_business_collections_read_and_credential_fields_masked(self):
        result=self.reader.find(self.caller,"products")
        self.assertEqual(result[0]["quantity"],10);self.assertNotIn("api_token",result[0])
        self.assertEqual(self.reader.count(self.caller,"invoices"),1)
        self.assertFalse(self.database.writes)

    def test_system_collection_cross_query_and_secret_filter_rejected(self):
        for collection in ("system.users","$cmd",""):
            with self.assertRaises(Denied):self.reader.find(self.caller,collection)
        for query in ({"$where":"return true"},{"$expr":{}},{"api_token":"x"},
                      {"quantity":{"$in":[{"secret":"x"}]}}):
            with self.assertRaises(Denied):self.reader.find(self.caller,"products",query)
        for limit in (0,101,True):
            with self.assertRaises(Denied):self.reader.find(self.caller,"products",limit=limit)

    def test_proposal_does_not_mutate_and_before_hash_is_not_disclosed(self):
        before=copy.deepcopy(self.database.docs);proposal=self.proposal()
        self.assertEqual(self.database.docs,before);self.assertFalse(self.database.writes)
        self.assertTrue(proposal["approval_required"])
        self.assertNotIn("before_hash",proposal["plan"])
        self.assertNotIn("api_token",proposal["preview_before"])

    def test_update_requires_independent_signature_and_exact_plan(self):
        proposal=self.proposal()
        for token in ("Yes",json.dumps({"confirmation":True}),self.access_token(),
                      self.approve(proposal,key=self.read_key),self.approve(proposal,plan_sha256="0"*64),
                      self.approve(proposal,requester_client="claude-fixture"),self.approve(proposal,exp=1)):
            with self.assertRaises(Denied):self.authority.execute_approved(token)
        self.assertFalse(self.database.writes)
        result=self.authority.execute_approved(self.approve(proposal))
        self.assertEqual(result["affected"],1);self.assertEqual(self.database.docs["products"]["one"]["quantity"],9)

    def test_delete_without_approval_denied_then_exact_one_document(self):
        proposal=self.proposal("delete_one")
        with self.assertRaises(Denied):self.authority.execute_approved("accept")
        self.assertIn("one",self.database.docs["products"])
        self.authority.execute_approved(self.approve(proposal))
        self.assertNotIn("one",self.database.docs["products"])
        self.assertIn("two",self.database.docs["invoices"])

    def test_replay_or_new_ticket_for_completed_plan_never_executes_again(self):
        proposal=self.proposal();ticket=self.approve(proposal)
        self.authority.execute_approved(ticket)
        for repeated in (ticket,self.approve(proposal)):
            with self.assertRaises(Denied):self.authority.execute_approved(repeated)
        self.assertEqual(len(self.database.writes),1)

    def test_stale_document_requires_new_preview_and_approval(self):
        proposal=self.proposal();self.database.docs["products"]["one"]["quantity"]=11
        with self.assertRaises(Denied):self.authority.execute_approved(self.approve(proposal))
        self.assertEqual(self.database.docs["products"]["one"]["quantity"],11);self.assertFalse(self.database.writes)

    def test_unknown_outcome_never_retried(self):
        original=self.database.commit_if_unchanged
        def commit_then_disconnect(plan):original(plan);raise ConnectionError("fixture lost acknowledgement")
        self.database.commit_if_unchanged=commit_then_disconnect
        proposal=self.proposal()
        with self.assertRaisesRegex(Denied,"OUTCOME_UNKNOWN"):self.authority.execute_approved(self.approve(proposal))
        with self.assertRaises(Denied):self.authority.execute_approved(self.approve(proposal))
        self.assertEqual(len(self.database.writes),1)

    def test_read_only_principal_cannot_create_write_plan(self):
        caller=Principal(OWNER,"codex-fixture",frozenset((READ,)))
        with self.assertRaises(Denied):self.proposal(caller=caller)

    def test_bulk_drop_id_change_and_secret_changes_unavailable(self):
        for operation in ("delete_many","drop_database","aggregate","update_many"):
            with self.assertRaises(Denied):self.authority.propose(self.caller,"products","one",operation)
        for patch in ({"_id":"other"},{"password":"x"},{"$set":{}},{"x.y":1}):
            with self.assertRaises(Denied):self.authority.propose(self.caller,"products","one","update_one",patch)


class MCPTests(Setup,unittest.IsolatedAsyncioTestCase):
    def setUp(self):self.prepare()

    async def test_read_only_phase_exposes_no_proposal_or_writer_tools(self):
        for actor in CLIENTS:
            app=create_server(self.verifier,self.reader).http_app(path="/mcp",stateless_http=True)
            async with app.router.lifespan_context(app):
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app),base_url="https://fixture.invalid") as client:
                    headers={"Authorization":"Bearer "+self.access_token(actor,scope=READ),"Accept":"application/json, text/event-stream"}
                    response=await client.post("/mcp",headers=headers,json={"jsonrpc":"2.0","id":1,"method":"tools/list"})
                    self.assertEqual(response.status_code,200)
                    payload=response.text
                    if payload.startswith("event:"):
                        payload=next(line[6:] for line in payload.splitlines() if line.startswith("data: "))
                    names={tool["name"] for tool in json.loads(payload)["result"]["tools"]}
                    self.assertEqual(names,{"find","count"})
                    denied=await client.post("/mcp",headers=headers,json={"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"propose_update","arguments":{}}})
                    self.assertIn("Unknown tool",denied.text)
        self.assertFalse(self.database.writes)

    async def test_unauthenticated_and_wrong_audience_denied(self):
        app=create_server(self.verifier,self.reader,self.authority).http_app(path="/mcp",stateless_http=True)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app),base_url="https://fixture.invalid") as client:
            for token in (None,self.access_token(aud="https://wrong.invalid")):
                headers={} if token is None else {"Authorization":"Bearer "+token}
                response=await client.post("/mcp",headers=headers,json={"jsonrpc":"2.0","id":1,"method":"tools/list"})
                self.assertEqual(response.status_code,401)
        self.assertFalse(self.database.writes)

    async def test_codex_claude_without_elicitation_have_no_approve_or_execute_tool(self):
        for actor in CLIENTS:
            app=create_server(self.verifier,self.reader,self.authority).http_app(path="/mcp",stateless_http=True)
            async with app.router.lifespan_context(app):
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app),base_url="https://fixture.invalid") as client:
                    headers={"Authorization":"Bearer "+self.access_token(actor),"Accept":"application/json, text/event-stream"}
                    init=await client.post("/mcp",headers=headers,json={"jsonrpc":"2.0","id":1,"method":"initialize", "params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":actor,"version":"fixture"}}})
                    self.assertEqual(init.status_code,200)
                    response=await client.post("/mcp",headers=headers,json={"jsonrpc":"2.0","id":2,"method":"tools/list"})
                    self.assertEqual(response.status_code,200)
                    text=response.text
                    for allowed in ("find","count","propose_update","propose_delete"):self.assertIn('"name":"'+allowed+'"',text)
                    for forbidden in ("approve","execute_approved","connect","drop_database"):
                        self.assertNotIn('"name":"'+forbidden+'"',text)
                    result=await client.post("/mcp",headers=headers,json={"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"find","arguments":{"collection":"products","limit":1}}})
                    self.assertEqual(result.status_code,200);self.assertIn("Fixture battery",result.text)
                    self.assertNotIn("fixture-not-real",result.text)
                    proposed=await client.post("/mcp",headers=headers,json={"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"propose_update","arguments":{"collection":"products","document_id":"one","changes":{"quantity":8}}}})
                    self.assertEqual(proposed.status_code,200)
                    self.assertIn("approval_required",proposed.text)
                    self.assertEqual(self.database.docs["products"]["one"]["quantity"],10)
                    bypass=await client.post("/mcp",headers=headers,json={"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"execute_approved","arguments":{"confirmation":True}}})
                    self.assertNotIn('"status":"committed"',bypass.text)
        self.assertFalse(self.database.writes)

if __name__=="__main__":unittest.main()
