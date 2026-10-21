"""Offline access-control core. No credentials, network, real DB adapter or key issuance."""
from __future__ import annotations
import copy
import hashlib
import json
import re
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Protocol

import jwt

READ = "mongodb:read"
PROPOSE = "mongodb:propose"
APPROVAL_AUDIENCE = "mongodb-approved-executor"
SECRET = re.compile(r"password|passwd|secret|token|credential|connection.?string|api.?key|private.?key", re.I)


class Denied(ValueError):
    pass


def canonical(value):
    try:
        return json.dumps(value,sort_keys=True,separators=(",", ":"),ensure_ascii=True,allow_nan=False).encode()
    except (ValueError,TypeError):
        raise Denied("JSON_OR_CANONICAL_EXTENDED_JSON_REQUIRED") from None


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def field_name(name):
    if (not isinstance(name,str) or not name or len(name)>128 or "\0" in name
            or "$" in name or SECRET.search(name)):
        raise Denied("FIELD_NOT_ALLOWED")
    return name


def safe_query(query,depth=0):
    if not isinstance(query,dict) or depth>4 or len(query)>20:
        raise Denied("QUERY_NOT_ALLOWED")
    for key,value in query.items():
        if key in ("$and","$or"):
            if not isinstance(value,list) or not 1<=len(value)<=10:
                raise Denied("QUERY_NOT_ALLOWED")
            for child in value:safe_query(child,depth+1)
        else:
            field_name(key)
            if isinstance(value,dict):
                if len(value)>4:raise Denied("QUERY_NOT_ALLOWED")
                for operator,operand in value.items():
                    if operator not in ("$eq","$ne","$in","$gt","$gte","$lt","$lte","$exists"):
                        raise Denied("QUERY_OPERATOR_NOT_ALLOWED")
                    if operator=="$in" and (not isinstance(operand,list) or len(operand)>100 or any(isinstance(item,(dict,list)) for item in operand)):
                        raise Denied("QUERY_NOT_ALLOWED")
                    if operator!="$in" and isinstance(operand,(dict,list)):
                        raise Denied("QUERY_NOT_ALLOWED")
                    if operator=="$exists" and type(operand) is not bool:
                        raise Denied("QUERY_NOT_ALLOWED")
            elif isinstance(value,list):raise Denied("QUERY_NOT_ALLOWED")
    if len(canonical(query))>8192:raise Denied("QUERY_TOO_LARGE")


def redact(value):
    if isinstance(value,dict):return {k:redact(v) for k,v in value.items() if not SECRET.search(k)}
    if isinstance(value,list):return [redact(v) for v in value]
    return value


@dataclass(frozen=True)
class Namespace:
    database: str

    def __post_init__(self):
        if not isinstance(self.database,str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,63}",self.database):
            raise Denied("CONFIRMED_DATABASE_NAME_REQUIRED")

    def collection(self,name):
        if (not isinstance(name,str) or not name or len(name)>120 or "\0" in name
                or "$" in name or name.startswith("system.")):
            raise Denied("COLLECTION_NOT_ALLOWED")
        return name


@dataclass(frozen=True)
class Principal:
    subject: str
    client: str
    scopes: frozenset[str]

    def require(self,scope):
        if scope not in self.scopes:raise Denied("SCOPE_REQUIRED")


class TokenVerifier:
    """Read/proposal OAuth JWT verification only. The signer is external."""
    def __init__(self,public_key,issuer,audience,owner,clients,namespace):
        if not all((public_key,issuer,audience,owner,clients)) or b"PRIVATE KEY" in public_key:
            raise Denied("EXPLICIT_PUBLIC_TRUST_CONFIGURATION_REQUIRED")
        self.key,self.issuer,self.audience=public_key,issuer,audience
        self.owner,self.clients,self.namespace=owner,frozenset(clients),namespace

    def verify(self,token):
        try:
            claims=jwt.decode(token,self.key,algorithms=["EdDSA"],issuer=self.issuer,
                audience=self.audience,options={"require":["exp","iat","nbf","iss","aud","sub","jti","scope","database","client_id"]})
            if (claims["sub"]!=self.owner or claims["client_id"] not in self.clients
                    or claims["database"]!=self.namespace.database):raise ValueError()
            scopes=frozenset(claims["scope"].split())
            if not scopes or not scopes<=frozenset((READ,PROPOSE)):raise ValueError()
            return Principal(claims["sub"],claims["client_id"],scopes)
        except Exception:
            raise Denied("AUTHENTICATION_REJECTED") from None


class Reader(Protocol):
    def find(self,database,collection,query,limit): ...
    def count(self,database,collection,query): ...


class ReadGateway:
    def __init__(self,namespace,reader):self.namespace,self.reader=namespace,reader

    def find(self,principal,collection,query=None,limit=50):
        principal.require(READ);self.namespace.collection(collection)
        if type(limit) is not int or not 1<=limit<=100:raise Denied("LIMIT_OUT_OF_RANGE")
        query={} if query is None else query;safe_query(query)
        result=redact(self.reader.find(self.namespace.database,collection,query,limit))
        if not isinstance(result,list) or len(result)>limit:raise Denied("ADAPTER_RESULT_LIMIT_VIOLATION")
        if len(canonical(result))>1024*1024:raise Denied("RESULT_TOO_LARGE")
        return result

    def count(self,principal,collection,query=None):
        principal.require(READ);self.namespace.collection(collection)
        query={} if query is None else query;safe_query(query)
        return self.reader.count(self.namespace.database,collection,query)


class AtomicWriter(Protocol):
    def snapshot(self,database,collection,document_id): ...
    def commit_if_unchanged(self,plan): ...


class ProposalAuthority:
    """Must live on the trusted writer boundary, not the AI-administered reader host."""
    def __init__(self,namespace,writer,approval_key,approval_issuer,owner):
        if not approval_key or b"PRIVATE KEY" in approval_key:raise Denied("APPROVAL_PUBLIC_KEY_REQUIRED")
        self.namespace,self.writer=namespace,writer
        self.key,self.issuer,self.owner=approval_key,approval_issuer,owner
        self._plans={};self._snapshots={};self._states={};self._used_tickets=set();self._lock=threading.Lock()

    def propose(self,principal,collection,document_id,operation,changes=None):
        principal.require(PROPOSE);self.namespace.collection(collection)
        if operation not in ("update_one","delete_one"):raise Denied("OPERATION_NOT_ALLOWED")
        if not isinstance(document_id,str) or not 1<=len(document_id)<=128:
            raise Denied("EXACT_DOCUMENT_ID_REQUIRED")
        changes={} if changes is None else copy.deepcopy(changes)
        if operation=="delete_one" and changes:raise Denied("DELETE_PAYLOAD_NOT_ALLOWED")
        if operation=="update_one":
            if not isinstance(changes,dict) or not 1<=len(changes)<=20:raise Denied("PATCH_REQUIRED")
            for key,value in changes.items():
                field_name(key)
                if key=="_id" or "." in key or isinstance(value,(dict,list)):
                    raise Denied("PATCH_NOT_ALLOWED")
        if len(canonical(changes))>8192:raise Denied("PATCH_TOO_LARGE")
        before=self.writer.snapshot(self.namespace.database,collection,document_id)
        if before is None:raise Denied("DOCUMENT_NOT_FOUND")
        now=int(time.time())
        plan={"id":uuid.uuid4().hex,"database":self.namespace.database,"collection":collection,
            "document_id":document_id,"operation":operation,"changes":changes,
            "snapshot_ref":uuid.uuid4().hex,"requester_subject":principal.subject,
            "requester_client":principal.client,"max_affected":1,"created_at":now,"expires_at":now+300}
        plan_hash=digest(plan)
        with self._lock:
            self._plans[plan["id"]]=copy.deepcopy(plan);self._snapshots[plan["id"]]=digest(before);self._states[plan["id"]]="pending"
        return {"plan":copy.deepcopy(plan),"plan_sha256":plan_hash,
                "preview_before":redact(before),"approval_required":True}

    def execute_approved(self,approval_token):
        """Internal human-approval delivery only: never expose as an MCP/client tool."""
        try:
            approval=jwt.decode(approval_token,self.key,algorithms=["EdDSA"],issuer=self.issuer,
                audience=APPROVAL_AUDIENCE,options={"require":["exp","iat","nbf","iss","aud","sub","jti","plan_id","plan_sha256","requester_client","purpose"]})
            if (approval["sub"]!=self.owner or approval["purpose"]!="execute_exact_mongodb_plan"
                    or approval["exp"]-approval["iat"]>300):raise ValueError()
        except Exception:raise Denied("INDEPENDENT_HUMAN_APPROVAL_REQUIRED") from None
        with self._lock:
            plan=self._plans.get(approval["plan_id"])
            if (plan is None or plan["expires_at"]<=time.time()
                    or self._states[plan["id"]]!="pending" or approval["jti"] in self._used_tickets
                    or digest(plan)!=approval["plan_sha256"]
                    or plan["requester_client"]!=approval["requester_client"]):
                raise Denied("APPROVAL_PLAN_MISMATCH_OR_REPLAY")
            self._used_tickets.add(approval["jti"]);self._states[plan["id"]]="executing"
            try:
                internal=copy.deepcopy(plan);internal["before_hash"]=self._snapshots[plan["id"]]
                result=self.writer.commit_if_unchanged(internal)
            except Denied:
                self._states[plan["id"]]="rejected"
                raise
            except Exception:
                self._states[plan["id"]]="unknown"
                raise Denied("OUTCOME_UNKNOWN_NO_AUTOMATIC_RETRY") from None
            self._states[plan["id"]]="committed"
            return {"plan_id":plan["id"],"status":"committed","affected":result}
