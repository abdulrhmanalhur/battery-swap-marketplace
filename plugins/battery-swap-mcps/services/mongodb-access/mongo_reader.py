"""Fixed-namespace PyMongo reader. Never exposes the underlying client or commands."""
import json
import re
import threading
from urllib.parse import urlsplit, parse_qsl, unquote

from bson import ObjectId, json_util
from pymongo import MongoClient
from pymongo.read_concern import ReadConcern
from pymongo.read_preferences import ReadPreference

from access import Denied, Namespace, safe_query, canonical
from field_policy import validate_spec, leaves, sanitize, query_value

DATABASE = "test"
MAX_TIME_MS = 3000


def validate_uri(uri):
    try:
        parsed = urlsplit(uri)
        if (parsed.scheme != "mongodb+srv" or parsed.path != "/test"
                or unquote(parsed.username or "") != "batteryswap-mcp-reader" or not parsed.password or parsed.port is not None
                or not re.fullmatch(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.mongodb\.net", parsed.hostname or "")
                or parsed.fragment or any(c in uri for c in "\r\n\0")):
            raise ValueError()
        options = parse_qsl(parsed.query, strict_parsing=True)
        if any(k != "authSource" or v != "admin" for k, v in options) or len(options) > 1:
            raise ValueError()
    except (TypeError, ValueError):
        raise Denied("MONGODB_URI_CONFIGURATION_REJECTED") from None


class MongoReader:
    def __init__(self, uri, policy, client_factory=MongoClient):
        validate_uri(uri)
        if not isinstance(policy, dict) or not policy:
            raise Denied("EXPLICIT_FIELD_POLICY_REQUIRED")
        self.policy = {}
        namespace = Namespace(DATABASE)
        for collection, spec in policy.items():
            namespace.collection(collection)
            validate_spec(spec)
            if spec.get("kind")!="object":raise Denied("EXPLICIT_FIELD_POLICY_REQUIRED")
            self.policy[collection] = spec
        self.slots = threading.BoundedSemaphore(2)
        try:
            self.client = client_factory(uri, connect=False, tls=True, tlsAllowInvalidCertificates=False,
                tlsAllowInvalidHostnames=False, maxPoolSize=2, minPoolSize=0, maxConnecting=1,
                maxIdleTimeMS=30000, waitQueueTimeoutMS=500, serverSelectionTimeoutMS=5000,
                connectTimeoutMS=5000, socketTimeoutMS=5000, retryReads=False, retryWrites=False,
                appname="BatterySwap-Mongo-Read", readPreference="primary")
            self.database = self.client.get_database(DATABASE, read_concern=ReadConcern("majority"),
                                                     read_preference=ReadPreference.PRIMARY)
        except Exception:
            raise Denied("MONGODB_INITIALIZATION_UNAVAILABLE") from None

    def close(self):
        self.client.close()

    def _validate(self, database, collection, query):
        if database != DATABASE or collection not in self.policy:
            raise Denied("NAMESPACE_OR_COLLECTION_NOT_APPROVED")
        safe_query(query)
        allowed = leaves(self.policy[collection])
        def visit(value):
            converted = {}
            for key, operand in value.items():
                if key in ("$and", "$or"):
                    converted[key] = [visit(child) for child in operand]
                else:
                    if key not in allowed:
                        raise Denied("QUERY_FIELD_NOT_APPROVED")
                    spec,in_array=allowed[key]
                    if in_array or spec.get("query") is False or spec["kind"] in ("label","reference","phone","email","last4"):
                        raise Denied("QUERY_FIELD_NOT_APPROVED")
                    if spec["kind"] in ("id","enum") and isinstance(operand,dict) and not set(operand)<= {"$eq","$in"}:
                        raise Denied("QUERY_OPERATOR_NOT_APPROVED_FOR_FIELD")
                    if isinstance(operand,dict):
                        converted[key] = {op: val if op=="$exists" else
                            [query_value(x,spec) for x in val] if op=="$in" else query_value(val,spec)
                            for op,val in operand.items()}
                    else:
                        converted[key] = query_value(operand,spec)
            return converted
        return visit(query)

    def _operation(self, database, collection, query, limit=None):
        query = self._validate(database, collection, query)
        if limit is not None and (type(limit) is not int or not 1 <= limit <= 100):
            raise Denied("LIMIT_OUT_OF_RANGE")
        if not self.slots.acquire(timeout=0.05):
            raise Denied("READER_BUSY")
        try:
            target = self.database.get_collection(collection)
            if limit is None:
                count = target.count_documents(query, maxTimeMS=MAX_TIME_MS)
                if type(count) is not int or count < 0:
                    raise Denied("ADAPTER_COUNT_INVALID")
                return count
            fields = self.policy[collection]
            projection = {field: 1 for field in leaves(fields)}
            cursor = target.find(query, projection=projection, limit=limit, batch_size=min(limit,25),
                                 max_time_ms=MAX_TIME_MS)
            result = []
            size = 2
            try:
                for doc in cursor:
                    clean = sanitize(doc,fields)
                    raw = canonical(clean)
                    size += len(raw) + 1
                    if size > 1024 * 1024 or len(result) >= limit:
                        raise Denied("RESULT_TOO_LARGE")
                    result.append(clean)
            finally:
                cursor.close()
            return result
        except Denied:
            raise
        except Exception:
            # Driver errors may contain URI, query or document material.
            raise Denied("MONGODB_READ_UNAVAILABLE") from None
        finally:
            self.slots.release()

    def find(self,database,collection,query,limit):
        return self._operation(database,collection,query,limit)

    def count(self,database,collection,query):
        return self._operation(database,collection,query)
