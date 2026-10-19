import copy
import json
import unittest
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from unittest.mock import Mock

from bson import ObjectId
from access import Denied
from mongo_reader import MongoReader, validate_uri

URI="mongodb+srv://batteryswap-mcp-reader:fixture@cluster.fixture.mongodb.net/test?authSource=admin"
OID=ObjectId("0123456789abcdef01234567")

class Cursor:
    def __init__(self,docs):self.docs=docs;self.closed=False
    def __iter__(self):return iter(self.docs)
    def close(self):self.closed=True

class MongoReaderTests(unittest.TestCase):
    def make(self,docs=None,policy=None):
        self.cursor=Cursor(docs if docs is not None else [{"_id":OID,"password":"fake-secret","nested":{"key":"secret"}}])
        self.target=Mock();self.target.find.return_value=self.cursor;self.target.count_documents.return_value=5
        self.database=Mock();self.database.get_collection.return_value=self.target
        self.client=Mock();self.client.get_database.return_value=self.database
        self.factory=Mock(return_value=self.client)
        policy=policy or {"products":["_id"]}
        converted={}
        for collection,fields in policy.items():
            converted[collection]=fields if isinstance(fields,dict) else {"kind":"object","fields":{name:({"kind":"id"} if name=="_id" else {"kind":"label","max_length":160}) for name in fields}}
        return MongoReader(URI,converted,self.factory)

    def test_lazy_single_client_tls_small_pool_and_timeouts(self):
        reader=self.make();options=self.factory.call_args.kwargs
        self.assertFalse(options["connect"]);self.assertTrue(options["tls"])
        self.assertFalse(options["tlsAllowInvalidCertificates"])
        self.assertEqual(options["maxPoolSize"],2);self.assertEqual(options["minPoolSize"],0)
        self.assertEqual(options["maxConnecting"],1);self.assertFalse(options["retryReads"])
        self.assertEqual(self.client.get_database.call_args.args,("test",))
        reader.close();self.client.close.assert_called_once()

    def test_uri_without_query_is_valid_on_python310_and_newer(self):
        self.assertIsNone(validate_uri(URI.split("?",1)[0]))
        self.assertIsNone(validate_uri(URI.split("?",1)[0]+"?"))
        for query in ("authSource=admin&", "&", "tls=false", "authSource=admin&authSource=admin"):
            with self.assertRaises(Denied):validate_uri(URI.split("?",1)[0]+"?"+query)

    def test_uri_rejects_other_database_host_options_and_tls_bypass(self):
        for uri in (URI.replace("/test?","/other?"),URI+"&tls=false",URI.replace("mongodb+srv:","mongodb:"),
                    URI.replace("cluster.fixture.mongodb.net","localhost"),URI+"#fragment",URI+"&directConnection=true"):
            with self.assertRaisesRegex(Denied,"CONFIGURATION_REJECTED"):validate_uri(uri)

    def test_projection_and_bson_output_hide_unapproved_fields(self):
        reader=self.make();result=reader.find("test","products",{},1)
        self.assertEqual(result,[{"_id":{"$oid":str(OID)}}])
        self.assertNotIn("fake-secret",json.dumps(result))
        options=self.target.find.call_args.kwargs
        self.assertEqual(options["projection"],{"_id":1});self.assertEqual(options["limit"],1)
        self.assertEqual(options["max_time_ms"],3000);self.assertTrue(self.cursor.closed)

    def test_no_queries_on_unapproved_collection_database_or_fields(self):
        reader=self.make()
        for database,collection,query in (("other","products",{}),("test","unknown",{}),
                ("test","system.users",{}),("test","products",{"name":"x"}),
                ("test","products",{"$where":"true"}),("test","products",{"_id":{"$regex":".*"}})):
            with self.assertRaises(Denied):reader.find(database,collection,query,1)
        self.target.find.assert_not_called();self.target.count_documents.assert_not_called()

    def test_oid_conversion_only_for_id(self):
        reader=self.make();reader.find("test","products",{"$or":[{"_id":{"$in":[str(OID)]}}]},1)
        self.assertEqual(self.target.find.call_args.args[0],{"$or":[{"_id":{"$in":[OID]}}]})

    def test_count_deadline_and_no_unapproved_inference(self):
        reader=self.make();self.assertEqual(reader.count("test","products",{}),5)
        self.target.count_documents.assert_called_once_with({},maxTimeMS=3000)
        with self.assertRaises(Denied):reader.count("test","products",{"api_token":"x"})

    def test_errors_never_expose_driver_message_or_uri(self):
        reader=self.make();self.target.find.side_effect=RuntimeError(URI+" fake-secret")
        with self.assertRaisesRegex(Denied,"^MONGODB_READ_UNAVAILABLE$"):reader.find("test","products",{},1)
        self.assertTrue(reader.slots.acquire(blocking=False));reader.slots.release()

    def test_result_limit_closes_cursor_and_releases_slot(self):
        reader=self.make([{"_id":OID},{"_id":OID}])
        with self.assertRaisesRegex(Denied,"RESULT_TOO_LARGE"):reader.find("test","products",{},1)
        self.assertTrue(self.cursor.closed)
        reader=self.make([{"_id":OID,"name":"x"*(1024*1024)}],{"products":["_id","name"]})
        self.assertNotIn("name",reader.find("test","products",{},1)[0])
        self.assertTrue(self.cursor.closed)

    def test_concurrency_rejects_instead_of_growing_pool(self):
        reader=self.make();reader.slots.acquire();reader.slots.acquire()
        try:
            with self.assertRaisesRegex(Denied,"READER_BUSY"):reader.find("test","products",{},1)
        finally:reader.slots.release();reader.slots.release()
        self.target.find.assert_not_called()

    def test_policy_rejects_secret_nested_or_unbounded_fields(self):
        for fields in (["password"],["api_token"],["x.y"],[],["a"]*51):
            with self.assertRaises(Denied):MongoReader(URI,{"products":fields},Mock())
        reader=self.make([{"_id":OID,"name":{"token":"fake-secret"}}],{"products":["_id","name"]})
        self.assertNotIn("name",reader.find("test","products",{},1)[0])

if __name__=="__main__":unittest.main()
