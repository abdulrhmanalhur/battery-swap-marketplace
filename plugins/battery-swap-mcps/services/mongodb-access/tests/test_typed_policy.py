import importlib.util
import json
import sys
import unittest
from datetime import datetime,timezone
from pathlib import Path
from unittest.mock import Mock,patch
import getpass

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from bson import ObjectId,Binary,Code,Decimal128
from access import Denied
from field_policy import sanitize,DROP,leaves
from mongo_reader import MongoReader
from quota_store import QuotaStore
from key_value.aio.stores.memory import MemoryStore

P=Path(__file__).resolve().parents[1]
URI="mongodb+srv://batteryswap-mcp-reader:fixture@cluster.fixture.mongodb.net/test"

class TypedPolicyTests(unittest.TestCase):
    def setUp(self):self.policy=json.loads((P/"read-policy.json").read_text(encoding="utf-8"))
    def test_all57_public_models_have_a_valid_policy(self):
        evidence=json.loads((P/"POLICY-EVIDENCE.json").read_text(encoding="utf-8"))
        self.assertEqual(set(self.policy),set(evidence["models"]))
        self.assertEqual(len(self.policy),57)
        client=Mock();client.get_database.return_value=Mock()
        MongoReader(URI,self.policy,Mock(return_value=client))
    def test_product_financials_and_nested_invoice_items_preserved(self):
        invoice={"invoiceNumber":42,"grossTotal":115,"netTotal":100,
                 "products":[{"productName":"Battery 70 Ah","unitCost":50,"quantity":2,"password":"fixture-secret"}],
                 "bankCheck":{"status":"verified","matchedAmount":115,"reason":"Bearer fixture-secret"},
                 "invoiceImageUrl":"https://private.invalid/?token=fixture"}
        result=sanitize(invoice,self.policy["managerinvoices"])
        self.assertEqual(result["products"],[{"productName":"Battery 70 Ah","unitCost":50,"quantity":2}])
        self.assertEqual(result["bankCheck"]["matchedAmount"],115)
        self.assertNotIn("fixture-secret",json.dumps(result));self.assertNotIn("invoiceImageUrl",result)
    def test_sms_body_login_codes_tokens_and_mixed_data_never_projected(self):
        for collection,blocked in {"smsmessages":["body","address"],"managerusers":["code","telegramBotToken"],
            "discountcodes":["code","derivedFromCode"],"sitecontents":["data"],"attribution_contacts":["phone","attributionSnapshot"]}.items():
            paths=leaves(self.policy[collection])
            for field in blocked:self.assertNotIn(field,paths)
    def test_secret_like_values_and_unapproved_bson_are_dropped_in_safe_field(self):
        label={"kind":"label","max_length":160}
        for value in ("mongodb+srv://private", "Bearer fixture-value", "ghp_"+"x"*30,
                      "eyJhbGciOiJIUzI1NiJ9."+"a"*40, Binary(b"fixture"), Code("fixture secret"),
                      b"fixture",{"token":"fixture"},["fixture"],"x"*161):
            self.assertIs(sanitize(value,label),DROP)
        self.assertEqual(sanitize("بطارية 70 أمبير",label),"بطارية 70 أمبير")
    def test_personal_contact_values_masked_and_reference_correlates(self):
        phone=sanitize("+966501234567",{"kind":"phone"})
        email=sanitize("fixture@example.com",{"kind":"email"})
        self.assertEqual(phone["last4"],"4567");self.assertNotIn("96650",json.dumps(phone))
        self.assertEqual(email["domain"],"example.com");self.assertNotIn("fixture@",json.dumps(email))
        spec={"kind":"reference"};self.assertEqual(sanitize("fixture-uid",spec),sanitize("fixture-uid",spec))
    def test_masked_free_text_array_and_secret_filter_cannot_infer_through_count(self):
        client=Mock();client.get_database.return_value=Mock()
        reader=MongoReader(URI,self.policy,Mock(return_value=client))
        for collection,query in (("smsmessages",{"body":"x"}),("managerusers",{"code":"1234"}),
                ("depositpayments",{"customerPhone":"1234567"}),("managerinvoices",{"products.quantity":1}),
                ("products",{"name":"Bearer fixture"}),("products",{"name":{"$gt":"a"}}),
                ("products",{"_id":{"$gt":"0123456789abcdef01234567"}})):
            with self.assertRaises(Denied):reader.count("test",collection,query)
        client.get_database.return_value.get_collection.assert_not_called()
    def test_unknown_nested_fields_large_arrays_and_nonfinite_numbers_dropped(self):
        spec={"kind":"array","max_items":2,"items":{"kind":"number"}}
        self.assertIs(sanitize([1,2,3],spec),DROP)
        for value in (float("nan"),float("inf"),True,10**20):self.assertIs(sanitize(value,{"kind":"number"}),DROP)
        self.assertEqual(sanitize(Decimal128("12.50"),{"kind":"number"}),{"$numberDecimal":"12.50"})
    def test_secret_input_requires_tty_and_never_falls_back_to_echo(self):
        spec=importlib.util.spec_from_file_location("owner_input",P/"deploy/store-private-value.py")
        helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
        with patch.object(helper.sys.stdin,"isatty",return_value=False),patch.object(helper.getpass,"getpass") as prompt:
            with self.assertRaisesRegex(SystemExit,"SECURE_TTY_REQUIRED"):helper.main()
            prompt.assert_not_called()
        with patch.object(helper.sys.stdin,"isatty",return_value=True),patch.object(helper.sys.stderr,"isatty",return_value=True), \
             patch.object(helper.sys,"argv",["owner_input","github-client-secret"]), \
             patch.object(helper.os,"geteuid",return_value=0,create=True), \
             patch.object(helper.Path,"mkdir"),patch.object(helper.Path,"lstat") as stat, \
             patch.object(helper.getpass,"getpass",side_effect=getpass.GetPassWarning("fixture")), \
             patch.object(helper.os,"open") as create:
            import stat as modes
            stat.return_value.st_mode=modes.S_IFDIR|0o700;stat.return_value.st_uid=0
            with self.assertRaisesRegex(SystemExit,"SECURE_TTY_REQUIRED"):helper.main()
            create.assert_not_called()

class QuotaTests(unittest.IsolatedAsyncioTestCase):
    async def test_registration_capacity_and_ttl_fail_closed(self):
        raw=MemoryStore();store=QuotaStore(raw)
        collection="mcp-oauth-proxy-clients"
        for i in range(64):await store.put(str(i),{"id":i},collection=collection)
        with self.assertRaisesRegex(ValueError,"CAPACITY"):await store.put("overflow",{},collection=collection)
        self.assertEqual(len(await raw.keys(collection)),64)
        value,remaining=await raw.ttl("0",collection=collection)
        self.assertLessEqual(remaining,30*86400)
        await store.put("0",{"id":0},collection=collection)
    async def test_encrypted_file_backend_quota_survives_wrapper_restart(self):
        import tempfile
        from key_value.aio.stores.filetree import FileTreeStore
        from key_value.aio.wrappers.encryption import FernetEncryptionWrapper
        from cryptography.fernet import Fernet
        with tempfile.TemporaryDirectory() as folder:
            raw=FernetEncryptionWrapper(key_value=FileTreeStore(data_directory=folder),fernet=Fernet(Fernet.generate_key()))
            store=QuotaStore(raw)
            for i in range(64):await store.put(str(i),{"fixture":i},collection="mcp-oauth-proxy-clients")
            store=QuotaStore(raw)
            with self.assertRaisesRegex(ValueError,"CAPACITY"):await store.put("overflow",{},collection="mcp-oauth-proxy-clients")
            await store.delete("0",collection="mcp-oauth-proxy-clients")
            await store.put("replacement",{},collection="mcp-oauth-proxy-clients")
            self.assertIsNone(await raw.get("overflow",collection="mcp-oauth-proxy-clients"))

    async def test_expired_registration_and_large_payload(self):
        raw=MemoryStore();store=QuotaStore(raw)
        await store.put("expired",{},collection="mcp-oauth-transactions",ttl=-1)
        await store.put("new",{},collection="mcp-oauth-transactions")
        self.assertIsNone(await raw.get("expired",collection="mcp-oauth-transactions"))
        with self.assertRaisesRegex(ValueError,"TOO_LARGE"):await store.put("large",{"data":"x"*65537},collection="mcp-oauth-transactions")

if __name__=="__main__":unittest.main()
