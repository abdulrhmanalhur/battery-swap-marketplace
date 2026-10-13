import copy
import importlib.util
import unittest
from pathlib import Path

path=Path(__file__).resolve().parents[1]/"deploy/bootstrap_admin.py"
spec=importlib.util.spec_from_file_location("atlas_bootstrap_fixture",path)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class BootstrapPolicyTests(unittest.TestCase):
    def test_only_new_record_added_and_publication_closed(self):
        base={"schema_version":1,"projects":{"existing":{"id":"existing","source_root":"/opt/existing","private_policy":"fixture"}}}
        before=copy.deepcopy(base)
        new=module.proposed(base,"a"*40)
        self.assertEqual(base,before)
        self.assertEqual(new["projects"]["existing"],before["projects"]["existing"])
        policy=new["projects"]["atlas-monitor"]
        self.assertTrue(policy["readiness"]["snapshot"])
        self.assertFalse(policy["readiness"]["publish"])
        self.assertEqual(policy["provider_policy"]["service"],"batteryswap-atlas-monitor.service")
        self.assertEqual(set(policy["source_policy"]["include_files"]),module.FILES)
        self.assertNotIn("requirements.txt",module.FILES)
        self.assertNotIn("AGENTS.md",module.FILES)
        self.assertNotIn("deploy/bootstrap_admin.py",module.FILES)

    def test_overlapping_source_already_registered_rejected(self):
        for source in ("/opt/batteryswap-atlas-mcp","/opt/batteryswap-atlas-mcp/child","/opt"):
            with self.assertRaises(ValueError):
                module.proposed({"schema_version":1,"projects":{"existing":{"source_root":source}}},"a"*40)

    def test_duplicate_registration_and_invalid_source_commit_rejected(self):
        with self.assertRaises(ValueError):module.proposed({"schema_version":1,"projects":{"atlas-monitor":{}}},"a"*40)
        for commit in ("main","../source","a"*39):
            with self.assertRaises(ValueError):module.proposed({"schema_version":1,"projects":{}},commit)

if __name__=="__main__":unittest.main()
