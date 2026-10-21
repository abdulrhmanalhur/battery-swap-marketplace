"""Real MongoDB tests. Fail closed if local replica set is unavailable, never skip."""
import concurrent.futures
import multiprocessing
import os
import unittest
import uuid
from persistent_candidate import SyntheticDurableCandidate, Record, Rejected

class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.owner=object()
        self.a=SyntheticDurableCandidate('synthetic_edit_'+uuid.uuid4().hex,self.owner)
        hello=self.a.client.admin.command('hello')
        self.assertEqual(hello.get('setName'),'synthetic_rs')
        self.a.seed([Record('a','fixture-client',1,'old',100),Record('b','fixture-client',1,'old',200)])
    def tearDown(self):
        # Retain synthetic DB evidence; no drop/delete needed.
        self.a.client.close()
    def proposal(self, both=False):
        ids=['a','b'] if both else ['a']
        p=self.a.preview('fixture-client',[{'operation':'edit','id':rid,'expected_version':1,
                                          'changes':{'label':'new'}} for rid in ids])
        return p,self.a.fixture_approve(self.owner,p)
    def state(self):
        return self.a.db.records.find_one({'_id':'a'})['label']
    def assert_committed(self,t):
        self.assertEqual(self.state(),'new')
        self.assertEqual(self.a.db.receipts.count_documents({'grant':t}),1)
        self.assertEqual(self.a.db.grants.find_one({'_id':t})['state'],'consumed')
        self.assertEqual(self.a.reconcile(t),'committed')
    def test_atomic_commit_and_durable_replay(self):
        p,t=self.proposal();self.a.commit(p,'fixture-client',t);self.assert_committed(t)
        restarted=SyntheticDurableCandidate(self.a.db.name)
        with self.assertRaises(Rejected):restarted.commit(p,'fixture-client',t)
        restarted.client.close();self.assert_committed(t)
    def test_no_real_authority_by_default(self):
        p,_=self.proposal();b=SyntheticDurableCandidate(self.a.db.name)
        with self.assertRaises(Rejected):b.fixture_approve(object(),p)
        b.client.close()
    def test_concurrent_replay_single_success(self):
        p,t=self.proposal()
        def run(_):
            try:self.a.commit(p,'fixture-client',t);return 1
            except Rejected:return 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            self.assertEqual(sum(pool.map(run,range(64))),1)
        self.assert_committed(t)
    def test_stale_multi_record_aborts_every_edit(self):
        p,t=self.proposal(True)
        self.a.db.records.update_one({'_id':'b'},{'$inc':{'version':1}})
        with self.assertRaises(Rejected):self.a.commit(p,'fixture-client',t)
        self.assertEqual(self.state(),'old');self.assertEqual(self.a.db.receipts.count_documents({}),0)
        self.assertEqual(self.a.reconcile(t),'abandoned')
    def test_changed_before_value_same_version_rejected(self):
        p,t=self.proposal();self.a.db.records.update_one({'_id':'a'},{'$set':{'label':'other'}})
        with self.assertRaises(Rejected):self.a.commit(p,'fixture-client',t)
        self.assertEqual(self.a.db.receipts.count_documents({}),0)
    def test_exception_before_commit_aborts_and_reconciles(self):
        p,t=self.proposal()
        def hook(stage):
            if stage=='before_commit':raise RuntimeError('injected failure')
        with self.assertRaises(RuntimeError):self.a.commit(p,'fixture-client',t,hook)
        self.assertEqual(self.state(),'old');self.assertEqual(self.a.reconcile(t),'abandoned')
        with self.assertRaises(Rejected):self.a.commit(p,'fixture-client',t)
    def test_lost_acknowledgment_reconciles_success(self):
        p,t=self.proposal()
        def hook(stage):
            if stage=='after_commit':raise ConnectionError('lost response')
        with self.assertRaises(ConnectionError):self.a.commit(p,'fixture-client',t,hook)
        self.assert_committed(t)
    def test_reconciliation_fences_active_transaction(self):
        p,t=self.proposal()
        def hook(stage):
            if stage=='after_reservation':self.assertEqual(self.a.reconcile(t),'abandoned')
        with self.assertRaises(Rejected):self.a.commit(p,'fixture-client',t,hook)
        self.assertEqual(self.state(),'old')
    def test_worker_crash_after_reservation(self):
        self.crash_case('after_reservation',False)
    def test_worker_crash_inside_transaction(self):
        self.crash_case('after_edit',False)
    def test_worker_crash_after_commit(self):
        self.crash_case('after_commit',True)
    def crash_case(self,stage,committed):
        p,t=self.proposal();db_name=self.a.db.name
        def worker():
            # Do not reuse parent MongoClient across fork.
            a=SyntheticDurableCandidate(db_name)
            def hook(s):
                if s==stage:os._exit(73)
            a.commit(p,'fixture-client',t,hook)
        proc=multiprocessing.get_context('fork').Process(target=worker)
        proc.start();proc.join(15)
        if proc.is_alive():proc.terminate();proc.join();self.fail('Worker timeout')
        self.assertEqual(proc.exitcode,73)
        if committed:self.assert_committed(t)
        else:
            self.assertEqual(self.state(),'old')
            self.assertEqual(self.a.db.receipts.count_documents({}),0)
            self.assertEqual(self.a.reconcile(t),'abandoned')
    def test_disallowed_business_operations_rejected(self):
        for op in ('create','delete','upsert','archive'):
            with self.subTest(op=op),self.assertRaises(Rejected):
                self.a.preview('fixture-client',[{'operation':op,'id':'a','expected_version':1,'changes':{'label':'x'}}])
    def test_missing_approval_no_edit(self):
        p,_=self.proposal()
        with self.assertRaises(Rejected):self.a.commit(p,'fixture-client','missing')
        self.assertEqual(self.state(),'old')

if __name__=='__main__':unittest.main(verbosity=2)
