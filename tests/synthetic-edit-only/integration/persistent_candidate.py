"""UNEXECUTED integration candidate, not the original adapter or production code.

Uses the hash-verified prototype's preview validator; adds a MongoDB durability
experiment. Synthetic local replica set only. Owner authentication remains a
harness-provisioned test double, never a production authorization mechanism.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'baseline'))
import time
import uuid
from dataclasses import asdict
from pymongo import MongoClient, ReturnDocument
from pymongo.read_concern import ReadConcern
from pymongo.write_concern import WriteConcern
from prototype import Record, Preview, EditOnlyPrototype, InMemoryFixtures, FixtureAudit, Rejected

URI = 'mongodb://127.0.0.1:27191/?replicaSet=synthetic_rs'

class SyntheticDurableCandidate:
    def __init__(self, db_name, owner_credential=None):
        if not db_name.startswith('synthetic_edit_'):
            raise ValueError('Only synthetic test database names allowed')
        self.client = MongoClient(URI, serverSelectionTimeoutMS=3000)
        self.db = self.client.get_database(db_name, write_concern=WriteConcern('majority', j=True))
        self.owner = owner_credential
        self.db.receipts.create_index('nonce', unique=True)
        self.db.receipts.create_index('grant', unique=True)

    def seed(self, records):
        """Test harness only, not a business create endpoint."""
        self.db.records.insert_many([dict(_id=r.id, **asdict(r)) for r in records])

    def preview(self, client, requests, ttl=60):
        records = [Record(**{k:v for k,v in r.items() if k != '_id'}) for r in self.db.records.find({})]
        p = EditOnlyPrototype(InMemoryFixtures(records), FixtureAudit()).preview(client, requests, ttl)
        self.db.previews.insert_one({'_id':p.nonce, 'digest':p.digest(), 'client':p.client, 'expires':p.expires})
        return p

    def fixture_approve(self, credential, p):
        if self.owner is None or type(self.owner) is not object or credential is not self.owner:
            raise Rejected('Independent owner verifier is not configured; fixture credential required')
        token = uuid.uuid4().hex
        self.db.grants.insert_one({'_id':token, 'nonce':p.nonce, 'digest':p.digest(), 'client':p.client,
                                   'expires':p.expires, 'state':'approved'})
        return token

    def commit(self, p, client, token, hook=lambda stage: None):
        if type(p) is not Preview or type(client) is not str or type(token) is not str:
            raise Rejected('Invalid types')
        digest = p.digest()
        now = time.time()
        if p.client != client or now >= p.expires or not self.db.previews.find_one(
                {'_id':p.nonce,'digest':digest,'client':client,'expires':p.expires}):
            raise Rejected('Unknown, tampered, expired or wrong-client preview')
        reservation = uuid.uuid4().hex
        grant = self.db.grants.find_one_and_update(
            {'_id':token,'nonce':p.nonce,'digest':digest,'client':client,'expires':{'$gt':now},'state':'approved'},
            {'$set':{'state':'reserved','reservation':reservation}}, return_document=ReturnDocument.AFTER)
        if not grant:
            raise Rejected('Missing, used, revoked, mismatched or expired approval')
        # Durable reservation survives worker crash. No automatic re-approval.
        hook('after_reservation')
        def txn(s):
            if time.time() >= p.expires:
                raise Rejected('Expired before transaction')
            fence = self.db.grants.update_one(
                {'_id':token,'state':'reserved','reservation':reservation},
                {'$set':{'state':'consumed'}},session=s)
            if fence.matched_count != 1:
                raise Rejected('Reservation fenced by revocation/reconciliation')
            for edit in p.edits:
                f = {'_id':edit.id,'client':client,'version':edit.expected_version}
                f.update({field:old for field,old,new in edit.diff})
                result = self.db.records.update_one(f,{'$set':{field:new for field,old,new in edit.diff},
                                                       '$inc':{'version':1}},upsert=False,session=s)
                if result.matched_count != 1:
                    raise Rejected('Stale version/value, wrong client or missing record')
                hook('after_edit')
            self.db.receipts.insert_one({'_id':digest,'nonce':p.nonce,'grant':token,'client':client,
                                         'digest':digest,'edits':[asdict(e) for e in p.edits]},session=s)
            hook('before_commit')
            return digest
        with self.client.start_session() as s:
            result = s.with_transaction(txn, read_concern=ReadConcern('snapshot'),
                                        write_concern=WriteConcern('majority',j=True))
        hook('after_commit')  # Simulates loss of caller acknowledgment after durable success.
        return result

    def reconcile(self, token):
        """Fence a stranded reservation; never silently retry a business edit.

        Races with an active transaction are resolved by the grant write conflict.
        A successful committed receipt is the only evidence of business success.
        """
        with self.client.start_session() as s:
            def txn(s):
                g=self.db.grants.find_one({'_id':token},session=s)
                if not g: return 'missing'
                receipt=self.db.receipts.find_one({'grant':token},session=s)
                if g['state']=='consumed':
                    if not receipt: raise AssertionError('Consumed grant without atomic receipt')
                    return 'committed'
                if receipt: raise AssertionError('Receipt without consumed grant')
                if g['state']=='reserved':
                    self.db.grants.update_one({'_id':token,'state':'reserved'},
                                              {'$set':{'state':'abandoned'}},session=s)
                    return 'abandoned'
                return g['state']
            return s.with_transaction(txn,read_concern=ReadConcern('snapshot'),
                                      write_concern=WriteConcern('majority',j=True))
