from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
import threading
import unittest

from prototype import (EditOnlyPrototype, FixtureAudit, FixtureOwnerVerifier,
                       InMemoryFixtures, Record, Rejected)


class EditOnlyTests(unittest.TestCase):
    def setUp(self):
        self.now = 1000
        self.db = InMemoryFixtures([Record("a", "client1", 1, "Fixture A", 100),
                                    Record("b", "client1", 1, "Fixture B", 200),
                                    Record("c", "client2", 1, "Fixture C", 300)])
        self.before = self.db.snapshot()
        self.audit = FixtureAudit()
        self.owner = object()  # independently provisioned test credential
        self.verifier = FixtureOwnerVerifier(self.owner)
        self.engine = EditOnlyPrototype(self.db, self.audit, self.verifier, lambda: self.now)

    def req(self, rid="a", **extra):
        return dict(operation="edit", id=rid, expected_version=1,
                    changes={"price_cents": 150}, **extra)

    def preview(self):
        return self.engine.preview("client1", [self.req()])

    def approve(self, p):
        return self.verifier.issue_for_owner(self.owner, p)

    def unchanged(self):
        self.assertEqual(self.db.snapshot(), self.before)

    def test_success_exact_diff_and_preservation(self):
        p = self.preview()
        self.assertEqual(p.edits[0].diff, (("price_cents", 100, 150),))
        self.engine.commit(p, "client1", self.approve(p))
        after = self.db.snapshot()
        self.assertEqual(after["a"], Record("a", "client1", 2, "Fixture A", 150))
        self.assertEqual(after["b"], self.before["b"])
        self.assertEqual(after["c"], self.before["c"])
        self.assertEqual(set(after), set(self.before))
        self.assertEqual(len(self.audit.events), 1)

    def test_no_approval_or_caller_boolean(self):
        p = self.preview()
        for approval in (None, True, False, "fabricated"):
            with self.assertRaises(Rejected):
                self.engine.commit(p, "client1", approval)
        self.unchanged()

    def test_independent_owner_authority(self):
        for invalid in (True, False, None, "owner"):
            with self.assertRaises(ValueError):
                FixtureOwnerVerifier(invalid)
        with self.assertRaises(Rejected):
            self.verifier.issue_for_owner(object(), self.preview())
        class EqualToAnything:
            def __eq__(self, other):
                return True
        with self.assertRaises(Rejected):
            self.verifier.issue_for_owner(EqualToAnything(), self.preview())
        self.unchanged()

    def test_verifier_failure_leaves_records_and_audit_untouched(self):
        class UnavailableVerifier:
            def consume(self, *args):
                raise Rejected("Authority unavailable")
        engine = EditOnlyPrototype(self.db, self.audit, UnavailableVerifier(), lambda: self.now)
        p = engine.preview("client1", [self.req()])
        with self.assertRaisesRegex(Rejected, "Authority unavailable"):
            engine.commit(p, "client1", "anything")
        self.unchanged()
        self.assertEqual(self.audit.events, [])

    def test_before_value_tamper_without_version_change(self):
        p = self.preview()
        # Simulate an external adapter writer violating the version convention.
        with self.db._lock:
            self.db._records["a"] = replace(self.db._records["a"], price_cents=101)
        changed = self.db.snapshot()
        with self.assertRaisesRegex(Rejected, "Before value changed"):
            self.engine.commit(p, "client1", self.approve(p))
        self.assertEqual(self.db.snapshot(), changed)
        self.assertEqual(self.audit.events, [])

    def test_separate_engines_share_adapter_concurrency_guard(self):
        other = EditOnlyPrototype(self.db, self.audit, self.verifier, lambda: self.now)
        p1 = self.preview()
        p2 = other.preview("client1", [self.req()])
        token1, token2 = self.approve(p1), self.approve(p2)
        barrier = threading.Barrier(2)
        def attempt(args):
            engine, preview, token = args
            barrier.wait()
            try:
                engine.commit(preview, "client1", token)
                return True
            except Rejected:
                return False
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(attempt, [(self.engine, p1, token1), (other, p2, token2)]))
        self.assertEqual(sum(outcomes), 1)
        self.assertEqual(self.db.snapshot()["a"].version, 2)
        self.assertEqual(len(self.audit.events), 1)

    def test_malformed_duplicate_noop_and_range_validation(self):
        bad = [[], [self.req(), self.req()], [self.req() for _ in range(21)]]
        for changes in ({"price_cents": -1}, {"price_cents": 1000001},
                        {"price_cents": 1.5}, {"label": "   "},
                        {"label": "x" * 81}, {"price_cents": 100}):
            req = self.req()
            req["changes"] = changes
            bad.append([req])
        for requests in bad:
            with self.subTest(requests=requests), self.assertRaises(Rejected):
                self.engine.preview("client1", requests)
        for ttl in (0, 301, True):
            with self.assertRaises(Rejected):
                self.engine.preview("client1", [self.req()], ttl)
        self.unchanged()

    def test_unconfigured_real_verifier_fails_closed(self):
        engine = EditOnlyPrototype(self.db, self.audit, clock=lambda: self.now)
        p = engine.preview("client1", [self.req()])
        with self.assertRaisesRegex(Rejected, "unconfigured"):
            engine.commit(p, "client1", True)
        self.unchanged()

    def test_immutable_and_tamper(self):
        p = self.preview()
        token = self.approve(p)
        with self.assertRaises(FrozenInstanceError):
            p.client = "client2"
        variants = [replace(p, expires=p.expires + 100), replace(p, client="client2"),
                    replace(p, edits=(replace(p.edits[0], id="b"),)),
                    replace(p, edits=(replace(p.edits[0], expected_version=2),)),
                    replace(p, edits=(replace(p.edits[0], diff=(("price_cents", 100, 999),)),))]
        for changed in variants:
            with self.assertRaises(Rejected):
                self.engine.commit(changed, "client1", token)
        self.unchanged()

    def test_approval_bound_to_exact_preview(self):
        p, other = self.preview(), self.preview()
        with self.assertRaises(Rejected):
            self.engine.commit(other, "client1", self.approve(p))
        self.unchanged()

    def test_wrong_identity(self):
        p = self.preview()
        with self.assertRaises(Rejected):
            self.engine.commit(p, "client2", self.approve(p))
        with self.assertRaises(Rejected):
            self.engine.preview("client1", [self.req("c")])
        self.unchanged()

    def test_expiry(self):
        p = self.preview()
        token = self.approve(p)
        self.now = p.expires
        with self.assertRaises(Rejected):
            self.engine.commit(p, "client1", token)
        self.unchanged()

    def test_stale_versions_entire_batch_unchanged(self):
        p = self.engine.preview("client1", [self.req("a"), self.req("b")])
        other = self.engine.preview("client1", [self.req("b")])
        self.engine.commit(other, "client1", self.approve(other))
        expected = self.db.snapshot()
        with self.assertRaises(Rejected):
            self.engine.commit(p, "client1", self.approve(p))
        self.assertEqual(self.db.snapshot(), expected)
        self.assertEqual(self.db.snapshot()["a"], self.before["a"])

    def test_replay(self):
        p = self.preview()
        token = self.approve(p)
        self.engine.commit(p, "client1", token)
        expected = self.db.snapshot()
        with self.assertRaises(Rejected):
            self.engine.commit(p, "client1", token)
        self.assertEqual(self.db.snapshot(), expected)
        self.assertEqual(len(self.audit.events), 1)

    def test_concurrent_duplicate_commit(self):
        p = self.preview()
        token = self.approve(p)
        barrier = threading.Barrier(8)
        def attempt(_):
            barrier.wait()
            try:
                self.engine.commit(p, "client1", token)
                return True
            except Rejected:
                return False
        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(attempt, range(8)))
        self.assertEqual(sum(outcomes), 1)
        self.assertEqual(self.db.snapshot()["a"].version, 2)
        self.assertEqual(len(self.audit.events), 1)

    def test_audit_failure_consumes_approval_without_edit(self):
        p = self.preview()
        token = self.approve(p)
        self.audit.fail = True
        with self.assertRaisesRegex(Rejected, "Audit unavailable"):
            self.engine.commit(p, "client1", token)
        self.unchanged()
        self.assertEqual(self.audit.events, [])
        self.audit.fail = False
        with self.assertRaises(Rejected):
            self.engine.commit(p, "client1", token)
        self.unchanged()

    def test_unsupported_operations_fields_and_absent_records(self):
        for operation in ("create", "insert", "upsert", "delete", "soft_delete", "archive"):
            req = self.req()
            req["operation"] = operation
            with self.subTest(operation=operation), self.assertRaises(Rejected):
                self.engine.preview("client1", [req])
        for changes in ({"$set": {"label": "bad"}}, {"deleted": True},
                        {"archived": True}, {"deleted_at": "now"}, {"id": "new"},
                        {"client": "client2"}, {"version": 99}, {"label": None},
                        {"price_cents": True}):
            req = self.req()
            req["changes"] = changes
            with self.subTest(changes=changes), self.assertRaises(Rejected):
                self.engine.preview("client1", [req])
        req = self.req()
        req["upsert"] = True
        with self.assertRaises(Rejected):
            self.engine.preview("client1", [req])
        with self.assertRaises(Rejected):
            self.engine.preview("client1", [self.req("missing")])
        self.unchanged()


if __name__ == "__main__":
    unittest.main(verbosity=2)
