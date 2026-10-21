"""Bounded synthetic-only adversarial and partial-failure campaign."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import threading
import unittest

from prototype import (EditOnlyPrototype, FixtureAudit, FixtureOwnerVerifier,
                       InMemoryFixtures, Record, Rejected)


class SimulatedCrash(BaseException):
    pass


class Campaign(unittest.TestCase):
    def setUp(self):
        self.now = 1000
        self.db = InMemoryFixtures([Record("a", "one", 1, "A", 100),
                                    Record("b", "one", 1, "B", 200),
                                    Record("c", "two", 1, "C", 300)])
        self.owner = object()
        self.auth = FixtureOwnerVerifier(self.owner)
        self.audit = FixtureAudit()
        self.engine = EditOnlyPrototype(self.db, self.audit, self.auth, lambda: self.now)

    def req(self, rid="a", version=1, changes=None):
        return dict(operation="edit", id=rid, expected_version=version,
                    changes={"price_cents": 150} if changes is None else changes)

    def p(self, requests=None):
        return self.engine.preview("one", [self.req()] if requests is None else requests)

    def grant(self, p):
        return self.auth.issue_for_owner(self.owner, p)

    def test_original_request_mutation_cannot_change_preview(self):
        request = self.req()
        p = self.p([request])
        digest = p.digest()
        request["id"] = "b"
        request["changes"]["price_cents"] = 999
        self.assertEqual(p.digest(), digest)
        self.engine.commit(p, "one", self.grant(p))
        self.assertEqual(self.db.snapshot()["a"].price_cents, 150)
        self.assertEqual(self.db.snapshot()["b"].price_cents, 200)

    def test_all_preview_components_and_batch_binding(self):
        p = self.p([self.req(), self.req("b", changes={"label": "B2"})])
        token = self.grant(p)
        before = self.db.snapshot()
        variants = [replace(p, nonce="unregistered"), replace(p, edits=p.edits[::-1]),
                    replace(p, edits=p.edits[:1]),
                    replace(p, edits=(replace(p.edits[0], diff=(("label", "A", "evil"),)), p.edits[1])),
                    replace(p, edits=(replace(p.edits[0], diff=(("price_cents", 99, 150),)), p.edits[1]))]
        for changed in variants:
            with self.assertRaises(Rejected):
                self.engine.commit(changed, "one", token)
        self.assertEqual(self.db.snapshot(), before)
        self.assertEqual(self.audit.events, [])

    def test_wrong_typed_client_cannot_override_equality(self):
        class ForgedClient:
            def __eq__(self, other):
                return True
        p = self.p()
        for client in (ForgedClient(), True, None, b"one", ["one"]):
            with self.assertRaises(Rejected):
                self.engine.commit(p, client, self.grant(p))
        self.assertEqual(self.db.snapshot()["a"].version, 1)

    def test_fake_token_revocation_and_wrong_owner(self):
        p = self.p()
        token = self.grant(p)
        with self.assertRaises(Rejected):
            self.auth.revoke(object(), token)
        self.auth.revoke(self.owner, token)
        with self.assertRaises(Rejected):
            self.engine.commit(p, "one", token)
        self.assertEqual(self.audit.events, [])

    def test_fake_owner_revocation_blocks_existing_and_new_grants(self):
        p = self.p()
        token = self.grant(p)
        self.auth.revoke(self.owner)
        with self.assertRaises(Rejected):
            self.engine.commit(p, "one", token)
        with self.assertRaises(Rejected):
            self.grant(p)
        self.assertEqual(self.db.snapshot()["a"].version, 1)

    def test_direct_verifier_digest_client_and_expiry_binding(self):
        p = self.p()
        token = self.grant(p)
        for digest, client, now in (("bad", "one", 1000), (p.digest(), "two", 1000),
                                   (p.digest(), "one", p.expires)):
            with self.assertRaises(Rejected):
                self.auth.consume(token, digest, client, now)
        # Invalid attempts do not convert the token to a different authorization.
        self.engine.commit(p, "one", token)

    def test_expiry_before_and_at_boundary(self):
        p = self.p()
        self.now = p.expires - .001
        self.engine.commit(p, "one", self.grant(p))
        other = self.p([self.req("b")])
        token = self.grant(other)
        self.now = other.expires
        with self.assertRaises(Rejected):
            self.engine.commit(other, "one", token)
        self.assertEqual(self.db.snapshot()["b"].version, 1)

    def test_invalid_clock_and_backward_clock_fail_closed(self):
        p = self.p()
        token = self.grant(p)
        for bad in (float("nan"), float("inf"), True, None, "1001", 999):
            self.now = bad
            with self.assertRaises(Rejected):
                self.engine.commit(p, "one", token)
        self.assertEqual(self.db.snapshot()["a"].version, 1)
        self.now = p.expires
        with self.assertRaises(Rejected):
            self.engine.commit(p, "one", token)
        self.now = 1001
        with self.assertRaisesRegex(Rejected, "backwards"):
            self.engine.commit(p, "one", token)

    def test_known_json_shapes_operator_and_nonedit_matrix(self):
        before = self.db.snapshot()
        operations = ("create", "insert_one", "replace", "replace_one", "delete", "delete_one",
                      "remove", "archive", "soft_delete", "upsert", "update_many", "UPDATE", None, 1)
        for op in operations:
            request = self.req()
            request["operation"] = op
            with self.subTest(op=op), self.assertRaises(Rejected):
                self.p([request])
        fields = ("$set", "$unset", "$inc", "$rename", "$push", "$pull", "$setOnInsert",
                  "label.x", "__proto__", "constructor", "deleted", "isDeleted", "archivedAt",
                  "status", "roles", "password", "client", "id", "version")
        for field in fields:
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.p([self.req(changes={field: "x"})])
        for value in ([], {}, None, True, 1.1, float("nan"), float("inf"), "100", -1):
            with self.subTest(value=value), self.assertRaises(Rejected):
                self.p([self.req(changes={"price_cents": value})])
        for requests in (None, {}, "edit", [None], [[]]):
            # p(None) is a convenience default; exercise the actual interface here.
            with self.subTest(requests=requests), self.assertRaises(Rejected):
                self.engine.preview("one", requests)
        for key in ("upsert", "approved", "owner", "$where", "session"):
            request = self.req()
            request[key] = True
            with self.assertRaises(Rejected):
                self.p([request])
        self.assertEqual(self.db.snapshot(), before)
        self.assertEqual(self.audit.events, [])

    def test_raw_label_length_and_no_mutable_scalar(self):
        for label in (" " * 10000 + "x", "x" + " " * 10000, "", "\t\n", {}, []):
            with self.assertRaises(Rejected):
                self.p([self.req(changes={"label": label})])
        p = self.p([self.req(changes={"label": "x" * 80, "price_cents": 0})])
        self.engine.commit(p, "one", self.grant(p))
        self.assertEqual(self.db.snapshot()["a"].label, "x" * 80)

    def test_aba_via_valid_edits_cannot_revive_stale_preview(self):
        original = self.p()
        original_token = self.grant(original)
        forward = self.p([self.req(changes={"price_cents": 101})])
        self.engine.commit(forward, "one", self.grant(forward))
        reverse = self.p([self.req(version=2, changes={"price_cents": 100})])
        self.engine.commit(reverse, "one", self.grant(reverse))
        with self.assertRaises(Rejected):
            self.engine.commit(original, "one", original_token)
        self.assertEqual(self.db.snapshot()["a"].version, 3)
        self.assertEqual(self.db.snapshot()["a"].price_cents, 100)

    def test_foreign_or_absent_target_after_preview_rejects_whole_batch(self):
        for corruption in ("absent", "foreign"):
            with self.subTest(corruption=corruption):
                self.setUp()
                p = self.p([self.req(), self.req("b")])
                with self.db._lock:
                    if corruption == "absent":
                        del self.db._records["b"]  # external fault simulation only
                    else:
                        self.db._records["b"] = replace(self.db._records["b"], client="two")
                fault_state = self.db.snapshot()
                with self.assertRaises(Rejected):
                    self.engine.commit(p, "one", self.grant(p))
                self.assertEqual(self.db.snapshot(), fault_state)
                self.assertEqual(self.audit.events, [])

    def test_batch_staging_exception_does_not_partially_write(self):
        p = self.p([self.req(), self.req("b")])
        # Adapter corruption on second row, before approval consumption.
        with self.db._lock:
            self.db._records["b"] = replace(self.db._records["b"], version="broken")
        fault_state = self.db.snapshot()
        with self.assertRaises(Rejected):
            self.engine.commit(p, "one", self.grant(p))
        self.assertEqual(self.db.snapshot(), fault_state)

    def test_verifier_consumes_then_crashes_no_automatic_retry(self):
        p = self.p()
        token = self.grant(p)
        real = self.auth.consume
        def crash(*args):
            real(*args)
            raise SimulatedCrash("after consume")
        self.auth.consume = crash
        with self.assertRaises(SimulatedCrash):
            self.engine.commit(p, "one", token)
        self.auth.consume = real
        with self.assertRaises(Rejected):
            self.engine.commit(p, "one", token)
        self.assertEqual(self.db.snapshot()["a"].version, 1)
        self.assertEqual(self.audit.events, [])

    def test_audit_append_then_crash_records_intent_not_success(self):
        p = self.p()
        token = self.grant(p)
        original = self.audit.append
        def crash(event):
            original(event)
            raise SimulatedCrash("after audit, before snapshot swap")
        self.audit.append = crash
        with self.assertRaises(SimulatedCrash):
            self.engine.commit(p, "one", token)
        self.assertEqual(self.db.snapshot()["a"].version, 1)
        self.assertEqual(self.audit.events[0][0], "fixture_edit_intent")
        self.audit.append = original
        with self.assertRaises(Rejected):
            self.engine.commit(p, "one", token)

    def test_success_response_loss_is_not_rollback(self):
        p = self.p()
        token = self.grant(p)
        def response_lost():
            self.engine.commit(p, "one", token)
            raise ConnectionError("synthetic response loss")
        with self.assertRaises(ConnectionError):
            response_lost()
        self.assertEqual(self.db.snapshot()["a"].price_cents, 150)
        with self.assertRaises(Rejected):
            self.engine.commit(p, "one", token)
        self.assertEqual(self.db.snapshot()["a"].version, 2)

    def test_engine_restart_forgets_pending_preview_fails_closed(self):
        p = self.p()
        token = self.grant(p)
        restarted = EditOnlyPrototype(self.db, self.audit, self.auth, lambda: self.now)
        with self.assertRaises(Rejected):
            restarted.commit(p, "one", token)
        self.assertEqual(self.db.snapshot()["a"].version, 1)

    def test_reverse_edit_needs_new_approval_and_current_version(self):
        p = self.p()
        old_token = self.grant(p)
        self.engine.commit(p, "one", old_token)
        reverse = self.p([self.req(version=2, changes={"price_cents": 100})])
        with self.assertRaises(Rejected):
            self.engine.commit(reverse, "one", old_token)
        self.engine.commit(reverse, "one", self.grant(reverse))
        self.assertEqual(self.db.snapshot()["a"].price_cents, 100)
        self.assertEqual(self.db.snapshot()["a"].version, 3)

    def test_stale_reverse_edit_does_not_overwrite_later_edit(self):
        p = self.p()
        self.engine.commit(p, "one", self.grant(p))
        reverse = self.p([self.req(version=2, changes={"price_cents": 100})])
        later = self.p([self.req(version=2, changes={"price_cents": 175})])
        self.engine.commit(later, "one", self.grant(later))
        with self.assertRaises(Rejected):
            self.engine.commit(reverse, "one", self.grant(reverse))
        self.assertEqual(self.db.snapshot()["a"].price_cents, 175)

    def test_bounded_thread_stress_exactly_one_per_revision(self):
        # 20 rounds x 8 independent engines sharing one adapter, 160 attempts.
        for round_no in range(20):
            engines = [EditOnlyPrototype(self.db, self.audit, self.auth, lambda: self.now)
                       for _ in range(8)]
            revision = self.db.snapshot()["a"].version
            proposals = [e.preview("one", [self.req(version=revision,
                          changes={"price_cents": 500 + round_no})]) for e in engines]
            tokens = [self.grant(p) for p in proposals]
            barrier = threading.Barrier(8)
            def attempt(args):
                engine, preview, token = args
                barrier.wait(timeout=10)
                try:
                    engine.commit(preview, "one", token)
                    return True
                except Rejected:
                    return False
            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(attempt, zip(engines, proposals, tokens)))
            self.assertEqual(sum(results), 1)
        self.assertEqual(self.db.snapshot()["a"].version, 21)
        self.assertEqual(len(self.audit.events), 20)
        self.assertEqual(set(self.db.snapshot()), {"a", "b", "c"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
