"""Independent synthetic-fixture boundary checks, including named limitations."""
from dataclasses import replace
import unittest

from prototype import (EditOnlyPrototype, FixtureAudit, FixtureOwnerVerifier,
                       InMemoryFixtures, Record, Rejected)


class IndependentBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.now = 100
        self.owner = object()
        self.verifier = FixtureOwnerVerifier(self.owner)
        self.audit = FixtureAudit()
        self.db = InMemoryFixtures([Record("A", "client", 7, "Original", 500)])
        self.engine = EditOnlyPrototype(self.db, self.audit, self.verifier, lambda: self.now)
        self.before = self.db.snapshot()

    def request(self):
        return {"operation": "edit", "id": "A", "expected_version": 7,
                "changes": {"label": "Approved"}}

    def preview(self):
        return self.engine.preview("client", [self.request()])

    def grant(self, preview):
        return self.verifier.issue_for_owner(self.owner, preview)

    def test_operation_cannot_be_an_equality_spoofing_object(self):
        class EqualToEdit:
            def __eq__(self, other):
                return True
        class EditSubclass(str):
            pass
        for operation in (EqualToEdit(), EditSubclass("edit")):
            request = self.request()
            request["operation"] = operation
            with self.subTest(operation=type(operation).__name__), self.assertRaises(Rejected):
                self.engine.preview("client", [request])
        self.assertEqual(self.db.snapshot(), self.before)

    def test_mutating_original_request_cannot_mutate_approved_preview(self):
        request = self.request()
        p = self.engine.preview("client", [request])
        token = self.grant(p)
        request["changes"]["label"] = "UNAPPROVED"
        request["changes"]["price_cents"] = 0
        request["id"] = "absent"
        self.engine.commit(p, "client", token)
        self.assertEqual(self.db.snapshot()["A"], Record("A", "client", 8, "Approved", 500))

    def test_wrong_identity_and_tamper_do_not_consume_valid_grant(self):
        p = self.preview()
        token = self.grant(p)
        with self.assertRaises(Rejected):
            self.engine.commit(p, "different", token)
        altered = replace(p, edits=(replace(p.edits[0], diff=(("label", "Original", "bad"),)),))
        with self.assertRaises(Rejected):
            self.engine.commit(altered, "client", token)
        self.assertEqual(self.db.snapshot(), self.before)
        self.engine.commit(p, "client", token)
        self.assertEqual(self.db.snapshot()["A"].label, "Approved")

    def test_owner_revocation_is_required_for_new_grants_too(self):
        p = self.preview()
        token = self.grant(p)
        with self.assertRaises(Rejected):
            self.verifier.revoke(object(), token)
        self.verifier.revoke(self.owner)
        with self.assertRaises(Rejected):
            self.grant(p)
        with self.assertRaises(Rejected):
            self.engine.commit(p, "client", token)
        self.assertEqual(self.db.snapshot(), self.before)

    def test_failed_old_token_does_not_consume_replacement_grant(self):
        p = self.preview()
        revoked = self.grant(p)
        replacement = self.grant(p)
        self.verifier.revoke(self.owner, revoked)
        with self.assertRaises(Rejected):
            self.engine.commit(p, "client", revoked)
        self.engine.commit(p, "client", replacement)
        self.assertEqual(self.db.snapshot()["A"].version, 8)

    def test_expiry_during_validation_rejects_before_audit_or_swap(self):
        ticks = iter((100, 159, 160))
        engine = EditOnlyPrototype(self.db, self.audit, self.verifier, lambda: next(ticks))
        p = engine.preview("client", [self.request()], ttl=60)
        token = self.grant(p)
        with self.assertRaises(Rejected):
            engine.commit(p, "client", token)
        self.assertEqual(self.db.snapshot(), self.before)
        self.assertEqual(self.audit.events, [])

    def test_restored_field_with_monotonic_version_is_stale(self):
        p = self.preview()
        token = self.grant(p)
        # Simulate another trusted writer changing and restoring the label while
        # incrementing version for each edit. Original preview must remain stale.
        with self.db._lock:
            initial = self.db._records["A"]
            self.db._records["A"] = replace(initial, label="Temporary", version=8)
            self.db._records["A"] = replace(initial, version=9)
        changed = self.db.snapshot()
        with self.assertRaises(Rejected):
            self.engine.commit(p, "client", token)
        self.assertEqual(self.db.snapshot(), changed)

    def test_limitation_unversioned_aba_cannot_be_detected(self):
        """PASS documents a known limitation, not proof of ABA protection."""
        p = self.preview()
        token = self.grant(p)
        with self.db._lock:
            initial = self.db._records["A"]
            self.db._records["A"] = replace(initial, label="Temporary")
            self.db._records["A"] = initial  # broken external writer restores version too
        self.engine.commit(p, "client", token)
        self.assertEqual(self.db.snapshot()["A"].version, 8)

    def test_limitation_audit_append_then_raise_leaves_orphan_intent(self):
        """Simulated audit fault proves no record edit, but no durable transaction."""
        class AppendThenFailAudit:
            def __init__(self):
                self.events = []
            def append(self, event):
                self.events.append(event)
                raise RuntimeError("synthetic append acknowledgement loss")
        audit = AppendThenFailAudit()
        engine = EditOnlyPrototype(self.db, audit, self.verifier, lambda: self.now)
        p = engine.preview("client", [self.request()])
        token = self.grant(p)
        with self.assertRaisesRegex(RuntimeError, "acknowledgement loss"):
            engine.commit(p, "client", token)
        self.assertEqual(self.db.snapshot(), self.before)
        self.assertEqual(len(audit.events), 1)
        self.assertEqual(audit.events[0][0], "fixture_edit_intent")
        with self.assertRaises(Rejected):
            engine.commit(p, "client", token)


if __name__ == "__main__":
    unittest.main(verbosity=2)
