"""Offline fixture demonstration. No network, persistence, or real authority verifier."""
from dataclasses import dataclass, replace
from hashlib import sha256
import json
import math
import threading
import time
import uuid


class Rejected(Exception):
    pass


@dataclass(frozen=True)
class Record:
    id: str
    client: str
    version: int
    label: str
    price_cents: int


@dataclass(frozen=True)
class Edit:
    id: str
    expected_version: int
    # field, old value, new value; tuple-only, immutable scalar values
    diff: tuple


@dataclass(frozen=True)
class Preview:
    nonce: str
    client: str
    expires: float
    edits: tuple

    def digest(self):
        payload = [self.nonce, self.client, self.expires,
                   [[e.id, e.expected_version, e.diff] for e in self.edits]]
        return sha256(json.dumps(payload, separators=(",", ":"),
                                 allow_nan=False).encode()).hexdigest()


class UnconfiguredOwnerVerifier:
    def consume(self, token, digest, client, now):
        raise Rejected("Real owner authority verifier is unconfigured")


class FixtureOwnerVerifier:
    """TEST DOUBLE ONLY. Provisioned owner credential stands in for independent auth.

    Never accept caller assertions such as approved=True. This fake is not suitable
    for production: the trusted test harness provisions its owner credential.
    """
    def __init__(self, owner_credential):
        if type(owner_credential) is not object:
            raise ValueError("Fixture owner credential must be a harness-owned opaque object")
        self._owner_credential = owner_credential
        self._grants = {}
        self._active = True
        self._lock = threading.Lock()

    def issue_for_owner(self, credential, preview):
        # The harness provisions an opaque object capability, never a boolean,
        # string assertion, or caller-controlled equality implementation.
        with self._lock:
            if credential is not self._owner_credential or not self._active:
                raise Rejected("Independent active owner credential required")
            token = uuid.uuid4().hex
            self._grants[token] = (preview.digest(), preview.client, preview.expires)
        return token

    def revoke(self, credential, token=None):
        """Trusted-harness-only simulation of token or owner revocation."""
        with self._lock:
            if credential is not self._owner_credential:
                raise Rejected("Independent owner credential required")
            if token is None:
                self._active = False
                self._grants.clear()
            else:
                self._grants.pop(token, None)

    def consume(self, token, digest, client, now):
        with self._lock:
            if not self._active or type(token) is not str or token not in self._grants:
                raise Rejected("Missing, invalid, or consumed owner approval")
            bound_digest, bound_client, expiry = self._grants[token]
            if (bound_digest, bound_client) != (digest, client) or now >= expiry:
                raise Rejected("Approval binding or expiry mismatch")
            del self._grants[token]


class FixtureAudit:
    def __init__(self):
        self.events = []
        self.fail = False

    def append(self, event):
        if self.fail:
            raise Rejected("Audit unavailable; approval consumed, no edits applied")
        self.events.append(event)


class InMemoryFixtures:
    def __init__(self, records):
        records = tuple(records)
        if len({r.id for r in records}) != len(records):
            raise ValueError("Duplicate fixture IDs")
        self._records = {r.id: r for r in records}
        self._lock = threading.RLock()

    def snapshot(self):
        with self._lock:
            return dict(self._records)  # frozen Record values


class EditOnlyPrototype:
    def __init__(self, fixtures, audit, verifier=None, clock=time.time):
        self.fixtures = fixtures
        self.audit = audit
        self.verifier = verifier or UnconfiguredOwnerVerifier()
        self.clock = clock
        self._previews = {}
        self._used = set()
        self._last_time = None

    def _now(self):
        now = self.clock()
        if type(now) not in (int, float) or not math.isfinite(now):
            raise Rejected("Invalid clock")
        if self._last_time is not None and now < self._last_time:
            raise Rejected("Clock moved backwards")
        self._last_time = now
        return now

    def preview(self, client, requests, ttl=60):
        """requests: [{operation:'edit', id, expected_version, changes:{...}}]."""
        if type(client) is not str or not client or type(ttl) is not int or not 1 <= ttl <= 300:
            raise Rejected("Invalid identity or TTL")
        if type(requests) is not list or not 1 <= len(requests) <= 20:
            raise Rejected("Expected 1..20 explicit edits")
        with self.fixtures._lock:
            edits, seen = [], set()
            for req in requests:
                if type(req) is not dict or set(req) != {"operation", "id", "expected_version", "changes"}:
                    raise Rejected("Unsupported request shape")
                if type(req["operation"]) is not str or req["operation"] != "edit":
                    raise Rejected("Only edit is supported; create/delete/upsert/archive prohibited")
                rid, version, changes = req["id"], req["expected_version"], req["changes"]
                if type(rid) is not str or rid in seen or type(version) is not int:
                    raise Rejected("Invalid or duplicate ID/version")
                record = self.fixtures._records.get(rid)
                if record is None or record.client != client or record.version != version:
                    raise Rejected("Record absent, wrong client, or stale version")
                if type(changes) is not dict or not changes or not set(changes) <= {"label", "price_cents"}:
                    raise Rejected("Only explicit allowed fields; operators and deletion markers prohibited")
                diff = []
                for field, value in sorted(changes.items()):
                    if field == "label" and (type(value) is not str or not value.strip() or not 1 <= len(value) <= 80):
                        raise Rejected("Invalid fixture label")
                    if field == "price_cents" and (type(value) is not int or not 0 <= value <= 1000000):
                        raise Rejected("Invalid fixture price")
                    old = getattr(record, field)
                    if old != value:
                        diff.append((field, old, value))
                if not diff:
                    raise Rejected("No field change")
                seen.add(rid)
                edits.append(Edit(rid, version, tuple(diff)))
            preview = Preview(uuid.uuid4().hex, client, self._now() + ttl, tuple(edits))
            self._previews[preview.nonce] = preview
            return preview

    def commit(self, preview, client, owner_approval=None):
        # Shared adapter lock covers validation, approval consumption, audit and swap.
        # This demonstrates thread safety ONLY; it proves no database atomicity.
        with self.fixtures._lock:
            if type(client) is not str or not client:
                raise Rejected("Invalid client identity")
            if type(preview) is not Preview:
                raise Rejected("Expected immutable preview")
            saved = self._previews.get(preview.nonce)
            if saved is None or saved != preview or saved.digest() != preview.digest():
                raise Rejected("Unrecognized or tampered preview")
            if client != saved.client or self._now() >= saved.expires:
                raise Rejected("Wrong client or expired preview")
            if saved.nonce in self._used:
                raise Rejected("Preview already committed")
            staged = dict(self.fixtures._records)
            for edit in saved.edits:
                current = staged.get(edit.id)
                if current is None or current.client != client or current.version != edit.expected_version:
                    raise Rejected("Record absent, wrong client, or stale version")
                if any(getattr(current, field) != old for field, old, new in edit.diff):
                    raise Rejected("Before value changed")
                staged[edit.id] = replace(current, version=current.version + 1,
                                          **{field: new for field, old, new in edit.diff})
            digest = saved.digest()
            self.verifier.consume(owner_approval, digest, client, self._now())
            # This is an intent only: a crash before swap cannot certify commit.
            self.audit.append(("fixture_edit_intent", digest, client, saved.edits))
            self.fixtures._records = staged
            self._used.add(saved.nonce)
            return tuple(staged[e.id] for e in saved.edits)
