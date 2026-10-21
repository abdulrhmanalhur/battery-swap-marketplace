# Bounded offline campaign — 2026-10-21

Scope: synthetic Python fixtures only. No application edit, production request,
connector change, credentials, service installation, permission expansion, push,
deployment, or production metadata creation. Local fault injection modifies only
synthetic in-memory records to represent external corruption/crashes.

## Commands and results

Working directory:
`C:/Users/abdul/Documents/Codex/2026-10-21/task/edit-only-offline-20261021`

```powershell
python -B -m unittest discover -v
```

Actual result: **46 test methods passed, 0 failed, 0 skipped, exit 0, 0.058s**.
Breakdown: 17 baseline methods, 20 campaign methods, 9 independent methods. Methods
contain additional parameterized subcases; the count is methods, not scenario count.
Raw saved output: `CAMPAIGN-OUTPUT.txt`.

Independent review first reproduced the operation-type validation bug in two
subcases (object and string subclass); it was fixed. Independent rerun separately
passed 9 methods, exit 0 (0.001s), recorded in `REVIEW-INDEPENDENT.md`.
The full 46-test run above includes the fixed independent tests.

## Matrix

| Area | Status | Executed evidence / practical boundary |
| --- | --- | --- |
| No approval, caller booleans, fabricated token | PASS | All reject with records unchanged; real verifier unconfigured rejects. |
| Independent owner capability | PASS, TEST DOUBLE ONLY | Wrong owner, equality spoof, bool/string credential setup rejected. No real owner auth verified. |
| Revocation | PASS, TEST DOUBLE ONLY | Token revoke, owner revoke, replacement-token preservation and no new grants for revoked owner. |
| Exact preview binding | PASS | Nonce, ID, version, before/after, field, batch order/membership, client and expiry tampering rejected; grant cannot authorize another preview. |
| Immutable preview / input alias | PASS | Mutating source request does not alter preview/digest or approved effect. |
| Client and operation types | PASS AFTER FIX | Exact string checks reject equality-spoofing Python objects/subclasses. No HTTP/JSON transport implemented. |
| Edit-only API | PASS | Create/insert/replace/delete/remove/soft-delete/archive/upsert/bulk/arbitrary operators, unknown fields, roles/credentials/deletion markers rejected. |
| Input boundaries | PASS AFTER FIX | Empty/oversize/no-op/duplicate requests, bool/float/NaN/Inf prices, absent/foreign ID, TTL/range and excessive raw whitespace length rejected. |
| Expiry and clock | PASS, IN-PROCESS ONLY | Before/at expiry, expiry between validation and consume, nonfinite/invalid/backwards clock reject. No cross-process trusted-time proof. |
| Stale and before-values | PASS | Stale batch writes nothing; mismatched before-value rejects even without incremented version. |
| Versioned ABA | PASS | A→B→A increments revision twice; old preview remains stale. |
| Unversioned ABA | LIMITATION DEMONSTRATED | Broken external writer restores original value AND revision; old preview can commit. Explicit passing limitation test shows this detection guarantee is unavailable. All writers must maintain monotonic versions. |
| Replay | PASS, IN-PROCESS ONLY | Same approval/preview cannot commit twice; pending preview after engine recreation is rejected. No persisted replay ledger exists. |
| Shared-adapter concurrency | PASS | Eight duplicate attempts; two competing engines; bounded 20 rounds × 8 engines = 160 attempts, one success per round. |
| Audit rejection | PASS | Rejection before append preserves records and consumes approval; retry with old approval rejected. |
| Audit append then fault | LIMITATION DEMONSTRATED | Runtime acknowledgement loss and simulated crash after append leave an orphan INTENT, no record edit; approval consumed. Intent explicitly does not claim commit. No durable transaction demonstrated. |
| Failure before swap | PASS, SIMULATION ONLY | Consumed approval then simulated crash leaves records/audit untouched; stale second batch row cannot partially write. No OS process was killed. |
| Response loss after swap | PASS, SIMULATION ONLY | Edit remains committed; retry rejected. Response failure is not rollback; durable status lookup absent. |
| Reverse/rollback semantics | PASS, COMPENSATING FIXTURE EDIT ONLY | Fresh exact preview + approval + current revision required; stale reverse cannot overwrite later edit. No automatic document restore or real database rollback claimed. |
| Database transaction rollback, audit atomicity | NOT RUN | No verified isolated suitable DB was found. |
| Durable replay, restart recovery, worker/process races | NOT RUN | Need persistent ledger/transaction adapter and isolated DB; thread locks are not evidence. |
| Real crash recovery / uncertain DB commit | NOT RUN | Need kill/restart fault harness in disposable isolated environment and durable outcome reconciliation; no production process manipulation authorized. |
| Owner Firebase revocation, recent reauth, CSRF/Origin | NOT RUN | No production auth integration implemented; test-double results cannot establish these. |
| Effective DB role/no-upsert enforcement | NOT RUN | No roles changed or credentials used; must test narrow effective role in isolated DB. |
| Real BannerText, caches and other domains | NOT RUN | No real edits authorized; local source review only. |

## Local fixes made

Only `prototype.py` and local test/document files changed. Added exact commit-client
and operation type guards, raw label-size validation, finite/nonregressing observed
clock validation, trusted fake revocation, and accurate pre-swap audit intent naming.
Independent review identified and reproduced the operation type flaw before its fix.
The fixture verifier is still explicitly fake; production verifier still rejects.

## Database discovery and exact prerequisite

Safe metadata check at **2026-10-21 09:47:45 UTC**:

```powershell
Get-Process -Name mongod -ErrorAction SilentlyContinue
Get-Command mongod,mongosh -ErrorAction SilentlyContinue
```

Both inventories returned zero entries. This is bounded discovery, not a claim
that no database can exist anywhere on this computer. No database connection,
production credential lookup, service installation or remote probe was attempted.

**Unrun action:** transaction/durable replay integration tests against MongoDB.
**Target:** no verified isolated synthetic-only instance supplied or discovered.
**Reason:** cannot establish suitable test topology, isolation and credentials from
safe local metadata. **Status:** not attempted; not denied and no uncertain outcome.

Exact prerequisite: an already running disposable test MongoDB instance supporting
transactions, independently verified separate from production, with synthetic-only
collections, dedicated test credentials and permission to write approval/audit test
metadata there; plus a transaction/ledger adapter under test. Supply a verified local
endpoint and test-only setup provenance without production secrets. Installing or
configuring a service would need separate authorization and was not done. Real crash
tests additionally require explicit authority to stop/restart disposable test workers.

## Read-only application integration recheck

Local checkout `C:/Users/abdul/AppData/Local/Temp/battery-swap-mongo-01a1307e`
was re-read at the relevant source boundaries. It was not modified.

- `src/app/api/site/banner-texts/[id]/route.ts:22` still uses unversioned
  `findByIdAndUpdate`; line 42 has deletion. Neither is an approved assistant path.
- `src/lib/managerAuth/session.ts:53` has session caching; lines 218/247/258 have
  degraded cookie-claim verification and 269/297 permit a configured bypass. A
  dedicated fresh strict owner guard must reject those paths for approvals.
- No durable approved-edit service, transactional metadata, strict owner approval
  UI or domain-specific writer was implemented in this campaign.
- The prepared generic MCP bridge's saved delete-proposal capability remains a
  prior source finding, unchanged. Do not activate it for edit-only scope.

See `SECURITY-AND-INTEGRATION-REVIEW.md` for exact proposed application components,
minimum privileges and owner-facing banner-text proposal. The user authorized this
test campaign, not actual BannerText changes or security metadata creation. Those
remain separately unapproved, and all-domain production safety is unproved.
