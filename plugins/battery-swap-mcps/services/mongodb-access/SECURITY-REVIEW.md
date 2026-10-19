# Local security review — 2026-10-19

Status: reviewable read-only implementation, NOT DEPLOYED and NOT live-certified.
Review performed by implementation agent; this is not an independent penetration test.

## Decisions and evidence

- Namespace test is from the separate authenticated browser task reported by the
  parent, not from an environment secret. Public GitHub API confirmed owner
  abdulrhmanalhur /108840765. The read issuer/resource and app credentials are
  separate from Atlas Monitor. Atlas PR1/source were not modified or activated.
- Runtime registers exactly find/count. It contains no writer credential, mutation
  command, connection-switch tool, approval endpoint or proposal relay. The legacy
  server remains unchanged with --readOnly; its fail-open elicitation confirmation
  is not used. Legacy URL authentication/RBAC is not proven by this new package.
- DB-enforced read role on test is mandatory. A username check and fixed namespace
  cannot certify the actual Atlas role; owner verifies role assignment on creation.
- Deny-by-default projection/query policy prevents filtering on hidden fields.
  All57 public schemas now have typed recursive field policies; exclusions are
  recorded in POLICY-EVIDENCE.json. Three collections expose metadata only. No claim of complete secret classification is made.
- Arbitrary operators, pipelines, raw commands, regex/JS, cross-DB input and URI
  options are blocked; TLS certificate and hostname checks are mandatory.
- One reusable client, one worker, pool2 per server/min0, two DB calls, deadlines,
  bounded body/query/output and cursors closed on failure constrain added load.
  Monitoring sockets are additional. This does not establish the cause of old
  Atlas500connection/TLS incidents or imply they are resolved.
- OAuth requires owner verification, empty GitHub scopes, exact resource/scope,
  S256 PKCE, consent and redirect validation. Raw GitHub tokens do not authenticate
  to MCP. Access tokens last15minutes; refresh rotation is bounded30days and owner
  rechecked. Identity cache can delay revocation by up to30seconds.
- DCR is public for client interoperability but grants no DB privilege without
  owner login/consent. Nginx rate limits/body cap mitigate registration abuse;
  durable encrypted quotas cap clients64, transactions/codes128 and JTI512,
  with record/index limits and TTL. The real encrypted file backend was tested.
  CIMD is restricted to configured ChatGPT HTTPS metadata paths; other hosts are
  rejected. Exact hosted-client interoperability still needs approved login tests.
- OAuth state is library-managed Fernet-encrypted file storage with keys derived
  from the dedicated app secret. Private StateDirectory/UMask isolate local state;
  current root can still read/alter it. Secret rotation invalidates sessions and
  requires client reauthorization; never delete ledger/state as a silent repair.
- Application error details, HTTP request logs and new-route Nginx query logs are
  suppressed. Driver exceptions return a fixed message without URI/query content.
  Owner credential input is getpass-only, creates root0600 files without overwrite
  or symlink following, and is never executed by the assistant in this preparation.

## Local checks

53unittest cases cover HTTP/OAuth/protocol and mock PyMongo read behavior; no
production DB credential or MongoDB network call used. Tests include unapproved
operators/fields/collections, TLS/URI rejection, output/cursor/slot limits,
ObjectId conversion, fixed error sanitization, foreign owner/audience/scope,
PKCE, redirects, refresh replay, raw upstream token rejection and no writer tools.
Historical proposal fixtures remain nonproduction and never execute real writes.

72Linux wheels are hash pinned. verify_bundle.py checks each SHA256, version,
Requires-Python and dependency closure for Linux CPython3.10 x86_64. Tests execute
on local Windows Python3.12; Linux runtime, Nginx/systemd parsers, actual DNS/TLS,
Atlas RBAC and real client consent have NOT been exercised. Authlib deprecation
and AnyIO fixture stream ResourceWarning messages remain; all assertions pass.
No dependency vulnerability scanner was run; pinned versions are not a claim of
zero vulnerabilities.

## Mandatory activation gates

1. Review/approve exact source manifest, least-privilege DB role and OAuth app card.
2. Register authoritative source per server-source workflow; no ad hoc /opt copy.
   Produce freshest Nginx diff under deployment lock; identify real virtual-host
   filename and preserve existing root OAuth/other connector locations.
3. Review the57-collection typed policy and financial/personal categories in
   ACTIVATION-APPROVAL.md; do not silently expand excluded fields.
4. Owner privately creates/inserts the approved credentials. No secret in chat,
   screenshots, shell arguments/history, Git, logs or agent-readable diagnostics.
5. Verify port8018 free, Linux imports, systemd unit and nginx syntax before enable.
   Existing Atlas network allowance must permit the server; if not, stop and seek
   separate exact-IP authorization. Never add0.0.0.0/0 or relax TLS.
6. After explicit activation approval: start only new reader, test unauthenticated
   401, owner login/resource-bound read/count, foreign token denial and absent
   mutation tools; no destructive real-write probe. Verify current connector URLs
   still work without printing their credentials/hidden aliases.
7. Only then begin old Atlas/Sentry incident investigation through authorized
   read access. No causal finding has been made by this connector work.

## Guarantee boundary

This package can enforce read-only behavior for its dedicated DB account and MCP
surface. It cannot make every existing root/CI/deployment/production writer path
require human approval. Write access later needs a genuinely independent trusted
executor/approval boundary or separately approved removal of AI administration
rights to every environment holding writer credentials. Read-only activation does
not need that writer host and does not authorize its creation.

## Independent review and fixes

Independent static review found scalar/BSON value leakage, possible getpass echo,
unbounded public client registration and absent-resource Claude incompatibility.
All were fixed with typed sanitization, fail-closed TTY input, durable encrypted
quota/TTL admission, and fixed-resource fallback. Re-review found label range/count
inference; all label querying is now forbidden, and id/enum range/ne/exists are
rejected before DB access. Added regression checks and all53tests pass.
The quota was additionally tested with real encrypted FileTree fixtures across
wrapper restart. Raw business labels still rely on their approved schema meaning;
pattern rejection is defense in depth, not a universal secret classifier.
Stable unsalted phone/email references are not strong anonymization; approval
explicitly discloses this and the OpenAI/Anthropic result recipients.
