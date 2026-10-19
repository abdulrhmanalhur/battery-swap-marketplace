# BatterySwap MongoDB read runtime — local review package

Nothing here has been deployed. No MongoDB credential, GitHub app, production
service, route, document or security setting was created/changed.

The fixed namespace is test, verified in Atlas by the parent-reported browser task
01a154ca-4931-7212-a741-35aa2661c0c3: project69cd58b657e3ebb03722b5ba,
Cluster0,57 collections. Public application code alone did not identify it.
No .env, MongoDB URI, rejected data source or browser session file was inspected.

## Runtime and authentication

http_server.py is a runnable loopback-only HTTP entry point, disabled unless
MONGODB_READ_ACTIVATED=1. It uses systemd credential files at runtime, one
MongoReader and one worker, owner GitHub OAuth and exactly two MCP tools: find
and count. It never registers proposal, approval, execute, connect, aggregation,
export or administrative tools. Legacy mcp_gateway.py/access.py proposal classes
are separate fixture research; the read runtime does not expose them.

owner_auth.py is an isolated adapted copy of the existing Atlas Reader auth code;
Atlas files and PR1 are untouched. GitHub public API confirmed abdulrhmanalhur is
numeric ID108840765. A NEW dedicated OAuth App must be approved and created;
no Atlas app secret is reused. GitHub scopes stay empty. Owner ID is checked at
exchange/refresh and token use (30-second bounded identity cache). Local scope is
mongodb:read; tokens bind to https://mcpgooads.batteryswap.cc/mongodb/mcp.
Access lasts15minutes, rotating refresh at most30days. PKCE S256, resource checks,
owner consent and fixed redirect patterns are required. Auth store is encrypted
on disk using material derived from the dedicated app secret, under the service's
private StateDirectory. One process only; this is not a distributed token store.

Issuer: https://mcpgooads.batteryswap.cc/mongodb/auth
GitHub callback: https://mcpgooads.batteryswap.cc/mongodb/auth/callback
Consent: https://mcpgooads.batteryswap.cc/mongodb/auth/consent
Authorize/token/register: same issuer plus /authorize, /token, /register.
Metadata: /.well-known/oauth-authorization-server/mongodb/auth and
/.well-known/oauth-protected-resource/mongodb/mcp on the same host.
Root OAuth metadata is deliberately not replaced.

Local Codex and Claude Code use DCR with exact registered loopback redirects,
then owner login/consent. Supported ChatGPT clients may use ChatGPT-only CIMD;
untrusted metadata hosts are rejected before fetching. Claude remote callbacks
are constrained to the configured exact claude.ai/claude.com MCP callback paths;
actual hosted-client compatibility must be checked during approved activation.
No callback wildcard for arbitrary hosts is permitted. Fixture interoperability
is not a live Codex/Claude browser-login certification.

## Data and connection policy

mongo_reader.py uses PyMongo4.17.0. It accepts only a TLS SRV URI under mongodb.net,
explicit /test, dedicated username batteryswap-mcp-reader and optional authSource=admin.
Other URI options, insecure TLS and other DBs are rejected. Runtime identity must
have read on test only; username and URI validation alone do not prove RBAC.
MongoDB enforces the read-only role; the gateway additionally limits namespaces.

read-policy.json covers all57collections via typed public schemas at commit
 a71824819f80cd6ce97c74e216f8b11a1a0f3fb1. POLICY-EVIDENCE.json records sources
and115exclusions. Recursive typed projections preserve financial/inventory data;
free text, SMS bodies, Mixed, select:false, credentials/login/redeemable codes and
private URLs/files are excluded. Phones/emails and textual references are masked
or hashed; SHA256 is stable correlation, not strong anonymization. Label outputs
are bounded and reject credential-like content and arbitrary BSON Binary/Code.
Labels and masked fields cannot be queried, including count; id/enum use eq/in
only. Three collections are metadata-only as documented in the approval card.

Queries use an operator allowlist; no regex/$where/$expr/JS/pipelines. Filtering
on unapproved fields is blocked to avoid inference through count. Only _id values
of24hex characters are converted to ObjectId; results use canonical Extended JSON.
Limits:100documents,1MiB output,8KiB query,depth4,20keys,3-second server execution
limit. Pool max2 PER SERVER, min0, maxConnecting1; two concurrent DB operations;
500ms wait queue,5-second connect/selection/socket timeouts; no retries. Replica
set monitoring uses additional sockets: maxPoolSize2 is NOT a total cap of2.
Driver errors are replaced with a fixed message; request/credential logging is off.

## Review and validation

Run in isolated local runtime with requirements.txt, never against production:

    python -m unittest discover -s plugins/battery-swap-mcps/services/mongodb-access/tests -v
    python plugins/battery-swap-mcps/services/mongodb-access/verify_bundle.py .

The independent review findings were fixed with regression tests. OAuth state now
has durable encrypted quotas, and owner input rejects missing TTY/GetPassWarning.
The local fixture suite covers owner-only OAuth, PKCE/resource/scope/redirect
rejection, rotating refresh, upstream-token rejection, actual HTTP metadata and
catalog, read-only mode, mock PyMongo projection/BSON/deadline/pool/error handling,
and historical proposal/approval negative fixtures. All signing material is fake
or ephemeral in memory; no DB network calls occur. AnyIO stream cleanup warnings
and Authlib deprecation warnings remain in the test harness/dependencies.

linux-runtime-requirements.lock pins72wheel hashes. linux-wheels/ is local build
material, not source to commit. Hashes, Requires-Python and dependency closure are
verified for Linux CPython3.10 x86_64; execution on Linux remains untested here.

See SECURITY-REVIEW.md and ACTIVATION-APPROVAL.md. Proposed deployment templates
are in deploy/. They are additive templates, not a freshness-verified patch of
live Nginx. No local nginx or systemd executable was available to validate syntax;
nginx -t and systemd-analyze verify are mandatory before activation. No deployment
script silently applies them. Existing12MCP definitions remain unchanged.

Primary implementation references: installed FastMCP3.2.4 OAuthProxy source;
https://api.github.com/users/abdulrhmanalhur ;
https://code.claude.com/docs/en/mcp ;
https://www.mongodb.com/docs/manual/reference/built-in-roles/#read ;
https://www.mongodb.com/docs/languages/python/pymongo-driver/current/connect/connection-options/connection-pools/
