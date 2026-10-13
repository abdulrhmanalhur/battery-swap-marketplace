# Atlas CONNECTIONS reader: reviewed candidate

## Verified state, 2026-10-13

Authoritative source: `abdulrhmanalhur/battery-swap-marketplace`, baseline
`ca280293679060f26c3921e8e177a29b672314b4`, branch `feat/atlas-connections-reader`.
Development and tests run in an isolated local checkout outside Drive.
The source branch is published for review. The reader is not deployed, installed
or enabled in the suite.
The existing twelve MCP definitions remain unchanged.

The user chose and privately saved a traditional project-only read API key.
Metadata confirms `/etc/batteryswap-atlas-monitor` is root-owned 0700 and
`api-public-key` / `api-private-key` are nonempty root-owned 0600 regular files.
The assistant did not read their values. Do not repeat credential setup or
ask for keys in chat. Do not put them in manifests, command arguments, logs,
environment dumps, Git, Drive or operator screenshots.

An explicitly approved historical read ran on the server using systemd
LoadCredential and DynamicUser. Cluster0 measurements were available for all
three nodes in 2026-10-13 05:10–05:45 UTC at PT1M. One node sampled exactly
500 connections at six consecutive minutes, 05:25–05:30 UTC. A worker HTTP500
occurred at 05:26:25 UTC. This is correlation, not proof of TLS causation,
client identity, full-site downtime or values exceeding 500. The transient
unit ended inactive. This is not a current-state or recovery check.

## Runtime and limits

`server.py` registers only `atlas_connections` and runs STDIO. It has no HTTP
listener or public endpoint. Dependencies: Python >=3.10, pinned httpx and MCP
SDK in requirements.txt. Run synthetic tests locally:

```text
python -m unittest discover -s plugins/battery-swap-mcps/services/atlas-monitor/tests -v
```

For the chosen API-key mode the runtime receives only these settings:

```ini
Environment=ATLAS_MONITOR_AUTH_MODE=api_key
LoadCredential=atlas_public_key:/etc/batteryswap-atlas-monitor/api-public-key
LoadCredential=atlas_private_key:/etc/batteryswap-atlas-monitor/api-private-key
```

Systemd supplies CREDENTIALS_DIRECTORY automatically. Missing/invalid credential
files fail closed. OAuth uses separate credential names and explicit mode;
there is no automatic cross-mode fallback. Environment credential values are
only a local development option. Do not share these keys with the existing
MongoDB MCP deployment: its traditional API-key compatibility is unverified.

The reader uses only cloud.mongodb.com with verified TLS, disabled proxies and
redirects, bounded response bodies (including Digest challenge bodies), 10s
request deadlines and a 60s whole-call deadline. It allows fixed-project cluster
metadata, bounded process discovery and CONNECTIONS only, over UTC windows <=24h.
It opens no database sockets, queries no business collections and changes no
Atlas settings. 429/Retry-After returns cooldown; access denial stops querying
additional nodes. Returned-node count reflects actual node results; mapped-node
count separately records discovered processes. Per-node peaks must not be summed.
Missing/null samples and partial results do not prove recovery.

Existing `atlas-inspect-cluster` / `atlas-list-alerts` may supply metadata and
alerts only when already available with suitable permissions. Sanitizing adapters
are pure functions, not additional API tools or proof those tools are connected.

## Permanent activation gates

Ordinary activation has been authorized; new OAuth grants, open ports or
security-policy changes have not. The source-workflow registry check succeeds,
but no publication provider for this new Atlas reader is registered. The
`server-source-workflow` instructions
from the Drive launcher requires a registered source and ready provider before
server publication. Do not bypass the registry by copying code to /opt.

A restricted SSH STDIO design can reuse existing SSH authentication and systemd
LoadCredential without an HTTP listener. It still requires a reviewed deployment
provider, fixed credential-loading runner, isolated pinned dependencies, and a
verified source release. STDIO availability in local Codex does not establish
availability in a Cloud Work conversation. Cloud access needs its supported
plugin/transport and authenticated gateway to be verified separately. Never
expose metrics through unauthenticated HTTP to solve that gap.

After establishing the provider and transport:

1. Refresh origin/main, reconcile any changes, rerun tests and review the diff.
2. Publish only the source, tests, skill and documentation. Exclude repository-root
   probe/evidence/operator artifacts; never publish credentials.
3. Back up only non-sensitive affected configuration; preserve existing twelve
   entries and services. Deploy a versioned release with an isolated environment.
4. Verify MCP initialize/list_tools and the one read-only tool through the actual
   intended client. A passing Python test or SSH read is not plugin activation.
5. Add one optional MCP entry only for the verified transport. Update validation
   and plugin version, then test a fresh conversation on the intended surface.
6. Record commit, provider deployment proof, tool access and health. For rollback,
   disable/remove only the new entry and new release; preserve existing services
   and private key files. Do not delete credentials as part of code rollback.

Do not claim permanent activation until those gates pass. Current remaining gaps
are deployment-provider registration and verified client transport, plus client
attribution and causal evidence for the application failures.

References: [Atlas API access](https://www.mongodb.com/docs/atlas/configure-api-access/),
[authentication](https://www.mongodb.com/docs/atlas/api/api-authentication/),
[measurements](https://www.mongodb.com/docs/api/doc/atlas-admin-api-v2/operation/operation-getgroupprocessmeasurements),
[Codex MCP transports](https://learn.chatgpt.com/docs/extend/mcp).


## Authorized OAuth implementation and closed bootstrap

The owner subsequently approved the limited devhub source/service publication
policy and a separate GitHub OAuth App, BatterySwap Atlas Reader. The application
source now includes owner_auth.py and http_server.py. GitHub scope is explicitly
empty, identity verification accepts numeric owner ID108840765 only, and local
MCP permission is atlas:connections:read with a resource-bound signed token.
Local mock tests cover OAuth/PKCE, wrong owner/audience/scope, rotating local
refresh, metadata/tool discovery, body limits and the initial registry policy.
This is not a successful real-user OAuth login or deployment claim.

GitHub app creation remains user-assisted because no supported browser/app-creation
tool is exposed. Client ID and Client Secret are privately entered by the owner
only after the app is created. The destination github-oauth under the private
Atlas directory has been prepared; never restart entry or overwrite nonempty
files automatically. No new input window may be opened until the user is ready.

The root-only deploy/bootstrap_admin.py imports one exact Git-backed frozen source
bundle under the installed workflow activation lock and preserves every existing
registry row. It records only atlas-monitor, a four-file publication allowlist,
read-only AGENTS.md instructions and the fixed batteryswap-atlas-monitor.service.
Dependencies, units, admin code and secret state are outside that allowlist.
Initial readiness is snapshot=true and publish=false. The existing administrative
verify_projects.py enable gate requires an active healthy provider; it cannot be
bypassed merely because publication was authorized. Enable only after private
credential setup, loopback runtime health and fresh provider verification.

The fixed unit runs DynamicUser with root-loaded credentials, private state and
an immutable isolated Linux wheel runtime. It starts neither during registration
nor without completed private credentials. The public gateway is not modified
by this bootstrap. Gateway installation must add only the exact Atlas resource,
callback and discovery routes after authenticating transport is verified, with
OAuth access/query logging disabled. Preserve existing routes and a protected
configuration backup. Never reuse a hidden URL as authentication or reuse the
Google Ads consent-only authorization implementation.

Rollback first disables the new optional suite entry, closes only Atlas routes,
and stops only the new service; restore an affected configuration only after a
hash/CAS check so newer unrelated changes remain intact. Keep protected source,
registration journals and credential files. Source changes after initial import
use the ordinary registered workflow with its backups and provider validation.
No direct app-source replacement or reset is authorized by the bootstrap.
