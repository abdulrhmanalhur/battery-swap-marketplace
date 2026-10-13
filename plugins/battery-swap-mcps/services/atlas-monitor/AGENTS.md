# Restricted Atlas reader

Use the source-workflow project `atlas-monitor` and its isolated local WORK.
Read its attached instructions before editing. Only atlas_monitor.py, server.py,
owner_auth.py and http_server.py are publishable application source.
Dependencies and administrative assets are not editable through that provider.

Preserve the fixed Atlas project/Cluster0, owner GitHub ID108840765, empty upstream
GitHub scopes, local atlas:connections:read scope, audience binding and PKCE.
Never expose metrics anonymously, add write/database tools, return credentials,
log auth input/URLs/bodies, or copy OAuth/Atlas state into source or Drive.

Run the complete local unittest suite with the pinned isolated runtime, check
Python syntax and git diff --check. Tests use mock credentials/transports only.
Administrative registration, dependencies, service identity and gateway changes
require their reviewed root deployment path; do not edit /opt or registry ad hoc.
Source publication uses the fixed service and ready provider under workflow locks.
