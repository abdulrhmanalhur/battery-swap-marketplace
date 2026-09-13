# BatterySwap MCP security policy

This public repository intentionally does not disclose production endpoint
inventories, service versions, tool counts, authentication gaps, or probe
results. Keep those records in private operational documentation.

## Release requirements

Before enabling a production MCP route:

1. Require OAuth or a server-side bearer-token gateway.
2. Grant the minimum read/write scope required for that service.
3. Keep credentials in the host secret store; never commit them to this
   repository or add them to MCP configuration files.
4. Verify the route with an authenticated MCP initialization and a least-risk
   read-only tool call.
5. Review write and delete tools before granting them to a new integration.

## Incident handling

If a route, token, or deployment is suspected to be exposed, revoke the
affected credential, disable the route, review server logs, and issue a new
credential before re-enabling the service.
