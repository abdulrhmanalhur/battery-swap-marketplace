# BatterySwap MCP Suite

إضافة Codex واحدة تحتوي كل تعريفات MCP المطلوبة الخاصة بـ BatterySwap كحزمة واحدة.

## Included MCPs

The suite contains definitions for Advertisement, Google Merchant Center,
Google Ads, Google Tag Manager, Google Business Profile, Google Search Console,
MongoDB, n8n, AWS S3, Vercel, and WordPress. Each server is optional, so a
temporarily unavailable service cannot block healthy services from loading.

All entries use `required: false`. A route that is unavailable is isolated and does not prevent Codex from loading the other MCP servers.

> Security: all production MCP routes must enforce server-side authentication and
> least-privilege access before use. Keep endpoint-specific audit results and
> remediation notes in private operational documentation.

See [`SERVER-AUDIT.md`](SERVER-AUDIT.md) for the public-safe security policy.

## التثبيت من هذا المجلد

### Windows

انقر مرتين على `install.cmd`، أو شغّل PowerShell:

```powershell
.\install.ps1
```

### macOS or Linux

```bash
./install.sh
```

تسجّل الأدوات هذا المجلد كـ Marketplace باسم `battery-swap` ثم تثبّت `battery-swap-mcps`.

افتح محادثة Codex جديدة بعد التثبيت. نفّذ OAuth للخدمات التي تطلبه، واضبط `N8N_MCP_BEARER_TOKEN` لاتصال n8n الأصلي، ثم استخدم `/mcp` للتحقق.

## Install from a Git repository

From this repository:

```bash
codex plugin marketplace add abdulrhmanalhur/battery-swap-marketplace --ref main
codex plugin add battery-swap-mcps@battery-swap
```

Do not commit OAuth tokens, API keys, database connection strings, or static Authorization headers. The plugin transports MCP configuration only; each device stores its own credentials.

## MongoDB on another device

The `mongodb` entry already points to the protected HTTPS reader. It uses owner
OAuth with the local scope `mongodb:read` and exposes only `find` and `count`.
The MongoDB URI/password and the server's GitHub application secret stay on the
server. Each client completes its own OAuth connection; do not copy credential
files or keyring entries between devices.

For another computer with Codex CLI, add the verified Git marketplace and install
the suite using the commands above. Open a new session, select the suite in
`/plugins`, and complete its MongoDB connection when prompted. Authenticate as
the approved GitHub owner. Other connectors remain optional and retain their
existing settings. A Git marketplace install is local setup, not proof that every
device or ChatGPT surface has been connected automatically.

### Supported surfaces

The existing suite uses the Codex `.codex-plugin/plugin.json` compatibility
layout and `.mcp.json`. OpenAI currently marks workspace-imported plugins with
MCP declarations as **Desktop only**, including remote HTTPS servers. Do not
promise this bundle works on ChatGPT web or mobile. Cloud access needs a
separately registered MCP app and a supported app-backed plugin/reference; no
app ID or cloud publication is created by this repository change.

See the official [plugin management documentation](https://learn.chatgpt.com/docs/enterprise/plugin-management)
and [plugin packaging guide](https://developers.openai.com/plugins/build/plugins)
for supported surfaces and registered-app mappings. A workspace import is a
separate administrator action and must retain the intended private audience.

Claude is a separate client. This repository does not currently include a
Claude marketplace/plugin manifest. Its MCP HTTP/OAuth connection needs its own
setup and verification; do not claim that installing this Codex suite configures
Claude.

### Avoid duplicate MongoDB connections

A computer may already have a direct Codex entry such as
`batteryswap_mongodb_read`, while the suite's entry is `mongodb`. Installing the
suite on that same computer may show the reader twice and require a separate
OAuth connection. Keep the working
direct entry until the plugin has been validated in that client. Disable or
remove only that direct entry after an explicitly approved migration; never
replace the whole MCP configuration or change another connector.
