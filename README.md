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
