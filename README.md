# BatterySwap MCP Suite

إضافة Codex واحدة تحتوي كل تعريفات MCP المطلوبة الخاصة بـ BatterySwap كحزمة واحدة.

## MCP inventory

| MCP | Endpoint | Auth | Probe result (2026-09-08) |
| --- | --- | --- | --- |
| Advertisement MCP | `https://advertisement.batteryswap.cc/mcp` | Server-defined | Declared; public route currently returns 404 |
| GMerchantsC | `https://mcpgooads.batteryswap.cc/gmc/mcp` | Server-defined | Declared; public route currently returns 404 |
| Google Ads | `https://mcpgooads.batteryswap.cc/mcp` | OAuth/DCR | Verified MCP; OAuth challenge |
| google-tag-manager-mcp-server | `https://gtm-mcp.stape.ai/mcp` | OAuth | Included remote MCP |
| GooMapProfil | `https://mcpgooads.batteryswap.cc/gbp/mcp` | None currently | Verified `gbp-mcp` 1.26.0; 19 tools |
| GSC | `https://mcpgooads.batteryswap.cc/gsc/mcp` | None currently | Verified `google-search-console` 1.0.0; 27 tools |
| MongoDB | `https://mcpgooads.batteryswap.cc/mongodb/mcp` | Server-defined | Declared; public route currently returns 404 |
| N8NMCP | `https://mcpgooads.batteryswap.cc/N8NMCP/mcp` | None currently | Verified `n8n-documentation-mcp` 2.47.14; 24 tools |
| n8n instance | `https://n8n.batteryswap.cc/mcp-server/http` | Bearer env `N8N_MCP_BEARER_TOKEN` | Verified MCP challenge |
| s3AWS | `https://mcpgooads.batteryswap.cc/s3/mcp` | None currently | Verified `s3-combined` 3.2.4; 11 tools |
| Vercel | `https://mcp.vercel.com` | OAuth | Included remote MCP |
| WordPress MCP | `https://mcpgooads.batteryswap.cc/wp/mcp` | None currently | Verified `wordpress_mcp` 1.27.0; 67 tools |

All entries use `required: false`. A route that is unavailable is isolated and does not prevent Codex from loading the other MCP servers.

> Security: the GSC, S3, WordPress, GBP, and N8NMCP routes currently accept MCP initialization without authentication while exposing write-capable tools. Put OAuth or a bearer-token gateway in front of them before treating the server as production-safe. N8NMCP also advertises a limit of 20 requests per 15 minutes.

See [`SERVER-AUDIT.md`](SERVER-AUDIT.md) for the tested server identities and route status.

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

After publishing this entire folder as a Git repository:

```bash
codex plugin marketplace add OWNER/REPOSITORY --ref main
codex plugin add battery-swap-mcps@battery-swap
```

Do not commit OAuth tokens, API keys, database connection strings, or static Authorization headers. The plugin transports MCP configuration only; each device stores its own credentials.
