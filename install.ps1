$ErrorActionPreference = "Stop"

$MarketplaceRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not (Get-Command codex -ErrorAction SilentlyContinue)) {
    throw "Codex CLI was not found in PATH. Install or open Codex, then run this installer again."
}

& codex plugin marketplace add $MarketplaceRoot
& codex plugin add "battery-swap-mcps@battery-swap"

Write-Host "BatterySwap MCP Suite installed. Restart Codex and authenticate the listed MCP servers."
