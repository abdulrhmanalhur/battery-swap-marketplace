#!/usr/bin/env sh
set -eu

marketplace_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if ! command -v codex >/dev/null 2>&1; then
  echo "Codex CLI was not found in PATH. Install or open Codex, then run this installer again." >&2
  exit 1
fi

codex plugin marketplace add "$marketplace_root"
codex plugin add "battery-swap-mcps@battery-swap"

echo "BatterySwap MCP Suite installed. Restart Codex and authenticate the listed MCP servers."
