#!/usr/bin/env bash
# AgentPay PreToolUse hook - called by Claude Code on every tool call.
# Reads JSON from stdin, runs the 5-stage payment security pipeline,
# writes decision JSON to stdout.

set -euo pipefail

PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-$(dirname "$(dirname "$0")")}"
BINARY="${PLUGIN_ROOT}/agentpay-bin"

# Build on first run if binary doesn't exist.
if [ ! -f "$BINARY" ]; then
  if command -v go &>/dev/null; then
    (cd "$PLUGIN_ROOT" && go build -o agentpay-bin . 2>/dev/null)
  fi
fi

# If binary still doesn't exist, fail-closed.
if [ ! -f "$BINARY" ]; then
  printf '%s\n' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"[AgentPay] BLOCKED: guard binary is missing"}}'
  exit 0
fi

exec "$BINARY" guard
