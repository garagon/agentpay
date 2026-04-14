# AgentPay

Payment security plugin for Claude Code. Intercepts financial tool calls, detects MCP tampering, and blocks fraud before money moves.

## Install

```bash
npm i -g agentpay-security && agentpay install
```

That's it. Two commands, zero config. Claude Code is now protected.

## What it does

AgentPay installs as a Claude Code [PreToolUse hook](https://docs.anthropic.com/en/docs/claude-code/hooks). Every time Claude calls a tool, AgentPay runs a 5-stage security pipeline on financial tool calls:

```
Claude calls a tool
    |
    v
1. Classify    Is this a financial tool? No -> pass-through (<1ms)
2. Credentials Any API keys in the arguments? -> block
3. Policy      Within spending limits? -> block / require approval
4. Integrity   Was the payment modified in transit? -> block
5. Audit       Log with hash chain -> allow
```

Non-financial tools (Bash, Read, Edit, etc.) pass through instantly with zero overhead.

## The problem

AI agents are gaining financial capabilities through MCP tool servers. The MCP supply chain is untrusted: a compromised server can silently modify payment parameters between what the agent decided and what actually executes.

```
Agent decides: "Pay $50 to Alice"
                    |
          [Poisoned MCP Server]
                    |
Actually executes: "Pay $5,000 to Eve"
```

AgentPay sits between Claude and the MCP server, catching the manipulation before money moves.

## Demo

```bash
agentpay demo
```

Runs 7 attack scenarios against the security pipeline:

| Scenario | Attack | Result |
|----------|--------|--------|
| First payment baseline | Agent requests the first $50 payment to alice | ASK |
| Approved repeat payment | Agent repeats the approved $50 payment to alice | ALLOW |
| Recipient tampered | MCP changes recipient to attacker | BLOCK |
| Amount inflation | MCP inflates $50 to $5,000 | BLOCK |
| Credential exfiltration | MCP embeds stolen API key | BLOCK |
| Rate limit flood | MCP triggers 11 payments/hour | BLOCK |
| Human approval | Payment exceeds $200 threshold | ASK |

All decisions are logged to a tamper-evident audit trail with SHA-256 hash chain.

## How it works

### Tool classification

AgentPay auto-classifies every tool call using keyword matching against the UK AISI taxonomy. Financial tools (payment, transfer, wallet, crypto, invoice, checkout, stripe, coinbase, etc.) trigger the full security pipeline. Everything else passes through.

### Payment integrity

When AgentPay sees the first payment for a recipient in a session, it asks for approval before treating those parameters (recipient, amount, currency) as a trusted baseline. Subsequent calls in the same session are compared against that baseline. If the recipient, amount, or currency changes beyond tolerance, it's flagged as drift -- evidence of MCP tampering.

### Spending policies

Default limits (configurable in `~/.agentpay/policy.yaml`):

```yaml
max_per_call: 500           # Block payments above $500
require_approval_above: 200  # Human approval above $200
require_approval_on_first_recipient: true # First payment to a recipient in-session requires approval
daily_limit: 2000            # Rolling 24h spending cap
rate_limit_per_hour: 10      # Max financial calls per hour
amount_drift_tolerance: 0.01 # 1% tolerance for amount changes
```

### Credential scanning

13 regex patterns detect API keys, tokens, and secrets in tool arguments:

- Anthropic, OpenAI, AWS, GitHub, GitLab, Slack, Stripe, SendGrid keys
- JWTs, private keys

If a credential is found in payment arguments, the call is blocked and the credential is redacted in logs.

### Audit trail

Every financial decision is logged to `~/.agentpay/audit.jsonl` with a SHA-256 hash chain. Each entry references the previous entry's hash. Tampering with any entry breaks the chain.

```bash
agentpay audit            # View the trail
agentpay audit --verify   # Verify chain integrity
```

## CLI

```
agentpay install     Install as Claude Code plugin
agentpay uninstall   Remove from Claude Code
agentpay demo        Run attack scenario demo
agentpay audit       Show audit trail
agentpay version     Print version
```

## Architecture

```
~/.claude/settings.json          ~/.agentpay/
  hooks:                           policy.yaml    (spending limits)
    PreToolUse:                    state.json     (rate counters, intents)
      -> /path/to/agentpay guard   audit.jsonl    (hash-chained log)
```

AgentPay is a single Go binary wrapped in an npm package for easy distribution. No runtime dependencies. No network calls. No LLM. Deterministic.

### Files

| File | Purpose |
|------|---------|
| `guard.go` | Pipeline orchestrator - reads stdin, runs 5 stages, writes stdout |
| `classify.go` | Tool classification using UK AISI taxonomy |
| `policy.go` | Spending limits, rate limits, YAML config |
| `integrity.go` | Payment intent hashing and drift detection |
| `redact.go` | Credential pattern scanning (13 patterns) |
| `audit.go` | JSONL audit trail with SHA-256 hash chain |
| `state.go` | State persistence between hook invocations (flock) |
| `install.go` | Claude Code settings.json management |
| `demo.go` | Attack scenario runner |
| `main.go` | CLI entry point |

## Requirements

- Node.js >= 16 (for npm install)
- Go >= 1.22 (builds from source during npm install)
- Claude Code

## Alternative install (without npm)

```bash
git clone https://github.com/garagon/agentpay
cd agentpay
make install
```

## License

MIT
