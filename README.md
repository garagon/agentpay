# AgentPay

Security plugin for Claude Code that protects agent-to-agent payments and transactions.

## Why this matters

AI agents are writing 90% of code in production. They install MCP servers, add skills, and execute tools with minimal human review. This creates a new class of risk:

- **Supply chain attacks on AI tooling** -- Compromised libraries like axios (v1.7.8, 1.7.9) ship malicious postinstall scripts that exfiltrate credentials. Agents install them without awareness.
- **MCP server poisoning** -- A compromised MCP server can silently modify payment parameters between what the agent decided and what actually executes.
- **Agent-to-agent transactions** -- As agents start transacting with each other (A2A payments, stablecoin transfers), there is no security layer verifying that the payment leaving one agent matches what arrives at the other.

AgentPay addresses the vulnerability in agent-agent payment flows by intercepting every financial operation and verifying it before execution.

## Install

As a Claude Code plugin:

```bash
claude plugins marketplace add garagon/agentpay
claude plugins install agentpay@agentpay
```

Or via npm:

```bash
npm i -g agentpay-security && agentpay install
```

Or from source:

```bash
git clone https://github.com/garagon/agentpay && cd agentpay
go build -o agentpay-bin . && ./agentpay-bin install
```

## How it works

AgentPay installs as a Claude Code PreToolUse hook. Every tool call passes through a 5-stage security pipeline:

```
Agent calls a tool
    |
    v
1. Classify      Is this a financial operation? No -> pass-through (<1ms)
2. Credentials   Are API keys leaking in the arguments? -> block
3. Policy        Within spending limits? -> block / require human approval
4. Integrity     Was the payment modified in transit? -> block
5. Audit         Log with cryptographic hash chain -> allow
```

Non-financial tools pass through with zero overhead.

## What it detects

### Payment fraud (real-time, via PreToolUse hook)

| Attack | What happens | Response |
|--------|-------------|----------|
| Recipient swap | MCP changes payment destination to attacker | ASK (human verifies) |
| Amount inflation | MCP multiplies the payment amount | BLOCK |
| Amount drift | Same recipient, amount changed beyond tolerance | BLOCK |
| Credential theft | MCP embeds stolen API key in payment args | BLOCK |
| Rate flood | MCP triggers rapid successive payments | BLOCK |
| Daily limit | Cumulative spend exceeds rolling 24h cap | BLOCK |
| Large payment | Amount exceeds auto-approval threshold | ASK (human approves) |

### Supply chain (on-demand scan)

| Attack | What happens | Response |
|--------|-------------|----------|
| Compromised axios | Versions 1.7.8/1.7.9 exfiltrate env vars via postinstall | Quarantine |

```bash
agentpay scan .     # Scan node_modules + lockfile
agentpay clean .    # Quarantine compromised packages to /tmp
```

Detection engine adapted from [Aguara](https://github.com/garagon/aguara).

## Payment integrity

When AgentPay sees the first payment to a recipient in a session, it asks for human approval before treating those parameters as a trusted baseline. Subsequent calls are compared against that baseline:

- **New recipient** -- Requires human approval (is this a legitimate payee or a MCP swap?)
- **Known recipient, same parameters** -- Allowed automatically
- **Known recipient, parameters changed** -- Blocked as drift (evidence of tampering)

This means an agent can pay Alice 10 times without interruption, but if the MCP silently changes the amount or switches the destination, AgentPay catches it.

## Spending policies

Configurable in `~/.agentpay/policy.yaml`:

```yaml
max_per_call: 500                          # Block payments above $500
require_approval_above: 200                # Human approval above $200
require_approval_on_first_recipient: true   # First payment to a recipient requires approval
daily_limit: 2000                          # Rolling 24h spending cap
rate_limit_per_hour: 10                    # Max financial tool calls per hour
amount_drift_tolerance: 0.01               # 1% tolerance for amount changes
```

## Credential scanning

13 compiled regex patterns detect secrets in tool call arguments:

Anthropic, OpenAI, AWS, GitHub, GitLab, Slack, Stripe, SendGrid API keys, JWTs, and private keys. Credentials are redacted in logs (first 10 chars + `***`).

## Audit trail

Every financial decision is logged to `~/.agentpay/audit.jsonl` with a SHA-256 hash chain. Each entry references the previous entry's hash. Modifying any entry breaks the chain.

```bash
agentpay audit            # View decisions with colored output
agentpay audit --verify   # Verify chain integrity
```

## Demo

```bash
agentpay demo
```

Runs 7 scenarios against the pipeline:

1. First payment baseline (ASK)
2. Approved repeat payment (ALLOW)
3. Recipient tampered by MCP (ASK)
4. Amount inflated by MCP (BLOCK)
5. Credential exfiltration attempt (BLOCK)
6. Rate limit flood (BLOCK)
7. Large payment approval gate (ASK)

## CLI

```
agentpay install     Install as Claude Code plugin
agentpay uninstall   Remove from Claude Code
agentpay demo        Run attack scenario demo
agentpay scan        Scan for compromised npm packages
agentpay clean       Quarantine compromised packages
agentpay audit       Show audit trail
agentpay version     Print version
```

## Architecture

```
Claude Code                          ~/.agentpay/
  |                                    policy.yaml   (spending limits)
  +-- PreToolUse hook                  state.json    (rate counters, intents)
       +-- agentpay guard             audit.jsonl   (hash-chained decisions)
            +-- 5-stage pipeline
```

Single Go binary. No runtime dependencies. No network calls. No LLM. Deterministic. Builds from source during plugin install if Go is available.

## Design decisions

- **Deterministic, not AI** -- The security layer uses regex and hashes, not an LLM. You cannot prompt-inject a regex.
- **Fail-closed** -- Invalid payloads and initialization failures block the tool call. Security over availability.
- **Human-in-the-loop** -- New recipients and large amounts require human approval. The agent proposes, the human disposes.
- **Tamper-evident** -- SHA-256 hash chain on every decision. If someone edits the audit log, the chain breaks.
- **Zero config** -- Installs with sensible defaults. Adjust limits only if needed.

## Requirements

- Go >= 1.22 (builds from source during install)
- Claude Code

## License

MIT
