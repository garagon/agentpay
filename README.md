# AgentPay

**Security plugin for Claude Code that protects agent-to-agent payments and transactions.**

Built at the [Kaszek & Anthropic Buenos Aires Hackathon 2026](https://dev.kaszek.com/) -- Open Track.

## Install and use

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

Once installed, AgentPay runs automatically on every tool call. Try the demo:

```bash
agentpay demo        # Run 7 attack scenarios
agentpay scan .      # Scan for compromised npm packages
agentpay audit       # View payment audit trail
```

---

## What we built

AgentPay is a Claude Code plugin that intercepts financial tool calls in real time, detects when a compromised MCP server tampers with payments, and blocks fraud before money moves. It also detects and quarantines compromised npm packages (axios supply chain attack).

- **Real-time payment guard** -- 5-stage security pipeline on every financial tool call
- **Payment drift detection** -- Catches when a MCP changes the recipient, amount, or currency
- **Supply chain scanner** -- Detects and removes compromised axios versions from node_modules
- **Tamper-evident audit** -- Every decision logged with SHA-256 hash chain

No existing Claude Code plugin or MCP middleware provides financial security for agent transactions.

## Why this matters

We are in the middle of a fundamental shift in how software is built and operated. The risks are compounding:

1. **90% of code is AI-generated** -- Agents write, review, and ship code with minimal human oversight. The attack surface is no longer just human error.
2. **MCP/library supply chain is vulnerable** -- Compromised packages like axios (v1.7.8, 1.7.9) ship malicious postinstall scripts that exfiltrate credentials. Agents install them without awareness.
3. **Vibe coding introduces security blind spots** -- Developers accept AI-generated code without reviewing dependencies, configurations, or security implications.
4. **MCP servers and skills are added as defaults** -- Agents operate with tools they didn't choose, from sources they didn't verify, with permissions they didn't audit.
5. **Agent-to-agent interaction (A2A) is arriving with real money** -- Stablecoin payments, API billing, and automated procurement mean agents are executing financial transactions autonomously.
6. **No security layer exists for agent-agent payments** -- There is no verification that the payment leaving one agent matches what was agreed, what was authorized, or what arrives at the other side.
7. **AgentPay fills this gap** -- A security plugin that intercepts, verifies, and audits every financial operation before it executes.

### The attack

```
Agent decides: "Pay $50 to Alice"
                    |
          [Poisoned MCP Server]
                    |
Actually executes: "Pay $5,000 to Eve"
```

Nobody verifies that what the agent requested is what actually executes. AgentPay sits in the middle and verifies every payment.

## Demo output

```
$ agentpay demo

AgentPay Demo - Payment Security Plugin for Claude Code
==============================================================

Scenario 1: First payment baseline
  Agent requests a first $50 payment to alice@company.com
  Pipeline:  classify:financial:critical -> credentials:clean -> policy:allow -> integrity:registered
  Decision:  ASK (human approval)

Scenario 2: Approved repeat payment
  Agent repeats the same $50 payment to alice
  Pipeline:  classify:financial:critical -> credentials:clean -> policy:allow -> integrity:verified
  Decision:  ALLOW

Scenario 3: Poisoned MCP - recipient tampered
  MCP changes recipient from alice to attacker
  Pipeline:  classify:financial:critical -> credentials:clean -> policy:allow -> integrity:new_recipient
  Decision:  ASK (human approval)

Scenario 4: Amount inflation
  MCP inflates $50 payment to $5,000
  Pipeline:  classify:financial:critical -> credentials:clean -> policy:amount_exceeded
  Decision:  BLOCK

Scenario 5: Credential exfiltration
  MCP embeds stolen API key in payment description
  Pipeline:  classify:financial:critical -> credentials:DETECTED
  Decision:  BLOCK
  Reason:    Anthropic API key detected in field "note" (sk-ant-abc***)

Scenario 6: Rate limit flood
  MCP triggers 11th payment call in one hour
  Pipeline:  classify:financial:critical -> credentials:clean -> policy:rate_limited
  Decision:  BLOCK

Scenario 7: Human approval required
  Payment of $250 exceeds auto-approval threshold ($200)
  Pipeline:  classify:financial:critical -> credentials:clean -> policy:approval_required
  Decision:  ASK (human approval)

Audit trail: 7 entries, hash chain valid
```

## How it works

### Where AgentPay sits

```
                         WITHOUT AgentPay
                         ================

  ┌─────────┐         ┌─────────────────┐         ┌─────────┐
  │  Claude  │────────>│   MCP Server    │────────>│ Payment  │
  │  Agent   │  tool   │  (potentially   │ executes│ Service  │
  │          │  call   │  compromised)   │         │ (Stripe) │
  └─────────┘         └─────────────────┘         └─────────┘
                       Can silently change
                       recipient, amount,
                       or steal credentials
                       with ZERO detection


                          WITH AgentPay
                          =============

  ┌─────────┐   ┌────────────────────┐   ┌──────────────┐   ┌─────────┐
  │  Claude  │──>│     AgentPay       │──>│  MCP Server  │──>│ Payment  │
  │  Agent   │   │  ┌──────────────┐  │   │              │   │ Service  │
  │          │   │  │  1. Classify  │  │   │              │   │          │
  │ "pay $50 │   │  │  2. Creds    │  │   │              │   │          │
  │  to Alice│   │  │  3. Policy   │  │   │              │   │          │
  │  via     │   │  │  4. Integrity│  │   │              │   │          │
  │  Stripe" │   │  │  5. Audit    │  │   │              │   │          │
  │          │   │  └──────────────┘  │   │              │   │          │
  └─────────┘   │                    │   └──────────────┘   └─────────┘
                │  ALLOW / ASK /     │
                │  BLOCK             │
                │                    │
                │  ~/.agentpay/      │
                │   audit.jsonl      │
                └────────────────────┘
```

### The pipeline in detail

```
  Tool call arrives from Claude Code
                │
                v
        ┌───────────────┐
        │  1. CLASSIFY   │  Is this financial?
        │   22 keywords  │  (payment, transfer, stripe, crypto...)
        └───────┬───────┘
                │
           ┌────┴────┐
           │         │
         NO          YES
           │         │
           v         v
        ALLOW   ┌───────────────┐
       (<1ms)   │ 2. CREDENTIALS│  API keys in arguments?
                │  13 patterns  │  (sk-ant-, ghp_, AKIA...)
                └───────┬───────┘
                        │
                   ┌────┴────┐
                   │         │
                 CLEAN     FOUND
                   │         │
                   v         v
           ┌───────────┐  BLOCK
           │ 3. POLICY  │  "Anthropic API key
           │ max amount │   detected in field
           │ rate limit │   'note'"
           │ daily cap  │
           │ approval   │
           └─────┬─────┘
                 │
            ┌────┴────┐
            │         │
          PASS    EXCEEDED
            │         │
            v         v
    ┌────────────┐  BLOCK / ASK
    │4. INTEGRITY│  "amount $5000
    │ recipient  │   exceeds limit"
    │ amount     │
    │ currency   │
    │ drift check│
    └─────┬─────┘
          │
     ┌────┴────┐
     │         │
   MATCH     DRIFT
     │         │
     v         v
┌─────────┐  BLOCK
│ 5. AUDIT│  "recipient drift:
│ SHA-256 │   expected alice,
│  hash   │   got eve"
│  chain  │
└────┬────┘
     │
     v
   ALLOW
  (payment
  proceeds)
```

Non-financial tools (Bash, Read, Edit, etc.) exit at step 1 with zero overhead.

### Payment integrity (drift detection)

When AgentPay sees the first payment to a recipient in a session, it asks for human approval before treating those parameters as a trusted baseline. Subsequent calls are compared against that baseline:

- **New recipient** -- Requires human approval (legitimate payee or MCP swap?)
- **Known recipient, same parameters** -- Allowed automatically
- **Known recipient, parameters changed** -- Blocked as drift (evidence of tampering)

### Supply chain scanner

Detects compromised npm packages in node_modules and lockfiles. Currently tracks axios v1.7.8 and v1.7.9 (postinstall credential exfiltration). Detection engine adapted from [Aguara](https://github.com/garagon/aguara).

```bash
agentpay scan .     # Scan node_modules + package-lock.json
agentpay clean .    # Quarantine compromised packages to /tmp
```

## Detection matrix

### Real-time (PreToolUse hook)

| Attack | What happens | Response |
|--------|-------------|----------|
| Recipient swap | MCP changes payment destination | ASK |
| Amount inflation | MCP multiplies the payment amount | BLOCK |
| Amount drift | Same recipient, amount changed beyond tolerance | BLOCK |
| Credential theft | MCP embeds stolen API key in payment args | BLOCK |
| Rate flood | MCP triggers rapid successive payments | BLOCK |
| Daily limit | Cumulative spend exceeds 24h cap | BLOCK |
| Large payment | Amount exceeds auto-approval threshold | ASK |

### On-demand (scan + clean)

| Attack | What happens | Response |
|--------|-------------|----------|
| axios supply chain | Versions 1.7.8/1.7.9 exfiltrate env vars | Quarantine |

## Key numbers

| Metric | Value |
|--------|-------|
| Tests | 107 (all passing, race detector enabled) |
| Source LOC | 2,800 |
| Latency (non-financial) | <1ms pass-through |
| Latency (financial) | <5ms full pipeline |
| Credential patterns | 13 (Anthropic, OpenAI, AWS, GitHub, Slack, Stripe...) |
| Financial keywords | 22 (auto-classification, UK AISI taxonomy) |
| Binary size | 6.5MB |
| Dependencies | 2 (cobra, yaml) |
| LLM usage in detection | Zero. Deterministic only. |

## Tech stack

- **Language**: Go 1.22+ (single binary, no CGO)
- **Distribution**: Claude Code plugin marketplace + npm (`agentpay-security`)
- **Hook system**: Claude Code PreToolUse (stdin JSON -> pipeline -> stdout JSON)
- **Audit**: JSONL with SHA-256 hash chain (tamper-evident)
- **State**: JSON file with flock (concurrent guard serialization)
- **Config**: YAML policy file with sensible defaults
- **Detection engine**: Adapted from [oktsec](https://github.com/oktsec/oktsec) (30K LOC, 420+ tests) and [Aguara](https://github.com/garagon/aguara) (190+ detection rules)

## Design decisions

- **Deterministic, not AI** -- Regex and hashes, not an LLM. You cannot prompt-inject a regex.
- **Fail-closed** -- Invalid payloads and initialization failures block the tool call.
- **Human-in-the-loop** -- New recipients and large amounts require human approval.
- **Tamper-evident** -- SHA-256 hash chain on every decision.
- **Zero config** -- Sensible defaults, adjust only if needed.

## CLI

```
agentpay install     Install as Claude Code plugin
agentpay uninstall   Remove from Claude Code
agentpay demo        Run attack scenario demo
agentpay scan        Scan for compromised npm packages
agentpay clean       Quarantine compromised packages
agentpay audit       Show payment audit trail
agentpay version     Print version
```

## Spending policies

Configurable in `~/.agentpay/policy.yaml`:

```yaml
max_per_call: 500                          # Block payments above $500
require_approval_above: 200                # Human approval above $200
require_approval_on_first_recipient: true   # First payment to recipient requires approval
daily_limit: 2000                          # Rolling 24h spending cap
rate_limit_per_hour: 10                    # Max financial tool calls per hour
amount_drift_tolerance: 0.01               # 1% tolerance for amount changes
```

## Team

| Name | GitHub |
|------|--------|
| Gus Aragon | [@garagon](https://github.com/garagon) |
| Ignacio Aracena | [@ignacio-aracena](https://github.com/ignacio-aracena) |
| Mauro Proto Cassina | [@MauroProto](https://github.com/MauroProto) |
| Nicolas Spagnuolo | [@nicoespa](https://github.com/nicoespa) |
| Sebastian Buffo Sempe | [@sbuffose](https://github.com/sbuffose) |

## License

MIT
