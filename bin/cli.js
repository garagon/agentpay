#!/usr/bin/env node

const { execFileSync } = require("child_process");
const path = require("path");
const fs = require("fs");

const binary = path.join(__dirname, "..", "agentpay-bin");

if (!fs.existsSync(binary)) {
  console.error("AgentPay binary not found. Run: npm rebuild agentpay");
  process.exit(1);
}

const args = process.argv.slice(2);

// Default command: install (simplest onboarding)
if (args.length === 0) {
  args.push("install");
}

try {
  execFileSync(binary, args, { stdio: "inherit" });
} catch (e) {
  process.exit(e.status || 1);
}
