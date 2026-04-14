const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const binary = path.join(root, "agentpay-bin");

// Skip if binary already exists.
if (fs.existsSync(binary)) {
  process.exit(0);
}

// Check if Go is available.
try {
  execSync("go version", { stdio: "ignore" });
} catch {
  console.error("");
  console.error("  AgentPay requires Go to build from source.");
  console.error("  Install Go: https://go.dev/dl/");
  console.error("");
  console.error("  Or download a prebuilt binary from:");
  console.error("  https://github.com/garagon/agentpay/releases");
  console.error("");
  process.exit(1);
}

// Build the Go binary.
console.log("Building AgentPay...");
try {
  execSync("go build -o agentpay-bin .", { cwd: root, stdio: "inherit" });
  fs.chmodSync(binary, 0o755);
  console.log("AgentPay built successfully.");
} catch (e) {
  console.error("Build failed:", e.message);
  process.exit(1);
}
