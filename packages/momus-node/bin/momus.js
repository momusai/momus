#!/usr/bin/env node
// Thin launcher: exec the downloaded momus binary, forwarding all args and
// stdio, and exit with its exit code.
"use strict";

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const ext = process.platform === "win32" ? ".exe" : "";
const binPath = path.join(__dirname, "..", "vendor", "momus" + ext);

// With --ignore-scripts (pnpm 10's default, Yarn Berry, many CI setups) the
// postinstall never ran, so there is no binary yet. Fetch it on first use
// instead of failing — otherwise the install looks fine but nothing works.
if (!fs.existsSync(binPath)) {
  console.error("momus: binary not present (install scripts may be disabled); fetching it now…");
  const res = spawnSync(process.execPath, [path.join(__dirname, "..", "install.js")], {
    stdio: "inherit",
  });
  if (res.status !== 0 || !fs.existsSync(binPath)) {
    console.error(
      "\nmomus: no binary available.\n" +
        "Fix one of these ways:\n" +
        "  • npm rebuild momus            (re-runs the installer)\n" +
        "  • MOMUS_BINARY=/path/to/momus npm rebuild momus\n" +
        "  • go install github.com/momusai/momus/cmd/momus@latest"
    );
    process.exit(1);
  }
}

const res = spawnSync(binPath, process.argv.slice(2), { stdio: "inherit" });
if (res.error) {
  console.error(`momus: failed to run binary: ${res.error.message}`);
  process.exit(1);
}
process.exit(res.status === null ? 1 : res.status);
