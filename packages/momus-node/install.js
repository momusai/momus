#!/usr/bin/env node
// Downloads the prebuilt momus binary for this platform from the matching GitHub
// release, verifies its SHA-256 against the release checksums.txt, and stores it
// in vendor/. The core attack pack is embedded in the binary, so the download is
// fully self-contained. Runs as an npm postinstall step.
"use strict";

const fs = require("fs");
const path = require("path");
const https = require("https");
const crypto = require("crypto");

const REPO = process.env.MOMUS_REPO || "momus-ai/momus";
const { version } = require("./package.json");

// Map Node's platform/arch to the release asset tokens (see .goreleaser.yaml).
function platformTokens() {
  const osMap = { darwin: "darwin", linux: "linux", win32: "windows" };
  const archMap = { x64: "amd64", arm64: "arm64" };
  const os = osMap[process.platform];
  const arch = archMap[process.arch];
  if (!os || !arch) {
    throw new Error(
      `unsupported platform ${process.platform}/${process.arch} — build from source with Go instead`
    );
  }
  return { os, arch, exeExt: process.platform === "win32" ? ".exe" : "" };
}

function get(url, redirects = 0) {
  return new Promise((resolve, reject) => {
    if (redirects > 5) {
      reject(new Error("too many redirects"));
      return;
    }
    const req = https.get(
      url,
      { headers: { "user-agent": "momus-npm-installer" }, timeout: 60000 },
      (res) => {
        const { statusCode, headers } = res;
        if ([301, 302, 303, 307, 308].includes(statusCode) && headers.location) {
          res.resume();
          resolve(get(new URL(headers.location, url).toString(), redirects + 1));
          return;
        }
        if (statusCode !== 200) {
          res.resume();
          reject(new Error(`HTTP ${statusCode} for ${url}`));
          return;
        }
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve(Buffer.concat(chunks)));
        res.on("error", reject);
      }
    );
    req.on("timeout", () => req.destroy(new Error(`timed out fetching ${url}`)));
    req.on("error", reject);
  });
}

// A postinstall runs once on a possibly-flaky network; retry transient failures
// rather than leaving the user with no binary.
async function getWithRetry(url, attempts = 3) {
  let lastErr;
  for (let i = 0; i < attempts; i++) {
    try {
      return await get(url);
    } catch (err) {
      lastErr = err;
      const transient =
        /timed out|ECONNRESET|ETIMEDOUT|ENOTFOUND|EAI_AGAIN|socket hang up|HTTP 5\d\d|HTTP 429/i.test(
          String(err.message)
        );
      if (!transient || i === attempts - 1) throw err;
      const wait = 500 * 2 ** i;
      console.error(`momus: ${err.message} — retrying in ${wait}ms`);
      await new Promise((r) => setTimeout(r, wait));
    }
  }
  throw lastErr;
}

function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

// Find this platform's asset in a goreleaser checksums.txt ("<sha256>  <file>").
// Deriving the exact filename from the manifest avoids guessing whether the
// release appends an .exe suffix, and gives us its checksum in one pass.
function findAsset(checksums, { os, arch }) {
  const want = new RegExp(`^momus_${os}_${arch}(\\.exe)?$`);
  for (const line of checksums.toString("utf8").split("\n")) {
    const m = line.trim().match(/^([0-9a-f]{64})\s+\*?(\S+)$/i);
    if (m && want.test(m[2])) {
      return { name: m[2], sha256: m[1].toLowerCase() };
    }
  }
  return null;
}

// A proxy env var means direct https.get will hang or be refused: Node does not
// route through a proxy on its own and this package has no dependencies to do
// the CONNECT tunnelling. Fail fast with instructions instead of hanging.
//
// Only the vars that actually govern https:// URLs count — every request here is
// HTTPS, so an http_proxy-only environment used to be blocked from a download
// that would have worked. no_proxy is honoured for the same reason: if the one
// host we contact is excluded, there is no proxy to tunnel through.
const DOWNLOAD_HOST = "github.com";

function proxyBypassed(noProxy, host) {
  return noProxy
    .split(",")
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean)
    .some((entry) => {
      if (entry === "*") return true;
      const bare = entry.replace(/^\./, "");
      return host === bare || host.endsWith("." + bare);
    });
}

function checkProxy() {
  const proxy = process.env.HTTPS_PROXY || process.env.https_proxy;
  if (!proxy || process.env.MOMUS_BINARY) return;

  const noProxy = process.env.NO_PROXY || process.env.no_proxy || "";
  if (proxyBypassed(noProxy, DOWNLOAD_HOST)) return;

  throw new Error(
    `an HTTPS proxy is configured (${proxy}) but this installer downloads directly.\n` +
      "  Download the binary for your platform from the releases page and use\n" +
      "  MOMUS_BINARY=/path/to/momus npm install, or install with Go."
  );
}

async function main() {
  checkProxy();
  const vendorDir = path.join(__dirname, "vendor");
  const tokens = platformTokens();
  const binPath = path.join(vendorDir, "momus" + tokens.exeExt);
  fs.mkdirSync(vendorDir, { recursive: true });

  // Escape hatch: use a locally-built binary instead of downloading.
  if (process.env.MOMUS_BINARY) {
    fs.copyFileSync(process.env.MOMUS_BINARY, binPath);
    fs.chmodSync(binPath, 0o755);
    console.error(`momus: using MOMUS_BINARY=${process.env.MOMUS_BINARY}`);
    return;
  }

  const base = `https://github.com/${REPO}/releases/download/v${version}`;
  const checksums = await getWithRetry(`${base}/checksums.txt`);
  const asset = findAsset(checksums, tokens);
  if (!asset) {
    throw new Error(
      `release v${version} has no binary for ${tokens.os}/${tokens.arch}`
    );
  }

  console.error(`momus: downloading ${asset.name} (v${version})...`);
  const bin = await getWithRetry(`${base}/${asset.name}`);

  const got = sha256(bin);
  if (got !== asset.sha256) {
    throw new Error(
      `checksum mismatch for ${asset.name}: got ${got}, want ${asset.sha256}`
    );
  }

  // Write to a temp file then rename, so an interrupted install never leaves a
  // half-written binary that later "runs".
  const tmp = binPath + ".download";
  fs.writeFileSync(tmp, bin, { mode: 0o755 });
  fs.renameSync(tmp, binPath);
  console.error(`momus: installed ${binPath}`);
}

main().catch((err) => {
  console.error(`\nmomus: could not install the prebuilt binary: ${err.message}`);
  console.error("Alternatives:");
  console.error("  • build from source (Go 1.25+):");
  console.error("      go install github.com/momus-ai/momus/cmd/momus@latest");
  console.error("  • point the installer at a local binary:");
  console.error("      MOMUS_BINARY=/path/to/momus npm install");
  console.error("  • re-run `npm rebuild momus` once network access is available\n");
  // Exit 0 deliberately: a postinstall failure must NOT abort the consumer's
  // whole `npm install` (momus is often one dependency among many). Running
  // `momus` without a binary prints the same guidance and exits non-zero.
  process.exit(0);
});
