#!/usr/bin/env node
// CI guard: the npm installer resolves its binary by matching
// `momus_<os>_<arch>[.exe]` inside the release's checksums.txt. If
// .goreleaser.yaml's name_template ever changes, `npx momus` silently 404s on
// every platform. This asserts the two stay in agreement, on each runner OS.
"use strict";

const fs = require("fs");
const path = require("path");

const repoRoot = path.join(__dirname, "..", "..");
const goreleaser = fs.readFileSync(path.join(repoRoot, ".goreleaser.yaml"), "utf8");

// The raw-binary archive's name template (the one the installer downloads).
const rawBlock = goreleaser.match(/id:\s*raw[\s\S]*?(?=\n\w|$)/);
if (!rawBlock) {
  console.error("could not find the `raw` archive block in .goreleaser.yaml");
  process.exit(1);
}
const m = rawBlock[0].match(/name_template:\s*'([^']+)'/);
if (!m) {
  console.error("the `raw` archive has no name_template");
  process.exit(1);
}
const template = m[1];

// The installer downloads a RAW binary. If this archive ever becomes tar.gz/zip,
// every `npx momus` install would fetch an archive and try to exec it.
if (!/formats?:\s*\[?\s*binary/.test(rawBlock[0])) {
  console.error(
    "the `raw` archive is no longer published as a bare binary — the npm installer " +
      "downloads and execs it directly, so it must stay `formats: [binary]`."
  );
  process.exit(1);
}

// Render the template the way goreleaser would for this platform.
const osMap = { darwin: "darwin", linux: "linux", win32: "windows" };
const archMap = { x64: "amd64", arm64: "arm64" };
const rendered = template
  .replace(/\{\{\s*\.ProjectName\s*\}\}/g, "momus")
  .replace(/\{\{\s*\.Os\s*\}\}/g, osMap[process.platform])
  .replace(/\{\{\s*\.Arch\s*\}\}/g, archMap[process.arch]);

// The pattern install.js matches against checksums.txt.
const want = new RegExp(
  `^momus_${osMap[process.platform]}_${archMap[process.arch]}(\\.exe)?$`
);

if (!want.test(rendered)) {
  console.error(
    `asset-name drift: goreleaser would publish "${rendered}", but the npm ` +
      `installer looks for /${want.source}/.\n` +
      "Update packages/momus-node/install.js or .goreleaser.yaml so they agree."
  );
  process.exit(1);
}
console.log(`asset name OK for ${process.platform}/${process.arch}: ${rendered}`);
