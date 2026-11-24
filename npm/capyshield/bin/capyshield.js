#!/usr/bin/env node
// Launcher: runs the native binary from the platform package npm installed for this machine.
"use strict";
const { spawn } = require("node:child_process");

const pkg = `@capyshield/${process.platform}-${process.arch}`;
let bin;
try {
  bin = require.resolve(`${pkg}/bin/capyshield`);
} catch {
  console.error(
    `capyshield: no prebuilt binary for ${process.platform}-${process.arch} (${pkg} is missing).\n` +
      "Supported: darwin-arm64, darwin-x64, linux-arm64, linux-x64. If you installed with --omit=optional, reinstall without it.",
  );
  process.exit(1);
}

const child = spawn(bin, process.argv.slice(2), { stdio: "inherit" });
// Ctrl-C already reaches the child through the terminal's process group; stay alive so it can print its summary.
process.on("SIGINT", () => {});
for (const sig of ["SIGTERM", "SIGHUP"]) process.on(sig, () => child.kill(sig));
child.on("error", (e) => {
  console.error(`capyshield: ${e.message}`);
  process.exit(1);
});
child.on("exit", (code, signal) => {
  if (signal) {
    process.removeAllListeners(signal);
    process.kill(process.pid, signal);
  } else {
    process.exit(code);
  }
});
