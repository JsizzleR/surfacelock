#!/usr/bin/env node
// Launcher for the npm distribution: resolve the platform package's binary and
// replace ourselves with it as nearly as node allows (spawn with inherited
// stdio, exit code and signals forwarded). The proxy verb in particular must
// own stdin/stdout and see the client's signals.
"use strict";

const { spawn } = require("child_process");

const PLATFORMS = {
  "darwin-arm64": "surfacelock-darwin-arm64",
  "darwin-x64": "surfacelock-darwin-x64",
  "linux-arm64": "surfacelock-linux-arm64",
  "linux-x64": "surfacelock-linux-x64",
};

function binaryPath() {
  const override = process.env.SURFACELOCK_BIN;
  if (override) return override;
  const key = `${process.platform}-${process.arch}`;
  const pkg = PLATFORMS[key];
  if (!pkg) {
    console.error(`surfacelock: unsupported platform ${key}`);
    process.exit(2);
  }
  try {
    return require.resolve(`${pkg}/bin/surfacelock`);
  } catch {
    console.error(
      `surfacelock: platform package ${pkg} is not installed ` +
        "(optionalDependencies disabled, or an unsupported install)"
    );
    process.exit(2);
  }
}

const child = spawn(binaryPath(), process.argv.slice(2), { stdio: "inherit" });
for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(sig, () => child.kill(sig));
}
child.on("error", (err) => {
  console.error(`surfacelock: ${err.message}`);
  process.exit(2);
});
child.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code === null ? 2 : code);
});
