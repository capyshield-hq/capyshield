#!/usr/bin/env node
// Builds the npm packages from release archives and optionally publishes them.
// usage: node npm/publish.mjs <version> <dir-with-release-tarballs> [--publish]
import { execFileSync } from "node:child_process";
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const [version, archives, flag] = process.argv.slice(2);
if (!version || !archives) {
  console.error("usage: node npm/publish.mjs <version> <archives-dir> [--publish]");
  process.exit(1);
}
const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, "dist");
const main = JSON.parse(readFileSync(join(here, "capyshield/package.json"), "utf8"));

// npm platform name -> Rust target of the release archive
const PLATFORMS = {
  "darwin-arm64": "aarch64-apple-darwin",
  "darwin-x64": "x86_64-apple-darwin",
  "linux-arm64": "aarch64-unknown-linux-musl",
  "linux-x64": "x86_64-unknown-linux-musl",
};

rmSync(out, { recursive: true, force: true });
const dirs = [];
for (const [platform, target] of Object.entries(PLATFORMS)) {
  const [os, cpu] = platform.split("-");
  const dir = join(out, platform);
  mkdirSync(join(dir, "bin"), { recursive: true });
  execFileSync("tar", ["xzf", resolve(archives, `capyshield-${target}.tar.gz`), "-C", join(dir, "bin")]);
  const pkg = {
    name: `@capyshield/${platform}`,
    version,
    description: `capyshield native binary for ${platform}`,
    repository: main.repository,
    license: main.license,
    author: main.author,
    homepage: main.homepage,
    keywords: main.keywords,
    os: [os],
    cpu: [cpu],
    files: ["bin"],
  };
  writeFileSync(join(dir, "package.json"), JSON.stringify(pkg, null, 2) + "\n");
  writeFileSync(
    join(dir, "README.md"),
    `# @capyshield/${platform}\n\nThe native \`capyshield\` binary for ${platform}. Don't install this directly: it is an optional\n` +
      `dependency of [\`capyshield\`](https://www.npmjs.com/package/capyshield), which picks the right platform package.\n\n` +
      "```bash\nnpx capyshield watch -- npm install\n```\n\n" +
      "See https://github.com/capyshield-hq/capyshield for documentation.\n",
  );
  dirs.push(dir);
}

const mainDir = join(out, "capyshield");
cpSync(join(here, "capyshield"), mainDir, { recursive: true });
cpSync(join(here, "..", "README.md"), join(mainDir, "README.md"));
cpSync(join(here, "..", "LICENSE"), join(mainDir, "LICENSE"));
main.version = version;
for (const dep of Object.keys(main.optionalDependencies)) main.optionalDependencies[dep] = version;
writeFileSync(join(mainDir, "package.json"), JSON.stringify(main, null, 2) + "\n");
dirs.push(mainDir); // platform packages first so the main package never points at missing versions

// Idempotent: a re-run after a partial failure skips versions that are already on the registry.
const published = (name) => {
  try {
    return execFileSync("npm", ["view", `${name}@${version}`, "version"], { encoding: "utf8" }).trim() === version;
  } catch {
    return false;
  }
};

for (const dir of dirs) {
  const { name } = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
  if (flag !== "--publish") {
    execFileSync("npm", ["pack", "--pack-destination", out], { cwd: dir, stdio: "inherit" });
  } else if (published(name)) {
    console.log(`skip ${name}@${version}: already published`);
  } else {
    execFileSync("npm", ["publish", "--provenance", "--access", "public"], { cwd: dir, stdio: "inherit" });
  }
}
