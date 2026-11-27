# Contributing to capyshield

Thanks for helping! Bug reports, new secret patterns, lockfile formats and docs fixes are all welcome.

## Development

```bash
cargo build                 # debug build, binary at target/debug/capyshield
cargo test                  # all tests, in each crate's tests/ folder (no network needed)
cargo build --release       # optimized static-ish binary
```

Rust stable (edition 2024) is required.

### Pre-commit hooks

```bash
pip install pre-commit          # or: brew install pre-commit
rustup component add rustfmt clippy
pre-commit install              # run hooks on every commit
pre-commit run --all-files      # run them on demand
```

The hooks run `cargo fmt`, `cargo clippy -D warnings`, gitleaks, typos, actionlint and basic file hygiene checks. CI runs the same hooks, plus a gitleaks scan of the full git history. If a test needs a fake credential, mark its line with `// gitleaks:allow`. There are no C dependencies besides `ring`'s bundled assembly.

## Where things live

| Crate | Responsibility |
|---|---|
| `capyshield-policy` | `capyshield.yaml` schema, validation, host glob matching |
| `capyshield-scanner` | Builtin patterns (`src/patterns.rs`), ENV fingerprints, entropy, PII |
| `capyshield-proxy` | Forward proxy, SNI parsing, MITM CA, policy decisions, event log |
| `capyshield-reach` | Manifest/lockfile parsing and import scanning for Node.js and Python |
| `capyshield-vex` | Trivy/Grype ingestion, triage, OpenVEX output |
| `capyshield-sync` | Optional cloud client |
| `capyshield` (`crates/capyshield-cli`) | CLI wiring, terminal output, exit codes |

[docs/how-it-works.md](docs/how-it-works.md) has Mermaid diagrams of every decision path: the process wrapper, CONNECT/SNI/MITM, request inspection, the scanner pipeline, and VEX triage. If you change one of those flows, update its diagram in the same PR.

## Adding a secret pattern

Add a row to `crates/capyshield-scanner/src/patterns.rs`:

```rust
("vendor_token", &["vtok_"], r"\bvtok_[A-Za-z0-9]{32}\b"),
```

- The id is snake_case and unique (a test enforces this).
- Every match must contain at least one keyword (ASCII case-insensitive); keywords drive the Aho-Corasick prefilter.
- Regexes run on bytes with Unicode disabled; no look-around.
- Prefer a distinctive prefix over generic `key = value` heuristics, and add a positive case to `detects_known_formats` when the format is common.

## Demo GIF

`docs/demos/watch.gif` (shown at the top of the README) is rendered from `docs/demos/watch.tape` with [VHS](https://github.com/charmbracelet/vhs):

```bash
brew install vhs
cargo build --release
vhs docs/demos/watch.tape
vhs docs/demos/agent.tape   # AI-agent before/after demo
vhs docs/demos/vex.tape     # VEX demo; uses the trimmed Trivy report in docs/demos/fixtures/
```

- **What runs off-camera:** a hidden setup block puts `target/release` on `PATH`, uses a throwaway `HOME` (with a CA from `capyshield init`) and a fresh npm cache, and exports AWS's documented fake `EXAMPLE` key. No personal paths or real secrets appear.
- **Network:** the recording makes real requests to `registry.npmjs.org` and `httpbin.org`.
- **When to re-record:** whenever `watch`/`guard` terminal output changes. Check a few frames before committing, for example `ffmpeg -sseof -0.2 -i docs/demos/watch.gif -frames:v 1 last.png`.
- **Size:** keep the GIF under the 512 KB `check-added-large-files` limit. The current one is about 210 KB.

## Packaging

The same native binary is distributed through several channels. All of them are built by `.github/workflows/release.yml` on a `v*` tag:

| Channel | Source |
|---|---|
| GitHub Releases, Docker (GHCR, optional Docker Hub) | `Cargo.toml`, `Dockerfile` |
| Homebrew | Not automated yet: needs the `capyshield-hq/homebrew-tap` repo and a formula-bump step |
| crates.io | workspace crates (`cargo publish --workspace`) |
| PyPI (`uvx`, `pip`) | `pyproject.toml` (maturin `bindings = "bin"`) |
| npm (`npx`) | `npm/`. Test it locally with `node npm/publish.mjs <version> <dir-with-release-tarballs>`, which packs `.tgz` files into `npm/dist/`. |

## Pull requests

- Keep changes focused and covered by a test when they change behavior.
- Tests live in each crate's `tests/` folder (no inline `#[cfg(test)]` modules). They test the public API; the binary's pure helpers live in `crates/capyshield-cli/src/lib.rs` for that reason.
- `cargo test` and `pre-commit run --all-files` must pass.
- Never commit real credentials, not even revoked ones; use obviously fake values like `AKIAIOSFODNN7EXAMPLE`.
- By contributing you agree that your work is licensed under the Apache License 2.0.

Security issues go through [SECURITY.md](SECURITY.md), not public issues or PRs.
