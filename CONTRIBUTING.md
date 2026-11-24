# Contributing to capyshield

Thanks for helping! Bug reports, new secret patterns, lockfile formats and docs fixes are all welcome.

## Development

```bash
cargo build                 # debug build, binary at target/debug/capyshield
cargo test                  # unit + proxy integration tests (no network needed)
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

## Packaging

The same native binary is distributed through several channels. All of them are built by `.github/workflows/release.yml` on a `v*` tag:

| Channel | Source |
|---|---|
| GitHub Releases, Homebrew, Docker | `Cargo.toml`, `Dockerfile` |
| crates.io | workspace crates (`cargo publish --workspace`) |
| PyPI (`uvx`, `pip`) | `pyproject.toml` (maturin `bindings = "bin"`) |
| npm (`npx`) | `npm/`. Test it locally with `node npm/publish.mjs <version> <dir-with-release-tarballs>`, which packs `.tgz` files into `npm/dist/`. |

## Pull requests

- Keep changes focused and covered by a test when they change behavior.
- `cargo test` and `pre-commit run --all-files` must pass.
- Never commit real credentials, not even revoked ones; use obviously fake values like `AKIAIOSFODNN7EXAMPLE`.
- By contributing you agree that your work is licensed under the Apache License 2.0.

Security issues go through [SECURITY.md](SECURITY.md), not public issues or PRs.
