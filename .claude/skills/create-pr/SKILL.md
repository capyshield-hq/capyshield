---
name: create-pr
description: Create a GitHub pull request for the current capyshield changes. Branches off main if needed, runs the repo's tests and pre-commit hooks, commits with Conventional Commits, pushes, and opens the PR with the repo template. Use when the user asks to open, create or raise a PR, or to ship or submit their changes for review.
---

# Create a pull request (capyshield)

Follow these steps in order. Stop and ask the user when a step fails in a way you can't fix safely.

## 1. Inspect the working tree

```bash
git status --short
git diff --stat
git log --oneline origin/main..HEAD 2>/dev/null
```

- Work out what changed and why. If the intent is unclear, ask the user before committing.
- **Never stage** `.env*`, `target/`, `*.openvex.json`, `trivy-report.json`, egress `--report` output, or anything that looks like a real credential. Stage files by name, not with `git add -A`.

## 2. Branch

If you are on `main`, create a branch first:

```bash
git switch -c <type>/<short-kebab-summary>   # e.g. feat/allow-presets, fix/sni-timeout
```

`<type>` is one of `feat`, `fix`, `docs`, `refactor`, `perf`, `test`, `ci` or `chore`.

## 3. Keep docs and config in sync

Check which of these apply to the diff and update them in the same PR:

| If the diff changes… | Also update |
|---|---|
| CLI flags, subcommands or exit codes (`crates/capyshield-cli`) | `README.md` command/exit-code tables |
| `capyshield.yaml` schema (`crates/capyshield-policy`) | `TEMPLATE` in `capyshield-policy/src/lib.rs`, the README config block, `examples/*/capyshield.yaml` |
| Host presets (`capyshield-policy/src/presets.yaml`) | Preset list in README and the `init` template comment |
| Secret patterns (`capyshield-scanner/src/patterns.rs`) | A positive case in `detects_known_formats`; mark fake credentials `// gitleaks:allow` |
| Proxy decision flow, fail modes, scanner pipeline, reachability or triage rules | The matching Mermaid diagram in `docs/how-it-works.md` |
| Release, CI or the action | `actionlint` passes (run by pre-commit) |

## 4. Verify

```bash
cargo test --locked --workspace
pre-commit run --all-files
```

If the toolchain isn't on `PATH`, prefix with `PATH=$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH`.

- Fix failures and rerun. `cargo fmt` and `end-of-file-fixer` change files in place, so re-stage after they run.
- For behavior changes, also run the release binary against the real scenario (for example `capyshield watch -- curl -sS https://example.com`) and keep the output for the PR body.
- Don't open the PR while anything is red. Report the failure to the user instead.

## 5. Commit

Use Conventional Commits, `<type>(<crate-or-area>): <imperative summary>`, at most 72 characters. For example:

```
feat(policy): add allow_presets for common registries
fix(proxy): record SNI tunnels at open so keep-alive connections are reported
```

Put the why in the body when it isn't obvious. Prefer one focused commit per logical change.

## 6. Push and open the PR

```bash
git push -u origin HEAD
gh pr create --base main --title "<same style as the commit subject>" --body-file <file>
```

Write the body from `.github/pull_request_template.md`:

- Fill **What**, **How** and **Verification** with the actual commands run and their results.
- Tick only the checklist items that are true. Leave the others unticked and explain why.
- Write the body to a scratch file and pass it with `--body-file`, which avoids shell-quoting problems.

If the user asked for a draft, add `--draft`. If `gh` isn't authenticated, tell the user to run `! gh auth login` rather than working around it.

## 7. Report

Give the user the PR URL, the branch name, and a one-line verification summary (tests and hooks passed, plus any manual check). Mention anything you deliberately left out of the PR.
