## What

<!-- One or two sentences: what changes and why. Link the issue if there is one. -->

## How

<!-- Notable implementation choices, trade-offs, anything a reviewer should look at first. -->

## Verification

- [ ] `cargo test --locked --workspace`
- [ ] `pre-commit run --all-files`
- [ ] Manual check: <!-- command(s) run and what they showed, or "n/a" -->

## Checklist

- [ ] Docs updated (README / CONTRIBUTING / examples) if CLI flags, config keys or exit codes changed
- [ ] `capyshield.yaml` schema changes are reflected in the `init` template and `examples/*/capyshield.yaml`
- [ ] New secret patterns have a positive test case; fake credentials are marked `// gitleaks:allow`
- [ ] No real secrets, `.env` files or local reports committed
