# Security Policy

capyshield sits in the path of secrets and outbound traffic, so we treat vulnerability reports as top priority.

## Reporting a vulnerability

**Please do not open a public issue.** Report privately through either:

- GitHub: **Security → Report a vulnerability** on this repository (private advisory), or
- Email: **security@capyshield.com** (PGP key on request).

Include affected version(s), platform, a description of the impact, and reproduction steps or a proof of concept.

## What to expect

| Step | Target |
|---|---|
| Acknowledgement | within 2 business days |
| Initial assessment & severity | within 5 business days |
| Fix or mitigation for critical/high issues | within 30 days |
| Public advisory + CVE (when applicable) | together with the fixed release |

We credit reporters in the advisory unless you prefer to stay anonymous. We will not pursue legal action for good-faith research that respects user privacy, avoids data destruction, and gives us reasonable time to fix the issue before disclosure.

## Scope

In scope:

- Policy bypasses: secret/ENV leaks or disallowed hosts that pass `guard` in `enforce` mode through traffic routed via the proxy
- Leaks of ENV values or secrets into logs, reports, OpenVEX output or sync payloads
- Weaknesses in the local CA / MITM implementation (key handling, certificate validation of upstream servers)
- Memory-safety or denial-of-service issues in the proxy, parsers (TLS ClientHello, lockfiles, scanner reports) or CLI
- Incorrect `not_affected` VEX decisions caused by parser bugs

Out of scope:

- Programs that deliberately ignore `HTTP(S)_PROXY` (documented limitation; use a container/network namespace for a hard boundary)
- Findings that require an already-compromised local user account

## Supported versions

Security fixes land on the latest minor release line. Pin to a release tag and verify the SHA-256 checksum and SLSA provenance attached to every GitHub release.
