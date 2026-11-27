# How CapyShield works

This document explains what happens inside `capyshield` when you run `watch`, `guard` or `vex`. Everything described here runs locally, in a single process.

- [Architecture](#architecture)
- [Process wrapper: `watch` and `guard`](#process-wrapper-watch-and-guard)
- [Egress proxy](#egress-proxy)
  - [CONNECT tunnels: SNI and MITM](#connect-tunnels-sni-and-mitm)
  - [Request inspection](#request-inspection)
  - [Scanner pipeline](#scanner-pipeline)
- [VEX & reachability: `vex`](#vex--reachability-vex)
  - [Triage decision](#triage-decision)
  - [Cloud sync (optional)](#cloud-sync-optional)
- [Exit codes](#exit-codes)

## Architecture

The binary is a Cargo workspace of small, single-purpose crates. The CLI wires them together. Only `capyshield-sync` talks to the network on its own, and only with `vex --sync` or `guard --sync`.

```mermaid
flowchart TB
    cli["capyshield-cli<br/>clap commands · terminal output · exit codes"]
    policy["capyshield-policy<br/>capyshield.yaml · validation · host presets"]
    scanner["capyshield-scanner<br/>secret patterns · ENV fingerprints · entropy · PII"]
    proxy["capyshield-proxy<br/>HTTP/HTTPS forward proxy · SNI · MITM CA"]
    reach["capyshield-reach<br/>lockfiles · manifests · import scanning"]
    vex["capyshield-vex<br/>Trivy/Grype parsing · triage · OpenVEX"]
    sync["capyshield-sync<br/>optional cloud client"]

    cli -->|watch / guard| proxy
    cli -->|vex| vex
    cli -->|vex --sync / guard --sync| sync
    proxy --> scanner
    proxy --> policy
    scanner --> policy
    vex --> reach
```

## Process wrapper: `watch` and `guard`

`watch` and `guard` share one code path. `watch` forces `mode: audit` and `fail_mode: fail_open`. `guard` uses your `capyshield.yaml`, or enforces the built-in checks when there's no file.

```mermaid
flowchart TD
    start(["capyshield guard -- cmd"]) --> cfg["Load capyshield.yaml<br/>validate · expand allow_presets"]
    cfg -->|invalid| exit1(["exit 1"])
    cfg --> env["Fingerprint sensitive ENV values<br/>in memory only"]
    env --> tls{"tls_inspection: mitm?"}
    tls -->|yes| ca["Load ~/.capyshield CA<br/>or generate an ephemeral one<br/>write CA + bundle to a temp dir"]
    tls -->|no| bind
    ca --> bind["Start proxy on 127.0.0.1:0"]
    bind -->|bind failed| fail{"fail_open or audit?"}
    fail -->|yes| unguarded["Warn and run cmd unguarded"]
    fail -->|no| exit1
    bind -->|ok| spawn["Spawn cmd with HTTP_PROXY / HTTPS_PROXY / ALL_PROXY<br/>NO_PROXY=localhost<br/>+ CA vars in mitm mode"]
    unguarded --> wait
    spawn --> wait["Wait for cmd · Ctrl-C reaches cmd,<br/>capyshield stays up for the summary"]
    wait --> report["Print connection table · ENV leak warnings<br/>--report events.json · --emit-policy file"]
    report --> blocked{"Any event blocked?"}
    blocked -->|yes| exit2(["exit 2"])
    blocked -->|no| passthrough(["exit with cmd's own code"])
```

Proxy variables are cooperative: tools that honor them (npm, pip, uv, curl, git, most SDKs) route through the proxy, but code that opens raw sockets can bypass it. For a hard boundary, run the command in a container or network namespace whose only route out is the proxy.

## Egress proxy

The proxy speaks plain HTTP/1.1 forward-proxy requests and `CONNECT` tunnels. Every decision produces one event: `timestamp`, `destination_host`, `port`, `protocol`, `bytes_sent`, `action` and `rule_id`.

The **host policy** check runs first for every connection, request and SNI name:

```mermaid
flowchart LR
    host["host"] --> deny{"matches deny_hosts?<br/>global + agent"}
    deny -->|yes| v1["disallowed_host:deny_hosts"]
    deny -->|no| allow{"allowlist set and<br/>host not in it?<br/>allow_hosts + presets,<br/>or the agent's own list"}
    allow -->|yes| v2["disallowed_host:not_in_allow_hosts"]
    allow -->|no| dns{"secret inside<br/>the hostname?"}
    dns -->|yes| v3["secret_leak:…"]
    dns -->|no| ok["no violation"]
```

A violation becomes `blocked` in `enforce` mode and `audited` in `audit` mode. The agent identity comes from the `X-Agent-ID` request header, falling back to `--agent-id`.

### CONNECT tunnels: SNI and MITM

```mermaid
sequenceDiagram
    autonumber
    participant C as Client (npm, curl, agent)
    participant P as capyshield proxy
    participant U as Upstream host

    C->>P: CONNECT registry.npmjs.org:443
    P->>P: Host policy check
    alt blocked
        P-->>C: 403 Forbidden
    else allowed
        P-->>C: 200 Connection established
        alt SNI mode (default, or host in tls_bypass_hosts)
            C->>P: TLS ClientHello
            P->>P: Parse SNI, re-check policy if it differs from the CONNECT host
            P->>U: TCP connect + replay ClientHello
            loop Encrypted bytes, never decrypted
                C->>P: bytes
                P->>P: Count bytes_sent, cut past max_outbound_bytes (non-allowlisted hosts)
                P->>U: bytes
                U-->>C: response bytes
            end
        else MITM mode
            C->>P: TLS handshake
            P-->>C: Leaf cert for the host, signed by the local CA
            loop Each HTTP request inside the tunnel
                C->>P: Decrypted request
                P->>P: Request inspection (below)
                P->>U: New TLS connection, upstream cert verified against public roots
                U-->>C: Response streamed back
            end
        end
    end
```

Notes:
- **Domain fronting:** in SNI mode, a ClientHello whose SNI differs from the CONNECT target is checked against the policy too. In MITM mode, a `Host` header that differs from the target is.
- **Fail modes:** in SNI mode, a tunnel that doesn't start with a TLS ClientHello within 3 seconds is blocked under `enforce` + `fail_closed`, and allowed otherwise. If a leaf certificate can't be generated, MITM falls back to an SNI tunnel under `fail_open` and blocks under `fail_closed`.
- **Long-lived tunnels:** events are recorded when the tunnel opens and their byte counts update live, so keep-alive connections that outlive the wrapped command still show up in the summary.

### Request inspection

This applies to plain HTTP requests and to every decrypted request in MITM mode:

```mermaid
flowchart TD
    req["HTTP request"] --> hostcheck["Host policy:<br/>target host + Host header"]
    hostcheck -->|violation, enforce| block(["403 · event blocked"])
    hostcheck --> body["Buffer request body"]
    body --> payload["Scan URL + non-auth headers + body"]
    payload -->|secret or PII,<br/>not in secret_allow| verdict
    payload --> known{"host explicitly<br/>allow-listed?"}
    known -->|yes| verdict
    known -->|no| auth["Scan auth headers<br/>Authorization, X-Api-Key, Cookie, …"]
    auth --> limit["Body > max_outbound_bytes?"]
    limit --> entropy["High-entropy query values<br/>and custom headers"]
    entropy --> verdict{"violation?"}
    verdict -->|none| fwd(["forward upstream · allowed"])
    verdict -->|audit mode| fwdaudit(["forward upstream · audited"])
    verdict -->|enforce mode| block
```

Credentials in authentication headers sent to an allow-listed host count as normal API usage. The same value anywhere else in the request, or sent to any other host, counts as a leak. `secret_allow` grants named exceptions (`OPENAI_API_KEY: ["api.openai.com"]`).

### Scanner pipeline

```mermaid
flowchart LR
    data["outbound bytes"] --> ac["Aho-Corasick keyword prefilter<br/>e.g. ghp_, AKIA, sk-ant-"]
    ac --> rx["Run only the candidate rules' regexes<br/>210+ credential formats"]
    data --> envac["Aho-Corasick over ENV value variants<br/>plain · Base64 · URL-encoded · hex"]
    data --> pii["PII regexes<br/>credit_card + Luhn · email · ssn · nik · private_key"]
    rx --> findings["Findings: rule id or env:NAME,<br/>never the matched value"]
    envac --> findings
    pii --> findings
```

The entropy check runs separately on individual header and query values (Shannon entropy ≥ `entropy_threshold`, tokens of 24+ characters, skipping SRI hashes like `sha512-…`).

## VEX & reachability: `vex`

```mermaid
flowchart TD
    report["trivy --format json<br/>grype -o json"] --> parse["Parse report<br/>auto-detect scanner · normalize severity and purl"]
    parse --> dedupe["Dedupe on vulnerability + purl"]
    repo[("Repository")] --> walk["Walk the tree<br/>skip node_modules, .venv, dot-dirs,<br/>tests and exclude_paths"]
    walk --> manifests["Manifests and lockfiles<br/>package.json · package-lock · pnpm-lock · yarn.lock<br/>pyproject · poetry.lock · uv.lock · requirements*.txt"]
    walk --> imports["Production imports<br/>import · require() · import() · from … import<br/>+ npm scripts"]
    manifests --> facts["Facts per package<br/>in_lockfile · dependency_scope ·<br/>imported_in_prod · matched_files_count"]
    imports --> facts
    dedupe --> triage["Triage each finding"]
    facts --> triage
    rules[".capyshield/vex-rules.yaml"] --> triage
    triage --> openvex["OpenVEX v0.2.0 JSON<br/>facts in status_notes"]
    triage --> summary["Terminal summary · --summary vex.md"]
    triage --> failon{"--fail-on severity<br/>matched an affected finding?"}
    failon -->|yes| exit3(["exit 3"])
    failon -->|no| exit0(["exit 0"])
```

### Triage decision

The first matching source wins:

```mermaid
flowchart TD
    f["finding: CVE + package"] --> local{"local rule matches?"}
    local -->|yes| useLocal(["rule's status"])
    local -->|no| cloud{"cloud rule matches?<br/>(--sync only)"}
    cloud -->|yes| useCloud(["rule's status"])
    cloud -->|no| eco{"node or python<br/>package?"}
    eco -->|no| ui1(["under_investigation"])
    eco -->|yes| scope{"dependency_scope"}
    scope -->|dev_only| na1(["not_affected<br/>vulnerable_code_not_in_execute_path"])
    scope -->|direct| dimp{"imported_in_prod?"}
    dimp -->|no| na2(["not_affected<br/>vulnerable_code_not_in_execute_path"])
    dimp -->|yes| aff1(["affected<br/>+ upgrade action_statement"])
    scope -->|transitive / not_found| timp{"imported_in_prod?"}
    timp -->|yes| aff2(["affected"])
    timp -->|no| ui2(["under_investigation"])
```

Reachability is static and package-level: it works from lockfiles and import statements, not call graphs. Transitive packages that production code doesn't import directly stay `under_investigation` rather than being guessed. Record your own decisions as local rules.

### Cloud sync (optional)

```mermaid
sequenceDiagram
    participant V as capyshield vex
    participant A as CapyShield Cloud API

    alt --dry-run
        V->>V: Print the exact payload to stdout, send nothing
    else --sync with CAPYSHIELD_TOKEN
        V->>A: GET /v1/vex/rules?project=…
        A-->>V: Team VEX rules, applied after local rules
        V->>V: Triage + OpenVEX
        V->>A: POST /v1/vex/sync (metadata only, ≤ 500 KB)
    end
```

The payload contains vulnerability ids, purls, statuses and reachability facts, never source code. With `--redact-paths`, file paths and the project name are replaced by deterministic `sha256:` hashes.

```mermaid
sequenceDiagram
    participant G as capyshield guard --sync
    participant A as CapyShield Cloud API
    participant C as wrapped command

    G->>A: GET /v1/egress/policy?project=…
    A-->>G: Team allow_presets / allow_hosts / deny_hosts, unioned with capyshield.yaml
    G->>C: Run with the proxy, CAPYSHIELD_TOKEN / CAPYSHIELD_API_KEY removed
    C-->>G: Exit
    G->>A: POST /v1/egress/report (blocked host, port, rule_id, count)
```

The team policy rejects unknown fields. If the pull or the report fails, `guard` warns and keeps enforcing the local policy; the exit code still reflects blocked egress.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success, no egress violation (or audit mode). Otherwise the wrapped command's own exit code. |
| `1` | Internal error or invalid configuration |
| `2` | Egress violation blocked |
| `3` | `vex --fail-on` matched an `affected` finding |
