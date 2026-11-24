# Guarding Claude Code and MCP servers

Coding agents read untrusted text (issues, web pages, dependency READMEs). If that text carries an
*indirect prompt injection*, the agent may be told to `curl` your `.env` to an attacker. capyshield
wraps the agent so that every outbound request is checked against a policy, and any ENV secret
(plain, Base64, URL-encoded or hex) is blocked before it leaves the machine.

## Claude Code

```bash
capyshield init                                   # once: capyshield.yaml + local CA
capyshield guard --config examples/claude-code/capyshield.yaml --agent-id claude-code -- claude
```

Every tool the agent runs (Bash, `npm`, `pip`, `curl`, `git`) inherits the proxy settings and CA
variables, so it is guarded too.

## MCP servers

Wrap the server command in your MCP client config ([`mcp.json`](mcp.json)). capyshield writes only to
stderr, so the stdio JSON-RPC channel on stdout is untouched.

```json
{
  "mcpServers": {
    "fetch": {
      "command": "capyshield",
      "args": ["guard", "--config", "capyshield.yaml", "--agent-id", "mcp-fetch", "--", "uvx", "mcp-server-fetch"]
    }
  }
}
```

[`mcp.json`](mcp.json) wraps two servers: `fetch`, which browses but may only upload 4 KB, and
`filesystem`, which is local-only, so its agent profile denies all egress (`deny_hosts: ["*"]`). If the
filesystem server is ever tricked into making a network call, capyshield blocks it.

To skip installing capyshield, swap `"command": "capyshield"` for `"command": "uvx"` and put
`"capyshield"` first in `args` (or use `npx` the same way).

The `agents:` block in [`capyshield.yaml`](capyshield.yaml) gives each agent its own allowlist and
upload limit. A request can also pick its identity per call with the `X-Agent-ID` header.
