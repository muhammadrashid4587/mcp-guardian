# mcp-guardian

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18-green.svg)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)](https://www.typescriptlang.org/)
[![Tests](https://img.shields.io/badge/Tests-vitest-yellow.svg)](https://vitest.dev/)

**A security middleware proxy that sits between MCP clients and MCP servers.** It intercepts every tool call, enforces configurable security policies, redacts sensitive data, rate-limits abuse, and writes a structured audit trail -- all with zero external runtime dependencies.

---

## Architecture

```
                         mcp-guardian
                    ┌─────────────────────┐
                    │                     │
  MCP Client       │  ┌───────────────┐  │       MCP Server
  (Claude, etc.)   │  │  Rule Engine  │  │       (any stdio server)
       │           │  │               │  │            │
       │  stdin    │  │ - Allow/Deny  │  │   stdin    │
       ├──────────►│  │ - Glob match  │  ├───────────►│
       │           │  │ - Arg checks  │  │            │
       │           │  │ - Rate limit  │  │            │
       │  stdout   │  └───────┬───────┘  │   stdout   │
       │◄──────────┤          │          │◄───────────┤
       │           │  ┌───────▼───────┐  │            │
                   │  │   Redactor    │  │
                   │  │               │  │
                   │  │ - API keys    │  │
                   │  │ - Tokens      │  │
                   │  │ - Emails      │  │
                   │  └───────┬───────┘  │
                   │          │          │
                   │  ┌───────▼───────┐  │
                   │  │ Audit Logger  │──┼──► guardian-audit.jsonl
                   │  │   (JSONL)     │──┼──► stderr
                   │  └───────────────┘  │
                   │                     │
                   └─────────────────────┘
```

### Request flow

```
1. Client sends JSON-RPC  ──►  Guardian receives on stdin
2. Parse message              Is it a tools/call?
   ├─ No  ────────────────►  Forward to server unchanged
   └─ Yes ────────────────►  3. Redact sensitive args
                              4. Evaluate rules
                                 ├─ DENY  ──►  Return error to client, log
                                 ├─ RATE LIMITED ──► Return error, log
                                 └─ ALLOW ──►  5. Forward to server
                              6. Server response ──► Forward to client
                              7. Write audit log entry
```

---

## Features

| Feature | Description |
|---------|-------------|
| **Allow/Deny Rules** | Block or allow tools by exact name or glob patterns (`exec_*`, `*_dangerous`) |
| **Argument Validation** | Require tool arguments to match regex patterns (e.g., file paths in `/allowed/`) |
| **Rate Limiting** | Sliding-window rate limits per tool -- prevent runaway loops |
| **Secret Redaction** | Strip API keys, AWS credentials, emails, and custom patterns from arguments |
| **Audit Logging** | JSONL audit trail with timestamps, tool names, actions, and latency |
| **Zero Dependencies** | Only uses Node.js built-ins at runtime -- minimal attack surface for a security tool |
| **First-Match Wins** | Rules are evaluated top-to-bottom; the first match decides the outcome |

---

## Quick Start

### Install

```bash
# Clone and build
git clone https://github.com/muhammadrashid4587/mcp-guardian.git
cd mcp-guardian
npm install
npm run build

# Or install globally
npm install -g .
```

### Run

```bash
# Wrap any MCP server
mcp-guardian -- npx @modelcontextprotocol/server-filesystem /tmp

# With a custom config
mcp-guardian --config guardian.yaml -- node my-server.js

# Short flag
mcp-guardian -c policy.yaml -- python mcp_server.py
```

### Use with Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "guarded-filesystem": {
      "command": "mcp-guardian",
      "args": [
        "--config", "/path/to/guardian.yaml",
        "--",
        "npx", "@modelcontextprotocol/server-filesystem", "/home/user/documents"
      ]
    }
  }
}
```

---

## Configuration

Copy `guardian.example.yaml` to `guardian.yaml` and customize:

```yaml
rules:
  # Block shell execution
  - tool: "exec_command"
    action: deny
    reason: "Shell execution blocked by policy"

  # Allow file reads only from safe paths
  - tool: "read_file"
    action: allow
    conditions:
      args_match:
        path: "^/allowed/.*"

  - tool: "read_file"
    action: deny
    reason: "File read outside allowed directory"

  # Rate-limit everything as a safety net
  - tool: "*"
    rate_limit:
      max_calls: 100
      window_seconds: 60

redaction:
  patterns:
    - "(sk-[a-zA-Z0-9]{32,})"                              # OpenAI API keys
    - "(AKIA[0-9A-Z]{16})"                                  # AWS access keys
    - "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"   # Email addresses
    - "(ghp_[a-zA-Z0-9]{36})"                               # GitHub tokens
    - "(xox[bpoas]-[a-zA-Z0-9-]+)"                          # Slack tokens

audit:
  file: "./guardian-audit.jsonl"
  log_args: true
  log_results: false
```

### Rule Matching

Rules are evaluated **top-to-bottom**. The first rule that matches a tool call wins.

| Pattern | Matches |
|---------|---------|
| `"exec_command"` | Exact match only |
| `"exec_*"` | Any tool starting with `exec_` |
| `"*_dangerous"` | Any tool ending with `_dangerous` |
| `"file_*_remote"` | Wildcard in the middle |
| `"*"` | Every tool (catch-all) |

If **no rule matches**, the call is **allowed by default**.

### Argument Conditions

Rules can require arguments to match regex patterns. All specified patterns must match (AND logic):

```yaml
- tool: "http_request"
  action: allow
  conditions:
    args_match:
      url: "^https://api\\.trusted\\.com"
      method: "^GET$"
```

### Rate Limiting

Sliding-window counters track calls per tool. When the limit is hit, the call is blocked with a clear error:

```yaml
- tool: "http_*"
  rate_limit:
    max_calls: 30
    window_seconds: 60
```

---

## Audit Log

Every intercepted tool call is logged to a JSONL file and stderr:

```json
{"timestamp":"2026-03-11T10:30:00.123Z","request_id":"a1b2c3d4e5f67890","tool":"exec_command","action":"deny","reason":"Shell execution blocked by policy"}
{"timestamp":"2026-03-11T10:30:01.456Z","request_id":"f0e1d2c3b4a59876","tool":"read_file","action":"allow","args":{"path":"/allowed/data.txt"},"latency_ms":2}
{"timestamp":"2026-03-11T10:30:02.789Z","request_id":"1a2b3c4d5e6f7890","tool":"search","action":"redact","args":{"query":"[REDACTED]"}}
```

Each entry contains:
- **timestamp** -- ISO 8601
- **request_id** -- Unique ID for correlation
- **tool** -- Tool name that was called
- **action** -- `allow`, `deny`, `redact`, or `rate_limited`
- **reason** -- Why it was denied (if applicable)
- **args** -- Tool arguments (if `log_args: true`)
- **latency_ms** -- Processing overhead in milliseconds

---

## Development

```bash
# Install dependencies
npm install

# Run tests
npm test

# Watch mode
npm run test:watch

# Type-check without emitting
npm run lint

# Build
npm run build
```

### Project Structure

```
mcp-guardian/
├── src/
│   ├── index.ts        Entry point — CLI arg parsing, starts the proxy
│   ├── proxy.ts        Stdio proxy — spawns child server, intercepts messages
│   ├── rules.ts        Rule engine — matching, conditions, rate limiting
│   ├── logger.ts       Structured JSONL audit logger
│   ├── config.ts       YAML config parser and validator (no dependencies)
│   ├── types.ts        TypeScript interfaces for everything
│   └── redactor.ts     Sensitive data pattern redactor
├── tests/
│   ├── rules.test.ts   Rule engine unit tests
│   ├── redactor.test.ts  Redactor unit tests
│   └── config.test.ts  Config parsing tests
├── guardian.example.yaml
├── package.json
├── tsconfig.json
└── vitest.config.ts
```

---

## Security Considerations

- **Zero runtime dependencies** -- Only Node.js built-ins are used at runtime. No supply-chain risk from transitive dependencies.
- **Config file exclusion** -- `guardian.yaml` is in `.gitignore` by default since it may contain environment-specific policies.
- **Redaction before rules** -- Sensitive data is redacted from arguments _before_ being logged or evaluated, so secrets never reach the audit trail.
- **Fail-open by default** -- If no rule matches, calls are allowed. This is intentional for ease of adoption. Add a `- tool: "*"` deny rule at the end to flip to fail-closed.

### Fail-Closed Mode

To deny all unrecognized tools, add a catch-all deny at the bottom of your rules:

```yaml
rules:
  - tool: "read_file"
    action: allow
  - tool: "list_files"
    action: allow
  # Deny everything else
  - tool: "*"
    action: deny
    reason: "Tool not in allowlist"
```

---

## License

[MIT](LICENSE)
