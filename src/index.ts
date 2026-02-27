#!/usr/bin/env node

/**
 * mcp-guardian — Security middleware proxy for MCP servers.
 *
 * Usage:
 *   mcp-guardian [--config guardian.yaml] -- <server-command> [server-args...]
 *
 * Examples:
 *   mcp-guardian -- npx @modelcontextprotocol/server-filesystem /tmp
 *   mcp-guardian --config ./guardian.yaml -- node my-server.js
 *   mcp-guardian -c policy.yaml -- python mcp_server.py
 */

import { loadConfigSafe } from "./config.js";
import { GuardianProxy } from "./proxy.js";

function printUsage(): void {
  process.stderr.write(`
mcp-guardian - Security middleware proxy for MCP servers

USAGE:
  mcp-guardian [OPTIONS] -- <server-command> [server-args...]

OPTIONS:
  --config, -c <path>   Path to guardian.yaml config file
  --help, -h            Show this help message
  --version, -v         Show version

EXAMPLES:
  mcp-guardian -- npx @modelcontextprotocol/server-filesystem /tmp
  mcp-guardian --config ./guardian.yaml -- node my-server.js
  mcp-guardian -c policy.yaml -- python mcp_server.py

DESCRIPTION:
  mcp-guardian sits between an MCP client and server, intercepting tool
  calls to enforce security policies. It can:

    - Block or allow tools by name (exact or glob patterns)
    - Validate tool arguments against regex patterns
    - Rate-limit tool calls per sliding time window
    - Redact sensitive data (API keys, tokens, emails) from arguments
    - Log all activity to a structured JSONL audit trail

  Without a config file, mcp-guardian applies default redaction patterns
  (OpenAI keys, AWS keys, emails) and logs to ./guardian-audit.jsonl.
`);
}

function printVersion(): void {
  process.stderr.write("mcp-guardian v1.0.0\n");
}

function main(): void {
  const args = process.argv.slice(2);

  // Find the "--" separator
  const separatorIdx = args.indexOf("--");

  let configPath: string | undefined;
  let guardianArgs: string[];
  let serverCommand: string;
  let serverArgs: string[];

  if (separatorIdx === -1) {
    // No separator — treat all args as guardian args + try to find server command
    guardianArgs = args;
    serverCommand = "";
    serverArgs = [];
  } else {
    guardianArgs = args.slice(0, separatorIdx);
    const serverPart = args.slice(separatorIdx + 1);
    serverCommand = serverPart[0] ?? "";
    serverArgs = serverPart.slice(1);
  }

  // Parse guardian args
  for (let i = 0; i < guardianArgs.length; i++) {
    const arg = guardianArgs[i];
    if (arg === "--help" || arg === "-h") {
      printUsage();
      process.exit(0);
    }
    if (arg === "--version" || arg === "-v") {
      printVersion();
      process.exit(0);
    }
    if (arg === "--config" || arg === "-c") {
      configPath = guardianArgs[++i];
    }
  }

  if (!serverCommand) {
    process.stderr.write("Error: No server command specified.\n");
    process.stderr.write("Usage: mcp-guardian [--config guardian.yaml] -- <server-command> [args...]\n");
    process.exit(1);
  }

  // Load config
  const config = loadConfigSafe(configPath);

  // Start the proxy
  const proxy = new GuardianProxy(config, serverCommand, serverArgs);
  proxy.start();
}

main();
