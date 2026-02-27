/**
 * MCP stdio proxy for mcp-guardian.
 *
 * Spawns an MCP server as a child process and sits between the client (stdin)
 * and the server. Intercepts JSON-RPC messages for "tools/call" to apply
 * security rules, redaction, and audit logging before forwarding.
 */

import { spawn, type ChildProcess } from "node:child_process";
import type { GuardianConfig, JsonRpcRequest, JsonRpcResponse, ToolCall } from "./types.js";
import { RuleEngine } from "./rules.js";
import { Redactor } from "./redactor.js";
import { AuditLogger } from "./logger.js";

export class GuardianProxy {
  private config: GuardianConfig;
  private ruleEngine: RuleEngine;
  private redactor: Redactor;
  private logger: AuditLogger;
  private child: ChildProcess | null = null;
  private serverCommand: string;
  private serverArgs: string[];
  private requestTimeoutMs: number;

  constructor(
    config: GuardianConfig,
    serverCommand: string,
    serverArgs: string[] = [],
    requestTimeoutMs: number = 30_000,
  ) {
    this.config = config;
    this.ruleEngine = new RuleEngine(config.rules);
    this.redactor = new Redactor(config.redaction);
    this.logger = new AuditLogger(config.audit);
    this.serverCommand = serverCommand;
    this.serverArgs = serverArgs;
    this.requestTimeoutMs = requestTimeoutMs;
  }

  /**
   * Start the proxy: spawn the child MCP server and wire up stdio pipes.
   */
  start(): void {
    process.stderr.write(
      `[mcp-guardian] Starting proxy for: ${this.serverCommand} ${this.serverArgs.join(" ")}\n`
    );
    process.stderr.write(
      `[mcp-guardian] Loaded ${this.config.rules.length} rules, ${this.config.redaction.patterns.length} redaction patterns\n`
    );

    this.child = spawn(this.serverCommand, this.serverArgs, {
      stdio: ["pipe", "pipe", "inherit"], // stdin: pipe, stdout: pipe, stderr: inherit
    });

    this.child.on("error", (err) => {
      process.stderr.write(`[mcp-guardian] Failed to start server: ${err.message}\n`);
      process.exit(1);
    });

    this.child.on("exit", (code) => {
      process.stderr.write(`[mcp-guardian] Server exited with code ${code}\n`);
      this.logger.close().then(() => process.exit(code ?? 0));
    });

    // Client -> Guardian -> Server
    this.pipeClientToServer();

    // Server -> Guardian -> Client
    this.pipeServerToClient();

    // Handle client disconnect
    process.stdin.on("end", () => {
      process.stderr.write("[mcp-guardian] Client disconnected\n");
      this.child?.kill();
    });

    process.on("SIGINT", () => {
      process.stderr.write("[mcp-guardian] Received SIGINT, shutting down\n");
      this.child?.kill();
      this.logger.close().then(() => process.exit(0));
    });

    process.on("SIGTERM", () => {
      process.stderr.write("[mcp-guardian] Received SIGTERM, shutting down\n");
      this.child?.kill();
      this.logger.close().then(() => process.exit(0));
    });
  }

  /**
   * Read lines from client stdin, intercept tool calls, forward to server.
   */
  private pipeClientToServer(): void {
    let buffer = "";

    process.stdin.on("data", (chunk: Buffer) => {
      buffer += chunk.toString("utf-8");

      // JSON-RPC over stdio uses newline-delimited JSON
      let newlineIdx: number;
      while ((newlineIdx = buffer.indexOf("\n")) !== -1) {
        const line = buffer.slice(0, newlineIdx).trim();
        buffer = buffer.slice(newlineIdx + 1);

        if (!line) continue;

        this.handleClientMessage(line);
      }
    });
  }

  /**
   * Read lines from server stdout and forward to client.
   */
  private pipeServerToClient(): void {
    if (!this.child?.stdout) return;

    let buffer = "";

    this.child.stdout.on("data", (chunk: Buffer) => {
      buffer += chunk.toString("utf-8");

      let newlineIdx: number;
      while ((newlineIdx = buffer.indexOf("\n")) !== -1) {
        const line = buffer.slice(0, newlineIdx).trim();
        buffer = buffer.slice(newlineIdx + 1);

        if (!line) continue;

        // Forward server responses to client as-is
        process.stdout.write(line + "\n");
      }
    });
  }

  /**
   * Process a single JSON-RPC message from the client.
   */
  private handleClientMessage(line: string): void {
    let request: JsonRpcRequest;

    try {
      request = JSON.parse(line) as JsonRpcRequest;
    } catch {
      // Not valid JSON — forward as-is (could be a partial message)
      this.forwardToServer(line);
      return;
    }

    // Only intercept tools/call requests
    if (request.method !== "tools/call") {
      this.forwardToServer(line);
      return;
    }

    const startTime = Date.now();
    const requestId = this.logger.generateRequestId();

    // Extract tool call info
    const toolCall = this.extractToolCall(request);
    if (!toolCall) {
      this.forwardToServer(line);
      return;
    }

    // Step 1: Apply redaction to arguments
    const { redacted, value: cleanedArgs } = this.redactor.redactObject(toolCall.arguments);
    if (redacted) {
      this.logger.logRedact(toolCall.tool_name, cleanedArgs, requestId);
      // Update the request with redacted args
      if (request.params) {
        (request.params as Record<string, unknown>).arguments = cleanedArgs;
      }
    }

    // Step 2: Evaluate rules
    const evaluation = this.ruleEngine.evaluate({
      ...toolCall,
      arguments: cleanedArgs,
    });

    if (!evaluation.allowed) {
      // Block the request — send error response back to client
      if (evaluation.rate_limited) {
        this.logger.logRateLimited(
          toolCall.tool_name,
          evaluation.reason ?? "Rate limited",
          requestId
        );
      } else {
        this.logger.logDeny(
          toolCall.tool_name,
          evaluation.reason ?? "Denied by policy",
          this.config.audit.log_args ? cleanedArgs : undefined,
          requestId
        );
      }

      const errorResponse: JsonRpcResponse = {
        jsonrpc: "2.0",
        id: request.id,
        error: {
          code: -32600,
          message: evaluation.reason ?? "Request denied by security policy",
          data: {
            guardian: true,
            rate_limited: evaluation.rate_limited ?? false,
          },
        },
      };

      process.stdout.write(JSON.stringify(errorResponse) + "\n");
      return;
    }

    // Step 3: Forward the (potentially redacted) request to the server
    const latencyMs = Date.now() - startTime;
    this.logger.logAllow(
      toolCall.tool_name,
      this.config.audit.log_args ? cleanedArgs : undefined,
      latencyMs,
      requestId
    );

    // Forward the modified request
    this.forwardToServer(JSON.stringify(request));
  }

  /**
   * Extract tool call information from a JSON-RPC request.
   */
  private extractToolCall(request: JsonRpcRequest): ToolCall | null {
    if (!request.params) return null;

    const params = request.params as Record<string, unknown>;
    const name = params.name as string | undefined;
    const args = (params.arguments as Record<string, unknown>) ?? {};

    if (!name) return null;

    return {
      id: request.id,
      tool_name: name,
      arguments: args,
    };
  }

  /**
   * Send a message to the child server's stdin.
   */
  private forwardToServer(message: string): void {
    if (this.child?.stdin?.writable) {
      this.child.stdin.write(message + "\n");
    } else {
      process.stderr.write(
        `[mcp-guardian] Cannot forward to server: stdin is not writable\n`
      );
    }
  }

  /**
   * Stop the proxy and clean up resources.
   */
  async stop(): Promise<void> {
    this.child?.kill();
    await this.logger.close();
  }
}
