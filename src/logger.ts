/**
 * Structured JSON audit logger for mcp-guardian.
 *
 * Writes JSONL entries to both a file and stderr.
 * Each entry includes a timestamp, tool name, action, and optional metadata.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { AuditConfig, AuditEntry } from "./types.js";
import { randomBytes } from "node:crypto";

export class AuditLogger {
  private config: AuditConfig;
  private stream: fs.WriteStream | null = null;

  constructor(config: AuditConfig) {
    this.config = config;
    this.initFileStream();
  }

  private initFileStream(): void {
    try {
      const dir = path.dirname(path.resolve(this.config.file));
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      this.stream = fs.createWriteStream(path.resolve(this.config.file), { flags: "a" });
      this.stream.on("error", (err) => {
        process.stderr.write(`[mcp-guardian] Audit log write error: ${err.message}\n`);
      });
    } catch (err) {
      process.stderr.write(
        `[mcp-guardian] Could not open audit log file ${this.config.file}: ${(err as Error).message}\n`
      );
    }
  }

  /**
   * Generate a unique request ID for correlating log entries.
   */
  generateRequestId(): string {
    return randomBytes(8).toString("hex");
  }

  /**
   * Log an audit entry.
   */
  log(entry: Omit<AuditEntry, "timestamp" | "request_id"> & { request_id?: string }): void {
    const full: AuditEntry = {
      timestamp: new Date().toISOString(),
      request_id: entry.request_id ?? this.generateRequestId(),
      tool: entry.tool,
      action: entry.action,
      ...(entry.reason ? { reason: entry.reason } : {}),
      ...(this.config.log_args && entry.args ? { args: entry.args } : {}),
      ...(this.config.log_results && entry.result !== undefined ? { result: entry.result } : {}),
      ...(entry.latency_ms !== undefined ? { latency_ms: entry.latency_ms } : {}),
    };

    const line = JSON.stringify(full);

    // Write to file
    if (this.stream) {
      this.stream.write(line + "\n");
    }

    // Write to stderr for observability
    process.stderr.write(`[mcp-guardian] ${line}\n`);
  }

  /**
   * Log a denied tool call.
   */
  logDeny(tool: string, reason: string, args?: Record<string, unknown>, requestId?: string): void {
    this.log({ tool, action: "deny", reason, args, request_id: requestId });
  }

  /**
   * Log an allowed tool call.
   */
  logAllow(tool: string, args?: Record<string, unknown>, latencyMs?: number, requestId?: string): void {
    this.log({ tool, action: "allow", args, latency_ms: latencyMs, request_id: requestId });
  }

  /**
   * Log a redaction event.
   */
  logRedact(tool: string, args?: Record<string, unknown>, requestId?: string): void {
    this.log({ tool, action: "redact", args, request_id: requestId });
  }

  /**
   * Log a rate-limited tool call.
   */
  logRateLimited(tool: string, reason: string, requestId?: string): void {
    this.log({ tool, action: "rate_limited", reason, request_id: requestId });
  }

  /**
   * Flush and close the audit log stream.
   */
  close(): Promise<void> {
    return new Promise((resolve) => {
      if (this.stream) {
        this.stream.end(() => resolve());
      } else {
        resolve();
      }
    });
  }
}
