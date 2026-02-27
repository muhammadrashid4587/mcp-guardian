/**
 * Core type definitions for mcp-guardian.
 */

/** Action a rule can take on a matching tool call. */
export type RuleAction = "allow" | "deny";

/** Conditions that must be met for a rule to apply. */
export interface RuleConditions {
  /** Map of argument name to regex pattern that the argument value must match. */
  args_match?: Record<string, string>;
}

/** Rate limit configuration for a rule. */
export interface RateLimit {
  max_calls: number;
  window_seconds: number;
}

/** A single security rule from the config. */
export interface Rule {
  /** Tool name to match. Supports exact names or glob patterns ("*", "read_*"). */
  tool: string;
  /** Whether to allow or deny the call. If omitted and rate_limit is set, defaults to allow. */
  action?: RuleAction;
  /** Human-readable reason for the rule (shown on deny). */
  reason?: string;
  /** Additional conditions that must match for the rule to apply. */
  conditions?: RuleConditions;
  /** Rate limit for matching calls. */
  rate_limit?: RateLimit;
}

/** Redaction configuration. */
export interface RedactionConfig {
  /** Regex patterns to redact from tool arguments. */
  patterns: string[];
}

/** Audit logging configuration. */
export interface AuditConfig {
  /** Path to the JSONL audit log file. */
  file: string;
  /** Whether to include tool arguments in the log. */
  log_args: boolean;
  /** Whether to include tool results in the log. */
  log_results: boolean;
}

/** Top-level guardian configuration. */
export interface GuardianConfig {
  rules: Rule[];
  redaction: RedactionConfig;
  audit: AuditConfig;
}

/** Result of evaluating a tool call against the rule engine. */
export interface RuleEvaluation {
  /** Whether the call is allowed. */
  allowed: boolean;
  /** The rule that matched (if any). */
  matched_rule?: Rule;
  /** Reason for denial (if denied). */
  reason?: string;
  /** Whether the call was rate-limited. */
  rate_limited?: boolean;
}

/** A single entry in the audit log. */
export interface AuditEntry {
  timestamp: string;
  tool: string;
  action: "allow" | "deny" | "redact" | "rate_limited";
  reason?: string;
  args?: Record<string, unknown>;
  result?: unknown;
  latency_ms?: number;
  request_id: string;
}

/** JSON-RPC 2.0 request. */
export interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: string | number;
  method: string;
  params?: Record<string, unknown>;
}

/** JSON-RPC 2.0 response. */
export interface JsonRpcResponse {
  jsonrpc: "2.0";
  id?: string | number;
  result?: unknown;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
}

/** Parsed tool call extracted from a JSON-RPC request. */
export interface ToolCall {
  id: string | number | undefined;
  tool_name: string;
  arguments: Record<string, unknown>;
}
