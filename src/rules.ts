/**
 * Rule engine for mcp-guardian.
 *
 * Evaluates incoming tool calls against a list of configured rules.
 * Supports exact name matching, glob patterns, argument condition checks,
 * and sliding-window rate limiting.
 */

import type { Rule, RuleEvaluation, ToolCall } from "./types.js";

/** Sliding window entry for rate limiting. */
interface RateWindow {
  timestamps: number[];
}

export class RuleEngine {
  private rules: Rule[];
  /** Map of tool name -> sliding window timestamps for rate limiting. */
  private rateCounts: Map<string, RateWindow> = new Map();

  constructor(rules: Rule[]) {
    this.rules = rules;
  }

  /**
   * Evaluate a tool call against all configured rules.
   * Rules are evaluated in order; the first matching rule wins.
   * If no rule matches, the call is allowed by default.
   */
  evaluate(call: ToolCall): RuleEvaluation {
    for (const rule of this.rules) {
      if (!this.toolMatches(rule.tool, call.tool_name)) {
        continue;
      }

      // Check argument conditions
      if (rule.conditions?.args_match) {
        if (!this.argsMatch(rule.conditions.args_match, call.arguments)) {
          continue;
        }
      }

      // Check rate limit
      if (rule.rate_limit) {
        const limited = this.checkRateLimit(call.tool_name, rule);
        if (limited) {
          return {
            allowed: false,
            matched_rule: rule,
            reason: `Rate limit exceeded: ${rule.rate_limit.max_calls} calls per ${rule.rate_limit.window_seconds}s`,
            rate_limited: true,
          };
        }
      }

      // If rule has an explicit action, enforce it
      if (rule.action === "deny") {
        return {
          allowed: false,
          matched_rule: rule,
          reason: rule.reason ?? `Denied by rule for tool "${rule.tool}"`,
        };
      }

      if (rule.action === "allow") {
        // Record the call for rate limiting (if this rule also has a rate limit)
        if (rule.rate_limit) {
          this.recordCall(call.tool_name);
        }
        return {
          allowed: true,
          matched_rule: rule,
        };
      }

      // Rule only has rate_limit and no explicit action — allow but record
      if (rule.rate_limit) {
        this.recordCall(call.tool_name);
        return {
          allowed: true,
          matched_rule: rule,
        };
      }
    }

    // No rule matched — default allow
    return { allowed: true };
  }

  /**
   * Match a tool name against a rule's tool pattern.
   * Supports:
   *   - "*" matches everything
   *   - "prefix_*" matches any tool starting with "prefix_"
   *   - "*_suffix" matches any tool ending with "_suffix"
   *   - Exact match
   */
  toolMatches(pattern: string, toolName: string): boolean {
    if (pattern === "*") return true;

    // Convert glob pattern to regex
    if (pattern.includes("*")) {
      const escaped = pattern
        .replace(/[.+?^${}()|[\]\\]/g, "\\$&") // escape regex special chars
        .replace(/\*/g, ".*"); // convert * to .*
      const regex = new RegExp(`^${escaped}$`);
      return regex.test(toolName);
    }

    return pattern === toolName;
  }

  /**
   * Check if tool arguments match the required patterns.
   */
  private argsMatch(patterns: Record<string, string>, args: Record<string, unknown>): boolean {
    for (const [argName, pattern] of Object.entries(patterns)) {
      const argValue = args[argName];
      if (argValue === undefined) return false;

      const strValue = String(argValue);
      try {
        const regex = new RegExp(pattern);
        if (!regex.test(strValue)) return false;
      } catch {
        // Invalid regex — treat as no match
        return false;
      }
    }
    return true;
  }

  /**
   * Check if a tool call would exceed the rate limit.
   * Returns true if the limit is exceeded.
   */
  private checkRateLimit(toolName: string, rule: Rule): boolean {
    if (!rule.rate_limit) return false;

    const now = Date.now();
    const windowMs = rule.rate_limit.window_seconds * 1000;
    const window = this.rateCounts.get(toolName);

    if (!window) {
      return false; // No calls yet
    }

    // Count calls within the window
    const cutoff = now - windowMs;
    const recentCalls = window.timestamps.filter((t) => t > cutoff);
    return recentCalls.length >= rule.rate_limit.max_calls;
  }

  /**
   * Record a tool call timestamp for rate limiting.
   */
  recordCall(toolName: string): void {
    const window = this.rateCounts.get(toolName);
    const now = Date.now();

    if (window) {
      window.timestamps.push(now);
      // Prune old entries to prevent unbounded growth.
      // Keep timestamps from the last 5 minutes max.
      const cutoff = now - 5 * 60 * 1000;
      window.timestamps = window.timestamps.filter((t) => t > cutoff);
    } else {
      this.rateCounts.set(toolName, { timestamps: [now] });
    }
  }

  /**
   * Reset all rate limit counters. Useful for testing.
   */
  resetRateLimits(): void {
    this.rateCounts.clear();
  }

  /**
   * Get the current count of calls within the rate limit window for a tool.
   */
  getRateCount(toolName: string, windowSeconds: number): number {
    const window = this.rateCounts.get(toolName);
    if (!window) return 0;

    const cutoff = Date.now() - windowSeconds * 1000;
    return window.timestamps.filter((t) => t > cutoff).length;
  }
}
