import { describe, it, expect, beforeEach } from "vitest";
import { RuleEngine } from "../src/rules.js";
import type { Rule, ToolCall } from "../src/types.js";

function makeCall(tool: string, args: Record<string, unknown> = {}): ToolCall {
  return { id: 1, tool_name: tool, arguments: args };
}

describe("RuleEngine", () => {
  describe("tool matching", () => {
    it("should match exact tool names", () => {
      const engine = new RuleEngine([{ tool: "read_file", action: "deny" }]);
      const result = engine.evaluate(makeCall("read_file"));
      expect(result.allowed).toBe(false);
    });

    it("should not match different tool names", () => {
      const engine = new RuleEngine([{ tool: "read_file", action: "deny" }]);
      const result = engine.evaluate(makeCall("write_file"));
      expect(result.allowed).toBe(true);
    });

    it("should match wildcard '*' to any tool", () => {
      const engine = new RuleEngine([{ tool: "*", action: "deny", reason: "All blocked" }]);
      const result = engine.evaluate(makeCall("anything"));
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe("All blocked");
    });

    it("should match glob prefix patterns", () => {
      const engine = new RuleEngine([{ tool: "exec_*", action: "deny" }]);

      expect(engine.evaluate(makeCall("exec_command")).allowed).toBe(false);
      expect(engine.evaluate(makeCall("exec_shell")).allowed).toBe(false);
      expect(engine.evaluate(makeCall("read_file")).allowed).toBe(true);
    });

    it("should match glob suffix patterns", () => {
      const engine = new RuleEngine([{ tool: "*_dangerous", action: "deny" }]);

      expect(engine.evaluate(makeCall("very_dangerous")).allowed).toBe(false);
      expect(engine.evaluate(makeCall("safe_operation")).allowed).toBe(true);
    });

    it("should match glob patterns with wildcard in the middle", () => {
      const engine = new RuleEngine([{ tool: "file_*_remote", action: "deny" }]);

      expect(engine.evaluate(makeCall("file_read_remote")).allowed).toBe(false);
      expect(engine.evaluate(makeCall("file_write_remote")).allowed).toBe(false);
      expect(engine.evaluate(makeCall("file_read_local")).allowed).toBe(true);
    });
  });

  describe("rule ordering", () => {
    it("should use the first matching rule", () => {
      const engine = new RuleEngine([
        { tool: "read_file", action: "allow" },
        { tool: "*", action: "deny" },
      ]);

      expect(engine.evaluate(makeCall("read_file")).allowed).toBe(true);
      expect(engine.evaluate(makeCall("write_file")).allowed).toBe(false);
    });

    it("should allow by default when no rules match", () => {
      const engine = new RuleEngine([
        { tool: "exec_command", action: "deny" },
      ]);

      const result = engine.evaluate(makeCall("read_file"));
      expect(result.allowed).toBe(true);
      expect(result.matched_rule).toBeUndefined();
    });
  });

  describe("argument conditions", () => {
    it("should match when args satisfy patterns", () => {
      const engine = new RuleEngine([
        {
          tool: "read_file",
          action: "allow",
          conditions: { args_match: { path: "^/allowed/" } },
        },
        { tool: "read_file", action: "deny", reason: "Path not in allowlist" },
      ]);

      const allowed = engine.evaluate(makeCall("read_file", { path: "/allowed/data.txt" }));
      expect(allowed.allowed).toBe(true);

      const denied = engine.evaluate(makeCall("read_file", { path: "/secret/keys.txt" }));
      expect(denied.allowed).toBe(false);
      expect(denied.reason).toBe("Path not in allowlist");
    });

    it("should not match when required arg is missing", () => {
      const engine = new RuleEngine([
        {
          tool: "read_file",
          action: "allow",
          conditions: { args_match: { path: "^/allowed/" } },
        },
        { tool: "*", action: "deny" },
      ]);

      const result = engine.evaluate(makeCall("read_file", {}));
      expect(result.allowed).toBe(false);
    });

    it("should match multiple arg conditions (AND logic)", () => {
      const engine = new RuleEngine([
        {
          tool: "http_request",
          action: "allow",
          conditions: {
            args_match: {
              url: "^https://api\\.safe\\.com",
              method: "^GET$",
            },
          },
        },
        { tool: "http_request", action: "deny" },
      ]);

      // Both conditions met
      const ok = engine.evaluate(
        makeCall("http_request", { url: "https://api.safe.com/data", method: "GET" })
      );
      expect(ok.allowed).toBe(true);

      // Only one condition met
      const bad = engine.evaluate(
        makeCall("http_request", { url: "https://api.safe.com/data", method: "POST" })
      );
      expect(bad.allowed).toBe(false);
    });
  });

  describe("rate limiting", () => {
    let engine: RuleEngine;

    beforeEach(() => {
      engine = new RuleEngine([
        { tool: "*", rate_limit: { max_calls: 3, window_seconds: 60 } },
      ]);
    });

    it("should allow calls within the rate limit", () => {
      expect(engine.evaluate(makeCall("tool_a")).allowed).toBe(true);
      expect(engine.evaluate(makeCall("tool_a")).allowed).toBe(true);
      expect(engine.evaluate(makeCall("tool_a")).allowed).toBe(true);
    });

    it("should deny calls exceeding the rate limit", () => {
      engine.evaluate(makeCall("tool_a"));
      engine.evaluate(makeCall("tool_a"));
      engine.evaluate(makeCall("tool_a"));

      const result = engine.evaluate(makeCall("tool_a"));
      expect(result.allowed).toBe(false);
      expect(result.rate_limited).toBe(true);
      expect(result.reason).toContain("Rate limit exceeded");
    });

    it("should track rate limits per tool name", () => {
      engine.evaluate(makeCall("tool_a"));
      engine.evaluate(makeCall("tool_a"));
      engine.evaluate(makeCall("tool_a"));

      // tool_b should still be allowed
      expect(engine.evaluate(makeCall("tool_b")).allowed).toBe(true);
    });

    it("should reset rate limits", () => {
      engine.evaluate(makeCall("tool_a"));
      engine.evaluate(makeCall("tool_a"));
      engine.evaluate(makeCall("tool_a"));

      engine.resetRateLimits();
      expect(engine.evaluate(makeCall("tool_a")).allowed).toBe(true);
    });

    it("should report rate count correctly", () => {
      engine.evaluate(makeCall("tool_a"));
      engine.evaluate(makeCall("tool_a"));

      expect(engine.getRateCount("tool_a", 60)).toBe(2);
      expect(engine.getRateCount("tool_b", 60)).toBe(0);
    });
  });

  describe("toolMatches method", () => {
    const engine = new RuleEngine([]);

    it("should handle special regex characters in tool names", () => {
      expect(engine.toolMatches("tool.name", "tool.name")).toBe(true);
      expect(engine.toolMatches("tool.name", "toolXname")).toBe(false);
    });

    it("should handle patterns with special chars and wildcards", () => {
      expect(engine.toolMatches("ns.tool_*", "ns.tool_read")).toBe(true);
      expect(engine.toolMatches("ns.tool_*", "ns.other_read")).toBe(false);
    });
  });

  describe("deny with reason", () => {
    it("should include the configured reason in denial", () => {
      const engine = new RuleEngine([
        {
          tool: "exec_command",
          action: "deny",
          reason: "Shell execution blocked by policy",
        },
      ]);

      const result = engine.evaluate(makeCall("exec_command"));
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe("Shell execution blocked by policy");
    });

    it("should provide a default reason when none configured", () => {
      const engine = new RuleEngine([
        { tool: "exec_command", action: "deny" },
      ]);

      const result = engine.evaluate(makeCall("exec_command"));
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("exec_command");
    });
  });
});
