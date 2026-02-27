import { describe, it, expect } from "vitest";
import { parseSimpleYaml, validateConfig, loadConfig, DEFAULT_CONFIG } from "../src/config.js";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

describe("parseSimpleYaml", () => {
  it("should parse simple key-value pairs", () => {
    const yaml = `
name: test
version: 1
enabled: true
`;
    const result = parseSimpleYaml(yaml);
    expect(result.name).toBe("test");
    expect(result.version).toBe(1);
    expect(result.enabled).toBe(true);
  });

  it("should parse quoted strings", () => {
    const yaml = `
single: 'hello world'
double: "hello world"
`;
    const result = parseSimpleYaml(yaml);
    expect(result.single).toBe("hello world");
    expect(result.double).toBe("hello world");
  });

  it("should parse nested mappings", () => {
    const yaml = `
audit:
  file: "./audit.jsonl"
  log_args: true
  log_results: false
`;
    const result = parseSimpleYaml(yaml);
    const audit = result.audit as Record<string, unknown>;
    expect(audit.file).toBe("./audit.jsonl");
    expect(audit.log_args).toBe(true);
    expect(audit.log_results).toBe(false);
  });

  it("should parse sequences of scalars", () => {
    const yaml = `
patterns:
  - "(sk-[a-zA-Z0-9]{32,})"
  - "(AKIA[0-9A-Z]{16})"
`;
    const result = parseSimpleYaml(yaml);
    const patterns = result.patterns as string[];
    expect(patterns).toHaveLength(2);
    expect(patterns[0]).toBe("(sk-[a-zA-Z0-9]{32,})");
    expect(patterns[1]).toBe("(AKIA[0-9A-Z]{16})");
  });

  it("should parse sequences of mappings", () => {
    const yaml = `
rules:
  - tool: "exec_command"
    action: deny
    reason: "Blocked"
  - tool: "read_file"
    action: allow
`;
    const result = parseSimpleYaml(yaml);
    const rules = result.rules as Record<string, unknown>[];
    expect(rules).toHaveLength(2);
    expect(rules[0].tool).toBe("exec_command");
    expect(rules[0].action).toBe("deny");
    expect(rules[0].reason).toBe("Blocked");
    expect(rules[1].tool).toBe("read_file");
    expect(rules[1].action).toBe("allow");
  });

  it("should ignore comments", () => {
    const yaml = `
# This is a comment
name: test
# Another comment
value: 42
`;
    const result = parseSimpleYaml(yaml);
    expect(result.name).toBe("test");
    expect(result.value).toBe(42);
  });

  it("should handle empty input", () => {
    const result = parseSimpleYaml("");
    expect(result).toEqual({});
  });

  it("should parse the full guardian config format", () => {
    const yaml = `
rules:
  - tool: "exec_command"
    action: deny
    reason: "Shell execution blocked"
  - tool: "*"
    rate_limit:
      max_calls: 100
      window_seconds: 60

redaction:
  patterns:
    - "(sk-[a-zA-Z0-9]{32,})"

audit:
  file: "./guardian-audit.jsonl"
  log_args: true
  log_results: false
`;
    const result = parseSimpleYaml(yaml);
    const rules = result.rules as Record<string, unknown>[];
    expect(rules).toHaveLength(2);
    expect(rules[0].tool).toBe("exec_command");

    const rl = rules[1].rate_limit as Record<string, unknown>;
    expect(rl.max_calls).toBe(100);
    expect(rl.window_seconds).toBe(60);

    const redaction = result.redaction as Record<string, unknown>;
    const patterns = redaction.patterns as string[];
    expect(patterns).toHaveLength(1);

    const audit = result.audit as Record<string, unknown>;
    expect(audit.file).toBe("./guardian-audit.jsonl");
  });
});

describe("validateConfig", () => {
  it("should return default config for empty input", () => {
    const config = validateConfig({});
    expect(config.rules).toEqual([]);
    expect(config.redaction.patterns.length).toBeGreaterThan(0);
    expect(config.audit.file).toBe("./guardian-audit.jsonl");
  });

  it("should parse rules with conditions", () => {
    const raw = {
      rules: [
        {
          tool: "read_file",
          action: "allow",
          conditions: {
            args_match: {
              path: "^/safe/",
            },
          },
        },
      ],
    };

    const config = validateConfig(raw);
    expect(config.rules).toHaveLength(1);
    expect(config.rules[0].conditions?.args_match?.path).toBe("^/safe/");
  });

  it("should parse rate limit rules", () => {
    const raw = {
      rules: [
        {
          tool: "*",
          rate_limit: {
            max_calls: 50,
            window_seconds: 30,
          },
        },
      ],
    };

    const config = validateConfig(raw);
    expect(config.rules[0].rate_limit?.max_calls).toBe(50);
    expect(config.rules[0].rate_limit?.window_seconds).toBe(30);
  });

  it("should use default audit config when not provided", () => {
    const config = validateConfig({ rules: [] });
    expect(config.audit.log_args).toBe(true);
    expect(config.audit.log_results).toBe(false);
  });
});

describe("loadConfig", () => {
  it("should throw on missing file", () => {
    expect(() => loadConfig("/nonexistent/guardian.yaml")).toThrow("Config file not found");
  });

  it("should load and parse a real YAML file", () => {
    // Write a temp config file
    const tmpDir = os.tmpdir();
    const tmpFile = path.join(tmpDir, `guardian-test-${Date.now()}.yaml`);
    fs.writeFileSync(
      tmpFile,
      `
rules:
  - tool: "test_tool"
    action: deny
    reason: "Blocked in test"

redaction:
  patterns:
    - "secret_[a-z]+"

audit:
  file: "./test-audit.jsonl"
  log_args: false
  log_results: true
`
    );

    try {
      const config = loadConfig(tmpFile);
      expect(config.rules).toHaveLength(1);
      expect(config.rules[0].tool).toBe("test_tool");
      expect(config.rules[0].action).toBe("deny");
      expect(config.redaction.patterns).toEqual(["secret_[a-z]+"]);
      expect(config.audit.log_args).toBe(false);
      expect(config.audit.log_results).toBe(true);
    } finally {
      fs.unlinkSync(tmpFile);
    }
  });
});

describe("DEFAULT_CONFIG", () => {
  it("should have sensible defaults", () => {
    expect(DEFAULT_CONFIG.rules).toEqual([]);
    expect(DEFAULT_CONFIG.redaction.patterns.length).toBe(3);
    expect(DEFAULT_CONFIG.audit.file).toBe("./guardian-audit.jsonl");
    expect(DEFAULT_CONFIG.audit.log_args).toBe(true);
    expect(DEFAULT_CONFIG.audit.log_results).toBe(false);
  });
});
