import { describe, it, expect } from "vitest";
import { Redactor } from "../src/redactor.js";

function makeRedactor(patterns?: string[]): Redactor {
  return new Redactor({
    patterns: patterns ?? [
      "(sk-[a-zA-Z0-9]{32,})",
      "(AKIA[0-9A-Z]{16})",
      "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",
    ],
  });
}

describe("Redactor", () => {
  describe("redactString", () => {
    it("should redact OpenAI API keys", () => {
      const redactor = makeRedactor();
      const key = "sk-" + "a".repeat(48);
      const result = redactor.redactString(`My key is ${key}`);
      expect(result.redacted).toBe(true);
      expect(result.value).not.toContain(key);
      expect(result.value).toContain("[REDACTED]");
    });

    it("should redact AWS access keys", () => {
      const redactor = makeRedactor();
      const key = "AKIA" + "A".repeat(16);
      const result = redactor.redactString(`AWS key: ${key}`);
      expect(result.redacted).toBe(true);
      expect(result.value).not.toContain(key);
      expect(result.value).toContain("[REDACTED]");
    });

    it("should redact email addresses", () => {
      const redactor = makeRedactor();
      const result = redactor.redactString("Contact user@example.com for help");
      expect(result.redacted).toBe(true);
      expect(result.value).not.toContain("user@example.com");
      expect(result.value).toContain("[REDACTED]");
    });

    it("should not modify strings without sensitive data", () => {
      const redactor = makeRedactor();
      const input = "This is a normal string with no secrets";
      const result = redactor.redactString(input);
      expect(result.redacted).toBe(false);
      expect(result.value).toBe(input);
    });

    it("should redact multiple occurrences", () => {
      const redactor = makeRedactor();
      const result = redactor.redactString("Email john@test.com and jane@test.com");
      expect(result.redacted).toBe(true);
      expect(result.value).not.toContain("john@test.com");
      expect(result.value).not.toContain("jane@test.com");
      // Should have two redacted markers
      expect(result.value.split("[REDACTED]").length).toBe(3);
    });

    it("should handle empty strings", () => {
      const redactor = makeRedactor();
      const result = redactor.redactString("");
      expect(result.redacted).toBe(false);
      expect(result.value).toBe("");
    });
  });

  describe("redactObject", () => {
    it("should redact nested string values", () => {
      const redactor = makeRedactor();
      const key = "sk-" + "b".repeat(48);
      const obj = {
        name: "test",
        config: {
          api_key: key,
          timeout: 30,
        },
      };

      const result = redactor.redactObject(obj);
      expect(result.redacted).toBe(true);
      expect((result.value.config as Record<string, unknown>).api_key).toBe("[REDACTED]");
      expect(result.value.name).toBe("test");
      expect((result.value.config as Record<string, unknown>).timeout).toBe(30);
    });

    it("should redact values in arrays", () => {
      const redactor = makeRedactor();
      const obj = {
        recipients: ["alice@example.com", "bob@example.com"],
        count: 2,
      };

      const result = redactor.redactObject(obj);
      expect(result.redacted).toBe(true);
      const recipients = result.value.recipients as string[];
      expect(recipients[0]).toBe("[REDACTED]");
      expect(recipients[1]).toBe("[REDACTED]");
    });

    it("should handle deeply nested objects", () => {
      const redactor = makeRedactor();
      const key = "AKIA" + "X".repeat(16);
      const obj = {
        level1: {
          level2: {
            level3: {
              secret: key,
            },
          },
        },
      };

      const result = redactor.redactObject(obj);
      expect(result.redacted).toBe(true);
      const deep = (
        (result.value.level1 as Record<string, unknown>).level2 as Record<string, unknown>
      ).level3 as Record<string, unknown>;
      expect(deep.secret).toBe("[REDACTED]");
    });

    it("should not modify the original object", () => {
      const redactor = makeRedactor();
      const original = { email: "test@example.com" };
      redactor.redactObject(original);
      expect(original.email).toBe("test@example.com");
    });

    it("should preserve non-string values", () => {
      const redactor = makeRedactor();
      const obj = {
        count: 42,
        active: true,
        data: null,
        name: "safe-string",
      };

      const result = redactor.redactObject(obj);
      expect(result.redacted).toBe(false);
      expect(result.value.count).toBe(42);
      expect(result.value.active).toBe(true);
      expect(result.value.data).toBe(null);
      expect(result.value.name).toBe("safe-string");
    });
  });

  describe("containsSensitive", () => {
    it("should detect sensitive data", () => {
      const redactor = makeRedactor();
      expect(redactor.containsSensitive("admin@corp.com")).toBe(true);
    });

    it("should return false for safe strings", () => {
      const redactor = makeRedactor();
      expect(redactor.containsSensitive("just a normal string")).toBe(false);
    });
  });

  describe("custom patterns", () => {
    it("should support custom regex patterns", () => {
      const redactor = makeRedactor(["password=[^&\\s]+"]);
      const result = redactor.redactString("url?password=secret123&user=bob");
      expect(result.redacted).toBe(true);
      expect(result.value).not.toContain("secret123");
      expect(result.value).toContain("[REDACTED]");
    });

    it("should handle invalid regex patterns gracefully", () => {
      // The Redactor constructor should not throw on invalid regex
      const redactor = makeRedactor(["[invalid", "valid_pattern"]);
      const result = redactor.redactString("matches valid_pattern here");
      expect(result.redacted).toBe(true);
    });
  });
});
