/**
 * Sensitive data redactor for mcp-guardian.
 *
 * Scans tool arguments for patterns that match sensitive data (API keys,
 * tokens, email addresses, etc.) and replaces them with [REDACTED].
 */

import type { RedactionConfig } from "./types.js";

const REDACTED_PLACEHOLDER = "[REDACTED]";

export class Redactor {
  private patterns: RegExp[];

  constructor(config: RedactionConfig) {
    this.patterns = config.patterns.map((p) => {
      try {
        return new RegExp(p, "g");
      } catch {
        process.stderr.write(`[mcp-guardian] Warning: Invalid redaction pattern: ${p}\n`);
        return null;
      }
    }).filter((p): p is RegExp => p !== null);
  }

  /**
   * Redact sensitive data from a string value.
   * Returns an object indicating whether redaction occurred and the cleaned value.
   */
  redactString(value: string): { redacted: boolean; value: string } {
    let result = value;
    let didRedact = false;

    for (const pattern of this.patterns) {
      // Reset lastIndex since we use the 'g' flag
      pattern.lastIndex = 0;
      if (pattern.test(result)) {
        didRedact = true;
        pattern.lastIndex = 0;
        result = result.replace(pattern, REDACTED_PLACEHOLDER);
      }
    }

    return { redacted: didRedact, value: result };
  }

  /**
   * Deep-clone and redact all string values in a nested object/array structure.
   * Returns the redacted copy and a boolean indicating if anything was redacted.
   */
  redactObject(obj: Record<string, unknown>): { redacted: boolean; value: Record<string, unknown> } {
    let anyRedacted = false;
    const result = this.deepRedact(obj, (didRedact) => {
      if (didRedact) anyRedacted = true;
    });
    return { redacted: anyRedacted, value: result as Record<string, unknown> };
  }

  private deepRedact(value: unknown, onRedact: (r: boolean) => void): unknown {
    if (typeof value === "string") {
      const { redacted, value: cleaned } = this.redactString(value);
      onRedact(redacted);
      return cleaned;
    }

    if (Array.isArray(value)) {
      return value.map((item) => this.deepRedact(item, onRedact));
    }

    if (value !== null && typeof value === "object") {
      const result: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value)) {
        result[k] = this.deepRedact(v, onRedact);
      }
      return result;
    }

    // Numbers, booleans, null — pass through unchanged
    return value;
  }

  /**
   * Check if a string contains any sensitive patterns (without modifying it).
   */
  containsSensitive(value: string): boolean {
    for (const pattern of this.patterns) {
      pattern.lastIndex = 0;
      if (pattern.test(value)) return true;
    }
    return false;
  }
}
