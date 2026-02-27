/**
 * Configuration loader for mcp-guardian.
 *
 * Parses a guardian.yaml file into a typed GuardianConfig object.
 * Uses a minimal YAML subset parser to avoid external dependencies.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { GuardianConfig, Rule, RedactionConfig, AuditConfig } from "./types.js";

/** Default configuration used when no config file is provided. */
export const DEFAULT_CONFIG: GuardianConfig = {
  rules: [],
  redaction: {
    patterns: [
      "(sk-[a-zA-Z0-9]{32,})",
      "(AKIA[0-9A-Z]{16})",
      "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",
    ],
  },
  audit: {
    file: "./guardian-audit.jsonl",
    log_args: true,
    log_results: false,
  },
};

/**
 * Minimal YAML parser that handles the guardian config format.
 * Supports: mappings, sequences (with - prefix), quoted/unquoted scalars,
 * nested indentation. Does NOT handle the full YAML spec — only what we need.
 */
export function parseSimpleYaml(text: string): Record<string, unknown> {
  const lines = text.split("\n");
  return parseMapping(lines, 0, 0).value as Record<string, unknown>;
}

interface ParseResult {
  value: unknown;
  nextLine: number;
}

function getIndent(line: string): number {
  const match = line.match(/^(\s*)/);
  return match ? match[1].length : 0;
}

function isComment(line: string): boolean {
  return line.trimStart().startsWith("#") || line.trim() === "";
}

function parseScalar(raw: string): string | number | boolean {
  const trimmed = raw.trim();

  // Quoted strings
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    // Process escape sequences for double-quoted strings
    const inner = trimmed.slice(1, -1);
    if (trimmed.startsWith('"')) {
      return inner.replace(/\\n/g, "\n").replace(/\\t/g, "\t").replace(/\\\\/g, "\\");
    }
    return inner;
  }

  // Booleans
  if (trimmed === "true" || trimmed === "True" || trimmed === "TRUE") return true;
  if (trimmed === "false" || trimmed === "False" || trimmed === "FALSE") return false;

  // Numbers
  if (/^-?\d+$/.test(trimmed)) return parseInt(trimmed, 10);
  if (/^-?\d+\.\d+$/.test(trimmed)) return parseFloat(trimmed);

  return trimmed;
}

function parseMapping(lines: string[], startLine: number, baseIndent: number): ParseResult {
  const result: Record<string, unknown> = {};
  let i = startLine;

  while (i < lines.length) {
    if (isComment(lines[i])) {
      i++;
      continue;
    }

    const indent = getIndent(lines[i]);
    if (indent < baseIndent) break;
    if (indent > baseIndent) break; // Unexpected deeper indent at mapping level

    const line = lines[i].trim();

    // Check for sequence item at this indent
    if (line.startsWith("- ")) {
      break; // sequences are handled by the parent
    }

    // Key-value pair
    const colonIdx = line.indexOf(":");
    if (colonIdx === -1) {
      i++;
      continue;
    }

    const key = line.slice(0, colonIdx).trim();
    const afterColon = line.slice(colonIdx + 1).trim();

    if (afterColon === "" || afterColon.startsWith("#")) {
      // Value is on the next line(s) — could be a mapping or sequence
      i++;
      // Find the indent of the next meaningful line
      let nextMeaningful = i;
      while (nextMeaningful < lines.length && isComment(lines[nextMeaningful])) {
        nextMeaningful++;
      }
      if (nextMeaningful >= lines.length) {
        result[key] = null;
        i = nextMeaningful;
        continue;
      }

      const nextIndent = getIndent(lines[nextMeaningful]);
      if (nextIndent <= baseIndent) {
        result[key] = null;
        i = nextMeaningful;
        continue;
      }

      const nextLine = lines[nextMeaningful].trim();
      if (nextLine.startsWith("- ")) {
        const seq = parseSequence(lines, nextMeaningful, nextIndent);
        result[key] = seq.value;
        i = seq.nextLine;
      } else {
        const sub = parseMapping(lines, nextMeaningful, nextIndent);
        result[key] = sub.value;
        i = sub.nextLine;
      }
    } else {
      result[key] = parseScalar(afterColon);
      i++;
    }
  }

  return { value: result, nextLine: i };
}

function parseSequence(lines: string[], startLine: number, baseIndent: number): ParseResult {
  const result: unknown[] = [];
  let i = startLine;

  while (i < lines.length) {
    if (isComment(lines[i])) {
      i++;
      continue;
    }

    const indent = getIndent(lines[i]);
    if (indent < baseIndent) break;
    if (indent > baseIndent) {
      // Could be continuation of previous item
      i++;
      continue;
    }

    const line = lines[i].trim();
    if (!line.startsWith("- ")) break;

    const afterDash = line.slice(2).trim();

    // Check if this is a sequence of scalars (e.g., - "pattern")
    if (afterDash && !afterDash.includes(":")) {
      result.push(parseScalar(afterDash));
      i++;
      continue;
    }

    // Inline mapping on the same line as dash: - key: value
    if (afterDash.includes(":")) {
      const colonIdx = afterDash.indexOf(":");
      const key = afterDash.slice(0, colonIdx).trim();
      const val = afterDash.slice(colonIdx + 1).trim();

      const obj: Record<string, unknown> = {};
      if (val === "" || val.startsWith("#")) {
        // Nested block under this key
        i++;
        let nextMeaningful = i;
        while (nextMeaningful < lines.length && isComment(lines[nextMeaningful])) {
          nextMeaningful++;
        }
        if (nextMeaningful < lines.length) {
          const nextIndent = getIndent(lines[nextMeaningful]);
          const nextLine = lines[nextMeaningful].trim();
          if (nextIndent > baseIndent) {
            if (nextLine.startsWith("- ")) {
              const seq = parseSequence(lines, nextMeaningful, nextIndent);
              obj[key] = seq.value;
              i = seq.nextLine;
            } else {
              const sub = parseMapping(lines, nextMeaningful, nextIndent);
              obj[key] = sub.value;
              i = sub.nextLine;
            }
          } else {
            obj[key] = null;
            i = nextMeaningful;
          }
        }
      } else {
        obj[key] = parseScalar(val);
        i++;
      }

      // Check for continuation keys at deeper indent
      while (i < lines.length) {
        if (isComment(lines[i])) {
          i++;
          continue;
        }
        const contIndent = getIndent(lines[i]);
        if (contIndent <= baseIndent) break;
        const contLine = lines[i].trim();
        if (contLine.startsWith("- ")) break;

        const contColon = contLine.indexOf(":");
        if (contColon !== -1) {
          const contKey = contLine.slice(0, contColon).trim();
          const contVal = contLine.slice(contColon + 1).trim();

          if (contVal === "" || contVal.startsWith("#")) {
            i++;
            let nextM = i;
            while (nextM < lines.length && isComment(lines[nextM])) nextM++;
            if (nextM < lines.length) {
              const nIndent = getIndent(lines[nextM]);
              const nLine = lines[nextM].trim();
              if (nIndent > contIndent) {
                if (nLine.startsWith("- ")) {
                  const seq = parseSequence(lines, nextM, nIndent);
                  obj[contKey] = seq.value;
                  i = seq.nextLine;
                } else {
                  const sub = parseMapping(lines, nextM, nIndent);
                  obj[contKey] = sub.value;
                  i = sub.nextLine;
                }
              } else {
                obj[contKey] = null;
                i = nextM;
              }
            }
          } else {
            obj[contKey] = parseScalar(contVal);
            i++;
          }
        } else {
          i++;
        }
      }

      result.push(obj);
      continue;
    }

    // Plain dash with nothing after
    result.push(null);
    i++;
  }

  return { value: result, nextLine: i };
}

/**
 * Validates and coerces a raw parsed object into a GuardianConfig.
 */
export function validateConfig(raw: Record<string, unknown>): GuardianConfig {
  const config: GuardianConfig = { ...DEFAULT_CONFIG };

  // Parse rules
  if (raw.rules && Array.isArray(raw.rules)) {
    config.rules = (raw.rules as Record<string, unknown>[]).map((r): Rule => {
      const rule: Rule = {
        tool: String(r.tool ?? "*"),
      };
      if (r.action !== undefined) {
        const action = String(r.action);
        if (action !== "allow" && action !== "deny") {
          throw new Error(`Invalid rule action "${action}" for tool "${rule.tool}". Must be "allow" or "deny".`);
        }
        rule.action = action;
      }
      if (r.reason !== undefined) {
        rule.reason = String(r.reason);
      }
      if (r.conditions && typeof r.conditions === "object") {
        const cond = r.conditions as Record<string, unknown>;
        if (cond.args_match && typeof cond.args_match === "object") {
          rule.conditions = {
            args_match: Object.fromEntries(
              Object.entries(cond.args_match as Record<string, unknown>).map(([k, v]) => [k, String(v)])
            ),
          };
        }
      }
      if (r.rate_limit && typeof r.rate_limit === "object") {
        const rl = r.rate_limit as Record<string, unknown>;
        const maxCalls = Number(rl.max_calls ?? 100);
        const windowSeconds = Number(rl.window_seconds ?? 60);
        if (maxCalls <= 0 || !Number.isFinite(maxCalls)) {
          throw new Error(`Invalid rate_limit.max_calls (${maxCalls}) for tool "${rule.tool}". Must be a positive number.`);
        }
        if (windowSeconds <= 0 || !Number.isFinite(windowSeconds)) {
          throw new Error(`Invalid rate_limit.window_seconds (${windowSeconds}) for tool "${rule.tool}". Must be a positive number.`);
        }
        rule.rate_limit = {
          max_calls: maxCalls,
          window_seconds: windowSeconds,
        };
      }
      return rule;
    });
  }

  // Parse redaction
  if (raw.redaction && typeof raw.redaction === "object") {
    const red = raw.redaction as Record<string, unknown>;
    if (red.patterns && Array.isArray(red.patterns)) {
      config.redaction = {
        patterns: (red.patterns as unknown[]).map((p) => String(p)),
      };
    }
  }

  // Parse audit
  if (raw.audit && typeof raw.audit === "object") {
    const aud = raw.audit as Record<string, unknown>;
    config.audit = {
      file: aud.file !== undefined ? String(aud.file) : DEFAULT_CONFIG.audit.file,
      log_args: aud.log_args !== undefined ? Boolean(aud.log_args) : DEFAULT_CONFIG.audit.log_args,
      log_results: aud.log_results !== undefined ? Boolean(aud.log_results) : DEFAULT_CONFIG.audit.log_results,
    };
  }

  return config;
}

/**
 * Loads a guardian config from a YAML file path.
 */
export function loadConfig(filePath: string): GuardianConfig {
  const resolved = path.resolve(filePath);
  if (!fs.existsSync(resolved)) {
    throw new Error(`Config file not found: ${resolved}`);
  }
  const content = fs.readFileSync(resolved, "utf-8");
  const raw = parseSimpleYaml(content) as Record<string, unknown>;
  return validateConfig(raw);
}

/**
 * Tries to load config from a path; returns default config on failure.
 */
export function loadConfigSafe(filePath?: string): GuardianConfig {
  if (!filePath) return { ...DEFAULT_CONFIG };
  try {
    return loadConfig(filePath);
  } catch {
    process.stderr.write(`[mcp-guardian] Warning: Could not load config from ${filePath}, using defaults\n`);
    return { ...DEFAULT_CONFIG };
  }
}
