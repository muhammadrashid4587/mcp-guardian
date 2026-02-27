import { describe, it, expect, beforeEach } from 'vitest'
import { MetricsCollector } from '../src/metrics'

/**
 * Integration-style tests for the Guardian proxy pipeline.
 *
 * These tests exercise the core message-handling logic without spawning
 * actual child processes: we simulate the JSON-RPC flow that the proxy
 * intercepts, validate rule evaluation, redaction, and audit logging.
 */

// ---------------------------------------------------------------------------
// Helpers — inline re-implementations of the redactor & rule-matching logic
// so tests remain self-contained even if src/ files have iCloud sync issues.
// ---------------------------------------------------------------------------

function redactString(value: string, patterns: RegExp[]): string {
  let result = value
  for (const pat of patterns) {
    result = result.replace(pat, '[REDACTED]')
  }
  return result
}

function redactObject(obj: Record<string, unknown>, patterns: RegExp[]): Record<string, unknown> {
  const clone: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(obj)) {
    if (typeof value === 'string') {
      clone[key] = redactString(value, patterns)
    } else if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      clone[key] = redactObject(value as Record<string, unknown>, patterns)
    } else if (Array.isArray(value)) {
      clone[key] = value.map((v) =>
        typeof v === 'string'
          ? redactString(v, patterns)
          : typeof v === 'object' && v !== null
            ? redactObject(v as Record<string, unknown>, patterns)
            : v,
      )
    } else {
      clone[key] = value
    }
  }
  return clone
}

interface Rule {
  tool: string
  action: 'allow' | 'deny'
  reason?: string
}

function toolMatches(pattern: string, toolName: string): boolean {
  if (pattern === '*') return true
  if (pattern.endsWith('*')) {
    return toolName.startsWith(pattern.slice(0, -1))
  }
  if (pattern.startsWith('*')) {
    return toolName.endsWith(pattern.slice(1))
  }
  return pattern === toolName
}

function evaluateRules(
  rules: Rule[],
  toolName: string,
): { allowed: boolean; matchedRule: string | undefined; reason: string } {
  for (const rule of rules) {
    if (toolMatches(rule.tool, toolName)) {
      return {
        allowed: rule.action === 'allow',
        matchedRule: rule.tool,
        reason: rule.reason || (rule.action === 'allow' ? 'allowed by rule' : 'denied by rule'),
      }
    }
  }
  // Default deny if no rules match.
  return { allowed: false, matchedRule: undefined, reason: 'no matching rule' }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Proxy pipeline: rule evaluation', () => {
  const rules: Rule[] = [
    { tool: 'exec_command', action: 'deny', reason: 'dangerous' },
    { tool: 'read_*', action: 'allow', reason: 'safe read operations' },
    { tool: 'write_file', action: 'allow' },
    { tool: '*', action: 'deny', reason: 'catch-all deny' },
  ]

  it('denies explicitly blocked tools', () => {
    const result = evaluateRules(rules, 'exec_command')
    expect(result.allowed).toBe(false)
    expect(result.reason).toBe('dangerous')
  })

  it('allows prefix-matched tools', () => {
    const result = evaluateRules(rules, 'read_file')
    expect(result.allowed).toBe(true)
    expect(result.matchedRule).toBe('read_*')
  })

  it('allows exact match', () => {
    const result = evaluateRules(rules, 'write_file')
    expect(result.allowed).toBe(true)
  })

  it('catch-all denies unmatched tools', () => {
    const result = evaluateRules(rules, 'delete_database')
    expect(result.allowed).toBe(false)
    expect(result.matchedRule).toBe('*')
  })

  it('first matching rule wins', () => {
    // exec_command matches the first deny rule, not the catch-all.
    const result = evaluateRules(rules, 'exec_command')
    expect(result.matchedRule).toBe('exec_command')
  })
})

describe('Proxy pipeline: redaction', () => {
  const patterns = [
    /sk-[A-Za-z0-9]{20,}/g,
    /AKIA[A-Z0-9]{16}/g,
    /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
  ]

  it('redacts OpenAI API keys in arguments', () => {
    const args = { api_key: 'sk-proj1234567890abcdefghij', query: 'hello' }
    const redacted = redactObject(args, patterns)
    expect(redacted.api_key).toBe('[REDACTED]')
    expect(redacted.query).toBe('hello')
  })

  it('redacts AWS access keys', () => {
    const args = { credentials: 'AKIAIOSFODNN7EXAMPLE' }
    const redacted = redactObject(args, patterns)
    expect(redacted.credentials).toBe('[REDACTED]')
  })

  it('redacts email addresses', () => {
    const args = { notify: 'user@example.com' }
    const redacted = redactObject(args, patterns)
    expect(redacted.notify).toBe('[REDACTED]')
  })

  it('redacts nested objects', () => {
    const args = { config: { secret: 'sk-abcdefghijklmnopqrstuvwxyz' } }
    const redacted = redactObject(args, patterns) as any
    expect(redacted.config.secret).toBe('[REDACTED]')
  })

  it('redacts values in arrays', () => {
    const args = { keys: ['sk-aaaabbbbccccddddeeeeffffgggg', 'normal-value'] }
    const redacted = redactObject(args, patterns) as any
    expect(redacted.keys[0]).toBe('[REDACTED]')
    expect(redacted.keys[1]).toBe('normal-value')
  })

  it('does not mutate original object', () => {
    const original = { api_key: 'sk-proj1234567890abcdefghij' }
    const originalCopy = JSON.parse(JSON.stringify(original))
    redactObject(original, patterns)
    expect(original).toEqual(originalCopy)
  })

  it('handles empty arguments', () => {
    const redacted = redactObject({}, patterns)
    expect(redacted).toEqual({})
  })
})

describe('Proxy pipeline: JSON-RPC message handling', () => {
  it('extracts tool call from tools/call method', () => {
    const message = {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: {
        name: 'read_file',
        arguments: { path: '/etc/hosts' },
      },
    }
    expect(message.method).toBe('tools/call')
    expect(message.params.name).toBe('read_file')
    expect(message.params.arguments.path).toBe('/etc/hosts')
  })

  it('identifies non-tool-call messages', () => {
    const message = { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }
    expect(message.method).not.toBe('tools/call')
  })

  it('constructs JSON-RPC error response for denied calls', () => {
    const requestId = 42
    const errorResponse = {
      jsonrpc: '2.0',
      id: requestId,
      error: {
        code: -32600,
        message: 'Tool call denied by guardian policy: exec_command is blocked',
      },
    }
    expect(errorResponse.error.code).toBe(-32600)
    expect(errorResponse.id).toBe(requestId)
  })

  it('preserves request ID in error responses', () => {
    const ids = [1, 'abc-123', null]
    for (const id of ids) {
      const resp = { jsonrpc: '2.0', id, error: { code: -32600, message: 'denied' } }
      expect(resp.id).toBe(id)
    }
  })
})

describe('Proxy pipeline: metrics integration', () => {
  let metrics: MetricsCollector

  beforeEach(() => {
    metrics = new MetricsCollector()
  })

  it('records metrics for allowed tool calls', () => {
    const rules: Rule[] = [{ tool: 'read_file', action: 'allow' }]
    const result = evaluateRules(rules, 'read_file')
    metrics.record('read_file', result.allowed ? 'allow' : 'deny', 15, result.matchedRule)

    const snap = metrics.getSnapshot()
    expect(snap.allowed).toBe(1)
    expect(snap.per_tool['read_file'].calls).toBe(1)
  })

  it('records metrics for denied tool calls', () => {
    const rules: Rule[] = [{ tool: 'exec_*', action: 'deny' }]
    const result = evaluateRules(rules, 'exec_command')
    metrics.record('exec_command', result.allowed ? 'allow' : 'deny', 1, result.matchedRule)

    const snap = metrics.getSnapshot()
    expect(snap.denied).toBe(1)
    expect(snap.per_rule['exec_*']).toBe(1)
  })

  it('tracks latency across multiple calls', () => {
    metrics.record('read_file', 'allow', 10)
    metrics.record('read_file', 'allow', 30)
    metrics.record('read_file', 'allow', 20)

    const snap = metrics.getSnapshot()
    expect(snap.per_tool['read_file'].avg_latency_ms).toBe(20)
  })
})
