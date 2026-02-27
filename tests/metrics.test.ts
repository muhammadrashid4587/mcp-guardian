import { describe, it, expect, beforeEach } from 'vitest'
import { MetricsCollector } from '../src/metrics'

describe('MetricsCollector', () => {
  let metrics: MetricsCollector

  beforeEach(() => {
    metrics = new MetricsCollector()
  })

  it('starts with zero counts', () => {
    const snap = metrics.getSnapshot()
    expect(snap.total_requests).toBe(0)
    expect(snap.allowed).toBe(0)
    expect(snap.denied).toBe(0)
    expect(snap.rate_limited).toBe(0)
    expect(snap.errors).toBe(0)
    expect(snap.requests_per_minute).toBe(0)
  })

  it('records allowed events', () => {
    metrics.record('read_file', 'allow', 10)
    metrics.record('read_file', 'allow', 20)
    const snap = metrics.getSnapshot()
    expect(snap.total_requests).toBe(2)
    expect(snap.allowed).toBe(2)
    expect(snap.denied).toBe(0)
  })

  it('records denied events', () => {
    metrics.record('exec_command', 'deny', 1, 'deny_exec_*')
    const snap = metrics.getSnapshot()
    expect(snap.denied).toBe(1)
    expect(snap.per_tool['exec_command'].denied).toBe(1)
  })

  it('records rate-limited events', () => {
    metrics.record('http_get', 'rate_limit', 0)
    const snap = metrics.getSnapshot()
    expect(snap.rate_limited).toBe(1)
    expect(snap.per_tool['http_get'].denied).toBe(1)
  })

  it('records error events', () => {
    metrics.record('broken_tool', 'error', 0)
    const snap = metrics.getSnapshot()
    expect(snap.errors).toBe(1)
  })

  it('tracks per-tool statistics', () => {
    metrics.record('read_file', 'allow', 10)
    metrics.record('read_file', 'allow', 30)
    metrics.record('write_file', 'allow', 50)

    const snap = metrics.getSnapshot()
    expect(snap.per_tool['read_file'].calls).toBe(2)
    expect(snap.per_tool['read_file'].avg_latency_ms).toBe(20)
    expect(snap.per_tool['write_file'].calls).toBe(1)
    expect(snap.per_tool['write_file'].avg_latency_ms).toBe(50)
  })

  it('tracks per-rule match counts', () => {
    metrics.record('read_file', 'allow', 10, 'allow_read_*')
    metrics.record('read_dir', 'allow', 5, 'allow_read_*')
    metrics.record('exec_cmd', 'deny', 1, 'deny_exec')

    const snap = metrics.getSnapshot()
    expect(snap.per_rule['allow_read_*']).toBe(2)
    expect(snap.per_rule['deny_exec']).toBe(1)
  })

  it('calculates requests per minute', () => {
    for (let i = 0; i < 10; i++) {
      metrics.record('tool', 'allow', 1)
    }
    const snap = metrics.getSnapshot()
    expect(snap.requests_per_minute).toBe(10)
  })

  it('tracks uptime', () => {
    const snap = metrics.getSnapshot()
    expect(snap.uptime_ms).toBeGreaterThanOrEqual(0)
    expect(snap.uptime_ms).toBeLessThan(1000)
  })

  it('serializes to JSON', () => {
    metrics.record('tool', 'allow', 5)
    const json = metrics.toJSON()
    const parsed = JSON.parse(json)
    expect(parsed.total_requests).toBe(1)
    expect(parsed.per_tool.tool.calls).toBe(1)
  })

  it('resets all metrics', () => {
    metrics.record('a', 'allow', 10)
    metrics.record('b', 'deny', 5)
    metrics.reset()

    const snap = metrics.getSnapshot()
    expect(snap.total_requests).toBe(0)
    expect(snap.allowed).toBe(0)
    expect(snap.denied).toBe(0)
    expect(Object.keys(snap.per_tool)).toHaveLength(0)
    expect(Object.keys(snap.per_rule)).toHaveLength(0)
  })

  it('handles no matched rule gracefully', () => {
    metrics.record('tool', 'allow', 10)
    const snap = metrics.getSnapshot()
    expect(Object.keys(snap.per_rule)).toHaveLength(0)
  })

  it('handles mixed actions for same tool', () => {
    metrics.record('http_get', 'allow', 100)
    metrics.record('http_get', 'allow', 200)
    metrics.record('http_get', 'deny', 1)
    metrics.record('http_get', 'rate_limit', 0)

    const snap = metrics.getSnapshot()
    const tool = snap.per_tool['http_get']
    expect(tool.calls).toBe(4)
    expect(tool.denied).toBe(2)
    expect(tool.avg_latency_ms).toBeCloseTo(75.25)
  })
})
