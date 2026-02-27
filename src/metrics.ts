/**
 * Request metrics and statistics collector.
 *
 * Tracks operational metrics for monitoring: total requests, allow/deny/rate-limit
 * counts, per-tool latency, per-rule match counts, and a sliding-window
 * requests-per-minute counter.
 */

export interface PerToolStats {
  calls: number
  total_latency_ms: number
  avg_latency_ms: number
  denied: number
}

export interface MetricsSnapshot {
  uptime_ms: number
  total_requests: number
  allowed: number
  denied: number
  rate_limited: number
  errors: number
  per_tool: Record<string, PerToolStats>
  per_rule: Record<string, number>
  requests_per_minute: number
}

export class MetricsCollector {
  private startTime: number
  private totalRequests = 0
  private allowedCount = 0
  private deniedCount = 0
  private rateLimitedCount = 0
  private errorCount = 0
  private toolStats: Map<string, { calls: number; totalLatency: number; denied: number }> = new Map()
  private ruleMatchCounts: Map<string, number> = new Map()
  private requestTimestamps: number[] = []

  constructor() {
    this.startTime = Date.now()
  }

  /**
   * Record an event after evaluating a tool call.
   */
  record(
    tool: string,
    action: 'allow' | 'deny' | 'rate_limit' | 'error',
    latency_ms: number,
    matchedRule?: string,
  ): void {
    this.totalRequests++
    this.requestTimestamps.push(Date.now())

    switch (action) {
      case 'allow':
        this.allowedCount++
        break
      case 'deny':
        this.deniedCount++
        break
      case 'rate_limit':
        this.rateLimitedCount++
        break
      case 'error':
        this.errorCount++
        break
    }

    // Per-tool stats.
    let ts = this.toolStats.get(tool)
    if (!ts) {
      ts = { calls: 0, totalLatency: 0, denied: 0 }
      this.toolStats.set(tool, ts)
    }
    ts.calls++
    ts.totalLatency += latency_ms
    if (action === 'deny' || action === 'rate_limit') {
      ts.denied++
    }

    // Per-rule match counts.
    if (matchedRule) {
      const count = this.ruleMatchCounts.get(matchedRule) || 0
      this.ruleMatchCounts.set(matchedRule, count + 1)
    }

    // Prune old timestamps (keep last 5 minutes).
    const fiveMinAgo = Date.now() - 5 * 60 * 1000
    while (this.requestTimestamps.length > 0 && this.requestTimestamps[0] < fiveMinAgo) {
      this.requestTimestamps.shift()
    }
  }

  /**
   * Calculate requests per minute over the last 60 seconds.
   */
  private calcRequestsPerMinute(): number {
    const oneMinAgo = Date.now() - 60 * 1000
    let count = 0
    for (let i = this.requestTimestamps.length - 1; i >= 0; i--) {
      if (this.requestTimestamps[i] >= oneMinAgo) {
        count++
      } else {
        break
      }
    }
    return count
  }

  /**
   * Return a snapshot of all current metrics.
   */
  getSnapshot(): MetricsSnapshot {
    const perTool: Record<string, PerToolStats> = {}
    for (const [tool, stats] of this.toolStats) {
      perTool[tool] = {
        calls: stats.calls,
        total_latency_ms: stats.totalLatency,
        avg_latency_ms: stats.calls > 0 ? stats.totalLatency / stats.calls : 0,
        denied: stats.denied,
      }
    }

    const perRule: Record<string, number> = {}
    for (const [rule, count] of this.ruleMatchCounts) {
      perRule[rule] = count
    }

    return {
      uptime_ms: Date.now() - this.startTime,
      total_requests: this.totalRequests,
      allowed: this.allowedCount,
      denied: this.deniedCount,
      rate_limited: this.rateLimitedCount,
      errors: this.errorCount,
      per_tool: perTool,
      per_rule: perRule,
      requests_per_minute: this.calcRequestsPerMinute(),
    }
  }

  /**
   * Serialize current metrics to JSON.
   */
  toJSON(): string {
    return JSON.stringify(this.getSnapshot(), null, 2)
  }

  /**
   * Reset all metrics.
   */
  reset(): void {
    this.totalRequests = 0
    this.allowedCount = 0
    this.deniedCount = 0
    this.rateLimitedCount = 0
    this.errorCount = 0
    this.toolStats.clear()
    this.ruleMatchCounts.clear()
    this.requestTimestamps = []
    this.startTime = Date.now()
  }
}
