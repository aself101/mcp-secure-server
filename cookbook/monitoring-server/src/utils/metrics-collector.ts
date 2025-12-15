/**
 * Metrics Collector
 *
 * Collects and stores security metrics in memory.
 * Provides aggregation, histograms, and Prometheus export.
 */

export interface SecurityEvent {
  timestamp: number;
  type: 'violation' | 'rate_limit' | 'success' | 'error';
  layer?: number;
  tool?: string;
  severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  violationType?: string;
  details?: string;
}

export interface LayerMetrics {
  totalRequests: number;
  blocked: number;
  latencySum: number;
  latencyCount: number;
  latencyHistogram: number[];
}

export interface ToolMetrics {
  totalCalls: number;
  successes: number;
  failures: number;
  latencySum: number;
  latencyCount: number;
  quotaUsed: number;
  quotaLimit: number;
}

interface MetricsState {
  events: SecurityEvent[];
  layers: Map<number, LayerMetrics>;
  tools: Map<string, ToolMetrics>;
  startTime: number;
  violationsByType: Map<string, number>;
  violationsBySeverity: Map<string, number>;
}

// Histogram buckets for latency (in ms)
const LATENCY_BUCKETS = [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000];

// In-memory metrics storage
const state: MetricsState = {
  events: [],
  layers: new Map(),
  tools: new Map(),
  startTime: Date.now(),
  violationsByType: new Map(),
  violationsBySeverity: new Map(),
};

// Configuration
let retentionMs = parseInt(process.env.METRICS_RETENTION_MS || '3600000', 10);

/**
 * Initialize layer metrics
 */
function getLayerMetrics(layer: number): LayerMetrics {
  if (!state.layers.has(layer)) {
    state.layers.set(layer, {
      totalRequests: 0,
      blocked: 0,
      latencySum: 0,
      latencyCount: 0,
      latencyHistogram: new Array(LATENCY_BUCKETS.length + 1).fill(0),
    });
  }
  return state.layers.get(layer)!;
}

/**
 * Initialize tool metrics
 */
function getToolMetrics(tool: string): ToolMetrics {
  if (!state.tools.has(tool)) {
    state.tools.set(tool, {
      totalCalls: 0,
      successes: 0,
      failures: 0,
      latencySum: 0,
      latencyCount: 0,
      quotaUsed: 0,
      quotaLimit: 60,
    });
  }
  return state.tools.get(tool)!;
}

/**
 * Record a security event
 */
export function recordEvent(event: Omit<SecurityEvent, 'timestamp'>): void {
  const fullEvent: SecurityEvent = {
    ...event,
    timestamp: Date.now(),
  };

  state.events.push(fullEvent);

  // Update violation counters
  if (event.type === 'violation') {
    if (event.violationType) {
      const count = state.violationsByType.get(event.violationType) || 0;
      state.violationsByType.set(event.violationType, count + 1);
    }
    if (event.severity) {
      const count = state.violationsBySeverity.get(event.severity) || 0;
      state.violationsBySeverity.set(event.severity, count + 1);
    }
  }

  // Cleanup old events
  cleanupOldEvents();
}

/**
 * Record layer processing
 */
export function recordLayerMetrics(
  layer: number,
  latencyMs: number,
  blocked: boolean
): void {
  const metrics = getLayerMetrics(layer);
  metrics.totalRequests++;
  if (blocked) metrics.blocked++;
  metrics.latencySum += latencyMs;
  metrics.latencyCount++;

  // Update histogram
  const bucketIndex = LATENCY_BUCKETS.findIndex((b) => latencyMs <= b);
  if (bucketIndex === -1) {
    metrics.latencyHistogram[LATENCY_BUCKETS.length]++;
  } else {
    metrics.latencyHistogram[bucketIndex]++;
  }
}

/**
 * Record tool call
 */
export function recordToolCall(
  tool: string,
  latencyMs: number,
  success: boolean
): void {
  const metrics = getToolMetrics(tool);
  metrics.totalCalls++;
  if (success) {
    metrics.successes++;
  } else {
    metrics.failures++;
  }
  metrics.latencySum += latencyMs;
  metrics.latencyCount++;
  metrics.quotaUsed++;
}

/**
 * Update tool quota info
 */
export function updateToolQuota(tool: string, used: number, limit: number): void {
  const metrics = getToolMetrics(tool);
  metrics.quotaUsed = used;
  metrics.quotaLimit = limit;
}

/**
 * Get current metrics snapshot
 */
export function getMetrics() {
  const now = Date.now();
  const uptimeMs = now - state.startTime;

  // Calculate per-layer stats
  const layerStats: Record<number, {
    totalRequests: number;
    blocked: number;
    blockRate: number;
    avgLatencyMs: number;
    p50LatencyMs: number;
    p95LatencyMs: number;
    p99LatencyMs: number;
  }> = {};

  for (const [layer, metrics] of state.layers) {
    const avgLatency = metrics.latencyCount > 0
      ? metrics.latencySum / metrics.latencyCount
      : 0;

    layerStats[layer] = {
      totalRequests: metrics.totalRequests,
      blocked: metrics.blocked,
      blockRate: metrics.totalRequests > 0
        ? metrics.blocked / metrics.totalRequests
        : 0,
      avgLatencyMs: Math.round(avgLatency * 100) / 100,
      p50LatencyMs: calculatePercentile(metrics.latencyHistogram, 50),
      p95LatencyMs: calculatePercentile(metrics.latencyHistogram, 95),
      p99LatencyMs: calculatePercentile(metrics.latencyHistogram, 99),
    };
  }

  // Calculate per-tool stats
  const toolStats: Record<string, {
    totalCalls: number;
    successRate: number;
    avgLatencyMs: number;
    quotaUsed: number;
    quotaLimit: number;
    quotaPercent: number;
  }> = {};

  for (const [tool, metrics] of state.tools) {
    const avgLatency = metrics.latencyCount > 0
      ? metrics.latencySum / metrics.latencyCount
      : 0;

    toolStats[tool] = {
      totalCalls: metrics.totalCalls,
      successRate: metrics.totalCalls > 0
        ? metrics.successes / metrics.totalCalls
        : 1,
      avgLatencyMs: Math.round(avgLatency * 100) / 100,
      quotaUsed: metrics.quotaUsed,
      quotaLimit: metrics.quotaLimit,
      quotaPercent: metrics.quotaLimit > 0
        ? (metrics.quotaUsed / metrics.quotaLimit) * 100
        : 0,
    };
  }

  // Recent events (last 100)
  const recentEvents = state.events.slice(-100);

  return {
    timestamp: now,
    uptimeMs,
    uptimeFormatted: formatUptime(uptimeMs),
    summary: {
      totalEvents: state.events.length,
      totalViolations: Array.from(state.violationsByType.values()).reduce((a, b) => a + b, 0),
      violationsByType: Object.fromEntries(state.violationsByType),
      violationsBySeverity: Object.fromEntries(state.violationsBySeverity),
    },
    layers: layerStats,
    tools: toolStats,
    recentEvents,
  };
}

/**
 * Get top blocked patterns
 */
export function getTopBlockedPatterns(limit: number = 10) {
  const sorted = Array.from(state.violationsByType.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit);

  return sorted.map(([type, count]) => ({ type, count }));
}

/**
 * Reset all metrics
 */
export function resetMetrics(): void {
  state.events = [];
  state.layers.clear();
  state.tools.clear();
  state.startTime = Date.now();
  state.violationsByType.clear();
  state.violationsBySeverity.clear();
}

/**
 * Cleanup events older than retention period
 */
function cleanupOldEvents(): void {
  const cutoff = Date.now() - retentionMs;
  state.events = state.events.filter((e) => e.timestamp > cutoff);
}

/**
 * Calculate percentile from histogram
 */
function calculatePercentile(histogram: number[], percentile: number): number {
  const total = histogram.reduce((a, b) => a + b, 0);
  if (total === 0) return 0;

  const target = (percentile / 100) * total;
  let cumulative = 0;

  for (let i = 0; i < histogram.length; i++) {
    cumulative += histogram[i];
    if (cumulative >= target) {
      return i < LATENCY_BUCKETS.length ? LATENCY_BUCKETS[i] : LATENCY_BUCKETS[LATENCY_BUCKETS.length - 1];
    }
  }

  return LATENCY_BUCKETS[LATENCY_BUCKETS.length - 1];
}

/**
 * Format uptime as human-readable string
 */
function formatUptime(ms: number): string {
  const seconds = Math.floor(ms / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (days > 0) return `${days}d ${hours % 24}h ${minutes % 60}m`;
  if (hours > 0) return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
  if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
  return `${seconds}s`;
}

// Seed with simulated data for demo purposes
export function seedDemoData(): void {
  const now = Date.now();
  const oneHourAgo = now - 3600000;

  // Simulate some events over the past hour
  const eventTypes: Array<SecurityEvent['type']> = ['success', 'success', 'success', 'violation', 'rate_limit'];
  const violationTypes = ['SQL_INJECTION', 'PATH_TRAVERSAL', 'COMMAND_INJECTION', 'XSS', 'RATE_LIMIT_EXCEEDED'];
  const severities: Array<SecurityEvent['severity']> = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  const tools = ['query-users', 'read-file', 'git-status', 'weather-forecast'];

  for (let i = 0; i < 500; i++) {
    const timestamp = oneHourAgo + Math.random() * 3600000;
    const type = eventTypes[Math.floor(Math.random() * eventTypes.length)];
    const tool = tools[Math.floor(Math.random() * tools.length)];

    const event: SecurityEvent = {
      timestamp,
      type,
      tool,
      layer: Math.floor(Math.random() * 5) + 1,
    };

    if (type === 'violation') {
      event.violationType = violationTypes[Math.floor(Math.random() * violationTypes.length)];
      event.severity = severities[Math.floor(Math.random() * severities.length)];
    }

    state.events.push(event);

    // Update counters
    if (type === 'violation' && event.violationType) {
      const count = state.violationsByType.get(event.violationType) || 0;
      state.violationsByType.set(event.violationType, count + 1);
    }
    if (type === 'violation' && event.severity) {
      const count = state.violationsBySeverity.get(event.severity) || 0;
      state.violationsBySeverity.set(event.severity, count + 1);
    }
  }

  // Seed layer metrics
  for (let layer = 1; layer <= 5; layer++) {
    const metrics = getLayerMetrics(layer);
    metrics.totalRequests = Math.floor(Math.random() * 1000) + 500;
    metrics.blocked = Math.floor(metrics.totalRequests * (Math.random() * 0.1));
    metrics.latencySum = metrics.totalRequests * (Math.random() * 10 + 5);
    metrics.latencyCount = metrics.totalRequests;

    // Populate histogram
    for (let i = 0; i < metrics.totalRequests; i++) {
      const latency = Math.random() * 50;
      const bucketIndex = LATENCY_BUCKETS.findIndex((b) => latency <= b);
      if (bucketIndex === -1) {
        metrics.latencyHistogram[LATENCY_BUCKETS.length]++;
      } else {
        metrics.latencyHistogram[bucketIndex]++;
      }
    }
  }

  // Seed tool metrics
  for (const tool of tools) {
    const metrics = getToolMetrics(tool);
    metrics.totalCalls = Math.floor(Math.random() * 200) + 50;
    metrics.successes = Math.floor(metrics.totalCalls * 0.95);
    metrics.failures = metrics.totalCalls - metrics.successes;
    metrics.latencySum = metrics.totalCalls * (Math.random() * 100 + 20);
    metrics.latencyCount = metrics.totalCalls;
    metrics.quotaUsed = Math.floor(Math.random() * 50);
    metrics.quotaLimit = 60;
  }
}
