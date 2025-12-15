/**
 * Audit Logger
 *
 * Structured audit logging with correlation IDs and compliance-ready format.
 * Stores entries in memory for querying.
 */

export interface AuditEntry {
  id: string;
  timestamp: number;
  correlationId: string;
  type: 'request' | 'response' | 'security_event' | 'system';
  level: 'debug' | 'info' | 'warn' | 'error';
  tool?: string;
  action?: string;
  userId?: string;
  sessionId?: string;
  sourceIp?: string;
  layer?: number;
  duration?: number;
  success?: boolean;
  message: string;
  metadata?: Record<string, unknown>;
}

export interface AuditQuery {
  startTime?: number;
  endTime?: number;
  type?: AuditEntry['type'];
  level?: AuditEntry['level'];
  tool?: string;
  correlationId?: string;
  success?: boolean;
  limit?: number;
  offset?: number;
}

// In-memory audit log storage
const entries: AuditEntry[] = [];
let maxEntries = parseInt(process.env.MAX_AUDIT_ENTRIES || '10000', 10);
let idCounter = 0;

/**
 * Generate a unique ID
 */
function generateId(): string {
  idCounter++;
  return `audit-${Date.now()}-${idCounter}`;
}

/**
 * Generate a correlation ID for request tracking
 */
export function generateCorrelationId(): string {
  return `corr-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

/**
 * Log an audit entry
 */
export function logAudit(entry: Omit<AuditEntry, 'id' | 'timestamp'>): AuditEntry {
  const fullEntry: AuditEntry = {
    ...entry,
    id: generateId(),
    timestamp: Date.now(),
  };

  entries.push(fullEntry);

  // Trim old entries if over limit
  while (entries.length > maxEntries) {
    entries.shift();
  }

  return fullEntry;
}

/**
 * Log a request
 */
export function logRequest(
  correlationId: string,
  tool: string,
  args?: Record<string, unknown>
): AuditEntry {
  return logAudit({
    correlationId,
    type: 'request',
    level: 'info',
    tool,
    action: 'tool_call',
    message: `Tool call: ${tool}`,
    metadata: args ? { args: sanitizeArgs(args) } : undefined,
  });
}

/**
 * Log a response
 */
export function logResponse(
  correlationId: string,
  tool: string,
  success: boolean,
  duration: number,
  error?: string
): AuditEntry {
  return logAudit({
    correlationId,
    type: 'response',
    level: success ? 'info' : 'error',
    tool,
    action: 'tool_response',
    success,
    duration,
    message: success ? `Tool completed: ${tool}` : `Tool failed: ${tool} - ${error}`,
    metadata: error ? { error } : undefined,
  });
}

/**
 * Log a security event
 */
export function logSecurityEvent(
  correlationId: string,
  layer: number,
  blocked: boolean,
  reason?: string,
  violationType?: string
): AuditEntry {
  return logAudit({
    correlationId,
    type: 'security_event',
    level: blocked ? 'warn' : 'debug',
    layer,
    action: blocked ? 'blocked' : 'allowed',
    success: !blocked,
    message: blocked
      ? `Request blocked at Layer ${layer}: ${reason}`
      : `Request passed Layer ${layer}`,
    metadata: { violationType, reason },
  });
}

/**
 * Log a system event
 */
export function logSystem(level: AuditEntry['level'], message: string, metadata?: Record<string, unknown>): AuditEntry {
  return logAudit({
    correlationId: 'system',
    type: 'system',
    level,
    action: 'system_event',
    message,
    metadata,
  });
}

/**
 * Query audit entries
 */
export function queryAuditLog(query: AuditQuery): {
  entries: AuditEntry[];
  total: number;
  hasMore: boolean;
} {
  let filtered = [...entries];

  // Apply filters
  if (query.startTime !== undefined) {
    filtered = filtered.filter((e) => e.timestamp >= query.startTime!);
  }
  if (query.endTime !== undefined) {
    filtered = filtered.filter((e) => e.timestamp <= query.endTime!);
  }
  if (query.type !== undefined) {
    filtered = filtered.filter((e) => e.type === query.type);
  }
  if (query.level !== undefined) {
    filtered = filtered.filter((e) => e.level === query.level);
  }
  if (query.tool !== undefined) {
    filtered = filtered.filter((e) => e.tool === query.tool);
  }
  if (query.correlationId !== undefined) {
    filtered = filtered.filter((e) => e.correlationId === query.correlationId);
  }
  if (query.success !== undefined) {
    filtered = filtered.filter((e) => e.success === query.success);
  }

  // Sort by timestamp descending (newest first)
  filtered.sort((a, b) => b.timestamp - a.timestamp);

  const total = filtered.length;
  const offset = query.offset || 0;
  const limit = query.limit || 100;

  const result = filtered.slice(offset, offset + limit);
  const hasMore = offset + limit < total;

  return { entries: result, total, hasMore };
}

/**
 * Get audit statistics
 */
export function getAuditStats() {
  const now = Date.now();
  const lastHour = now - 3600000;
  const last24h = now - 86400000;

  const hourEntries = entries.filter((e) => e.timestamp > lastHour);
  const dayEntries = entries.filter((e) => e.timestamp > last24h);

  const byType = new Map<string, number>();
  const byLevel = new Map<string, number>();
  const byTool = new Map<string, number>();

  for (const entry of entries) {
    byType.set(entry.type, (byType.get(entry.type) || 0) + 1);
    byLevel.set(entry.level, (byLevel.get(entry.level) || 0) + 1);
    if (entry.tool) {
      byTool.set(entry.tool, (byTool.get(entry.tool) || 0) + 1);
    }
  }

  return {
    totalEntries: entries.length,
    lastHourEntries: hourEntries.length,
    last24hEntries: dayEntries.length,
    oldestEntry: entries.length > 0 ? entries[0].timestamp : null,
    newestEntry: entries.length > 0 ? entries[entries.length - 1].timestamp : null,
    byType: Object.fromEntries(byType),
    byLevel: Object.fromEntries(byLevel),
    byTool: Object.fromEntries(byTool),
  };
}

/**
 * Export audit log in JSON format
 */
export function exportAuditLog(query?: AuditQuery): string {
  const result = query ? queryAuditLog(query) : { entries, total: entries.length, hasMore: false };
  return JSON.stringify(result, null, 2);
}

/**
 * Clear all audit entries
 */
export function clearAuditLog(): void {
  entries.length = 0;
  idCounter = 0;
}

/**
 * Sanitize arguments for logging (remove sensitive data)
 */
function sanitizeArgs(args: Record<string, unknown>): Record<string, unknown> {
  const sanitized: Record<string, unknown> = {};
  const sensitiveKeys = ['password', 'secret', 'token', 'key', 'credential', 'auth'];

  for (const [key, value] of Object.entries(args)) {
    const lowerKey = key.toLowerCase();
    if (sensitiveKeys.some((sk) => lowerKey.includes(sk))) {
      sanitized[key] = '[REDACTED]';
    } else if (typeof value === 'string' && value.length > 200) {
      sanitized[key] = value.slice(0, 200) + '...[truncated]';
    } else {
      sanitized[key] = value;
    }
  }

  return sanitized;
}

// Seed with demo data
export function seedDemoAuditData(): void {
  const now = Date.now();
  const tools = ['query-users', 'read-file', 'git-status', 'weather-forecast'];
  const types: AuditEntry['type'][] = ['request', 'response', 'security_event'];
  const levels: AuditEntry['level'][] = ['debug', 'info', 'warn', 'error'];

  for (let i = 0; i < 200; i++) {
    const timestamp = now - Math.random() * 3600000;
    const tool = tools[Math.floor(Math.random() * tools.length)];
    const type = types[Math.floor(Math.random() * types.length)];
    const level = type === 'security_event' ? 'warn' : levels[Math.floor(Math.random() * 3)];
    const correlationId = `corr-${Math.floor(timestamp / 1000)}-${Math.random().toString(36).slice(2, 6)}`;

    entries.push({
      id: `audit-${timestamp}-${i}`,
      timestamp,
      correlationId,
      type,
      level,
      tool,
      action: type === 'request' ? 'tool_call' : type === 'response' ? 'tool_response' : 'blocked',
      success: Math.random() > 0.1,
      duration: type === 'response' ? Math.floor(Math.random() * 200) : undefined,
      layer: type === 'security_event' ? Math.floor(Math.random() * 5) + 1 : undefined,
      message: type === 'request' ? `Tool call: ${tool}` : type === 'response' ? `Tool completed: ${tool}` : `Security check at Layer ${Math.floor(Math.random() * 5) + 1}`,
    });
  }

  // Sort by timestamp
  entries.sort((a, b) => a.timestamp - b.timestamp);
}
