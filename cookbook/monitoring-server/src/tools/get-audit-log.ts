/**
 * Get Audit Log Tool
 *
 * Query and retrieve audit log entries with filtering options.
 * Supports filtering by time range, type, level, tool, and more.
 */

import { z } from 'zod';
import { queryAuditLog, getAuditStats, type AuditQuery } from '../utils/index.js';

export const getAuditLogSchema = z.object({
  startTime: z
    .string()
    .optional()
    .describe('Start time (ISO 8601 format)'),
  endTime: z
    .string()
    .optional()
    .describe('End time (ISO 8601 format)'),
  type: z
    .enum(['request', 'response', 'security_event', 'system'])
    .optional()
    .describe('Filter by entry type'),
  level: z
    .enum(['debug', 'info', 'warn', 'error'])
    .optional()
    .describe('Filter by log level'),
  tool: z
    .string()
    .max(100)
    .optional()
    .describe('Filter by tool name'),
  correlationId: z
    .string()
    .max(100)
    .optional()
    .describe('Filter by correlation ID'),
  success: z
    .boolean()
    .optional()
    .describe('Filter by success status'),
  limit: z
    .number()
    .int()
    .min(1)
    .max(1000)
    .default(100)
    .describe('Maximum entries to return'),
  offset: z
    .number()
    .int()
    .min(0)
    .default(0)
    .describe('Offset for pagination'),
  includeStats: z
    .boolean()
    .default(false)
    .describe('Include audit log statistics'),
});

export type GetAuditLogArgs = z.infer<typeof getAuditLogSchema>;

export interface GetAuditLogResult {
  content: Array<{ type: 'text'; text: string }>;
}

export async function getAuditLog(args: GetAuditLogArgs): Promise<GetAuditLogResult> {
  const query: AuditQuery = {
    limit: args.limit,
    offset: args.offset,
  };

  // Parse time filters
  if (args.startTime) {
    const parsed = Date.parse(args.startTime);
    if (!isNaN(parsed)) {
      query.startTime = parsed;
    }
  }

  if (args.endTime) {
    const parsed = Date.parse(args.endTime);
    if (!isNaN(parsed)) {
      query.endTime = parsed;
    }
  }

  // Apply other filters
  if (args.type) query.type = args.type;
  if (args.level) query.level = args.level;
  if (args.tool) query.tool = args.tool;
  if (args.correlationId) query.correlationId = args.correlationId;
  if (args.success !== undefined) query.success = args.success;

  const result = queryAuditLog(query);

  const response: Record<string, unknown> = {
    entries: result.entries.map((entry) => ({
      ...entry,
      timestampFormatted: new Date(entry.timestamp).toISOString(),
    })),
    pagination: {
      total: result.total,
      returned: result.entries.length,
      offset: args.offset,
      limit: args.limit,
      hasMore: result.hasMore,
    },
  };

  if (args.includeStats) {
    response.statistics = getAuditStats();
  }

  return {
    content: [{
      type: 'text',
      text: JSON.stringify(response, null, 2),
    }],
  };
}
