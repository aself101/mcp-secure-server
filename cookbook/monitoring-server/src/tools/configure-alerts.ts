/**
 * Configure Alerts Tool
 *
 * Manage alert rules and channels.
 * Supports adding, updating, deleting, and listing alert configurations.
 */

import { z } from 'zod';
import {
  addAlertRule,
  updateAlertRule,
  deleteAlertRule,
  getAlertRules,
  getAlertChannels,
  getAlertHistory,
  getAlertStats,
  type AlertRule,
} from '../utils/index.js';

export const configureAlertsSchema = z.object({
  action: z
    .enum(['list', 'add', 'update', 'delete', 'history', 'stats'])
    .describe('Action to perform'),
  ruleId: z
    .string()
    .max(100)
    .optional()
    .describe('Rule ID (required for update/delete)'),
  rule: z
    .object({
      name: z.string().min(1).max(100),
      enabled: z.boolean().default(true),
      condition: z.object({
        metric: z.enum(['violations', 'rate_limit_hits', 'error_rate', 'latency_p99']),
        operator: z.enum(['>', '<', '>=', '<=', '==']),
        threshold: z.number(),
        windowMs: z.number().int().min(1000).max(86400000),
      }),
      severity: z.enum(['info', 'warning', 'critical']),
      channels: z.array(z.string()).min(1),
      cooldownMs: z.number().int().min(0).default(300000),
    })
    .optional()
    .describe('Rule configuration (required for add/update)'),
  historyLimit: z
    .number()
    .int()
    .min(1)
    .max(500)
    .default(50)
    .describe('Number of history entries to return'),
});

export type ConfigureAlertsArgs = z.infer<typeof configureAlertsSchema>;

export interface ConfigureAlertsResult {
  content: Array<{ type: 'text'; text: string }>;
}

export async function configureAlerts(
  args: ConfigureAlertsArgs
): Promise<ConfigureAlertsResult> {
  let result: Record<string, unknown>;

  switch (args.action) {
    case 'list': {
      const rules = getAlertRules();
      const channels = getAlertChannels();
      result = {
        success: true,
        action: 'list',
        rules: rules.map(formatRule),
        channels: channels.map((c) => ({
          id: c.id,
          name: c.name,
          type: c.type,
          enabled: c.enabled,
        })),
      };
      break;
    }

    case 'add': {
      if (!args.rule) {
        result = {
          success: false,
          error: 'Rule configuration required for add action',
        };
        break;
      }

      const newRule = addAlertRule(args.rule);
      result = {
        success: true,
        action: 'add',
        rule: formatRule(newRule),
        message: `Alert rule '${newRule.name}' created successfully`,
      };
      break;
    }

    case 'update': {
      if (!args.ruleId) {
        result = {
          success: false,
          error: 'Rule ID required for update action',
        };
        break;
      }

      const updated = updateAlertRule(args.ruleId, args.rule || {});
      if (!updated) {
        result = {
          success: false,
          error: `Rule '${args.ruleId}' not found`,
        };
        break;
      }

      result = {
        success: true,
        action: 'update',
        rule: formatRule(updated),
        message: `Alert rule '${updated.name}' updated successfully`,
      };
      break;
    }

    case 'delete': {
      if (!args.ruleId) {
        result = {
          success: false,
          error: 'Rule ID required for delete action',
        };
        break;
      }

      const deleted = deleteAlertRule(args.ruleId);
      result = {
        success: deleted,
        action: 'delete',
        ruleId: args.ruleId,
        message: deleted
          ? `Alert rule '${args.ruleId}' deleted successfully`
          : `Rule '${args.ruleId}' not found`,
      };
      break;
    }

    case 'history': {
      const history = getAlertHistory(args.historyLimit);
      result = {
        success: true,
        action: 'history',
        alerts: history.map((a) => ({
          ...a,
          timestampFormatted: new Date(a.timestamp).toISOString(),
        })),
        count: history.length,
      };
      break;
    }

    case 'stats': {
      const stats = getAlertStats();
      result = {
        success: true,
        action: 'stats',
        statistics: stats,
      };
      break;
    }

    default:
      result = {
        success: false,
        error: `Unknown action: ${args.action}`,
      };
  }

  return {
    content: [{
      type: 'text',
      text: JSON.stringify(result, null, 2),
    }],
  };
}

/**
 * Format rule for output
 */
function formatRule(rule: AlertRule): Record<string, unknown> {
  return {
    id: rule.id,
    name: rule.name,
    enabled: rule.enabled,
    condition: {
      metric: rule.condition.metric,
      operator: rule.condition.operator,
      threshold: rule.condition.threshold,
      windowMs: rule.condition.windowMs,
      windowFormatted: formatDuration(rule.condition.windowMs),
    },
    severity: rule.severity,
    channels: rule.channels,
    cooldownMs: rule.cooldownMs,
    cooldownFormatted: formatDuration(rule.cooldownMs),
    triggerCount: rule.triggerCount,
    lastTriggered: rule.lastTriggered
      ? new Date(rule.lastTriggered).toISOString()
      : null,
    createdAt: new Date(rule.createdAt).toISOString(),
  };
}

/**
 * Format duration in human-readable form
 */
function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${Math.floor(ms / 1000)}s`;
  if (ms < 3600000) return `${Math.floor(ms / 60000)}m`;
  return `${Math.floor(ms / 3600000)}h`;
}
