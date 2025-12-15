/**
 * Alert Manager
 *
 * Manages alert rules and triggers notifications.
 * Supports webhook integrations (Slack, Discord, PagerDuty style).
 */

export interface AlertRule {
  id: string;
  name: string;
  enabled: boolean;
  condition: {
    metric: 'violations' | 'rate_limit_hits' | 'error_rate' | 'latency_p99';
    operator: '>' | '<' | '>=' | '<=' | '==';
    threshold: number;
    windowMs: number;
  };
  severity: 'info' | 'warning' | 'critical';
  channels: string[];
  cooldownMs: number;
  lastTriggered?: number;
  triggerCount: number;
  createdAt: number;
}

export interface AlertChannel {
  id: string;
  name: string;
  type: 'webhook' | 'console' | 'memory';
  config: {
    url?: string;
    headers?: Record<string, string>;
  };
  enabled: boolean;
}

export interface AlertEvent {
  id: string;
  ruleId: string;
  ruleName: string;
  timestamp: number;
  severity: AlertRule['severity'];
  message: string;
  currentValue: number;
  threshold: number;
  channels: string[];
  delivered: boolean;
}

// In-memory storage
const rules: Map<string, AlertRule> = new Map();
const channels: Map<string, AlertChannel> = new Map();
const alertHistory: AlertEvent[] = [];
let idCounter = 0;

/**
 * Generate unique ID
 */
function generateId(prefix: string): string {
  idCounter++;
  return `${prefix}-${Date.now()}-${idCounter}`;
}

/**
 * Initialize default channels
 */
function initializeDefaults(): void {
  // Console channel (always available)
  channels.set('console', {
    id: 'console',
    name: 'Console Output',
    type: 'console',
    config: {},
    enabled: true,
  });

  // Memory channel (for retrieval via API)
  channels.set('memory', {
    id: 'memory',
    name: 'In-Memory History',
    type: 'memory',
    config: {},
    enabled: true,
  });

  // Webhook channel (configurable)
  const webhookUrl = process.env.ALERT_WEBHOOK_URL;
  if (webhookUrl) {
    channels.set('webhook', {
      id: 'webhook',
      name: 'Webhook',
      type: 'webhook',
      config: { url: webhookUrl },
      enabled: true,
    });
  }
}

// Initialize defaults on load
initializeDefaults();

/**
 * Add a new alert rule
 */
export function addAlertRule(rule: Omit<AlertRule, 'id' | 'triggerCount' | 'createdAt'>): AlertRule {
  const fullRule: AlertRule = {
    ...rule,
    id: generateId('rule'),
    triggerCount: 0,
    createdAt: Date.now(),
  };

  rules.set(fullRule.id, fullRule);
  return fullRule;
}

/**
 * Update an existing rule
 */
export function updateAlertRule(id: string, updates: Partial<AlertRule>): AlertRule | null {
  const rule = rules.get(id);
  if (!rule) return null;

  const updated = { ...rule, ...updates, id }; // Prevent ID change
  rules.set(id, updated);
  return updated;
}

/**
 * Delete a rule
 */
export function deleteAlertRule(id: string): boolean {
  return rules.delete(id);
}

/**
 * Get all rules
 */
export function getAlertRules(): AlertRule[] {
  return Array.from(rules.values());
}

/**
 * Get a specific rule
 */
export function getAlertRule(id: string): AlertRule | undefined {
  return rules.get(id);
}

/**
 * Add an alert channel
 */
export function addAlertChannel(channel: Omit<AlertChannel, 'id'>): AlertChannel {
  const fullChannel: AlertChannel = {
    ...channel,
    id: generateId('channel'),
  };

  channels.set(fullChannel.id, fullChannel);
  return fullChannel;
}

/**
 * Get all channels
 */
export function getAlertChannels(): AlertChannel[] {
  return Array.from(channels.values());
}

/**
 * Check if an alert should fire based on current value
 */
function shouldTrigger(rule: AlertRule, currentValue: number): boolean {
  const { operator, threshold } = rule.condition;

  switch (operator) {
    case '>': return currentValue > threshold;
    case '<': return currentValue < threshold;
    case '>=': return currentValue >= threshold;
    case '<=': return currentValue <= threshold;
    case '==': return currentValue === threshold;
    default: return false;
  }
}

/**
 * Check if rule is in cooldown period
 */
function isInCooldown(rule: AlertRule): boolean {
  if (!rule.lastTriggered) return false;
  return Date.now() - rule.lastTriggered < rule.cooldownMs;
}

/**
 * Trigger an alert
 */
export async function triggerAlert(
  ruleId: string,
  currentValue: number,
  message?: string
): Promise<AlertEvent | null> {
  const rule = rules.get(ruleId);
  if (!rule || !rule.enabled) return null;

  if (!shouldTrigger(rule, currentValue)) return null;
  if (isInCooldown(rule)) return null;

  const alertEvent: AlertEvent = {
    id: generateId('alert'),
    ruleId: rule.id,
    ruleName: rule.name,
    timestamp: Date.now(),
    severity: rule.severity,
    message: message || `Alert: ${rule.name} - ${rule.condition.metric} is ${currentValue} (threshold: ${rule.condition.threshold})`,
    currentValue,
    threshold: rule.condition.threshold,
    channels: rule.channels,
    delivered: false,
  };

  // Update rule state
  rule.lastTriggered = Date.now();
  rule.triggerCount++;

  // Deliver to channels
  for (const channelId of rule.channels) {
    const channel = channels.get(channelId);
    if (!channel || !channel.enabled) continue;

    try {
      await deliverAlert(alertEvent, channel);
      alertEvent.delivered = true;
    } catch (error) {
      console.error(`Failed to deliver alert to channel ${channelId}:`, error);
    }
  }

  // Store in history
  alertHistory.push(alertEvent);

  // Trim history if too large
  while (alertHistory.length > 1000) {
    alertHistory.shift();
  }

  return alertEvent;
}

/**
 * Deliver alert to a channel
 */
async function deliverAlert(alert: AlertEvent, channel: AlertChannel): Promise<void> {
  switch (channel.type) {
    case 'console':
      console.error(`[ALERT] [${alert.severity.toUpperCase()}] ${alert.message}`);
      break;

    case 'memory':
      // Already stored in alertHistory
      break;

    case 'webhook':
      if (channel.config.url) {
        // In a real implementation, this would make an HTTP request
        // For demo purposes, we just log it
        console.error(`[WEBHOOK] Would POST to ${channel.config.url}:`, {
          text: alert.message,
          severity: alert.severity,
          timestamp: new Date(alert.timestamp).toISOString(),
        });
      }
      break;
  }
}

/**
 * Check all rules against current metrics
 */
export async function evaluateRules(metrics: {
  violations: number;
  rateLimitHits: number;
  errorRate: number;
  latencyP99: number;
}): Promise<AlertEvent[]> {
  const triggered: AlertEvent[] = [];

  for (const rule of rules.values()) {
    if (!rule.enabled) continue;

    let currentValue: number;
    switch (rule.condition.metric) {
      case 'violations':
        currentValue = metrics.violations;
        break;
      case 'rate_limit_hits':
        currentValue = metrics.rateLimitHits;
        break;
      case 'error_rate':
        currentValue = metrics.errorRate;
        break;
      case 'latency_p99':
        currentValue = metrics.latencyP99;
        break;
      default:
        continue;
    }

    const alert = await triggerAlert(rule.id, currentValue);
    if (alert) {
      triggered.push(alert);
    }
  }

  return triggered;
}

/**
 * Get alert history
 */
export function getAlertHistory(limit: number = 100): AlertEvent[] {
  return alertHistory.slice(-limit).reverse();
}

/**
 * Clear alert history
 */
export function clearAlertHistory(): void {
  alertHistory.length = 0;
}

/**
 * Clear all alert rules (for testing)
 */
export function clearAlertRules(): void {
  rules.clear();
}

/**
 * Get alert statistics
 */
export function getAlertStats() {
  const now = Date.now();
  const lastHour = now - 3600000;
  const last24h = now - 86400000;

  const hourAlerts = alertHistory.filter((a) => a.timestamp > lastHour);
  const dayAlerts = alertHistory.filter((a) => a.timestamp > last24h);

  const bySeverity = new Map<string, number>();
  for (const alert of alertHistory) {
    bySeverity.set(alert.severity, (bySeverity.get(alert.severity) || 0) + 1);
  }

  return {
    totalRules: rules.size,
    enabledRules: Array.from(rules.values()).filter((r) => r.enabled).length,
    totalChannels: channels.size,
    enabledChannels: Array.from(channels.values()).filter((c) => c.enabled).length,
    totalAlerts: alertHistory.length,
    lastHourAlerts: hourAlerts.length,
    last24hAlerts: dayAlerts.length,
    bySeverity: Object.fromEntries(bySeverity),
  };
}

/**
 * Seed demo alert rules
 */
export function seedDemoAlertRules(): void {
  addAlertRule({
    name: 'High Violation Rate',
    enabled: true,
    condition: {
      metric: 'violations',
      operator: '>',
      threshold: 10,
      windowMs: 60000,
    },
    severity: 'warning',
    channels: ['console', 'memory'],
    cooldownMs: 300000, // 5 minutes
  });

  addAlertRule({
    name: 'Critical Violations',
    enabled: true,
    condition: {
      metric: 'violations',
      operator: '>',
      threshold: 50,
      windowMs: 60000,
    },
    severity: 'critical',
    channels: ['console', 'memory'],
    cooldownMs: 60000, // 1 minute
  });

  addAlertRule({
    name: 'High Latency',
    enabled: true,
    condition: {
      metric: 'latency_p99',
      operator: '>',
      threshold: 1000,
      windowMs: 300000,
    },
    severity: 'warning',
    channels: ['console', 'memory'],
    cooldownMs: 600000, // 10 minutes
  });

  addAlertRule({
    name: 'Error Rate Spike',
    enabled: true,
    condition: {
      metric: 'error_rate',
      operator: '>',
      threshold: 0.1,
      windowMs: 60000,
    },
    severity: 'critical',
    channels: ['console', 'memory'],
    cooldownMs: 300000,
  });
}
