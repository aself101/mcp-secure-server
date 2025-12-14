/**
 * Business Hours Validator
 *
 * Restricts certain operations to business hours only.
 * Useful for preventing expensive batch jobs outside working hours.
 */

// Simple validation result type compatible with Layer 5
interface SimpleValidationResult {
  passed: boolean;
  severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  reason?: string;
  violationType?: string;
}

export interface BusinessHoursConfig {
  timezone: string;
  startHour: number;  // 0-23
  endHour: number;    // 0-23
  workDays: number[]; // 0=Sunday, 1=Monday, ..., 6=Saturday
  blockedTools: string[];
  allowOverride: boolean;
}

interface MessageWithMethod {
  method?: string;
  params?: {
    name?: string;
    arguments?: {
      override?: boolean;
    };
  };
}

export function isWithinBusinessHours(config: BusinessHoursConfig): boolean {
  const now = new Date();

  // Get current hour and day in specified timezone
  const formatter = new Intl.DateTimeFormat('en-US', {
    timeZone: config.timezone,
    hour: 'numeric',
    hour12: false,
    weekday: 'short'
  });

  const parts = formatter.formatToParts(now);
  const hourPart = parts.find(p => p.type === 'hour');
  const dayPart = parts.find(p => p.type === 'weekday');

  const hour = parseInt(hourPart?.value || '0', 10);
  const dayMap: Record<string, number> = {
    'Sun': 0, 'Mon': 1, 'Tue': 2, 'Wed': 3, 'Thu': 4, 'Fri': 5, 'Sat': 6
  };
  const day = dayMap[dayPart?.value || 'Mon'] ?? 1;

  // Check if current day is a work day
  if (!config.workDays.includes(day)) {
    return false;
  }

  // Check if current hour is within business hours
  return hour >= config.startHour && hour < config.endHour;
}

export function createBusinessHoursValidator(config: BusinessHoursConfig) {
  return function businessHoursValidator(
    message: unknown,
    _context: unknown
  ): SimpleValidationResult {
    const msg = message as MessageWithMethod;
    const toolName = msg.params?.name || '';

    // Check if this tool is restricted
    if (!config.blockedTools.includes(toolName)) {
      return { passed: true };
    }

    // Check for override flag
    if (config.allowOverride && msg.params?.arguments?.override === true) {
      console.log(`[Business Hours] Override accepted for ${toolName}`);
      return { passed: true };
    }

    // Check business hours
    if (isWithinBusinessHours(config)) {
      return { passed: true };
    }

    const schedule = `${config.startHour}:00-${config.endHour}:00 on work days`;

    return {
      passed: false,
      severity: 'MEDIUM',
      reason: `Tool '${toolName}' is only available during business hours (${schedule}, ${config.timezone})`,
      violationType: 'BUSINESS_HOURS_VIOLATION'
    };
  };
}

export const DEFAULT_BUSINESS_HOURS: BusinessHoursConfig = {
  timezone: 'America/New_York',
  startHour: 9,
  endHour: 17,
  workDays: [1, 2, 3, 4, 5], // Monday-Friday
  blockedTools: [],
  allowOverride: false
};
