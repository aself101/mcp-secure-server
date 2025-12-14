/**
 * PII Detector Validator
 *
 * Scans responses for sensitive personally identifiable information.
 * Can redact or block responses containing PII.
 */

// Simple validation result type compatible with Layer 5
interface SimpleValidationResult {
  passed: boolean;
  severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  reason?: string;
  violationType?: string;
}

export interface PIIDetectorConfig {
  mode: 'block' | 'redact' | 'warn';
  patterns: {
    ssn: boolean;
    creditCard: boolean;
    email: boolean;
    phone: boolean;
    ipAddress: boolean;
  };
}

interface PIIMatch {
  type: string;
  value: string;
  redacted: string;
}

const PII_PATTERNS = {
  ssn: {
    pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
    name: 'Social Security Number',
    redact: (match: string) => 'XXX-XX-' + match.slice(-4)
  },
  creditCard: {
    pattern: /\b(?:\d{4}[\s-]?){3}\d{4}\b/g,
    name: 'Credit Card Number',
    redact: (match: string) => '**** **** **** ' + match.replace(/[\s-]/g, '').slice(-4)
  },
  email: {
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
    name: 'Email Address',
    redact: (match: string) => {
      const [local, domain] = match.split('@');
      return local[0] + '***@' + domain;
    }
  },
  phone: {
    pattern: /\b(?:\+1[\s-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g,
    name: 'Phone Number',
    redact: () => '(***) ***-****'
  },
  ipAddress: {
    pattern: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
    name: 'IP Address',
    redact: () => '***.***.***.***'
  }
};

export function detectPII(content: string, config: PIIDetectorConfig): PIIMatch[] {
  const matches: PIIMatch[] = [];

  for (const [type, { pattern, redact }] of Object.entries(PII_PATTERNS)) {
    if (!config.patterns[type as keyof typeof config.patterns]) continue;

    const found = content.match(pattern);
    if (found) {
      for (const value of found) {
        matches.push({
          type,
          value,
          redacted: redact(value)
        });
      }
    }
  }

  return matches;
}

export function createPIIDetectorValidator(config: PIIDetectorConfig) {
  return function piiDetector(
    response: unknown,
    _request: unknown,
    _context: unknown
  ): SimpleValidationResult {
    const content = JSON.stringify(response);
    const matches = detectPII(content, config);

    if (matches.length === 0) {
      return { passed: true };
    }

    const types = [...new Set(matches.map(m => PII_PATTERNS[m.type as keyof typeof PII_PATTERNS].name))];

    if (config.mode === 'block') {
      return {
        passed: false,
        severity: 'HIGH',
        reason: `PII detected in response: ${types.join(', ')}`,
        violationType: 'SENSITIVE_DATA_EXPOSURE'
      };
    }

    if (config.mode === 'warn') {
      console.warn(`[PII Warning] Detected: ${types.join(', ')}`);
    }

    return { passed: true };
  };
}

export function redactPII(content: string, config: PIIDetectorConfig): string {
  let redacted = content;

  for (const [type, { pattern, redact }] of Object.entries(PII_PATTERNS)) {
    if (!config.patterns[type as keyof typeof config.patterns]) continue;
    redacted = redacted.replace(pattern, redact);
  }

  return redacted;
}
