# Advanced Validation Server

Demonstrates Layer 5 custom validators for building application-specific security rules.

## Overview

This cookbook showcases:
- **5 Custom Validators** for different security scenarios
- **PII Detection** - Block or redact sensitive data in responses
- **Business Hours** - Time-based access control
- **Geofencing** - Location-based restrictions
- **Egress Tracking** - Prevent data exfiltration
- **Anomaly Detection** - Pattern-based threat detection

## Custom Validators

### 1. PII Detector (Response Validator)

Scans responses for sensitive personally identifiable information.

```typescript
import { createPIIDetectorValidator } from './validators/pii-detector.js';

layer5.addResponseValidator(
  'pii-detector',
  createPIIDetectorValidator({
    mode: 'block',  // 'block' | 'redact' | 'warn'
    patterns: {
      ssn: true,         // 123-45-6789
      creditCard: true,  // 4532-1234-5678-9012
      email: true,       // user@example.com
      phone: true,       // (555) 123-4567
      ipAddress: false
    }
  })
);
```

**Detects:**
- Social Security Numbers: `123-45-6789`
- Credit Cards: `4532-1234-5678-9012` or `4532 1234 5678 9012`
- Emails: `user@example.com`
- Phone Numbers: `(555) 123-4567`, `+1 555-123-4567`
- IP Addresses: `192.168.1.1`

### 2. Business Hours Validator (Request Validator)

Restricts expensive operations to business hours only.

```typescript
import { createBusinessHoursValidator } from './validators/business-hours.js';

layer5.addValidator(
  'business-hours',
  createBusinessHoursValidator({
    timezone: 'America/New_York',
    startHour: 9,
    endHour: 17,
    workDays: [1, 2, 3, 4, 5],  // Monday-Friday
    blockedTools: ['batch-process', 'full-export'],
    allowOverride: true
  }),
  { priority: 20 }
);
```

### 3. Geofencing Validator (Request Validator)

Restricts access based on geographic location.

```typescript
import { createGeofencingValidator, COMMON_BLOCKLIST } from './validators/geofencing.js';

layer5.addValidator(
  'geofencing',
  createGeofencingValidator({
    mode: 'blocklist',  // or 'allowlist'
    countries: COMMON_BLOCKLIST,  // ['CN', 'RU', 'KP', 'IR']
    mockLocation: process.env.MOCK_COUNTRY  // For testing
  }),
  { priority: 5 }  // High priority - runs early
);
```

**Predefined Lists:**
- `COMMON_BLOCKLIST`: CN, RU, KP, IR
- `US_ONLY_ALLOWLIST`: US
- `WESTERN_ALLOWLIST`: US, CA, GB, DE, FR, AU, NZ, IE, NL

### 4. Egress Tracker (Response Validator)

Tracks cumulative data sent per session to prevent exfiltration.

```typescript
import { createEgressTrackerValidator } from './validators/egress-tracker.js';

layer5.addResponseValidator(
  'egress-tracker',
  createEgressTrackerValidator({
    maxBytesPerSession: 10 * 1024 * 1024,  // 10MB total
    maxBytesPerRequest: 2 * 1024 * 1024,   // 2MB per response
    alertThreshold: 80,  // Alert at 80% usage
    onAlert: (sessionId, used, limit) => {
      console.warn(`Session ${sessionId} at ${(used/limit*100).toFixed(1)}% egress`);
    }
  })
);
```

### 5. Anomaly Detector (Request Validator)

Learns baseline behavior and flags deviations.

```typescript
import { createAnomalyDetector } from './validators/anomaly-detector.js';

layer5.addValidator(
  'anomaly-detector',
  createAnomalyDetector({
    learningPeriodMs: 60000,  // 1 minute to establish baseline
    maxRequestsPerWindow: 50,
    windowMs: 60000,
    toolFrequencyThreshold: 10,
    sensitiveTools: ['financial-query', 'export-data']
  }),
  { priority: 15 }
);
```

## Tools

| Tool | Validator Demo | Description |
|------|---------------|-------------|
| `financial-query` | PII Detector | Query financial data with sensitive info |
| `batch-process` | Business Hours | Run expensive batch operations |
| `export-data` | Egress Tracker | Export large datasets |
| `api-call` | Geofencing | Make geo-restricted API calls |

## Installation

```bash
cd cookbook/advanced-validation-server
npm install
npm run build
```

## Claude Desktop Configuration

```json
{
  "mcpServers": {
    "advanced-validation": {
      "command": "node",
      "args": ["cookbook/advanced-validation-server/dist/index.js"],
      "cwd": "/path/to/mcp-security",
      "env": {
        "MOCK_COUNTRY": "US"
      }
    }
  }
}
```

## Security Demos

### Demo 1: PII Detection

```
User: Query customer info for cust-001
```
**Result:** BLOCKED - Response contains SSN, credit card, email, phone

```
User: Query safe-summary for cust-003
```
**Result:** ALLOWED - No PII in response

### Demo 2: Business Hours

```
User: Run batch-process generate-reports (at 3am)
```
**Result:** BLOCKED - Outside business hours (9-5 ET, Mon-Fri)

```
User: Run batch-process generate-reports with override=true
```
**Result:** ALLOWED - Override flag accepted

### Demo 3: Geofencing

```bash
# Set mock location to blocked country
MOCK_COUNTRY=CN node dist/index.js
```
**Result:** All requests BLOCKED - Country 'CN' is blocked

### Demo 4: Egress Tracking

```
User: Export full-dump with limit=5000
User: Export full-dump with limit=5000 (again)
User: Export full-dump with limit=5000 (again)
```
**Result:** Third request BLOCKED - Session egress limit exceeded

### Demo 5: Anomaly Detection

```
User: (rapid-fire 20 financial queries in 10 seconds)
```
**Result:** BLOCKED - Tool frequency anomaly detected

## Validator Priority

Lower priority = runs earlier. Recommended ordering:

| Priority | Validator | Reason |
|----------|-----------|--------|
| 0 | Global Rules | Block admin ops first |
| 5 | Geofencing | Reject by location early |
| 10 | Rate Limiting | Prevent abuse |
| 15 | Anomaly Detection | Catch unusual patterns |
| 20 | Business Hours | Time-based restrictions |
| 50+ | Custom Logic | Application-specific |

## Creating Your Own Validators

### Request Validator Template

```typescript
function myValidator(message: unknown, context: unknown): ValidationResult {
  // Your logic here

  if (shouldBlock) {
    return {
      passed: false,
      severity: 'HIGH',  // 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
      reason: 'Human-readable reason',
      violationType: 'MY_CUSTOM_TYPE'
    };
  }

  return { passed: true };
}

layer5.addValidator('my-validator', myValidator, {
  priority: 50,
  enabled: true,
  failOnError: true  // Block if validator throws
});
```

### Response Validator Template

```typescript
function myResponseValidator(
  response: unknown,
  request: unknown,
  context: unknown
): ValidationResult {
  // Validate response content
  return { passed: true };
}

layer5.addResponseValidator('my-response-validator', myResponseValidator);
```

### Global Rule Template

```typescript
layer5.addGlobalRule(
  (message: unknown) => {
    // Return null to pass, or ValidationResult to block
    if (isBlocked(message)) {
      return {
        passed: false,
        severity: 'CRITICAL',
        reason: 'Blocked by global rule',
        violationType: 'POLICY_VIOLATION'
      };
    }
    return null;  // Continue to validators
  },
  { priority: 0 }
);
```

## Context Store

Share state across requests within a session:

```typescript
// Set context (with TTL in ms)
layer5.setContext('user:auth:abc123', { role: 'admin' }, 300000);

// Get context
const auth = layer5.getContext('user:auth:abc123');

// Use in validators
layer5.addValidator('auth-check', (message, context) => {
  const auth = layer5.getContext(`user:auth:${context.sessionId}`);
  if (!auth) {
    return { passed: false, reason: 'Not authenticated', severity: 'HIGH' };
  }
  return { passed: true };
});
```

## Security Features Demonstrated

- **Layer 5**: Custom validators, response filtering, context store
- **Defense in Depth**: Multiple validators work together
- **Fail Secure**: Any validator failure blocks the request
- **Extensibility**: Easy to add application-specific rules

## License

MIT
