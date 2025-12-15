/**
 * Advanced Validation Server
 *
 * Demonstrates Layer 5 custom validators with practical examples.
 * Shows how to build sophisticated security rules for business applications.
 */

import { SecureMcpServer, ContextualValidationLayer } from 'mcp-security';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import {
  financialQuerySchema,
  handleFinancialQuery,
  batchProcessSchema,
  handleBatchProcess,
  exportDataSchema,
  handleExportData,
  apiCallSchema,
  handleApiCall
} from './tools/index.js';

import {
  createPIIDetectorValidator,
  createBusinessHoursValidator,
  createGeofencingValidator,
  createEgressTrackerValidator,
  createAnomalyDetector,
  COMMON_BLOCKLIST
} from './validators/index.js';

// Create secure server with Layer 5 enabled
const server = new SecureMcpServer(
  {
    name: 'advanced-validation-server',
    version: '1.0.0'
  },
  {
    enableLogging: true,
    verboseLogging: true,

    // Tool registry - defines allowed tools and their policies
    toolRegistry: [
      {
        name: 'financial-query',
        sideEffects: 'read',
        maxArgsSize: 1024,
        maxEgressBytes: 10 * 1024, // 10KB
        quotaPerMinute: 30,
      },
      {
        name: 'batch-process',
        sideEffects: 'write',
        maxArgsSize: 1024,
        maxEgressBytes: 10 * 1024,
        quotaPerMinute: 10,
      },
      {
        name: 'export-data',
        sideEffects: 'read',
        maxArgsSize: 1024,
        maxEgressBytes: 2 * 1024 * 1024, // 2MB - for egress tracking demo
        quotaPerMinute: 20,
      },
      {
        name: 'api-call',
        sideEffects: 'network',
        maxArgsSize: 1024,
        maxEgressBytes: 10 * 1024,
        quotaPerMinute: 20,
      },
    ],

    // Default policy - allow network and writes for demo purposes
    defaultPolicy: {
      allowNetwork: true,
      allowWrites: true,
    },

    // Layer 5 built-in configuration
    contextual: {
      enabled: true,
      domainRestrictions: {
        enabled: true,
        blockedDomains: ['evil.com', 'malicious.net'],
        allowedDomains: [] // Empty = allow all except blocked
      },
      rateLimiting: {
        enabled: true,
        limit: 30,
        windowMs: 60000
      }
    }
  }
);

// Access Layer 5 for custom validator registration
// Cast to ContextualValidationLayer to access addValidator methods
const layer5 = server.validationPipeline.layers[4] as ContextualValidationLayer;

// ============================================
// Register Custom Validators
// Note: Using 'as any' casts because Layer 5 runtime handles partial results
// ============================================

// 1. PII Detector - Blocks responses containing sensitive data
layer5.addResponseValidator(
  'pii-detector',
  createPIIDetectorValidator({
    mode: 'block', // Change to 'warn' or 'redact' for different behavior
    patterns: {
      ssn: true,
      creditCard: true,
      email: true,
      phone: true,
      ipAddress: false
    }
  }) as any,
  { enabled: true }
);

// 2. Business Hours Validator - Restricts expensive operations
layer5.addValidator(
  'business-hours',
  createBusinessHoursValidator({
    timezone: 'America/New_York',
    startHour: 9,
    endHour: 17,
    workDays: [1, 2, 3, 4, 5], // Monday-Friday
    blockedTools: ['batch-process'], // Only batch-process is restricted
    allowOverride: true // Allow override flag in requests
  }) as any,
  { priority: 20, enabled: true }
);

// 3. Geofencing Validator - Blocks requests from certain countries
layer5.addValidator(
  'geofencing',
  createGeofencingValidator({
    mode: 'blocklist',
    countries: COMMON_BLOCKLIST, // CN, RU, KP, IR
    mockLocation: process.env.MOCK_COUNTRY // Set to test: MOCK_COUNTRY=CN
  }) as any,
  { priority: 5, enabled: true } // High priority - runs early
);

// 4. Egress Tracker - Limits total data sent per session
layer5.addResponseValidator(
  'egress-tracker',
  createEgressTrackerValidator({
    maxBytesPerSession: 10 * 1024 * 1024, // 10MB per session
    maxBytesPerRequest: 2 * 1024 * 1024,  // 2MB per request
    alertThreshold: 80, // Alert at 80% usage
    onAlert: (sessionId, used, limit) => {
      console.warn(`[ALERT] Session ${sessionId} approaching egress limit: ${(used/limit*100).toFixed(1)}%`);
    }
  }) as any,
  { enabled: true }
);

// 5. Anomaly Detector - Detects unusual request patterns
layer5.addValidator(
  'anomaly-detector',
  createAnomalyDetector({
    learningPeriodMs: 60000, // 1 minute learning period
    maxRequestsPerWindow: 50,
    windowMs: 60000,
    toolFrequencyThreshold: 10,
    sensitiveTools: ['financial-query', 'export-data']
  }) as any,
  { priority: 15, enabled: true }
);

// 6. Custom Global Rule - Block admin operations entirely
layer5.addGlobalRule(
  ((message: unknown) => {
    const msg = message as { params?: { name?: string } };
    if (msg.params?.name?.startsWith('admin-')) {
      return {
        passed: false,
        severity: 'CRITICAL' as const,
        reason: 'Admin operations are disabled in this environment',
        violationType: 'ADMIN_BLOCKED'
      };
    }
    return null; // Pass - continue to validators
  }) as any,
  { priority: 0 } // Runs first
);

// ============================================
// Register Tools
// ============================================

// Financial Query - Demonstrates PII detection
server.tool(
  'financial-query',
  'Query financial data (demonstrates PII detection in responses)',
  financialQuerySchema.shape,
  async (args) => handleFinancialQuery(args as Parameters<typeof handleFinancialQuery>[0])
);

// Batch Process - Demonstrates business hours validation
server.tool(
  'batch-process',
  'Run batch operations (restricted to business hours)',
  batchProcessSchema.shape,
  async (args) => handleBatchProcess(args as Parameters<typeof handleBatchProcess>[0])
);

// Export Data - Demonstrates egress tracking
server.tool(
  'export-data',
  'Export datasets (demonstrates cumulative egress tracking)',
  exportDataSchema.shape,
  async (args) => handleExportData(args as Parameters<typeof handleExportData>[0])
);

// API Call - Demonstrates geofencing
server.tool(
  'api-call',
  'Make API calls (demonstrates geofencing restrictions)',
  apiCallSchema.shape,
  async (args) => handleApiCall(args as Parameters<typeof handleApiCall>[0])
);

// ============================================
// Start Server
// ============================================

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);

  console.error('Advanced Validation Server started');
  console.error('Custom validators registered:');
  console.error('  - pii-detector (response)');
  console.error('  - business-hours (request)');
  console.error('  - geofencing (request)');
  console.error('  - egress-tracker (response)');
  console.error('  - anomaly-detector (request)');
  console.error('  - admin-blocker (global rule)');
}

main().catch(console.error);
