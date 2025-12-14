/**
 * API Call Tool
 *
 * Demonstrates geofencing validation.
 * Simulates external API calls with location-based restrictions.
 */

import { z } from 'zod';

export const apiCallSchema = z.object({
  endpoint: z.enum(['payment', 'user-data', 'public-api', 'internal-service']),
  method: z.enum(['GET', 'POST']).default('GET'),
  payload: z.record(z.unknown()).optional()
});

export type ApiCallArgs = z.infer<typeof apiCallSchema>;

// Simulated API endpoints with their restrictions
const ENDPOINT_INFO: Record<string, {
  description: string;
  requiresAuth: boolean;
  geoRestricted: boolean;
  mockResponse: unknown;
}> = {
  'payment': {
    description: 'Process payment transactions',
    requiresAuth: true,
    geoRestricted: true, // Only allowed from certain countries
    mockResponse: {
      status: 'success',
      transactionId: `txn-${Date.now()}`,
      message: 'Payment processed successfully'
    }
  },
  'user-data': {
    description: 'Access user personal data',
    requiresAuth: true,
    geoRestricted: true, // GDPR and other regulations
    mockResponse: {
      status: 'success',
      userData: {
        preferences: { theme: 'dark', language: 'en' },
        settings: { notifications: true }
      }
    }
  },
  'public-api': {
    description: 'Public API endpoint',
    requiresAuth: false,
    geoRestricted: false, // Available globally
    mockResponse: {
      status: 'success',
      data: {
        version: '2.0.0',
        uptime: '99.9%',
        serverTime: new Date().toISOString()
      }
    }
  },
  'internal-service': {
    description: 'Internal microservice communication',
    requiresAuth: true,
    geoRestricted: true, // Restricted to corporate IPs
    mockResponse: {
      status: 'success',
      serviceStatus: 'healthy',
      metrics: {
        requestsPerSecond: 1250,
        avgLatencyMs: 12
      }
    }
  }
};

export async function handleApiCall(args: ApiCallArgs) {
  const endpointInfo = ENDPOINT_INFO[args.endpoint];

  // Simulate processing time
  await new Promise(resolve => setTimeout(resolve, 50));

  const result = {
    endpoint: args.endpoint,
    method: args.method,
    description: endpointInfo.description,
    requiresAuth: endpointInfo.requiresAuth,
    geoRestricted: endpointInfo.geoRestricted,
    requestPayload: args.payload || null,
    response: endpointInfo.mockResponse,
    metadata: {
      timestamp: new Date().toISOString(),
      latencyMs: Math.floor(Math.random() * 50) + 10,
      requestId: `req-${Math.random().toString(36).slice(2, 10)}`
    }
  };

  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify(result, null, 2)
    }]
  };
}
