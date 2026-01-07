/**
 * Public API Server Configuration
 *
 * Restricted privileges, stricter rate limits, minimal logging.
 */

import { SecureMcpServer } from 'mcp-secure-server';
import { healthSchema, healthHandler } from '../tools/public/health.js';
import { statusSchema, statusHandler } from '../tools/public/status.js';

export function createPublicServer(): SecureMcpServer {
  const server = new SecureMcpServer(
    { name: 'public-api', version: '1.0.0' },
    {
      // Security preset - standard for public APIs with stricter rate limits
      securityLevel: 'standard',
      enableLogging: false, // Minimal logging for public API
      toolRegistry: [
        { name: 'health', sideEffects: 'none', quotaPerMinute: 120 },
        { name: 'status', sideEffects: 'none', quotaPerMinute: 60 }
      ],
      defaultPolicy: {
        allowNetwork: false,
        allowWrites: false
      },
      maxRequestsPerMinute: 100 // Stricter global rate limit
    }
  );

  return server;
}

export function registerPublicTools(server: SecureMcpServer): void {
  server.tool(
    'health',
    'Check if the service is healthy',
    healthSchema.shape,
    healthHandler
  );

  server.tool(
    'status',
    'Get service status and version information',
    statusSchema.shape,
    statusHandler
  );
}
