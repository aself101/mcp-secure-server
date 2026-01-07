/**
 * Admin API Server Configuration
 *
 * Higher privileges, more permissive policies, detailed logging.
 */

import { SecureMcpServer } from 'mcp-secure-server';
import { listUsersSchema, listUsersHandler } from '../tools/admin/user-management.js';
import { systemStatsSchema, systemStatsHandler } from '../tools/admin/system-stats.js';

export function createAdminServer(): SecureMcpServer {
  const server = new SecureMcpServer(
    { name: 'admin-api', version: '1.0.0' },
    {
      // Security preset - standard for admin operations with detailed logging
      securityLevel: 'standard',
      enableLogging: true, // Detailed logging for admin actions
      toolRegistry: [
        { name: 'list-users', sideEffects: 'read', quotaPerMinute: 30 },
        { name: 'system-stats', sideEffects: 'none', quotaPerMinute: 60 }
      ],
      defaultPolicy: {
        allowNetwork: true,
        allowWrites: false
      }
    }
  );

  return server;
}

export function registerAdminTools(server: SecureMcpServer): void {
  server.tool(
    'list-users',
    'List all users in the system (admin only)',
    listUsersSchema.shape,
    listUsersHandler
  );

  server.tool(
    'system-stats',
    'Get system statistics and health metrics',
    systemStatsSchema.shape,
    systemStatsHandler
  );
}
