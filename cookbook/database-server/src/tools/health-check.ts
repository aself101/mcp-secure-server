/**
 * Health Check Tool
 * Database connection and status verification
 */

import { z } from 'zod';
import { getDatabase } from '../utils/index.js';

export const healthCheckSchema = z.object({});

export type HealthCheckArgs = z.infer<typeof healthCheckSchema>;

export type HealthCheckResult = {
  content: Array<{ type: 'text'; text: string }>;
};

export async function healthCheck(): Promise<HealthCheckResult> {
  const startTime = Date.now();

  try {
    const db = getDatabase();

    // Test basic connectivity
    const pingStmt = db.prepare('SELECT 1 as ping');
    pingStmt.get();

    // Get database statistics
    const userCountStmt = db.prepare('SELECT COUNT(*) as count FROM users');
    const userCount = (userCountStmt.get() as { count: number }).count;

    const orderCountStmt = db.prepare('SELECT COUNT(*) as count FROM orders');
    const orderCount = (orderCountStmt.get() as { count: number }).count;

    // Get latest order timestamp
    const latestOrderStmt = db.prepare(
      'SELECT MAX(created_at) as latest FROM orders'
    );
    const latestOrder = (latestOrderStmt.get() as { latest: string | null }).latest;

    const responseTime = Date.now() - startTime;

    const result = {
      status: 'healthy',
      database: {
        type: 'sqlite',
        mode: 'in-memory',
        connected: true,
        responseTimeMs: responseTime,
      },
      statistics: {
        userCount,
        orderCount,
        latestOrderAt: latestOrder,
      },
      timestamp: new Date().toISOString(),
    };

    return {
      content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
    };
  } catch (error) {
    const responseTime = Date.now() - startTime;
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';

    const result = {
      status: 'unhealthy',
      database: {
        type: 'sqlite',
        mode: 'in-memory',
        connected: false,
        responseTimeMs: responseTime,
        error: errorMessage,
      },
      timestamp: new Date().toISOString(),
    };

    return {
      content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
    };
  }
}
