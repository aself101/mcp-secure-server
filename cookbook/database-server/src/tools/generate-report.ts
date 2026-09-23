/**
 * Generate Report Tool
 * Complex analytics query with read-only access
 */

import { z } from 'zod';
import { getDatabase } from '../utils/index.js';

export const generateReportSchema = z.object({
  startDate: z
    .string()
    .regex(/^\d{4}-\d{2}-\d{2}$/, 'Must be YYYY-MM-DD format')
    .describe('Report start date (YYYY-MM-DD)'),
  endDate: z
    .string()
    .regex(/^\d{4}-\d{2}-\d{2}$/, 'Must be YYYY-MM-DD format')
    .describe('Report end date (YYYY-MM-DD)'),
  groupBy: z
    .enum(['day', 'week', 'month', 'department', 'status'])
    .default('month')
    .describe('How to group the report data'),
});

export type GenerateReportArgs = z.infer<typeof generateReportSchema>;

export type GenerateReportResult = {
  content: Array<{ type: 'text'; text: string }>;
};

interface ReportRow {
  period: string;
  order_count: number;
  total_revenue: number;
  avg_order_value: number;
}

interface DepartmentRow {
  department: string;
  user_count: number;
  order_count: number;
  total_revenue: number;
}

interface StatusRow {
  status: string;
  order_count: number;
  total_revenue: number;
}

export async function generateReport(args: GenerateReportArgs): Promise<GenerateReportResult> {
  const db = getDatabase();
  const { startDate, endDate, groupBy } = args;

  // Validate date range
  const start = new Date(startDate);
  const end = new Date(endDate);

  if (start > end) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          error: 'Invalid date range',
          message: 'Start date must be before end date',
        }, null, 2),
      }],
    };
  }

  let query: string;
  let params: string[];

  switch (groupBy) {
    case 'day':
      query = `
        SELECT
          date(created_at) as period,
          COUNT(*) as order_count,
          SUM(total) as total_revenue,
          AVG(total) as avg_order_value
        FROM orders
        WHERE date(created_at) >= ? AND date(created_at) <= ?
        GROUP BY date(created_at)
        ORDER BY period
      `;
      params = [startDate, endDate];
      break;

    case 'week':
      query = `
        SELECT
          strftime('%Y-W%W', created_at) as period,
          COUNT(*) as order_count,
          SUM(total) as total_revenue,
          AVG(total) as avg_order_value
        FROM orders
        WHERE date(created_at) >= ? AND date(created_at) <= ?
        GROUP BY strftime('%Y-W%W', created_at)
        ORDER BY period
      `;
      params = [startDate, endDate];
      break;

    case 'month':
      query = `
        SELECT
          strftime('%Y-%m', created_at) as period,
          COUNT(*) as order_count,
          SUM(total) as total_revenue,
          AVG(total) as avg_order_value
        FROM orders
        WHERE date(created_at) >= ? AND date(created_at) <= ?
        GROUP BY strftime('%Y-%m', created_at)
        ORDER BY period
      `;
      params = [startDate, endDate];
      break;

    case 'department':
      query = `
        SELECT
          u.department,
          COUNT(DISTINCT u.id) as user_count,
          COUNT(o.id) as order_count,
          COALESCE(SUM(o.total), 0) as total_revenue
        FROM users u
        LEFT JOIN orders o ON u.id = o.user_id
          AND date(o.created_at) >= ? AND date(o.created_at) <= ?
        GROUP BY u.department
        ORDER BY total_revenue DESC
      `;
      params = [startDate, endDate];
      break;

    case 'status':
      query = `
        SELECT
          status,
          COUNT(*) as order_count,
          SUM(total) as total_revenue
        FROM orders
        WHERE date(created_at) >= ? AND date(created_at) <= ?
        GROUP BY status
        ORDER BY order_count DESC
      `;
      params = [startDate, endDate];
      break;

    default:
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            error: 'Invalid groupBy value',
            message: `"${groupBy}" is not a valid groupBy option`,
            provided: groupBy,
            validOptions: ['day', 'week', 'month', 'department', 'status'],
          }, null, 2),
        }],
      };
  }

  const stmt = db.prepare(query);
  const rows = stmt.all(...params);

  // Get summary statistics
  const summaryQuery = `
    SELECT
      COUNT(*) as total_orders,
      COALESCE(SUM(total), 0) as total_revenue,
      COALESCE(AVG(total), 0) as avg_order_value,
      COUNT(DISTINCT user_id) as unique_customers
    FROM orders
    WHERE date(created_at) >= ? AND date(created_at) <= ?
  `;
  const summaryStmt = db.prepare(summaryQuery);
  const summary = summaryStmt.get(startDate, endDate) as {
    total_orders: number;
    total_revenue: number;
    avg_order_value: number;
    unique_customers: number;
  };

  const result = {
    report: {
      startDate,
      endDate,
      groupBy,
      generatedAt: new Date().toISOString(),
    },
    summary: {
      totalOrders: summary.total_orders,
      totalRevenue: Math.round(summary.total_revenue * 100) / 100,
      avgOrderValue: Math.round(summary.avg_order_value * 100) / 100,
      uniqueCustomers: summary.unique_customers,
    },
    data: formatReportData(rows, groupBy),
  };

  return {
    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
  };
}

function formatReportData(
  rows: unknown[],
  groupBy: string
): Record<string, unknown>[] {
  if (groupBy === 'department') {
    return (rows as DepartmentRow[]).map((row) => ({
      department: row.department,
      userCount: row.user_count,
      orderCount: row.order_count,
      totalRevenue: Math.round(row.total_revenue * 100) / 100,
    }));
  }

  if (groupBy === 'status') {
    return (rows as StatusRow[]).map((row) => ({
      status: row.status,
      orderCount: row.order_count,
      totalRevenue: Math.round(row.total_revenue * 100) / 100,
    }));
  }

  return (rows as ReportRow[]).map((row) => ({
    period: row.period,
    orderCount: row.order_count,
    totalRevenue: Math.round(row.total_revenue * 100) / 100,
    avgOrderValue: Math.round(row.avg_order_value * 100) / 100,
  }));
}
