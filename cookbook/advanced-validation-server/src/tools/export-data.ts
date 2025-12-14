/**
 * Export Data Tool
 *
 * Demonstrates cumulative egress tracking.
 * Returns large datasets that are tracked for data exfiltration prevention.
 */

import { z } from 'zod';

export const exportDataSchema = z.object({
  dataset: z.enum(['users', 'products', 'orders', 'analytics', 'full-dump']),
  format: z.enum(['json', 'csv']).default('json'),
  limit: z.number().min(1).max(10000).default(100)
});

export type ExportDataArgs = z.infer<typeof exportDataSchema>;

// Generate mock data of specified size
function generateMockUsers(count: number) {
  const users = [];
  for (let i = 0; i < count; i++) {
    users.push({
      id: i + 1,
      username: `user_${i + 1}`,
      email: `user${i + 1}@example.com`,
      department: ['Engineering', 'Sales', 'Marketing', 'Support'][i % 4],
      createdAt: new Date(Date.now() - Math.random() * 365 * 24 * 60 * 60 * 1000).toISOString(),
      lastLogin: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000).toISOString(),
      status: ['active', 'active', 'active', 'inactive'][i % 4]
    });
  }
  return users;
}

function generateMockProducts(count: number) {
  const categories = ['Electronics', 'Clothing', 'Home', 'Books', 'Sports'];
  const products = [];
  for (let i = 0; i < count; i++) {
    products.push({
      id: `prod-${i + 1}`,
      name: `Product ${i + 1}`,
      category: categories[i % categories.length],
      price: Math.round((Math.random() * 500 + 10) * 100) / 100,
      stock: Math.floor(Math.random() * 1000),
      description: `Description for product ${i + 1}. This is a sample product with various features and specifications.`
    });
  }
  return products;
}

function generateMockOrders(count: number) {
  const orders = [];
  for (let i = 0; i < count; i++) {
    orders.push({
      orderId: `ORD-${100000 + i}`,
      customerId: `cust-${Math.floor(Math.random() * 1000)}`,
      items: Math.floor(Math.random() * 5) + 1,
      total: Math.round((Math.random() * 500 + 20) * 100) / 100,
      status: ['pending', 'shipped', 'delivered', 'cancelled'][i % 4],
      createdAt: new Date(Date.now() - Math.random() * 90 * 24 * 60 * 60 * 1000).toISOString()
    });
  }
  return orders;
}

function generateMockAnalytics(count: number) {
  const analytics = [];
  for (let i = 0; i < count; i++) {
    analytics.push({
      date: new Date(Date.now() - i * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
      pageViews: Math.floor(Math.random() * 10000),
      uniqueVisitors: Math.floor(Math.random() * 5000),
      bounceRate: Math.round(Math.random() * 100) / 100,
      avgSessionDuration: Math.floor(Math.random() * 600),
      conversions: Math.floor(Math.random() * 100)
    });
  }
  return analytics;
}

function toCSV(data: Record<string, unknown>[]): string {
  if (data.length === 0) return '';
  const headers = Object.keys(data[0]!);
  const rows = data.map(row =>
    headers.map(h => JSON.stringify(row[h] ?? '')).join(',')
  );
  return [headers.join(','), ...rows].join('\n');
}

export async function handleExportData(args: ExportDataArgs) {
  let data: Record<string, unknown>[];
  let datasetName: string;

  switch (args.dataset) {
    case 'users':
      data = generateMockUsers(args.limit);
      datasetName = 'Users';
      break;
    case 'products':
      data = generateMockProducts(args.limit);
      datasetName = 'Products';
      break;
    case 'orders':
      data = generateMockOrders(args.limit);
      datasetName = 'Orders';
      break;
    case 'analytics':
      data = generateMockAnalytics(Math.min(args.limit, 365));
      datasetName = 'Analytics';
      break;
    case 'full-dump':
      // Combine all datasets - this will be large!
      data = [
        ...generateMockUsers(args.limit),
        ...generateMockProducts(args.limit),
        ...generateMockOrders(args.limit)
      ];
      datasetName = 'Full Dump';
      break;
  }

  const output = args.format === 'csv' ? toCSV(data) : data;
  const sizeBytes = Buffer.byteLength(JSON.stringify(output), 'utf8');

  const result = {
    dataset: datasetName,
    recordCount: Array.isArray(output) ? output.length : data.length,
    format: args.format,
    sizeBytes,
    sizeFormatted: sizeBytes < 1024
      ? `${sizeBytes}B`
      : sizeBytes < 1024 * 1024
        ? `${(sizeBytes / 1024).toFixed(1)}KB`
        : `${(sizeBytes / (1024 * 1024)).toFixed(1)}MB`,
    data: output
  };

  return {
    content: [{
      type: 'text' as const,
      text: JSON.stringify(result, null, 2)
    }]
  };
}
