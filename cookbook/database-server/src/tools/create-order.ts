/**
 * Create Order Tool
 * Insert orders with transaction support and validation
 */

import { z } from 'zod';
import { getDatabase, type OrderItem } from '../utils/index.js';

const orderItemSchema = z.object({
  product: z.string().min(1).max(100).describe('Product name'),
  quantity: z.number().int().min(1).max(1000).describe('Quantity ordered'),
  price: z.number().min(0).max(1000000).describe('Price per unit'),
});

export const createOrderSchema = z.object({
  userId: z
    .number()
    .int()
    .positive()
    .describe('User ID placing the order'),
  items: z
    .array(orderItemSchema)
    .min(1)
    .max(50)
    .describe('Array of order items'),
  total: z
    .number()
    .min(0)
    .max(10000000)
    .describe('Total order amount'),
});

export type CreateOrderArgs = z.infer<typeof createOrderSchema>;

export type CreateOrderResult = {
  content: Array<{ type: 'text'; text: string }>;
};

export async function createOrder(args: CreateOrderArgs): Promise<CreateOrderResult> {
  const db = getDatabase();
  const { userId, items, total } = args;

  // Validate user exists
  const userStmt = db.prepare('SELECT id, name FROM users WHERE id = ?');
  const user = userStmt.get(userId) as { id: number; name: string } | undefined;

  if (!user) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          error: 'User not found',
          message: `No user exists with ID ${userId}`,
        }, null, 2),
      }],
    };
  }

  // Validate total matches calculated total
  const calculatedTotal = items.reduce(
    (sum: number, item: OrderItem) => sum + item.quantity * item.price,
    0
  );

  if (Math.abs(calculatedTotal - total) > 0.01) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          error: 'Total mismatch',
          message: `Provided total (${total}) does not match calculated total (${calculatedTotal})`,
          calculatedTotal,
        }, null, 2),
      }],
    };
  }

  // Insert order using transaction
  const insertOrder = db.prepare(`
    INSERT INTO orders (user_id, items, total, status)
    VALUES (?, ?, ?, 'pending')
  `);

  const transaction = db.transaction(() => {
    const result = insertOrder.run(userId, JSON.stringify(items), total);
    return result.lastInsertRowid;
  });

  const orderId = transaction();

  const result = {
    success: true,
    orderId: Number(orderId),
    userId,
    userName: user.name,
    itemCount: items.length,
    total,
    status: 'pending',
    createdAt: new Date().toISOString(),
  };

  return {
    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
  };
}
