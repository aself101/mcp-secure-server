/**
 * Query Users Tool
 * Safe user search with parameterized queries
 */

import { z } from 'zod';
import { getDatabase, type User } from '../utils/index.js';

export const queryUsersSchema = z.object({
  search: z
    .string()
    .min(1)
    .max(100)
    .describe('Search term to match against user name or email'),
  department: z
    .string()
    .max(50)
    .optional()
    .describe('Filter by department'),
  limit: z
    .number()
    .int()
    .min(1)
    .max(100)
    .default(20)
    .describe('Maximum number of results (1-100)'),
});

export type QueryUsersArgs = z.infer<typeof queryUsersSchema>;

export type QueryUsersResult = {
  content: Array<{ type: 'text'; text: string }>;
};

export async function queryUsers(args: QueryUsersArgs): Promise<QueryUsersResult> {
  const db = getDatabase();
  const { search, department, limit } = args;

  // ============================================================================
  // SAFE: Parameterized Query (What this server uses)
  // ============================================================================
  // The ? placeholders are replaced by the database driver with properly escaped
  // values. Even if 'search' contains SQL syntax like "' OR 1=1 --", it will be
  // treated as literal text, not executable SQL code.
  //
  // UNSAFE alternative (NEVER DO THIS):
  // const query = `SELECT * FROM users WHERE name LIKE '%${search}%'`;
  // This allows SQL injection! An attacker could use search="' OR '1'='1"
  // to bypass filters and extract all data.
  // ============================================================================
  let query = `
    SELECT id, name, email, department, created_at
    FROM users
    WHERE (name LIKE ? OR email LIKE ?)
  `;
  const params: (string | number)[] = [`%${search}%`, `%${search}%`];

  if (department) {
    query += ' AND department = ?';
    params.push(department);
  }

  query += ' ORDER BY name ASC LIMIT ?';
  params.push(limit);

  const stmt = db.prepare(query);
  const users = stmt.all(...params) as User[];

  const result = {
    count: users.length,
    limit,
    users: users.map((u) => ({
      id: u.id,
      name: u.name,
      email: u.email,
      department: u.department,
      createdAt: u.created_at,
    })),
  };

  return {
    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
  };
}
