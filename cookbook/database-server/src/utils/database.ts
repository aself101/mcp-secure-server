/**
 * Database utilities for the database MCP server
 * Uses SQLite in-memory for demonstration purposes, via Node's built-in
 * `node:sqlite` (Node >= 22.13). Until mcp-secure-server 0.0.27 this example
 * used the native `better-sqlite3`, which needed a compile step and was not
 * installed anywhere in the cookbook workspace, so the example and its tests
 * could not run out of the box.
 */

import { DatabaseSync } from 'node:sqlite';

export type SqliteDatabase = DatabaseSync;

export interface User {
  id: number;
  name: string;
  email: string;
  department: string;
  created_at: string;
}

export interface Order {
  id: number;
  user_id: number;
  items: string; // JSON string
  total: number;
  status: string;
  created_at: string;
}

export interface OrderItem {
  product: string;
  quantity: number;
  price: number;
}

let db: SqliteDatabase | null = null;

export function getDatabase(): SqliteDatabase {
  if (!db) {
    db = new DatabaseSync(':memory:');
    initializeSchema(db);
    seedData(db);
  }
  return db;
}

export function closeDatabase(): void {
  if (db) {
    db.close();
    db = null;
  }
}

/**
 * Runs `fn` inside a transaction, committing on success and rolling back on
 * throw — the `db.transaction()` helper better-sqlite3 provided.
 */
export function transaction<T>(database: SqliteDatabase, fn: () => T): T {
  database.exec('BEGIN');
  try {
    const result = fn();
    database.exec('COMMIT');
    return result;
  } catch (error) {
    database.exec('ROLLBACK');
    throw error;
  }
}

function initializeSchema(database: SqliteDatabase): void {
  database.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      department TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      items TEXT NOT NULL,
      total REAL NOT NULL,
      status TEXT DEFAULT 'pending',
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE INDEX IF NOT EXISTS idx_users_name ON users(name);
    CREATE INDEX IF NOT EXISTS idx_users_department ON users(department);
    CREATE INDEX IF NOT EXISTS idx_orders_user_id ON orders(user_id);
    CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status);
    CREATE INDEX IF NOT EXISTS idx_orders_created_at ON orders(created_at);
  `);
}

function seedData(database: SqliteDatabase): void {
  const insertUser = database.prepare(`
    INSERT INTO users (name, email, department, created_at) VALUES (?, ?, ?, ?)
  `);

  const insertOrder = database.prepare(`
    INSERT INTO orders (user_id, items, total, status, created_at) VALUES (?, ?, ?, ?, ?)
  `);

  // Seed users
  const users = [
    { name: 'Alice Johnson', email: 'alice@example.com', department: 'Engineering', created_at: '2024-01-15 09:00:00' },
    { name: 'Bob Smith', email: 'bob@example.com', department: 'Sales', created_at: '2024-01-20 10:30:00' },
    { name: 'Carol Williams', email: 'carol@example.com', department: 'Engineering', created_at: '2024-02-01 14:00:00' },
    { name: 'David Brown', email: 'david@example.com', department: 'Marketing', created_at: '2024-02-15 11:00:00' },
    { name: 'Eva Martinez', email: 'eva@example.com', department: 'Engineering', created_at: '2024-03-01 08:00:00' },
    { name: 'Frank Garcia', email: 'frank@example.com', department: 'Sales', created_at: '2024-03-10 16:00:00' },
    { name: 'Grace Lee', email: 'grace@example.com', department: 'HR', created_at: '2024-03-20 09:30:00' },
    { name: 'Henry Wilson', email: 'henry@example.com', department: 'Engineering', created_at: '2024-04-01 10:00:00' },
    { name: 'Ivy Chen', email: 'ivy@example.com', department: 'Marketing', created_at: '2024-04-15 13:00:00' },
    { name: 'Jack Taylor', email: 'jack@example.com', department: 'Sales', created_at: '2024-05-01 15:00:00' },
  ];

  transaction(database, () => {
    for (const user of users) {
      insertUser.run(user.name, user.email, user.department, user.created_at);
    }
  });

  // Seed orders
  const orders = [
    { user_id: 1, items: JSON.stringify([{ product: 'Laptop', quantity: 1, price: 1200 }]), total: 1200, status: 'completed', created_at: '2024-02-01 10:00:00' },
    { user_id: 1, items: JSON.stringify([{ product: 'Mouse', quantity: 2, price: 25 }]), total: 50, status: 'completed', created_at: '2024-03-15 11:00:00' },
    { user_id: 2, items: JSON.stringify([{ product: 'Monitor', quantity: 1, price: 400 }, { product: 'Keyboard', quantity: 1, price: 80 }]), total: 480, status: 'completed', created_at: '2024-02-20 14:00:00' },
    { user_id: 3, items: JSON.stringify([{ product: 'Headphones', quantity: 1, price: 150 }]), total: 150, status: 'pending', created_at: '2024-04-01 09:00:00' },
    { user_id: 4, items: JSON.stringify([{ product: 'Webcam', quantity: 1, price: 75 }]), total: 75, status: 'shipped', created_at: '2024-04-10 16:00:00' },
    { user_id: 5, items: JSON.stringify([{ product: 'Laptop', quantity: 2, price: 1200 }]), total: 2400, status: 'completed', created_at: '2024-03-01 10:00:00' },
    { user_id: 6, items: JSON.stringify([{ product: 'Phone', quantity: 1, price: 800 }]), total: 800, status: 'completed', created_at: '2024-05-01 11:00:00' },
    { user_id: 7, items: JSON.stringify([{ product: 'Tablet', quantity: 1, price: 500 }]), total: 500, status: 'pending', created_at: '2024-05-10 13:00:00' },
    { user_id: 8, items: JSON.stringify([{ product: 'SSD', quantity: 2, price: 100 }]), total: 200, status: 'shipped', created_at: '2024-05-15 15:00:00' },
    { user_id: 9, items: JSON.stringify([{ product: 'RAM', quantity: 4, price: 50 }]), total: 200, status: 'completed', created_at: '2024-05-20 09:00:00' },
  ];

  transaction(database, () => {
    for (const order of orders) {
      insertOrder.run(order.user_id, order.items, order.total, order.status, order.created_at);
    }
  });
}
