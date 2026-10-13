/**
 * Transaction Example
 *
 * Demonstrates safe transaction handling for atomic database operations.
 * If any part fails, the entire operation is rolled back.
 */

import { DatabaseSync } from 'node:sqlite';

const db = new DatabaseSync(':memory:');

// Setup tables
db.exec(`
  CREATE TABLE accounts (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    balance REAL NOT NULL DEFAULT 0
  )
`);
db.exec(`
  CREATE TABLE transfers (
    id INTEGER PRIMARY KEY,
    from_account INTEGER,
    to_account INTEGER,
    amount REAL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )
`);

// Seed data
db.exec(`INSERT INTO accounts (name, balance) VALUES ('Alice', 1000)`);
db.exec(`INSERT INTO accounts (name, balance) VALUES ('Bob', 500)`);

/**
 * SAFE: Transaction with automatic rollback on failure
 *
 * BEGIN ... COMMIT ensures that either ALL operations succeed, or NONE of
 * them are applied (ROLLBACK on any throw). This prevents partial updates.
 */
function transferMoney(fromId: number, toId: number, amount: number) {
  const transfer = () => {
    // Check sender has sufficient funds
    const sender = db.prepare('SELECT balance FROM accounts WHERE id = ?').get(fromId) as { balance: number };
    if (!sender || sender.balance < amount) {
      throw new Error('Insufficient funds');
    }

    // Deduct from sender
    db.prepare('UPDATE accounts SET balance = balance - ? WHERE id = ?').run(amount, fromId);

    // Add to receiver
    db.prepare('UPDATE accounts SET balance = balance + ? WHERE id = ?').run(amount, toId);

    // Record the transfer
    db.prepare('INSERT INTO transfers (from_account, to_account, amount) VALUES (?, ?, ?)').run(fromId, toId, amount);

    return { success: true, amount };
  };

  db.exec('BEGIN');
  try {
    const result = transfer();
    db.exec('COMMIT');
    return result;
  } catch (error) {
    db.exec('ROLLBACK');
    return { success: false, error: (error as Error).message };
  }
}

// Test successful transfer
console.log('Before transfer:');
console.log(db.prepare('SELECT * FROM accounts').all());

console.log('\nTransfer $200 from Alice to Bob:');
console.log(transferMoney(1, 2, 200));

console.log('\nAfter transfer:');
console.log(db.prepare('SELECT * FROM accounts').all());
// Alice: 800, Bob: 700

// Test failed transfer (insufficient funds)
console.log('\nAttempt transfer $5000 from Alice to Bob:');
console.log(transferMoney(1, 2, 5000));
// Returns: { success: false, error: 'Insufficient funds' }

console.log('\nBalances unchanged after failed transfer:');
console.log(db.prepare('SELECT * FROM accounts').all());
// Alice: 800, Bob: 700 (no change - transaction rolled back)
