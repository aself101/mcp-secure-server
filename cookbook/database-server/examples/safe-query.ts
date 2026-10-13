/**
 * Safe Query Example
 *
 * Demonstrates the CORRECT way to query databases using parameterized queries.
 * This pattern prevents SQL injection attacks by separating SQL code from data.
 */

import { DatabaseSync } from 'node:sqlite';

const db = new DatabaseSync(':memory:');

// Setup example table
db.exec(`
  CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL
  )
`);
db.exec(`INSERT INTO users (name, email) VALUES ('Alice', 'alice@example.com')`);
db.exec(`INSERT INTO users (name, email) VALUES ('Bob', 'bob@example.com')`);

/**
 * SAFE: Parameterized Query
 *
 * The ? placeholder is replaced with the search value by the database driver.
 * The database treats the value as DATA, not as SQL code.
 * Even if search contains SQL syntax, it won't be executed.
 */
function safeSearch(search: string) {
  // The search value is passed as a parameter, NOT concatenated into the query
  const query = `SELECT * FROM users WHERE name LIKE ? OR email LIKE ?`;
  const stmt = db.prepare(query);

  // Parameters are bound safely - they can NEVER be interpreted as SQL
  const searchPattern = `%${search}%`;
  return stmt.all(searchPattern, searchPattern);
}

// Test with normal input
console.log('Normal search for "alice":');
console.log(safeSearch('alice'));

// Test with SQL injection attempt - it's treated as literal text
console.log('\nSQL injection attempt "\\' OR 1=1 --":');
console.log(safeSearch("' OR 1=1 --"));
// Returns empty array - the injection is treated as a literal search string

// Test with another injection attempt
console.log('\nDROP TABLE attempt:');
console.log(safeSearch("'; DROP TABLE users; --"));
// Returns empty array - no tables are dropped!

console.log('\nTable still exists:');
console.log(db.prepare('SELECT COUNT(*) as count FROM users').get());
// Output: { count: 2 } - both users still exist
