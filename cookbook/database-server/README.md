# Database MCP Server

A secure MCP server demonstrating safe database operations with comprehensive SQL injection prevention and parameterized queries.

## Overview

This cookbook demonstrates how to build a secure database access layer using the MCP Security Framework. It showcases:

- **Layer 2**: SQL injection pattern detection (`' OR 1=1 --`, `UNION SELECT`, etc.)
- **Layer 4**: Parameterized queries validation
- **Layer 4**: Per-tool quotas for different operation costs
- **Layer 4**: Side effect enforcement (read vs write)
- **Layer 4**: Response size limits

## Security Features Demonstrated

| Feature | Layer | Description |
|---------|-------|-------------|
| SQL Injection Prevention | L2, App | Pattern detection + parameterized queries |
| NoSQL Injection Prevention | L2 | Blocks `$where`, `$regex`, etc. |
| Per-Tool Rate Limits | L4 | Different quotas per operation cost |
| Side Effect Enforcement | L4 | Separates read and write operations |
| Response Size Limits | L4 | Max egress bytes per tool |
| Input Validation | App | Zod schemas with constraints |
| Transaction Safety | App | Atomic writes with rollback |

## Installation

```bash
cd cookbook/database-server
npm install
npm run build
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VERBOSE_LOGGING` | `false` | Enable debug logging |
| `MAX_REPORT_SIZE` | `524288` | Max report size in bytes (500KB) |

### Basic Configuration

```typescript
const server = new SecureMcpServer({
  name: 'database-server',
  version: '1.0.0',
}, {
  defaultPolicy: {
    allowNetwork: false,
    allowWrites: true,  // Enable write operations
  },
});
```

### Advanced Configuration

```typescript
const server = new SecureMcpServer({
  name: 'database-server',
  version: '1.0.0',
}, {
  toolRegistry: [
    {
      name: 'query-users',
      sideEffects: 'read',
      maxArgsSize: 512,
      maxEgressBytes: 50 * 1024,    // 50KB for user list
      quotaPerMinute: 60,
      quotaPerHour: 1000,
    },
    {
      name: 'create-order',
      sideEffects: 'write',
      maxArgsSize: 24 * 1024,       // 24KB: fits 50 items with 3-byte UTF-8 product names
      maxEgressBytes: 2 * 1024,     // 2KB response
      quotaPerMinute: 10,           // Limited writes
      quotaPerHour: 200,
    },
    {
      name: 'generate-report',
      sideEffects: 'read',
      maxArgsSize: 256,
      maxEgressBytes: 500 * 1024,   // 500KB for reports
      quotaPerMinute: 2,            // Expensive operation
      quotaPerHour: 20,
    },
    {
      name: 'health-check',
      sideEffects: 'none',
      quotaPerMinute: 120,          // No effective limit
    },
  ],
  maxRequestsPerMinute: 100,
  maxRequestsPerHour: 2000,
});
```

## Tools Reference

### query-users

Search for users by name or email using parameterized queries.

**Parameters:**
- `search` (string, required): Search term (1-100 chars)
- `department` (string, optional): Filter by department
- `limit` (number, optional): Max results 1-100 (default: 20)

**Example:**
```json
{
  "search": "john",
  "department": "Engineering",
  "limit": 10
}
```

**Response:**
```json
{
  "count": 2,
  "limit": 10,
  "users": [
    {
      "id": 1,
      "name": "Alice Johnson",
      "email": "alice@example.com",
      "department": "Engineering",
      "createdAt": "2024-01-15 09:00:00"
    }
  ]
}
```

### create-order

Create a new order with transaction safety.

**Parameters:**
- `userId` (integer, required): User ID placing the order
- `items` (array, required): Order items (1-50 items)
  - `product` (string): Product name (1-100 chars)
  - `quantity` (integer): Quantity 1-1000
  - `price` (number): Price per unit 0-1,000,000
- `total` (number, required): Total amount (validated against items)

**Example:**
```json
{
  "userId": 1,
  "items": [
    { "product": "Widget", "quantity": 2, "price": 29.99 },
    { "product": "Gadget", "quantity": 1, "price": 49.99 }
  ],
  "total": 109.97
}
```

**Response:**
```json
{
  "success": true,
  "orderId": 11,
  "userId": 1,
  "userName": "Alice Johnson",
  "itemCount": 2,
  "total": 109.97,
  "status": "pending",
  "createdAt": "2024-01-15T10:30:00.000Z"
}
```

### generate-report

Generate sales analytics with various grouping options.

**Parameters:**
- `startDate` (string, required): Start date YYYY-MM-DD
- `endDate` (string, required): End date YYYY-MM-DD
- `groupBy` (enum, optional): day | week | month | department | status (default: month)

**Example:**
```json
{
  "startDate": "2024-01-01",
  "endDate": "2024-12-31",
  "groupBy": "department"
}
```

**Response:**
```json
{
  "report": {
    "startDate": "2024-01-01",
    "endDate": "2024-12-31",
    "groupBy": "department",
    "generatedAt": "2024-01-15T10:30:00.000Z"
  },
  "summary": {
    "totalOrders": 150,
    "totalRevenue": 45000.00,
    "avgOrderValue": 300.00,
    "uniqueCustomers": 45
  },
  "data": [
    { "department": "Engineering", "userCount": 10, "orderCount": 50, "totalRevenue": 15000 }
  ]
}
```

### health-check

Check database connection status and get basic statistics.

**Parameters:** None

**Response:**
```json
{
  "status": "healthy",
  "database": {
    "type": "sqlite",
    "mode": "in-memory",
    "connected": true,
    "responseTimeMs": 2
  },
  "statistics": {
    "userCount": 10,
    "orderCount": 150,
    "latestOrderAt": "2024-01-15 10:30:00"
  },
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

## Security Analysis

### Attacks Prevented

| Attack | Payload Example | Prevention |
|--------|-----------------|------------|
| SQL Injection | `' OR '1'='1` | Layer 2 pattern + parameterized queries |
| DROP TABLE | `'; DROP TABLE users; --` | Pattern detection + prepared statements |
| UNION SELECT | `' UNION SELECT * FROM passwords --` | Pattern detection |
| Tautology Attack | `' OR 1=1 --` | Layer 2 content validation |
| Comment Injection | `admin'--` | Pattern detection |
| Stacked Queries | `'; INSERT INTO admin --` | Pattern detection |
| NoSQL Injection | `{ "$gt": "" }` | Layer 2 NoSQL patterns |
| Integer Overflow | `9999999999999` | Zod schema constraints |
| XSS in Stored Data | `<script>alert('xss')</script>` | Input validation |

### Safe vs Unsafe Code

This server demonstrates the **safe** approach to database queries:

```typescript
// UNSAFE - SQL Injection Vulnerable (DO NOT USE)
const query = `SELECT * FROM users WHERE name = '${search}'`;

// SAFE - Parameterized Query (What this server uses)
const query = `SELECT * FROM users WHERE name = ?`;
const stmt = db.prepare(query);
const users = stmt.all(search);
```

### Defense in Depth

The database server implements multiple layers of protection:

1. **Layer 2 Pattern Detection**: Known SQL injection patterns blocked before reaching app
2. **Parameterized Queries**: All database queries use prepared statements
3. **Zod Input Validation**: Strong typing with constraints (min/max, regex patterns)
4. **Business Logic Validation**: User existence checks, total amount verification
5. **Transaction Safety**: Atomic writes with automatic rollback on failure
6. **Rate Limiting**: Per-tool quotas prevent abuse
7. **Response Limits**: Max egress bytes prevent data exfiltration

## Testing

```bash
# Run all tests (43 security tests)
npm test

# Watch mode
npm run test:watch
```

### Test Coverage

The test suite covers:
- 15+ SQL injection payloads
- 5+ NoSQL injection payloads
- Input validation edge cases
- Concurrent access safety
- XSS prevention in stored data
- Numeric overflow prevention

## Claude Desktop Integration

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS, `~/.config/Claude/claude_desktop_config.json` on Linux):

```json
{
  "mcpServers": {
    "database": {
      "command": "node",
      "args": ["dist/index.js"],
      "cwd": "/path/to/cookbook/database-server",
      "env": {
        "VERBOSE_LOGGING": "false"
      }
    }
  }
}
```

## Common Issues

### "Request could not be processed" for writes

Ensure `allowWrites` is enabled in the default policy:
```typescript
defaultPolicy: {
  allowWrites: true,
}
```

### Rate limit exceeded

Adjust per-tool quotas for your use case:
```typescript
{
  name: 'generate-report',
  quotaPerMinute: 10,  // Increase from default 2
}
```

### Total mismatch error on create-order

The total must match the sum of (quantity * price) for all items. Use precise decimal calculations:
```typescript
const total = items.reduce((sum, item) => sum + item.quantity * item.price, 0);
```

## License

MIT - Part of the MCP Security Framework cookbook examples.
