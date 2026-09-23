# Transaction MCP Server

Demonstrates Layer 4 method chaining security with a financial transaction pipeline.

## Overview

This cookbook showcases how **method chaining enforcement** creates a secure state machine for financial operations. The server prevents:

- **Out-of-order operations**: Cannot execute before confirming
- **State confusion attacks**: Cannot skip validation steps
- **Session hijacking**: Each session maintains isolated state
- **Protocol violations**: MCP method order is enforced

## Security Features

| Feature | Layer | Description |
|---------|-------|-------------|
| MCP Method Chaining | L4 | Enforces initialize -> tools/list -> tools/call |
| Workflow State Machine | L5 | Custom validator enforces transaction flow |
| Session Isolation | L4+L5 | Each client has independent state |
| Side Effect Control | L4 | Only execute-transaction has write permission |
| Per-Tool Quotas | L4 | execute-transaction limited to 10/min |

## Transaction Workflow

```text
DISCONNECTED
     │
     └── connect-session ─────────────────────────────────────┐
                                                              │
                                                              v
CONNECTED ─────── list-accounts ────────> ACCOUNTS_LISTED ───┐
     │                                         │              │
     │                           select-account│              │
     │                                         v              │
     │                                 ACCOUNT_SELECTED ─────┐│
     │                                         │             ││
     │                        prepare-transaction│            ││
     │                                         v             ││
     │                             TRANSACTION_PREPARED ────┐││
     │                                         │            │││
     │                       confirm-transaction│           │││
     │                                         v            │││
     │                             TRANSACTION_CONFIRMED ──┐│││
     │                                         │           ││││
     │                       execute-transaction│          ││││
     │                                         v           ││││
     │                             TRANSACTION_EXECUTED ───┤│││
     │                                                     ││││
     └─────────────── disconnect-session ──────────────────┘┘┘┘
```

## Tools

| Tool | State Required | Side Effects | Rate Limit |
|------|----------------|--------------|------------|
| `connect-session` | DISCONNECTED | none | 60/min |
| `list-accounts` | CONNECTED | read | 60/min |
| `select-account` | ACCOUNTS_LISTED | none | 60/min |
| `prepare-transaction` | ACCOUNT_SELECTED | none | 30/min |
| `confirm-transaction` | TRANSACTION_PREPARED | none | 30/min |
| `execute-transaction` | TRANSACTION_CONFIRMED | write | 10/min |
| `check-status` | CONNECTED+ | read | 120/min |
| `disconnect-session` | CONNECTED+ | none | 60/min |

## Attacks Prevented

### 1. Out-of-Order Execution
```text
Attacker: execute-transaction (without prepare/confirm)
Result: BLOCKED - "Invalid workflow: 'execute-transaction' not allowed in state 'CONNECTED'"
```

### 2. Skipping Confirmation
```text
Attacker: prepare-transaction -> execute-transaction
Result: BLOCKED - "Invalid workflow: 'execute-transaction' not allowed in state 'TRANSACTION_PREPARED'"
```

### 3. Session Confusion
```text
Session A: Advanced to TRANSACTION_CONFIRMED
Session B: Tries execute-transaction
Result: BLOCKED - Session B is still in CONNECTED state
```

### 4. Protocol Violation (Layer 4)
```text
Attacker: tools/call (before tools/list)
Result: BLOCKED by Layer 4 - "Method chaining not allowed: * -> tools/call"
```

## Installation

```bash
cd cookbook/transaction-server
npm install
npm run build
```

## Claude Desktop Configuration

```json
{
  "mcpServers": {
    "transaction": {
      "command": "node",
      "args": ["dist/index.js"],
      "cwd": "/path/to/mcp-secure-server/cookbook/transaction-server"
    }
  }
}
```

## Session Management

**Important:** The server tracks sessions using `clientId`. Tools that don't have a `clientId` parameter (like `list-accounts`, `check-status`) default to `clientId: "default"`.

**Recommended:** Use `clientId: "default"` when connecting to ensure all tools use the same session:

```text
connect-session(clientId: "default")  ✅ Works with all tools
connect-session(clientId: "my-id")    ⚠️  Only works with tools that accept clientId
```

If you need multiple isolated sessions, ensure tools that support `clientId` pass it consistently.

## Example Session

```text
1. connect-session(clientId: "default") -> "Session connected. Next: list-accounts"
2. list-accounts          -> [Primary Checking $5,000, Savings $25,000, ...]
3. select-account(acct-001) -> "Selected Primary Checking"
4. prepare-transaction(to: acct-002, amount: 500) -> "Prepared. Next: confirm"
5. confirm-transaction(confirm: true) -> "Confirmed. Next: execute"
6. execute-transaction    -> "Transaction completed! $500 transferred"
7. disconnect-session     -> "Session ended"
```

## Testing

```bash
# Run security tests
npm test

# Watch mode
npm run test:watch
```

## Why Method Chaining Matters

Without method chaining, an attacker could:

1. **Skip validation**: Jump directly to execute without prepare/confirm
2. **Confuse state**: Interleave operations from multiple sessions
3. **Bypass checks**: Execute transactions without proper account selection
4. **Protocol abuse**: Call tools without proper MCP handshake

Method chaining creates a **deterministic state machine** that ensures every operation follows the correct sequence. Combined with Layer 4's MCP protocol enforcement, this provides defense-in-depth against sophisticated attacks.

## Configuration Options

```typescript
const server = new SecureMcpServer(
  { name: 'transaction-server', version: '1.0.0' },
  {
    // Enable Layer 4 method chaining
    enforceChaining: true,

    // Session timeout (30 minutes)
    sessionTtlMs: 30 * 60 * 1000,

    // Maximum concurrent sessions
    maxSessions: 1000,

    // Tool-specific rate limits via toolRegistry
    toolRegistry: [
      { name: 'execute-transaction', quotaPerMinute: 10, sideEffects: 'write' },
      // ...
    ],
  }
);
```

## License

MIT - Part of the MCP Security Framework cookbook examples.
