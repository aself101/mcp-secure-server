# Multi-Endpoint MCP Server

An advanced MCP server demonstrating multiple endpoints with different tools and security policies. Uses `createSecureHttpHandler` to compose separate MCP servers on different HTTP paths.

## Architecture

```text
┌─────────────────────────────────────────────────────┐
│                   HTTP Server                        │
│                  localhost:3000                      │
├─────────────────────────────────────────────────────┤
│                                                      │
│  ┌──────────────────┐    ┌──────────────────┐      │
│  │   /api/admin     │    │   /api/public    │      │
│  │                  │    │                  │      │
│  │  Admin Handler   │    │  Public Handler  │      │
│  │  ┌────────────┐  │    │  ┌────────────┐  │      │
│  │  │ list-users │  │    │  │   health   │  │      │
│  │  │ sys-stats  │  │    │  │   status   │  │      │
│  │  └────────────┘  │    │  └────────────┘  │      │
│  │                  │    │                  │      │
│  │  Logging: ON     │    │  Logging: OFF    │      │
│  │  Writes: YES     │    │  Writes: NO      │      │
│  │  Rate: 30/min    │    │  Rate: 100/min   │      │
│  └──────────────────┘    └──────────────────┘      │
│                                                      │
└─────────────────────────────────────────────────────┘
```

## Features

- **Endpoint Isolation**: Admin and public tools on separate paths
- **Different Security Policies**: Admin has more permissions, public has stricter limits
- **Separate Rate Limits**: Admin 30/min, Public 100/min global
- **Selective Logging**: Admin logs everything, public minimal logging
- **CORS Support**: Browser clients can access the API
- **Zero External Dependencies**: Uses `node:http` directly

## Quick Start

```bash
# Install dependencies
npm install

# Build
npm run build

# Start server
npm start
```

Server starts with two endpoints:
- Admin API: `http://localhost:3000/api/admin`
- Public API: `http://localhost:3000/api/public`

## Endpoints

### Admin API (`/api/admin`)

Higher privileges, detailed logging, user management.

#### list-users

List all users in the system.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| limit | number | 10 | Max users to return (1-100) |
| offset | number | 0 | Pagination offset |
| role | string | - | Filter by role (admin, user, guest) |

```bash
curl -X POST http://localhost:3000/api/admin \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "id": 1,
    "params": {
      "name": "list-users",
      "arguments": {"limit": 5, "role": "admin"}
    }
  }'
```

#### system-stats

Get system statistics and health metrics.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| verbose | boolean | false | Include detailed memory/CPU stats |

```bash
curl -X POST http://localhost:3000/api/admin \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "id": 1,
    "params": {
      "name": "system-stats",
      "arguments": {"verbose": true}
    }
  }'
```

### Public API (`/api/public`)

Limited privileges, minimal logging, health checks only.

#### health

Simple health check endpoint.

```bash
curl -X POST http://localhost:3000/api/public \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "id": 1,
    "params": {"name": "health", "arguments": {}}
  }'
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

#### status

Get service status and version information.

```bash
curl -X POST http://localhost:3000/api/public \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "id": 1,
    "params": {"name": "status", "arguments": {}}
  }'
```

## Security Configuration

### Admin Server

```typescript
{
  enableLogging: true,
  toolRegistry: [
    { name: 'list-users', sideEffects: 'read', quotaPerMinute: 30 },
    { name: 'system-stats', sideEffects: 'none', quotaPerMinute: 60 }
  ],
  defaultPolicy: { allowNetwork: true, allowWrites: false }
}
```

### Public Server

```typescript
{
  enableLogging: false,
  toolRegistry: [
    { name: 'health', sideEffects: 'none', quotaPerMinute: 120 },
    { name: 'status', sideEffects: 'none', quotaPerMinute: 60 }
  ],
  defaultPolicy: { allowNetwork: false, allowWrites: false },
  maxRequestsPerMinute: 100
}
```

## Using createSecureHttpHandler

The key to multi-endpoint servers is `createSecureHttpHandler`:

```typescript
import { createServer } from 'node:http';
import { createSecureHttpHandler } from 'mcp-secure-server';

// Create separate MCP servers
const adminServer = new SecureMcpServer({ name: 'admin', version: '1.0' });
const publicServer = new SecureMcpServer({ name: 'public', version: '1.0' });

// Create handlers
const adminHandler = createSecureHttpHandler(adminServer);
const publicHandler = createSecureHttpHandler(publicServer);

// Compose with custom routing
const httpServer = createServer(async (req, res) => {
  if (req.url?.startsWith('/api/admin')) return adminHandler(req, res);
  if (req.url?.startsWith('/api/public')) return publicHandler(req, res);
  res.writeHead(404).end();
});
```

## Testing

```bash
npm test
```

Tests verify:
- Routing to correct handlers
- Tool execution on each endpoint
- Endpoint isolation (admin tools not on public, etc.)
- Security validation

## Use Cases

1. **Admin vs User Access**: Different tools for administrators and regular users
2. **Internal vs External APIs**: More features internally, restricted public API
3. **Multi-tenant**: Different MCP servers for different customers
4. **API Versioning**: v1 and v2 on different paths with different capabilities
