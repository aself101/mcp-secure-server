# Multi-Endpoint MCP Server

> **Experimental (mcp-secure-server 0.1.0).** The HTTP transport serves many clients, one MCP
> session each, but it has **no authentication**: anything that can reach the port can open a
> session on either endpoint, `/api/admin` included. The paths separate tools, not users. Keep it
> on `127.0.0.1` (the default here) and read *HTTP Transport* in the main README before exposing
> it. Through 0.0.27 this transport answered only the first request per process; this example's
> tests now drive several SDK clients per endpoint at once.

An advanced MCP server demonstrating multiple endpoints with different tools and security policies. Uses `createSecureHttpHandler` to compose separate MCP servers on different HTTP paths.

## Architecture

```text
┌─────────────────────────────────────────────────────┐
│                   HTTP Server                        │
│                  127.0.0.1:3000                      │
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
│  │  Writes: NO      │    │  Writes: NO      │      │
│  │  Network: YES    │    │  Network: NO     │      │
│  │  Rate: default   │    │  Rate: 100/min   │      │
│  └──────────────────┘    └──────────────────┘      │
│                                                      │
└─────────────────────────────────────────────────────┘
```

## Features

- **Endpoint Isolation**: Admin and public tools on separate paths
- **Different Security Policies**: Admin has more permissions, public has stricter limits
- **Separate Rate Limits**: each server has its own Layer 3 budget (public: 100/min), shared by that server's clients
- **Selective Logging**: Admin logs everything, public minimal logging
- **Sessions**: every client gets its own MCP session on each endpoint it initializes
- **CORS for listed origins only**: browser clients from `ALLOWED_ORIGINS`; any other origin gets 403
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
- Admin API: `http://127.0.0.1:3000/api/admin`
- Public API: `http://127.0.0.1:3000/api/public`

| Variable | Default | Description |
|----------|---------|-------------|
| PORT | 3000 | HTTP server port |
| HOST | 127.0.0.1 | Address to bind; wider only behind authentication |
| ALLOWED_ORIGINS | (none) | Comma-separated browser origins, e.g. `http://localhost:5173` |

Any MCP client handles sessions for you:

```bash
claude mcp add --transport http public-api http://127.0.0.1:3000/api/public
```

## Calling it with curl

Sessions are per endpoint: initialize on the path you will call, then send the
`Mcp-Session-Id` it returned with every request there (400 without it, 404 for an id the server
did not issue or has closed):

```bash
URL=http://127.0.0.1:3000/api/admin   # or /api/public
H=(-H "Content-Type: application/json" -H "Accept: application/json, text/event-stream")

SID=$(curl -s -D - -o /dev/null -X POST $URL "${H[@]}" \
  -d '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"1"}}}' \
  | awk -F': ' 'tolower($1)=="mcp-session-id" {print $2}' | tr -d '\r')
curl -s -X POST $URL "${H[@]}" -H "Mcp-Session-Id: $SID" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'

# ... tool calls below ...

curl -s -X DELETE $URL -H "Mcp-Session-Id: $SID"   # end the session
```

Responses arrive as server-sent events; the `data:` line carries the JSON-RPC message.

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
curl -X POST $URL "${H[@]}" -H "Mcp-Session-Id: $SID" \
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
curl -X POST $URL "${H[@]}" -H "Mcp-Session-Id: $SID" \
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
curl -X POST $URL "${H[@]}" -H "Mcp-Session-Id: $SID" \
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
curl -X POST $URL "${H[@]}" -H "Mcp-Session-Id: $SID" \
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
import { SecureMcpServer, createSecureHttpHandler } from 'mcp-secure-server';

// Create separate MCP servers and register their tools FIRST:
// creating a handler freezes that server's registrations.
const adminServer = new SecureMcpServer({ name: 'admin', version: '1.0' });
const publicServer = new SecureMcpServer({ name: 'public', version: '1.0' });
registerAdminTools(adminServer);
registerPublicTools(publicServer);

// One session handler per server; the same browser-origin list for each
const allowedOrigins = ['http://localhost:5173'];
const adminHandler = createSecureHttpHandler(adminServer, { allowedOrigins });
const publicHandler = createSecureHttpHandler(publicServer, { allowedOrigins });

// Compose with custom routing
const httpServer = createServer(async (req, res) => {
  if (req.url?.startsWith('/api/admin')) return adminHandler(req, res);
  if (req.url?.startsWith('/api/public')) return publicHandler(req, res);
  res.writeHead(404).end();
});
httpServer.listen(3000, '127.0.0.1');

// Shutting down: close every session, then the listener
await Promise.all([adminHandler.close(), publicHandler.close()]);
httpServer.close();
```

### CORS

`src/app.ts` wraps the routing for browser clients: it echoes the request's `Origin` only when
it is in `allowedOrigins` (never `*`, never `null`), answers preflights, allows
`GET, POST, DELETE, OPTIONS` and the `Mcp-Session-Id` request header, and exposes
`Mcp-Session-Id` so a page can read it. The same list goes to both handlers, which refuse any
other origin with 403.

**The wrapper must never delete or rewrite `Origin`.** The handlers validate it; a wrapper that
strips it turns that check off for every web page on the machine. A client with an opaque origin
(a `file://` page, a sandboxed frame) sends `Origin: null`, which cannot be listed: connect from
a context that sends no `Origin` (Electron's main process, a server-side client) or from a listed
origin.

## Behind a Reverse Proxy

Each `createSecureHttpHandler` resolves the client address for its own per-client limits. Behind a
proxy, pass the **same** `trustProxy` to every handler (and to any limiter you add around them):

```typescript
const trustProxy = ['10.0.0.12']; // your proxy's exact address — not a range clients could connect from
const adminHandler = createSecureHttpHandler(adminServer, { trustProxy });
const publicHandler = createSecureHttpHandler(publicServer, { trustProxy });
```

See *Client IP and `trustProxy`* in the main README.

## Testing

```bash
npm test
```

Tests run against the example's own app (`src/app.ts`) and verify:
- Routing to correct handlers
- Tool execution on each endpoint
- Endpoint isolation (admin tools not on public, etc.)
- Several MCP SDK clients per endpoint at once, each in its own session
- CORS for the listed origin, 403 for an unlisted one
- Security validation

## Use Cases

1. **Admin vs User Access**: Different tools for administrators and regular users
2. **Internal vs External APIs**: More features internally, restricted public API
3. **Different tool sets per audience** — not multi-tenant isolation: there is no authentication,
   and Layer 3's budget is shared by every client of a server until 0.2.0
4. **API Versioning**: v1 and v2 on different paths with different capabilities
