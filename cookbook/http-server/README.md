# HTTP Server Example

> **Experimental (mcp-secure-server 0.1.0).** The HTTP transport serves many clients, one MCP
> session each, but it has **no authentication**, session ids are bearer credentials, and Layer 3
> rate limits are shared by every client of a server. Keep it on `127.0.0.1` (the default here)
> and read *HTTP Transport* in the main README before exposing it. Through 0.0.27 this transport
> answered only the first request per process; this example's tests now drive several requests
> per client, from more than one client at once.

A simple MCP server exposed over HTTP with security validation. Demonstrates using `SecureMcpServer.createHttpServer()` for single-endpoint HTTP transport.

For several clients at once — per-session logging and sampling, browser clients, the
registration freeze — see [`http-session-server`](../http-session-server).

## Features

- Single HTTP endpoint (`/mcp`), one MCP session per client (server-issued `Mcp-Session-Id`)
- Calculator and echo tools
- Built-in security validation (path traversal, injection detection)
- Per-tool quota (60 calls/minute per tool, shared by every client of the server — Layer 4)
- Zero external HTTP dependencies (uses `node:http`)

## Quick Start

```bash
# Install dependencies
npm install

# Build
npm run build

# Start server
npm start
# or with verbose logging:
VERBOSE_LOGGING=true npm start
```

Server starts at `http://127.0.0.1:3000/mcp`. It binds loopback because the transport has no
authentication: anything that can reach the port can open a session and call tools. Set `HOST`
to bind wider only behind authentication.

Any MCP client handles sessions for you:

```bash
claude mcp add --transport http calculator http://127.0.0.1:3000/mcp
```

## Calling it with curl

Every request after `initialize` carries the `Mcp-Session-Id` the server returned, or it is
refused (400 without the header, 404 with an id the server did not issue or has closed):

```bash
URL=http://127.0.0.1:3000/mcp
H=(-H "Content-Type: application/json" -H "Accept: application/json, text/event-stream")

# 1. initialize — the session id arrives as a response header
SID=$(curl -s -D - -o /dev/null -X POST $URL "${H[@]}" \
  -d '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"1"}}}' \
  | awk -F': ' 'tolower($1)=="mcp-session-id" {print $2}' | tr -d '\r')

# 2. tell the server the client is ready (202, no body)
curl -s -X POST $URL "${H[@]}" -H "Mcp-Session-Id: $SID" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'

# 3. call tools (examples below)

# 4. end the session (a later request with this id gets 404)
curl -s -X DELETE $URL -H "Mcp-Session-Id: $SID"
```

A session left open ends after 30 minutes idle.

## Tools

### calculator

Perform basic arithmetic operations.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| operation | string | Yes | One of: add, subtract, multiply, divide |
| a | number | Yes | First operand |
| b | number | Yes | Second operand |

**Example:**

```bash
curl -X POST $URL "${H[@]}" -H "Mcp-Session-Id: $SID" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "id": 1,
    "params": {
      "name": "calculator",
      "arguments": {
        "operation": "add",
        "a": 5,
        "b": 3
      }
    }
  }'
```

**Response** (a server-sent event; the `data:` line carries the JSON-RPC message):

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [{
      "type": "text",
      "text": "{\"operation\":\"add\",\"a\":5,\"b\":3,\"result\":8,\"expression\":\"5 + 3 = 8\"}"
    }]
  }
}
```

### echo

Echo back a message with optional transformations.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| message | string | Yes | - | Message to echo (1-1000 chars) |
| uppercase | boolean | No | false | Convert to uppercase |
| reverse | boolean | No | false | Reverse the message |

**Example:**

```bash
curl -X POST $URL "${H[@]}" -H "Mcp-Session-Id: $SID" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "id": 2,
    "params": {
      "name": "echo",
      "arguments": {
        "message": "Hello, World!",
        "uppercase": true
      }
    }
  }'
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| PORT | 3000 | HTTP server port |
| HOST | 127.0.0.1 | Address to bind; wider only behind authentication |
| VERBOSE_LOGGING | false | Enable detailed security logging |

### Server Options

```typescript
// Register every tool first: creating the HTTP server freezes registrations.
const httpServer = server.createHttpServer({
  endpoint: '/mcp',      // MCP endpoint path
  maxBodySize: 50 * 1024 // Max request body (50KB)
});
httpServer.listen(3000, '127.0.0.1');
```

Session options (`maxHttpSessions`, `maxHttpSessionsPerClient`, `httpSessionIdleTtlMs`) and
`allowedOrigins` for browser clients are described under *HTTP Transport* in the main README.

## Security Features

This server includes all 5 layers of MCP Security validation:

1. **Layer 1 (Structure)**: JSON-RPC format validation
2. **Layer 2 (Content)**: Path traversal, injection detection
3. **Layer 3 (Behavior)**: Rate limiting and burst detection (one budget per server, shared by every client until 0.2.0)
4. **Layer 4 (Semantics)**: Tool contract enforcement and per-tool quotas (60 calls/min per tool here, shared by every client)
5. **Layer 5 (Contextual)**: Custom validators (extensible)

### Blocked Attacks

```bash
# Path traversal - BLOCKED
curl -X POST $URL "${H[@]}" -H "Mcp-Session-Id: $SID" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "id": 1,
    "params": {
      "name": "echo",
      "arguments": {"message": "../../../etc/passwd"}
    }
  }'
# Returns 400 with error code -32602
```

## Behind a Reverse Proxy

Per-client limits (the per-client session cap, the error lockout and the GET/DELETE ceilings) key on the TCP peer by default
and ignore `X-Forwarded-For`, which any client can write. Behind nginx, a load balancer or a CDN,
tell the server which proxies to trust, or every client shares the proxy's single budget:

```typescript
server.createHttpServer({ endpoint: '/mcp', trustProxy: ['10.0.0.12'] }); // your proxy's address
```

The proxy must append to `X-Forwarded-For`. See *Client IP and `trustProxy`* in the main README.

## Testing

```bash
npm test
```

The tests call the tools over raw HTTP (with the session handshake above) and with two MCP SDK
clients at once, several calls each, and check that an id the server never issued gets 404.

## Claude Code and Claude Desktop

Claude Code connects to HTTP servers directly (`claude mcp add --transport http …`, above). For
stdio-based Claude Desktop integration, see the cookbook examples that use `StdioServerTransport`.
