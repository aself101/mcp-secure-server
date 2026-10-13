# HTTP Server Example

A simple MCP server exposed over HTTP with security validation. Demonstrates using `SecureMcpServer.createHttpServer()` for single-endpoint HTTP transport.

## Features

- Single HTTP endpoint (`/mcp`)
- Calculator and echo tools
- Built-in security validation (path traversal, injection detection)
- Rate limiting (60 requests/minute per tool)
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

Server starts at `http://localhost:3000/mcp`

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
curl -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
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

**Response:**

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
curl -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
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
| VERBOSE_LOGGING | false | Enable detailed security logging |

### Server Options

```typescript
const httpServer = server.createHttpServer({
  endpoint: '/mcp',      // MCP endpoint path
  maxBodySize: 50 * 1024 // Max request body (50KB)
});
```

## Security Features

This server includes all 5 layers of MCP Security validation:

1. **Layer 1 (Structure)**: JSON-RPC format validation
2. **Layer 2 (Content)**: Path traversal, injection detection
3. **Layer 3 (Behavior)**: Rate limiting (60 req/min per tool)
4. **Layer 4 (Semantics)**: Tool contract enforcement
5. **Layer 5 (Contextual)**: Custom validators (extensible)

### Blocked Attacks

```bash
# Path traversal - BLOCKED
curl -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
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

Per-client limits (the error lockout and the GET/DELETE ceilings) key on the TCP peer by default
and ignore `X-Forwarded-For`, which any client can write. Behind nginx, a load balancer or a CDN,
tell the server which proxies to trust, or every client shares the proxy's single budget:

```typescript
server.createHttpServer({ endpoint: '/mcp', trustProxy: ['uniquelocal'] }); // proxy in a private subnet
```

The proxy must append to `X-Forwarded-For`. See *Client IP and `trustProxy`* in the main README.

## Testing

```bash
npm test
```

## Claude Desktop Integration

While this server uses HTTP transport (not stdio), you can still integrate with Claude Desktop using a proxy or by modifying Claude's configuration to support HTTP MCP servers.

For stdio-based Claude Desktop integration, see the other cookbook examples that use `StdioServerTransport`.
