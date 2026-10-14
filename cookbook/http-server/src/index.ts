/**
 * Simple HTTP Server Example
 *
 * Demonstrates using SecureMcpServer with HTTP transport.
 * Exposes calculator and echo tools over a single HTTP endpoint; every client gets its own
 * MCP session, identified by the Mcp-Session-Id the server issues on `initialize`.
 */

import { createHttpExample } from './server.js';

const { httpServer } = createHttpExample({ verbose: process.env.VERBOSE_LOGGING === 'true' });

const PORT = parseInt(process.env.PORT || '3000', 10);
// Loopback by default: the transport has no authentication, so anything that can reach the
// port can open a session and call tools. Bind wider only behind authentication.
const HOST = process.env.HOST || '127.0.0.1';

httpServer.listen(PORT, HOST, () => {
  const url = `http://${HOST}:${PORT}/mcp`;
  console.log(`MCP HTTP Server listening on ${url}`);
  console.log('');
  console.log('Available tools:');
  console.log('  - calculator: Perform arithmetic (add, subtract, multiply, divide)');
  console.log('  - echo: Echo back messages with optional transforms');
  console.log('');
  console.log('Connect an MCP client (it handles sessions for you):');
  console.log(`  claude mcp add --transport http calculator ${url}`);
  console.log('');
  console.log('Or by hand with curl: initialize, then send the Mcp-Session-Id it returns:');
  console.log(`  curl -i -X POST ${url} -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \\`);
  console.log('    -d \'{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"1"}}}\'');
  console.log('  # see the README for the next two requests');
});

const shutdown = () => httpServer.close(() => process.exit(0)); // closes the sessions first
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
