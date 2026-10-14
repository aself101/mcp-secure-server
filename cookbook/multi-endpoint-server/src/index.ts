/**
 * Multi-Endpoint MCP Server Example
 *
 * Demonstrates using createSecureHttpHandler to compose multiple MCP servers
 * with different tools and security policies on separate endpoints. Every client
 * gets its own MCP session on each endpoint it initializes.
 *
 * - /api/admin - Admin API with user management and system stats
 * - /api/public - Public API with health and status checks
 *
 * Environment: PORT (3000), HOST (127.0.0.1), ALLOWED_ORIGINS (comma-separated browser origins).
 */

import { createMultiEndpointApp } from './app.js';

const app = createMultiEndpointApp({
  allowedOrigins: process.env.ALLOWED_ORIGINS?.split(',').map(s => s.trim()).filter(Boolean)
});

const PORT = parseInt(process.env.PORT || '3000', 10);
// Loopback by default: the transport has no authentication, so anything that can reach the
// port can open a session on either endpoint, admin included. Bind wider only behind authentication.
const HOST = process.env.HOST || '127.0.0.1';

app.listener.listen(PORT, HOST, () => {
  const base = `http://${HOST}:${PORT}`;
  console.log(`Multi-Endpoint MCP Server listening on ${base}`);
  console.log('');
  console.log('Available endpoints:');
  console.log(`  Admin API:  ${base}/api/admin`);
  console.log('    - list-users: List all users (admin only)');
  console.log('    - system-stats: Get system metrics');
  console.log('');
  console.log(`  Public API: ${base}/api/public`);
  console.log('    - health: Health check');
  console.log('    - status: Service status');
  console.log('');
  console.log('Connect an MCP client to an endpoint (it handles sessions for you):');
  console.log(`  claude mcp add --transport http public-api ${base}/api/public`);
  console.log('By hand with curl, initialize first and send the Mcp-Session-Id it returns (see README).');
});

const shutdown = () => { void app.close().then(() => process.exit(0)); };
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
