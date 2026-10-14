/**
 * HTTP session example: run it, then connect several clients at once.
 *
 *   npm run dev                         # http://127.0.0.1:3010/mcp
 *   claude mcp add --transport http sessions http://127.0.0.1:3010/mcp
 *   npx @modelcontextprotocol/inspector # UI on http://localhost:6274 (listed in allowedOrigins)
 *
 * Environment: PORT (3010), HOST (127.0.0.1), ALLOWED_ORIGINS (comma-separated),
 * SECURITY_LEVEL (standard), IDLE_TTL_MS, MAX_SESSIONS_PER_CLIENT, LOG_REQUESTS (one line per request).
 */
import { createExample } from './server.js';

const PORT = Number(process.env.PORT ?? 3010);
// Loopback by default: the transport has no authentication, so anything that can reach the
// port can create a session and call tools. Bind wider only behind authentication.
const HOST = process.env.HOST ?? '127.0.0.1';
const numberFromEnv = (name: string) => (process.env[name] ? Number(process.env[name]) : undefined);

const { handler, listener } = createExample({
  allowedOrigins: process.env.ALLOWED_ORIGINS?.split(',').map(s => s.trim()).filter(Boolean),
  securityLevel: process.env.SECURITY_LEVEL as 'basic' | 'standard' | 'paranoid' | undefined,
  httpSessionIdleTtlMs: numberFromEnv('IDLE_TTL_MS'),
  maxHttpSessionsPerClient: numberFromEnv('MAX_SESSIONS_PER_CLIENT'),
  logRequest: process.env.LOG_REQUESTS ? line => console.log(`[req] ${line}`) : undefined
});

listener.listen(PORT, HOST, () => {
  console.log(`MCP HTTP session example on http://${HOST}:${PORT}/mcp`);
});

let last = -1;
setInterval(() => {
  if (handler.sessionCount !== last) {
    last = handler.sessionCount;
    console.log(`[sessions] ${last} open`);
  }
}, 2000).unref();

const shutdown = async () => {
  console.log('shutting down: closing sessions first');
  await handler.close(); // a GET stream whose client stopped reading is destroyed after 5 s
  listener.close(() => process.exit(0));
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
