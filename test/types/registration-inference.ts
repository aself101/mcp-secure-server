/**
 * Type-level regression guard for SecureMcpServer's registration methods.
 *
 * Compiled by `npm run check:types` against the package's own published
 * declarations (self-reference `mcp-secure-server` -> dist/). Until
 * 0.0.24-security `tool()` / `registerTool()` were typed
 * `(name, ...rest: unknown[]) => unknown`: handler arguments were implicitly
 * `any` and the README quick start failed `tsc --strict` (TS7031). This file
 * fails the check if that inference is ever lost again:
 *  - the quick start must compile under strict mode, and
 *  - each `@ts-expect-error` must still find an error — if `left` degrades to
 *    `any`, `left.toUpperCase()` stops erroring and tsc reports the directive
 *    as unused (TS2578).
 */
import { SecureMcpServer } from 'mcp-secure-server';
import { z } from 'zod';

const server = new SecureMcpServer(
  { name: 'types-fixture', version: '1.0.0' },
  { securityLevel: 'standard', toolRegistry: [{ name: 'calculator', sideEffects: 'none' }] },
);

// README quick start, verbatim shape.
server.tool('calculator', 'Basic calculator', {
  left: z.number(),
  right: z.number(),
}, async ({ left, right }) => {
  return { content: [{ type: 'text', text: `Result: ${left + right}` }] };
});

// Arguments are inferred from the schema, not `any`.
server.tool('inferred', 'args are numbers', { left: z.number() }, async ({ left }) => {
  // @ts-expect-error — `left` is a number
  left.toUpperCase();
  return { content: [{ type: 'text', text: String(left) }] };
});

// registerTool infers from inputSchema too.
server.registerTool('registered', { inputSchema: { name: z.string() } }, async ({ name }) => {
  // @ts-expect-error — `name` is a string
  name.toFixed(2);
  return { content: [{ type: 'text', text: name }] };
});

// A handler must return a CallToolResult-compatible value.
// @ts-expect-error — a bare string is not a tool result
server.tool('bad-result', 'wrong return', { x: z.string() }, async () => 'not a result');
