import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { createExample, type Example } from '../src/server.js';

describe('HTTP session example', () => {
  let example: Example;
  let url: URL;
  const warnings: string[] = [];

  beforeEach(async () => {
    warnings.length = 0;
    example = createExample({
      allowedOrigins: ['http://localhost:6274'],
      onWarning: (_message, code) => { warnings.push(code); }
    });
    await new Promise<void>(resolve => example.listener.listen(0, '127.0.0.1', resolve));
    const addr = example.listener.address();
    url = new URL(`http://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}/mcp`);
  });

  afterEach(async () => {
    await example.handler.close();
    example.listener.closeAllConnections();
    await new Promise<void>(resolve => example.listener.close(() => resolve()));
  });

  const connect = async (name: string) => {
    const client = new Client({ name, version: '1.0.0' });
    await client.connect(new StreamableHTTPClientTransport(url));
    return client;
  };
  const textOf = (result: unknown) => (result as { content: Array<{ text: string }> }).content[0]!.text;

  it('serves two clients at once, each in its own session', async () => {
    const [a, b] = await Promise.all([connect('client-a'), connect('client-b')]);
    const [whoA, whoB] = await Promise.all([
      a.callTool({ name: 'session-info', arguments: {} }),
      b.callTool({ name: 'session-info', arguments: {} })
    ]);
    const parsedA = JSON.parse(textOf(whoA));
    const parsedB = JSON.parse(textOf(whoB));
    expect(parsedA.client.name).toBe('client-a');
    expect(parsedB.client.name).toBe('client-b');
    expect(parsedA.session).not.toBe(parsedB.session);
    expect(example.handler.sessionCount).toBe(2);
    await Promise.all([a.close(), b.close()]);
  });

  it('refuses a runtime toggle: the client sees a tool error, the operator a warning', async () => {
    const client = await connect('toggler');
    const result = await client.callTool({ name: 'disable-notes-read', arguments: {} });
    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain('registrations are frozen');
    expect(warnings).toContain('MCP_SECURE_SERVER_LATE_REGISTRATION');
    const still = await client.callTool({ name: 'notes-read', arguments: { id: 'n1' } });
    expect(still.isError).toBeFalsy();
    await client.close();
  });

  it('answers CORS for the listed origin only, and the handler refuses an unlisted one', async () => {
    const preflight = (origin: string) => fetch(url, { method: 'OPTIONS', headers: { origin, 'access-control-request-method': 'POST' } });
    const listed = await preflight('http://localhost:6274');
    expect(listed.status).toBe(204);
    expect(listed.headers.get('access-control-allow-origin')).toBe('http://localhost:6274');
    expect(listed.headers.get('access-control-expose-headers')).toContain('Mcp-Session-Id');
    expect((await preflight('https://evil.example')).status).toBe(403);
    const post = await fetch(url, {
      method: 'POST',
      headers: { origin: 'https://evil.example', 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'x', version: '1' } } })
    });
    expect(post.status).toBe(403);
  });
});
