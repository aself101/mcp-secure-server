/**
 * Operation log, replay, freeze, Layer 5 name, and the warning channel
 * (spec http-transport-per-session v0.4.3, section A and D18; checklist Phase 1).
 *
 * Each assertion names, in a comment, the mutation that must make it fail; the
 * mutations were run when this file was written (checklist, Phase 1 record).
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { SecureMcpServer } from '../../../src/security/mcp-secure-server.js';
import { LateRegistrationError } from '../../../src/security/registration-log.js';
import { createSecureHttpHandler } from '../../../src/security/transport/http-server.js';
import { _resetProcessWarnings, type WarningCode } from '../../../src/security/warnings.js';

type Warning = { message: string; code: WarningCode };

function makeServer(extra: Record<string, unknown> = {}) {
  const warnings: Warning[] = [];
  const server = new SecureMcpServer({ name: 'log-test', version: '1.0.0' }, {
    onWarning: (message: string, code: WarningCode) => { warnings.push({ message, code }); },
    toolRegistry: ['a', 'b', 'c', 'd', 'a2', 'nos', 'late'].map(name => ({ name, sideEffects: 'read' as const })),
    ...extra
  });
  return { server, warnings };
}

const attach = (server: SecureMcpServer) => createSecureHttpHandler(server);
const codes = (warnings: Warning[]) => warnings.map(w => w.code);

/** Connect a client to an McpServer over an in-memory pair and return its listings. */
async function listings(server: McpServer) {
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await server.connect(st);
  const client = new Client({ name: 'c', version: '1' });
  await client.connect(ct);
  const caps = client.getServerCapabilities() ?? {};
  const out = {
    tools: caps.tools ? (await client.listTools()).tools : null,
    prompts: caps.prompts ? (await client.listPrompts()).prompts : null,
    resources: caps.resources ? (await client.listResources()).resources : null,
    caps
  };
  await client.close();
  await server.close();
  return out;
}

/** Probe 12's sequence, through the SecureMcpServer surface. */
function probe12Sequence(server: SecureMcpServer) {
  const cb = async () => ({ content: [] });
  const a = server.registerTool('a', {
    title: 'A', description: 'd', inputSchema: { q: z.string() },
    outputSchema: { n: z.number() }, annotations: { readOnlyHint: true }, _meta: { k: 1 }
  }, async () => ({ content: [], structuredContent: { n: 1 } }));
  const b = server.tool('b', cb);
  a.update({ name: 'a2' });
  b.disable();
  a.update({ description: 'x', paramsSchema: { q: z.string(), r: z.number() } });
  const c1 = server.tool('c', cb);
  c1.remove();
  server.tool('c', cb);
  c1.update({ name: 'd' }); // probe 09d: a removed handle acts on the reused name
  server.registerResource('r', 'file:///a', {}, async () => ({ contents: [] }));
  server.registerPrompt('p', { title: 'P' }, async () => ({ messages: [] }));
}

beforeEach(() => { _resetProcessWarnings(); });
afterEach(() => { vi.restoreAllMocks(); });

describe('operation log and replay', () => {
  it('replays exactly: a session lists what the primary lists, in full and in order', async () => {
    const { server } = makeServer();
    probe12Sequence(server);
    attach(server);
    // Mutation: drop handle calls that target a removed registration (the "obvious
    // cleanup") -> c1's rename is lost and the listings differ (probe 12's control).
    // Mutation: rebuild from tool() overload fields -> outputSchema and _meta are lost.
    const primary = await listings(server._mcpServer);
    const session1 = await listings(server._createSessionServer());
    const session2 = await listings(server._createSessionServer());
    expect(primary.tools?.map(t => t.name)).toEqual(['a2', 'd']);
    expect(session1.tools).toEqual(primary.tools);
    expect(session1.prompts).toEqual(primary.prompts);
    expect(session1.resources).toEqual(primary.resources);
    expect(session2).toEqual(session1);
    expect(session1.tools?.find(t => t.name === 'a2')).toMatchObject({ title: 'A', _meta: { k: 1 }, outputSchema: expect.anything() });
  });

  it('records nothing for a registration the connected primary refused (probe 11d)', async () => {
    const { server } = makeServer();
    server.tool('a', async () => ({ content: [] }));
    const [, st] = InMemoryTransport.createLinkedPair();
    await server.connect(st);
    // First prompt on a connected server: the SDK cannot declare the capability now.
    // Mutation: record before applying to the primary -> the session lists it.
    expect(() => server.registerPrompt('p', {}, async () => ({ messages: [] }))).toThrow();
    attach(server);
    const session = await listings(server._createSessionServer());
    expect(session.prompts).toBeNull();
    expect(session.tools?.map(t => t.name)).toEqual(['a']);
    await server.close();
  });

  it('records nothing for an update that throws part-way; sessions see none of it', async () => {
    const { server } = makeServer();
    const h = server.tool('a', 'original', async () => ({ content: [] }));
    // The SDK assigns description before paramsSchema; objectFromShape(null) throws.
    // Mutation: record before applying -> the session shows 'changed' (or every replay throws).
    expect(() => h.update({ description: 'changed', paramsSchema: null as never })).toThrow();
    attach(server);
    expect(server._mcpServer['_registeredTools'].a.description).toBe('changed'); // the SDK's partial change, primary only
    const session = await listings(server._createSessionServer());
    expect(session.tools?.[0]?.description).toBe('original');
  });

  it('records registerCapabilities, which returns nothing', async () => {
    const { server } = makeServer();
    server.registerCapabilities({ logging: {} });
    attach(server);
    // Mutation: record only calls that return a handle -> the session lacks logging.
    const session = await listings(server._createSessionServer());
    expect(session.caps.logging).toEqual({});
  });
});

describe('Layer 5', () => {
  async function callOverStdio(server: SecureMcpServer, name: string, args: Record<string, unknown>) {
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await server.connect(st);
    const client = new Client({ name: 'c', version: '1' });
    await client.connect(ct);
    const result = await client.callTool({ name, arguments: args });
    await client.close();
    await server.close();
    return result;
  }
  function spyLayer5(server: SecureMcpServer, verdict = { passed: true }) {
    const layer5 = server.validationPipeline.getLayerByClassName('ContextualValidationLayer') as unknown as {
      validateResponse: (...a: unknown[]) => Promise<unknown>;
    };
    return vi.spyOn(layer5, 'validateResponse').mockResolvedValue(verdict);
  }

  it('sees a renamed tool under the name the client called, over stdio', async () => {
    const { server } = makeServer();
    const spy = spyLayer5(server);
    const h = server.tool('a', { q: z.string() }, async ({ q }) => ({ content: [{ type: 'text', text: q }] }));
    h.update({ name: 'b' });
    // Mutation: capture the name at wrap time (0.0.27) -> "a" (probe 13C).
    await callOverStdio(server, 'b', { q: 'x' });
    expect(spy.mock.calls.map(c => (c[1] as { tool: string }).tool)).toEqual(['b']);
  });

  it('validates a callback installed by registration and one installed by update({ callback })', async () => {
    const { server } = makeServer();
    spyLayer5(server, { passed: false, reason: 'blocked', severity: 'HIGH' } as never);
    const h = server.tool('a', async () => ({ content: [{ type: 'text', text: 'raw' }] }));
    // Mutation: pass either callback through unwrapped -> 'raw' reaches the client.
    expect(await callOverStdio(server, 'a', {})).toMatchObject({ isError: true });
    h.update({ callback: async () => ({ content: [{ type: 'text', text: 'raw2' }] }) });
    expect(await callOverStdio(server, 'a', {})).toMatchObject({ isError: true });
  });

  it('gives a schema-less tool its extra and Layer 5 empty arguments', async () => {
    const { server } = makeServer();
    const spy = spyLayer5(server);
    let received: unknown;
    server.tool('nos', async (extra) => { received = extra; return { content: [] }; });
    // Mutation: keep handler(args) / pass the first argument as arguments -> both fail.
    await callOverStdio(server, 'nos', {});
    expect(received).toMatchObject({ requestId: expect.anything() });
    expect((spy.mock.calls[0]![1] as { arguments: unknown }).arguments).toEqual({});
  });
});

describe('stdio parity: no handler attached, nothing freezes', () => {
  it('registers, toggles and removes tools after connect(), and the client sees each change', async () => {
    const { server } = makeServer();
    // The SDK fixes capabilities at connect(), so one tool exists first; the rest arrive later.
    server.tool('a', async () => ({ content: [] }));
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await server.connect(st);
    const client = new Client({ name: 'c', version: '1' });
    await client.connect(ct);
    const names = async () => (await client.listTools()).tools.map(t => t.name).sort();

    // Mutation: freeze in connect() (or at construction) -> each of these throws LateRegistrationError.
    const late = server.tool('late', async () => ({ content: [{ type: 'text', text: 'late ran' }] }));
    expect(await names()).toEqual(['a', 'late']);
    expect(await client.callTool({ name: 'late', arguments: {} })).toMatchObject({ content: [{ text: 'late ran' }] });
    late.disable();
    expect(await names()).toEqual(['a']);
    late.enable();
    server.tool('b', async () => ({ content: [] }));
    expect(await names()).toEqual(['a', 'b', 'late']);
    late.remove();
    expect(await names()).toEqual(['a', 'b']);

    await client.close();
    await server.close();
  });
});

describe('the freeze', () => {
  it('leaves the server open when the handler constructor throws', () => {
    const { server } = makeServer();
    // Mutation: freeze first -> the later registration throws with no handler attached.
    expect(() => createSecureHttpHandler(server, { sessionlessRequestsPerMinute: 0 })).toThrow();
    expect(() => server.tool('late', async () => ({ content: [] }))).not.toThrow();
  });

  it('allows tool(), registerCapabilities() and handle calls before attach', () => {
    const { server } = makeServer();
    // Mutation: freeze at construction -> these throw.
    const h = server.tool('a', async () => ({ content: [] }));
    expect(() => server.registerCapabilities({ logging: {} })).not.toThrow();
    expect(() => h.disable()).not.toThrow();
  });

  it('refuses tool(), registerCapabilities() and handle calls after attach, changing nothing', () => {
    const { server, warnings } = makeServer();
    const h = server.tool('a', async () => ({ content: [] }));
    attach(server);
    const before = JSON.stringify(Object.keys(server._mcpServer['_registeredTools']));
    // Mutation: skip the frozen check in one of the three -> that case does not throw.
    // Mutation: skip the report -> no LATE_REGISTRATION warning.
    expect(() => server.tool('late', async () => ({ content: [] }))).toThrow(LateRegistrationError);
    expect(() => server.registerCapabilities({ logging: {} })).toThrow(LateRegistrationError);
    expect(() => h.disable()).toThrow(LateRegistrationError);
    expect(() => { (h as { enabled: boolean }).enabled = false; }).toThrow(LateRegistrationError);
    expect(JSON.stringify(Object.keys(server._mcpServer['_registeredTools']))).toBe(before);
    expect(server._mcpServer['_registeredTools'].a.enabled).toBe(true);
    expect(codes(warnings).filter(c => c === 'MCP_SECURE_SERVER_LATE_REGISTRATION')).toHaveLength(4);
    const err = (() => { try { h.disable(); } catch (e) { return e; } })() as LateRegistrationError;
    expect(err.name).toBe('LateRegistrationError');
    expect(err).toMatchObject({ method: 'disable', registrationName: 'a' });
    expect(err.message).toContain('kill switch belongs in the tool\'s callback');
  });

  it('counts a repeated late registration: reported at the 1st, 10th and 100th', () => {
    const { server, warnings } = makeServer();
    const h = server.tool('a', async () => ({ content: [] }));
    attach(server);
    for (let i = 0; i < 100; i++) expect(() => h.disable()).toThrow(LateRegistrationError);
    // Mutation: once per method and name (v0.4.2) -> 1 report.
    const late = warnings.filter(w => w.code === 'MCP_SECURE_SERVER_LATE_REGISTRATION');
    expect(late.map(w => /(\d+) so far/.exec(w.message)?.[1])).toEqual(['1', '10', '100']);
  });
});

describe('escape hatches', () => {
  it('reports one read after the freeze, once; registrations through it reach the primary', () => {
    const { server, warnings } = makeServer();
    attach(server);
    // Mutation: warn on every read -> more than one report.
    server.mcpServer.registerTool('raw', {}, async () => ({ content: [] }));
    void server.experimental;
    expect(codes(warnings).filter(c => c === 'MCP_SECURE_SERVER_ESCAPE_HATCH')).toHaveLength(1);
    expect(Object.keys(server._mcpServer['_registeredTools'])).toContain('raw');
  });

  it('reports a read made before the freeze, at the freeze', () => {
    const { server, warnings } = makeServer();
    void server.server;
    expect(codes(warnings)).not.toContain('MCP_SECURE_SERVER_ESCAPE_HATCH');
    attach(server);
    // Mutation: track only post-freeze reads (v0.4.2) -> no report.
    expect(codes(warnings).filter(c => c === 'MCP_SECURE_SERVER_ESCAPE_HATCH')).toHaveLength(1);
  });
});

describe('the warning channel (D18)', () => {
  it('reports server-level codes once to the one sink, across two handlers', () => {
    const { server, warnings } = makeServer();
    attach(server);
    attach(server);
    // Mutation: route through the security logger -> nothing with logging off.
    expect(codes(warnings).filter(c => c === 'MCP_SECURE_SERVER_HTTP_EXPERIMENTAL')).toHaveLength(1);
    expect(warnings[0]!.message).toContain('no authentication');
  });

  it('defaults to process.emitWarning with the code', () => {
    const emit = vi.spyOn(process, 'emitWarning').mockImplementation(() => {});
    const server = new SecureMcpServer({ name: 'd', version: '1' });
    attach(server);
    expect(emit).toHaveBeenCalledWith(expect.stringContaining('experimental'), { code: 'MCP_SECURE_SERVER_HTTP_EXPERIMENTAL' });
  });

  it('silences exactly the codes named', () => {
    const { server, warnings } = makeServer({ silenceWarnings: ['MCP_SECURE_SERVER_HTTP_EXPERIMENTAL'] });
    const h = server.tool('a', async () => ({ content: [] }));
    attach(server);
    expect(() => h.disable()).toThrow(LateRegistrationError);
    // Mutation: treat a non-empty silenceWarnings as "silence all" -> no late report.
    expect(codes(warnings)).toEqual(['MCP_SECURE_SERVER_LATE_REGISTRATION']);
  });

  it('throws at construction on an unknown code or a non-function onWarning', () => {
    expect(() => new SecureMcpServer({ name: 'x', version: '1' }, { silenceWarnings: ['NOPE' as WarningCode] }))
      .toThrow(/unknown code "NOPE"/);
    expect(() => new SecureMcpServer({ name: 'x', version: '1' }, { onWarning: false as never }))
      .toThrow(/onWarning must be a function/);
  });
});
