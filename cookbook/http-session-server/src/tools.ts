/**
 * Tools for the HTTP session example. Each one exercises a per-session behaviour of the
 * transport: read tools, progress and cancellation, a request back to the client's model
 * (sampling) through the calling session, per-session client info and logging, and a
 * runtime toggle that the registration freeze refuses.
 */
import { z } from 'zod';
import type { SecureMcpServer } from 'mcp-secure-server';
import { CreateMessageResultSchema } from '@modelcontextprotocol/sdk/types.js';

const NOTES = [
  { id: 'n1', title: 'Sessions', body: 'Every HTTP client gets its own MCP session, with a server-issued id.' },
  { id: 'n2', title: 'Freeze', body: 'Registrations freeze when an HTTP handler is attached.' },
  { id: 'n3', title: 'Origin', body: 'Browser clients must be listed in allowedOrigins.' }
];

/** The tool names, for Layer 4's tool registry. */
export const TOOL_NAMES = ['notes-list', 'notes-read', 'slow-task', 'summarize-note', 'session-info', 'log-to-me', 'disable-notes-read'] as const;

const text = (value: unknown) => ({ content: [{ type: 'text' as const, text: typeof value === 'string' ? value : JSON.stringify(value, null, 2) }] });

/** Register every tool. Must run before the HTTP handler is created (the freeze). */
export function registerTools(server: SecureMcpServer): void {
  server.registerTool('notes-list', { description: 'List the example notes', annotations: { readOnlyHint: true } },
    async () => text(NOTES.map(({ id, title }) => ({ id, title }))));

  const notesRead = server.registerTool('notes-read', {
    description: 'Read one note by id',
    inputSchema: { id: z.string().describe('A note id from notes-list') },
    annotations: { readOnlyHint: true }
  }, async ({ id }) => {
    const note = NOTES.find(n => n.id === id);
    return note ? text(note) : { ...text(`No note ${id}`), isError: true };
  });

  server.registerTool('slow-task', {
    description: 'Work for a number of seconds, reporting progress; honours cancellation',
    inputSchema: { seconds: z.number().int().min(1).max(120) }
  }, async ({ seconds }, extra) => {
    const token = extra._meta?.progressToken;
    for (let i = 1; i <= seconds; i++) {
      if (extra.signal.aborted) return text(`cancelled after ${i - 1} s`);
      await new Promise(resolve => setTimeout(resolve, 1000));
      if (token !== undefined) {
        await extra.sendNotification({ method: 'notifications/progress', params: { progressToken: token, progress: i, total: seconds } });
      }
    }
    return text(`finished ${seconds} s`);
  });

  server.registerTool('summarize-note', {
    description: "Ask the client's model to summarize a note (MCP sampling, through the calling session)",
    inputSchema: { id: z.string() }
  }, async ({ id }, extra) => {
    const note = NOTES.find(n => n.id === id);
    if (!note) return { ...text(`No note ${id}`), isError: true };
    if (!server.getClientCapabilities(extra.sessionId)?.sampling) {
      return { ...text('This client does not support sampling.'), isError: true };
    }
    // Over HTTP, server.server.createMessage() would go to the never-connected primary
    // ("Not connected"); extra.sendRequest goes to the session that called this tool.
    const result = await extra.sendRequest({
      method: 'sampling/createMessage',
      params: { messages: [{ role: 'user', content: { type: 'text', text: `Summarize in one line: ${note.body}` } }], maxTokens: 100 }
    }, CreateMessageResultSchema);
    return text(result.content);
  });

  server.registerTool('session-info', { description: "This session's client, as the server sees it", inputSchema: {} }, async (_args, extra) => {
    const sessionId = extra.sessionId;
    return text({
      session: sessionId ? `${sessionId.slice(0, 8)}…` : null,
      client: server.getClientVersion(sessionId) ?? null,
      capabilities: server.getClientCapabilities(sessionId) ?? null
    });
  });

  server.registerTool('log-to-me', {
    description: "Send a logging notification to this session only (shows on the client's GET stream)",
    inputSchema: { message: z.string() }
  }, async ({ message }, extra) => {
    await server.sendLoggingMessage({ level: 'info', logger: 'http-session-server', data: message }, extra.sessionId);
    return text('sent');
  });

  server.registerTool('disable-notes-read', {
    description: 'Try to switch notes-read off at runtime (refused: registrations are frozen once HTTP is attached)'
  }, async () => {
    // Throws LateRegistrationError; the client sees a tool error, the operator a
    // MCP_SECURE_SERVER_LATE_REGISTRATION warning. A kill switch belongs inside the tool.
    notesRead.disable();
    return text('disabled');
  });
}
