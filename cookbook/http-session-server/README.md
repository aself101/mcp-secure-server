# HTTP Session Server

> **Experimental (mcp-secure-server 0.1.0).** The HTTP transport has **no authentication**,
> session ids are bearer credentials, and Layer 3 rate limits are shared by every client of a
> server. This example binds `127.0.0.1` for that reason. Read *HTTP Transport* in the main
> README before exposing a server like it.

Several clients at once against one `SecureMcpServer`, each in its own MCP session. This is the
example the main README's *HTTP Transport* section points at: it was used to shake the 0.1.0
transport down with Claude Code, the MCP Inspector, a browser page and SDK clients.

What it shows:

- **One session per client**, with the `Mcp-Session-Id` the server issues on `initialize`.
- **The calling session inside a tool**: `extra.sessionId` for per-session logging and client
  info, and `extra.sendRequest` for sampling through the client that called the tool.
- **Progress and cancellation** on a long-running tool.
- **The registration freeze**: a tool that tries to switch another tool off at runtime is
  refused, and the operator gets a warning.
- **A CORS wrapper for browser clients** that echoes listed origins only and never rewrites
  `Origin`.
- **Warnings routed to the console** through `onWarning`, and an optional request log that
  hashes session ids.

## Run it

```bash
cd cookbook && npm install        # once, for the whole cookbook workspace
cd http-session-server
npm run dev                       # builds, then serves http://127.0.0.1:3010/mcp
```

Connect a client, as many as you like:

```bash
# Claude Code
claude mcp add --transport http sessions http://127.0.0.1:3010/mcp

# MCP Inspector (its UI, http://localhost:6274, is listed in allowedOrigins by default)
npx @modelcontextprotocol/inspector
```

Or from code, with the SDK's client:

```typescript
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const client = new Client({ name: 'my-client', version: '1.0.0' });
await client.connect(new StreamableHTTPClientTransport(new URL('http://127.0.0.1:3010/mcp')));
console.log(await client.callTool({ name: 'session-info', arguments: {} }));
```

The server prints `[sessions] N open` whenever the count changes. Stop it with Ctrl-C: it closes
every session before the listener.

## Tools

| Tool | Arguments | What it demonstrates |
|------|-----------|----------------------|
| `notes-list` | — | A read-only tool |
| `notes-read` | `id` | A read-only tool with an input schema |
| `slow-task` | `seconds` (1–120) | Progress notifications to the calling session; honours cancellation |
| `summarize-note` | `id` | Sampling through `extra.sendRequest`: the calling client's model summarizes the note (the client must support sampling) |
| `session-info` | — | What the server knows about the calling session: a shortened id, the client's name and version, its capabilities |
| `log-to-me` | `message` | `sendLoggingMessage(params, extra.sessionId)`: a log message to the calling session only, shown on its GET stream |
| `disable-notes-read` | — | Tries `notesRead.disable()` at runtime. It is refused with a tool error (registrations are frozen once HTTP is attached), the operator sees `MCP_SECURE_SERVER_LATE_REGISTRATION`, and `notes-read` keeps working |

Every tool is listed in `toolRegistry` (`src/server.ts`): Layer 4 refuses a tool that is not.

## Environment

| Variable | Default | Effect |
|----------|---------|--------|
| `PORT` | `3010` | Listening port |
| `HOST` | `127.0.0.1` | Address to bind; wider only behind authentication |
| `ALLOWED_ORIGINS` | `http://localhost:6274` | Comma-separated browser origins, exact (`scheme://host[:port]`) |
| `SECURITY_LEVEL` | `standard` | `basic`, `standard` or `paranoid` |
| `IDLE_TTL_MS` | 30 min | `httpSessionIdleTtlMs`: a session idle this long is closed |
| `MAX_SESSIONS_PER_CLIENT` | `10` | `maxHttpSessionsPerClient` |
| `LOG_REQUESTS` | unset | Set it to log one line per request: method, a hash of the session id, status, duration |

Under `standard`, Layer 3 admits a burst of about three short clients at once (each sends
`initialize`, `notifications/initialized` and a call); the fourth gets a 429 until the window
moves. For several clients arriving together, use `SECURITY_LEVEL=basic` or raise the limits —
the main README's *What is per client, and what is not* explains why.

## How it is built

- `src/tools.ts` registers the tools. It runs **before** the handler is created, because
  creating it freezes the server's registrations.
- `src/server.ts` builds the `SecureMcpServer` (with `toolRegistry`, logging capability and
  `onWarning`), creates the handler with `createSecureHttpHandler`, and wraps it in a
  `node:http` listener that answers CORS:
  - it echoes the request's `Origin` only when it is in `allowedOrigins` (never `*`, never
    `null`), and passes the same list to the handler, which refuses any other origin with 403;
  - it allows `GET, POST, DELETE, OPTIONS`, the `Mcp-Session-Id` and `Mcp-Protocol-Version`
    request headers, and exposes `Mcp-Session-Id` so a page can read it;
  - it **never deletes or rewrites `Origin`**: the handler validates it, and a wrapper that
    strips it turns that check off for every web page on the machine.
- `src/index.ts` reads the environment, listens, reports the session count, and on SIGINT or
  SIGTERM calls `handler.close()` before closing the listener.

## Testing

```bash
npm test
```

The tests run two SDK clients at once and check each sees its own session, that the runtime
toggle is refused with a tool error and a warning, and that the CORS wrapper answers the listed
origin while the handler refuses an unlisted one.

## Hosts recover differently

Every way a session ends (DELETE, idle time, a restart) reaches its client as a 404. Claude Code
re-initializes by itself; the MCP Inspector needs a manual reconnect. Neither sends DELETE when it
exits, so their sessions end by the idle time. See *Sessions end; hosts must recover* in the main
README.
