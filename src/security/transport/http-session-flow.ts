/**
 * The per-session HTTP request flow (spec http-transport-per-session v0.4.3, section C).
 *
 * Order: (1) malformed-request checks, which consult and charge the error lockout whatever
 * session header the request carries; (2) Origin and Host; (3) batch bodies; (4) no
 * session header — only a single `initialize` POST is served; (5) a session header —
 * unknown ids always 404, known ones are routed to their session. A well-formed request
 * never consults the lockout, and a pipeline rejection is never charged to it.
 * @module http-session-flow
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import type { PipelineContext, PipelineLogger, ValidationPipeline } from '../utils/validation-pipeline.js';
import { safeLogDecision } from '../utils/validation-pipeline.js';
import type { ErrorSanitizer } from '../utils/error-sanitizer.js';
import type { SecurityLogger } from '../utils/security-logger.js';
import { isSeverity, isViolationType } from '../../types/index.js';
import type { Severity, ViolationType } from '../../types/index.js';
import { parseJsonBody } from './http-body-parser.js';
import type { ErrorRateLimiter } from './error-rate-limiter.js';
import type { SessionRegistry } from './session-registry.js';
import { redactSessionId } from './session-registry.js';
import { checkOriginAndHost, type OriginPolicy } from './http-origin.js';
import {
  writeSecureResponse, writeJsonRpcError, writeRateLimited, getHttpStatusForViolation, isValidSessionId
} from './http-response.js';

/** Everything the flow needs from its handler. */
export interface SessionFlowConfig {
  pipeline: ValidationPipeline;
  errorSanitizer: ErrorSanitizer;
  logger: SecurityLogger | null;
  createContext(fields: Record<string, unknown>): PipelineContext;
  registry: SessionRegistry;
  resolveClientIp(req: IncomingMessage): string;
  errorLockout: ErrorRateLimiter;
  /** The GET/DELETE limiter (`sessionlessRequestsPer*`), per key, known sessions only (D10). */
  streamLimiter: ErrorRateLimiter;
  /** Client JSON-RPC responses, per session (600/min). */
  responseLimiter: ErrorRateLimiter;
  originPolicy: OriginPolicy;
  maxBodySize: number;
  requestTimeout: number;
  /** Called with every request before anything else (the exposure warning). */
  onRequest(req: IncomingMessage): void;
}

type Json = Record<string, unknown>;
const isRecord = (v: unknown): v is Json => typeof v === 'object' && v !== null && !Array.isArray(v);

/**
 * A client's JSON-RPC response (to sampling, elicitation, roots, ping): shape only (D14).
 * Layer 1's size and encoding checks are not applied: they were built for client
 * requests and would refuse legitimate answers that stdio forwards unchecked.
 */
function responseShape(body: Json): 'ok' | 'bad' | 'not-a-response' {
  if ('method' in body) return 'not-a-response';
  if (!('result' in body) && !('error' in body)) return 'not-a-response';
  const idOk = typeof body.id === 'string' || typeof body.id === 'number';
  const oneOf = ('result' in body) !== ('error' in body);
  const err = body.error;
  const errOk = !('error' in body) || (isRecord(err) && Number.isInteger(err.code) && typeof err.message === 'string');
  return body.jsonrpc === '2.0' && idOk && oneOf && errOk ? 'ok' : 'bad';
}

/** Build the request handler for one HTTP handler instance. */
export function createSessionFlow(config: SessionFlowConfig): (req: IncomingMessage, res: ServerResponse) => Promise<void> {
  const { pipeline, errorSanitizer, logger, registry, errorLockout, originPolicy } = config;
  const unknownLogged = new Map<string, number>();

  /** Refuse a malformed request: consult the lockout (429 if tripped), else charge it and answer. */
  const malformed = (res: ServerResponse, key: string, write: () => void): void => {
    if (errorLockout.shouldRateLimit(key)) { writeRateLimited(res, 'errors', key, logger); return; }
    errorLockout.recordError(key);
    write();
  };

  /** Run the pipeline; on rejection write the sanitized error and return false. */
  const admit = async (body: Json, sessionId: string, clientId: string, res: ServerResponse): Promise<boolean> => {
    const context = config.createContext({
      sessionId, clientId, transportLevel: true, httpRequest: true, originalMessage: body, requestId: body.id
    });
    const result = await pipeline.validate(body, context);
    safeLogDecision(logger as PipelineLogger | undefined, result, body, 'HTTP-Transport');
    if (result.passed) return true;
    const severity: Severity = isSeverity(result.severity) ? result.severity : 'HIGH';
    const violationType: ViolationType = isViolationType(result.violationType) ? result.violationType : 'POLICY_VIOLATION';
    const id = (body.id as string | number | null | undefined) ?? null;
    writeSecureResponse(res, getHttpStatusForViolation(violationType),
      errorSanitizer.createSanitizedErrorResponse(id, result.reason ?? 'Request blocked by security policy', severity, violationType));
    return false;
  };

  const notFound = (res: ServerResponse, key: string, id: string): void => {
    const now = Date.now();
    if (now - (unknownLogged.get(key) ?? 0) >= 60_000) {
      unknownLogged.set(key, now);
      if (unknownLogged.size > 10_000) unknownLogged.clear();
      logger?.logInfo(`HTTP 404 unknown session ${redactSessionId(id)} from ${key}`);
    }
    writeJsonRpcError(res, 404, -32001, 'Session not found: it ended or was never issued; initialize a new session without this Mcp-Session-Id');
  };

  return async (req, res) => {
    config.onRequest(req);
    const method = req.method;
    const key = config.resolveClientIp(req);

    // (1) Malformed shapes, before anything is looked up.
    if (method !== 'POST' && method !== 'GET' && method !== 'DELETE') {
      return malformed(res, key, () => writeSecureResponse(res, 405, { error: 'Method not allowed' }, { 'Allow': 'GET, POST, DELETE' }));
    }
    const header = req.headers['mcp-session-id'];
    if (header !== undefined && !isValidSessionId(header)) {
      return malformed(res, key, () => writeSecureResponse(res, 400, { error: 'Invalid Mcp-Session-Id header' }));
    }
    let body: unknown;
    if (method === 'POST') {
      if (!req.headers['content-type']?.includes('application/json')) {
        return malformed(res, key, () => writeSecureResponse(res, 415, { error: 'Content-Type must be application/json' }));
      }
      try {
        body = await parseJsonBody(req, config.maxBodySize, config.requestTimeout);
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Invalid request';
        return malformed(res, key, () => writeSecureResponse(res, message.includes('timeout') ? 408 : 400, { error: message }));
      }
    }

    // (2) Origin and Host: refused before anything below; not charged, not metered.
    const refusal = checkOriginAndHost(req, originPolicy);
    if (refusal) return writeJsonRpcError(res, 403, -32000, refusal);

    // (3) Batch bodies (D8): removed from MCP in 2025-06-18.
    if (Array.isArray(body)) {
      return malformed(res, key, () => writeJsonRpcError(res, 400, -32600, 'Batch requests are not supported'));
    }

    // (4) No session header: only a single initialize starts a session.
    if (header === undefined) {
      if (method === 'POST' && isRecord(body) && body.method === 'initialize') {
        const message = body;
        return registry.initialize(req, res, message, key, id => admit(message, id, key, res));
      }
      const refuse = () => writeJsonRpcError(res, 400, -32000, 'Mcp-Session-Id header is required: send the id the initialize response returned');
      // A well-formed JSON-RPC request is not malformed, so it is answered but not charged
      // (D20): Claude Code opens every connection with a header-less `server/discover` probe
      // from a newer protocol revision, then falls back to initialize; charging it put every
      // connect on the lockout. Same reasoning as D9's uncharged 404s.
      const wellFormed = isRecord(body) && body.jsonrpc === '2.0' && typeof body.method === 'string';
      return wellFormed ? refuse() : malformed(res, key, refuse);
    }

    // (5) A session header. Unknown ids always 404 (D9): no lockout, no pipeline, never 429.
    if (!registry.has(header)) return notFound(res, key, header);
    const forward = async (): Promise<void> => {
      if (!(await registry.handle(header, req, res, body))) return notFound(res, key, header);
      const rpc = isRecord(body) ? `: ${typeof body.method === 'string' ? body.method : 'response'}` : '';
      logger?.logInfo(`HTTP ${method} request completed${rpc}`);
    };

    if (method === 'GET' || method === 'DELETE') {
      if (config.streamLimiter.shouldRateLimit(key)) return writeRateLimited(res, 'sessionless', key, logger);
      config.streamLimiter.recordError(key);
      return forward();
    }
    if (!isRecord(body)) {
      return malformed(res, key, () => writeJsonRpcError(res, 400, -32600, 'Invalid JSON-RPC message'));
    }
    const shape = responseShape(body);
    if (shape === 'bad') {
      return malformed(res, key, () => writeJsonRpcError(res, 400, -32600, 'Invalid JSON-RPC response'));
    }
    if (shape === 'ok') {
      if (config.responseLimiter.shouldRateLimit(header)) return writeRateLimited(res, 'responses', redactSessionId(header), logger);
      config.responseLimiter.recordError(header);
      return forward();
    }
    if (!(await admit(body, header, key, res))) return;
    return forward();
  };
}
