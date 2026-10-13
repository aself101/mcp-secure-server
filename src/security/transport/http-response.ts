/**
 * Response helpers shared by the HTTP handler and the per-session request flow.
 * @module http-response
 */

import type { ServerResponse } from 'node:http';
import type { ViolationType } from '../../types/index.js';
import type { SecurityLogger } from '../utils/security-logger.js';

/** Security headers applied to all responses the package writes itself. */
export const SECURITY_HEADERS: Record<string, string> = {
  'Content-Type': 'application/json',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Cache-Control': 'no-store',
  'X-XSS-Protection': '0',
  // CSP: Strict policy for JSON API (no scripts, styles, or external resources)
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
  // HSTS: Enable strict transport security when served over HTTPS
  // Note: Browsers ignore this header over HTTP, so it's safe to include unconditionally
  // For production, consider increasing max-age to 31536000 (1 year) at reverse proxy level
  'Strict-Transport-Security': 'max-age=86400; includeSubDomains'
};

/** Write response with security headers */
export function writeSecureResponse(
  res: ServerResponse,
  statusCode: number,
  body: unknown,
  extraHeaders: Record<string, string> = {}
): void {
  res.writeHead(statusCode, { ...SECURITY_HEADERS, ...extraHeaders });
  res.end(JSON.stringify(body));
}

/** A JSON-RPC error with no `id`, for refusals made before a message is dispatched. */
export function writeJsonRpcError(
  res: ServerResponse,
  statusCode: number,
  code: number,
  message: string,
  extraHeaders: Record<string, string> = {}
): void {
  writeSecureResponse(res, statusCode, { jsonrpc: '2.0', error: { code, message }, id: null }, extraHeaders);
}

/** Map violation types to HTTP status codes */
export function getHttpStatusForViolation(violationType: ViolationType): number {
  switch (violationType) {
    case 'RATE_LIMIT_EXCEEDED':
    case 'QUOTA_EXCEEDED':
    case 'BURST_ACTIVITY':
      return 429;
    case 'SIZE_LIMIT_EXCEEDED':
    case 'OVERSIZED_MESSAGE':
    case 'OVERSIZED_PARAMS':
      return 413;
    case 'POLICY_VIOLATION':
    case 'TOOL_NOT_ALLOWED':
    case 'RESOURCE_POLICY_VIOLATION':
    case 'SIDE_EFFECT_NOT_ALLOWED':
      return 403;
    default:
      return 400;
  }
}

/**
 * Which limiter refused a request; sent as X-RateLimit-Scope so operators can tell the
 * 429s apart. `sessionless` is the GET/DELETE limiter (the name predates sessions);
 * `responses` is the per-session meter on client JSON-RPC responses.
 */
export type RateLimitScope = 'errors' | 'sessionless' | 'not-found' | 'responses';

/** Write a 429 for a limiter and log the key it fired on */
export function writeRateLimited(res: ServerResponse, scope: RateLimitScope, key: string, logger: SecurityLogger | null): void {
  logger?.logInfo(`HTTP 429 (${scope}) for ${key}`);
  writeSecureResponse(res, 429, { error: 'Too many requests' }, { 'Retry-After': '60', 'X-RateLimit-Scope': scope });
}

/** Per-IP request ceilings must be positive integers; NaN or Infinity would silently disable the limit. */
export function requirePositiveInteger(name: string, value: number): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new TypeError(`${name} must be a positive integer (got ${String(value)})`);
  }
  return value;
}

/** Session id header must be visible ASCII (MCP spec) and bounded; arrays (repeated header) are rejected. */
export function isValidSessionId(value: string | string[]): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 256 && /^[\x21-\x7e]+$/.test(value);
}
