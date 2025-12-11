/**
 * Request normalization utilities for MCP messages.
 * Converts various request formats into consistent JSON-RPC structure.
 */

/** JSON-RPC message interface */
export interface JsonRpcMessage {
  jsonrpc: string;
  method: string;
  params?: unknown;
  id?: string | number;
}

/** Request with potential body (HTTP-style) */
interface RequestWithBody {
  body?: JsonRpcMessage;
  [key: string]: unknown;
}

/** Generic request object */
interface GenericRequest {
  jsonrpc?: string;
  method?: string;
  params?: unknown;
  id?: string | number;
  body?: unknown;
  [key: string]: unknown;
}

/** Map of SDK-specific request types to MCP methods */
const SDK_METHOD_MAP: Record<string, string> = {
  'tools/call': 'tools/call',
  'tools/list': 'tools/list',
  'resources/read': 'resources/read',
  'resources/list': 'resources/list',
  'prompts/get': 'prompts/get',
  'prompts/list': 'prompts/list',
  'initialize': 'initialize',
  'ping': 'ping'
};

/**
 * Normalize different request formats into consistent JSON-RPC structure.
 * Handles: JSON-RPC messages, SDK request objects, HTTP requests, raw objects.
 */
export function normalizeRequest(request: GenericRequest): JsonRpcMessage {
  // Case 1: Already a JSON-RPC message
  if (request.jsonrpc && request.method) {
    return request as JsonRpcMessage;
  }

  // Case 2: Official SDK request object (CallToolRequest, etc.)
  if (request.method && request.params) {
    return {
      jsonrpc: "2.0",
      method: mapSdkMethod(request.method),
      params: request.params,
      id: request.id || generateRequestId()
    };
  }

  // Case 3: HTTP request body
  if (request.body && typeof request.body === 'object') {
    return (request as RequestWithBody).body as JsonRpcMessage;
  }

  // Case 4: Raw object - convert to JSON-RPC format
  return {
    jsonrpc: "2.0",
    method: request.method || "unknown",
    params: request.params || request,
    id: request.id || generateRequestId()
  };
}

/**
 * Map SDK-specific request types to MCP methods.
 */
export function mapSdkMethod(method: string): string {
  return SDK_METHOD_MAP[method] || method;
}

/**
 * Generate a random request ID.
 */
function generateRequestId(): string {
  return Math.random().toString(36);
}
