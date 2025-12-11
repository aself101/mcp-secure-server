/**
 * JSON-RPC and MCP message types for the MCP Security Framework.
 */

/** JSON-RPC 2.0 message base */
export interface JsonRpcMessage {
  /** JSON-RPC version (always '2.0') */
  jsonrpc: '2.0';
  /** Method name */
  method: string;
  /** Optional message ID (null for notifications) */
  id?: string | number | null;
  /** Method parameters */
  params?: Record<string, unknown> | unknown[];
}

/** JSON-RPC request (has ID) */
export interface JsonRpcRequest extends JsonRpcMessage {
  /** Request ID (required for requests) */
  id: string | number;
}

/** JSON-RPC notification (no ID) */
export interface JsonRpcNotification extends JsonRpcMessage {
  /** Notifications have no ID */
  id?: undefined;
}

/** JSON-RPC error object */
export interface JsonRpcError {
  /** Error code */
  code: number;
  /** Error message */
  message: string;
  /** Additional error data */
  data?: Record<string, unknown>;
}

/** JSON-RPC response */
export interface JsonRpcResponse {
  /** JSON-RPC version (always '2.0') */
  jsonrpc: '2.0';
  /** Response ID (matches request) */
  id: string | number | null;
  /** Success result */
  result?: unknown;
  /** Error result */
  error?: JsonRpcError;
}

/** JSON-RPC error response */
export interface JsonRpcErrorResponse extends JsonRpcResponse {
  /** Error is required */
  error: JsonRpcError;
  /** No result on error */
  result?: never;
}

/** MCP tools/call parameters */
export interface McpToolCallParams {
  /** Tool name */
  name: string;
  /** Tool arguments (new SDK format) */
  arguments?: Record<string, unknown>;
  /** Tool arguments (legacy format) */
  args?: Record<string, unknown>;
}

/** MCP resources/read parameters */
export interface McpResourceReadParams {
  /** Resource URI */
  uri: string;
}

/** MCP prompts/get parameters */
export interface McpPromptGetParams {
  /** Prompt name */
  name: string;
  /** Prompt arguments */
  arguments?: Record<string, unknown>;
}

/** MCP resources/list parameters */
export interface McpResourceListParams {
  /** Optional cursor for pagination */
  cursor?: string;
}

/** MCP tools/list parameters */
export interface McpToolListParams {
  /** Optional cursor for pagination */
  cursor?: string;
}

/** MCP prompts/list parameters */
export interface McpPromptListParams {
  /** Optional cursor for pagination */
  cursor?: string;
}

/** Message type classification */
export type MessageType = 'request' | 'response' | 'notification' | 'unknown';

/** MCP method names */
export type McpMethod =
  | 'initialize'
  | 'initialized'
  | 'ping'
  | 'tools/list'
  | 'tools/call'
  | 'resources/list'
  | 'resources/read'
  | 'resources/subscribe'
  | 'resources/unsubscribe'
  | 'prompts/list'
  | 'prompts/get'
  | 'logging/setLevel'
  | 'completion/complete'
  | 'sampling/createMessage'
  | 'notifications/initialized'
  | 'notifications/progress'
  | 'notifications/message'
  | 'notifications/resources/list_changed'
  | 'notifications/resources/updated'
  | 'notifications/tools/list_changed'
  | 'notifications/prompts/list_changed'
  | 'notifications/cancelled';
