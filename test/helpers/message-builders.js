/**
 * Shared test utilities for building MCP JSON-RPC messages.
 *
 * Eliminates duplication across test files by providing standardized
 * message factories for tools/call, resources/read, and other MCP methods.
 */

/**
 * Creates a JSON-RPC 2.0 tools/call message for testing.
 *
 * Flexible signature supports all common test patterns:
 * - `createToolCallMessage({ path: '../etc/passwd' })` - args only, default tool
 * - `createToolCallMessage('my-tool', { arg: 'value' })` - tool name + args
 * - `createToolCallMessage('my-tool')` - tool name only
 * - `createToolCallMessage()` - all defaults
 *
 * @param {string|object} [toolNameOrArgs] - Tool name string or arguments object
 * @param {object} [args] - Tool arguments (when first param is tool name)
 * @param {object} [messageOverrides] - Top-level message property overrides
 * @returns {object} Complete JSON-RPC tools/call message
 *
 * @example
 * // Default message
 * createToolCallMessage()
 * // => { jsonrpc: '2.0', method: 'tools/call', id: 1, params: { name: 'test-tool', arguments: {} } }
 *
 * @example
 * // With arguments only (default tool name)
 * createToolCallMessage({ path: '../etc/passwd' })
 * // => { ..., params: { name: 'test-tool', arguments: { path: '../etc/passwd' } } }
 *
 * @example
 * // With tool name and arguments
 * createToolCallMessage('file-reader', { path: '/data.txt' })
 * // => { ..., params: { name: 'file-reader', arguments: { path: '/data.txt' } } }
 *
 * @example
 * // With message overrides
 * createToolCallMessage('echo', { text: 'hi' }, { id: 42 })
 * // => { jsonrpc: '2.0', method: 'tools/call', id: 42, params: { name: 'echo', arguments: { text: 'hi' } } }
 */
export function createToolCallMessage(toolNameOrArgs, args, messageOverrides) {
  let toolName = 'test-tool';
  let toolArgs = {};
  let overrides = {};

  if (typeof toolNameOrArgs === 'string') {
    // Signature: (toolName, args?, overrides?)
    toolName = toolNameOrArgs;
    toolArgs = args || {};
    overrides = messageOverrides || {};
  } else if (toolNameOrArgs && typeof toolNameOrArgs === 'object') {
    // Signature: (args) or (args, overrides)
    toolArgs = toolNameOrArgs;
    overrides = args || {};
  }

  return {
    jsonrpc: '2.0',
    method: 'tools/call',
    id: 1,
    params: {
      name: toolName,
      arguments: toolArgs
    },
    ...overrides
  };
}

/**
 * Creates a JSON-RPC 2.0 resources/read message for testing.
 *
 * @param {string} uri - Resource URI
 * @param {object} [messageOverrides] - Top-level message property overrides
 * @returns {object} Complete JSON-RPC resources/read message
 *
 * @example
 * createResourceReadMessage('file:///etc/passwd')
 * // => { jsonrpc: '2.0', method: 'resources/read', id: 1, params: { uri: 'file:///etc/passwd' } }
 */
export function createResourceReadMessage(uri, messageOverrides = {}) {
  return {
    jsonrpc: '2.0',
    method: 'resources/read',
    id: 1,
    params: { uri },
    ...messageOverrides
  };
}

/**
 * Creates a JSON-RPC 2.0 message with custom method for testing.
 *
 * @param {string} method - JSON-RPC method name
 * @param {object} [params] - Method parameters
 * @param {object} [messageOverrides] - Top-level message property overrides
 * @returns {object} Complete JSON-RPC message
 *
 * @example
 * createJsonRpcMessage('prompts/get', { name: 'greeting' })
 * // => { jsonrpc: '2.0', method: 'prompts/get', id: 1, params: { name: 'greeting' } }
 */
export function createJsonRpcMessage(method, params = {}, messageOverrides = {}) {
  return {
    jsonrpc: '2.0',
    method,
    id: 1,
    params,
    ...messageOverrides
  };
}
