/**
 * Simple HTTP Server Example
 *
 * Demonstrates using SecureMcpServer with HTTP transport.
 * Exposes calculator and echo tools over a single HTTP endpoint.
 */

import { SecureMcpServer } from 'mcp-secure-server';
import { calculatorSchema, calculatorHandler } from './tools/calculator.js';
import { echoSchema, echoHandler } from './tools/echo.js';

const server = new SecureMcpServer(
  { name: 'http-server-example', version: '1.0.0' },
  {
    // Security preset - basic for development examples
    securityLevel: 'basic',
    enableLogging: process.env.VERBOSE_LOGGING === 'true',
    toolRegistry: [
      { name: 'calculator', sideEffects: 'none', quotaPerMinute: 60 },
      { name: 'echo', sideEffects: 'none', quotaPerMinute: 60 }
    ]
  }
);

// Register tools
server.tool(
  'calculator',
  'Perform basic arithmetic operations (add, subtract, multiply, divide)',
  calculatorSchema.shape,
  calculatorHandler
);

server.tool(
  'echo',
  'Echo back a message with optional transformations',
  echoSchema.shape,
  echoHandler
);

// Create HTTP server with security validation
const httpServer = server.createHttpServer({
  endpoint: '/mcp',
  maxBodySize: 50 * 1024 // 50KB
});

const PORT = parseInt(process.env.PORT || '3000', 10);

httpServer.listen(PORT, () => {
  console.log(`MCP HTTP Server listening on http://localhost:${PORT}/mcp`);
  console.log('');
  console.log('Available tools:');
  console.log('  - calculator: Perform arithmetic (add, subtract, multiply, divide)');
  console.log('  - echo: Echo back messages with optional transforms');
  console.log('');
  console.log('Test with curl:');
  console.log(`  curl -X POST http://localhost:${PORT}/mcp \\`);
  console.log('    -H "Content-Type: application/json" \\');
  console.log('    -H "Accept: application/json, text/event-stream" \\');
  console.log('    -d \'{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"calculator","arguments":{"operation":"add","a":5,"b":3}}}\'');
});
