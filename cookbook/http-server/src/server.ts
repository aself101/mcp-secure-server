/**
 * Build the example: a SecureMcpServer with the calculator and echo tools, served over HTTP.
 * Each HTTP client gets its own MCP session; tools are registered before the HTTP server is
 * created, because creating it freezes the server's registrations.
 */
import type { Server } from 'node:http';
import { SecureMcpServer } from 'mcp-secure-server';
import { calculatorSchema, calculatorHandler } from './tools/calculator.js';
import { echoSchema, echoHandler } from './tools/echo.js';

export interface HttpExample { server: SecureMcpServer; httpServer: Server }

export function createHttpExample(options: { verbose?: boolean } = {}): HttpExample {
  const server = new SecureMcpServer(
    { name: 'http-server-example', version: '1.0.0' },
    {
      // Security preset - basic for development examples
      securityLevel: 'basic',
      enableLogging: options.verbose ?? false,
      toolRegistry: [
        { name: 'calculator', sideEffects: 'none', quotaPerMinute: 60 },
        { name: 'echo', sideEffects: 'none', quotaPerMinute: 60 }
      ]
    }
  );

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

  // Create the HTTP server last: from here on, registrations are frozen.
  const httpServer = server.createHttpServer({
    endpoint: '/mcp',
    maxBodySize: 50 * 1024 // 50KB
  });

  return { server, httpServer };
}
