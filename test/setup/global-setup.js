import fs from 'fs/promises';

// Global test setup
global.beforeAll(async () => {
  // Create test-data directory if it doesn't exist
  try {
    await fs.mkdir('test-data', { recursive: true });
    
    // Create basic test files
    await fs.writeFile('test-data/safe-test.txt', 'Safe test content for file reading tests');
    await fs.writeFile('test-data/clean-safe.txt', 'Clean safe content');
    
  } catch (error) {
    console.warn('Test data setup warning:', error.message);
  }
});

// Mock process.env for consistent testing
global.beforeEach(() => {
  process.env.NODE_ENV = 'test';
  process.env.MCP_SECURITY_LOG_LEVEL = 'silent';
});

// Clean up event listeners after each test to prevent MaxListenersExceededWarning
global.afterEach(() => {
  process.removeAllListeners('SIGINT');
  process.removeAllListeners('SIGTERM');
  process.removeAllListeners('exit');
});

// Helper to create consistent test messages
global.createTestMessage = (overrides = {}) => ({
  jsonrpc: "2.0",
  method: "tools/call",
  id: `test-${Date.now()}`,
  params: {
    name: "debug-calculator",
    arguments: { expression: "2+2" }
  },
  ...overrides
});

// Helper to create attack payloads
global.createAttackPayload = (type, payload) => ({
  jsonrpc: "2.0",
  method: "tools/call",
  id: `attack-${Date.now()}`,
  params: {
    name: "debug-file-reader",
    arguments: getAttackArgs(type, payload)
  }
});

function getAttackArgs(type, payload) {
  switch (type) {
    case 'path_traversal':
      return { path: payload || '../../../etc/passwd' };
    case 'xss':
      return { expression: payload || '<script>alert("xss")</script>' };
    case 'sql_injection':
      return { expression: payload || "'; DROP TABLE users; --" };
    case 'command_injection':
      return { expression: payload || '$(rm -rf /)' };
    default:
      return { data: payload };
  }
}