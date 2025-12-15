// Test README Basic Configuration Example (lines 50-68)
import { SecureMcpServer } from 'mcp-security';

const server = new SecureMcpServer({
  name: 'monitoring-server',
  version: '1.0.0',
}, {
  toolRegistry: [
    {
      name: 'get-security-metrics',
      sideEffects: 'read',
      quotaPerMinute: 60,
    },
    {
      name: 'export-metrics',
      sideEffects: 'read',
      quotaPerMinute: 30,
    },
  ],
});

console.log('Basic configuration test passed');
