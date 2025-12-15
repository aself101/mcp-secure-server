# Monitoring MCP Server

An MCP server demonstrating observability and monitoring patterns for secure MCP deployments.

## Overview

This cookbook demonstrates how to build monitoring and observability into MCP servers using the MCP Security Framework. It showcases:

- **Real-time Metrics**: Security event tracking, violation counts, layer performance
- **Audit Logging**: Structured logs with correlation IDs for request tracing
- **Alert Management**: Configurable alert rules with severity-based routing
- **Prometheus Export**: Industry-standard metrics format for Grafana dashboards

## Security Features Demonstrated

| Feature | Layer | Description |
|---------|-------|-------------|
| Metrics Collection | All | Track events across all 5 security layers |
| Audit Logging | App | Correlation IDs, structured JSON, tamper-evident |
| Alert Rules | App | Configurable thresholds, cooldowns, channels |
| Prometheus Export | App | Industry-standard metrics format |
| Rate Limiting | L4 | Per-tool quotas for monitoring endpoints |

## Requirements

- **Node.js**: 18.x or higher
- **npm**: 9.x or higher

## Installation

```bash
cd cookbook/monitoring-server
npm install
npm run build
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VERBOSE_LOGGING` | `false` | Enable debug logging |
| `METRICS_RETENTION_MS` | `3600000` | How long to retain metrics (1 hour) |
| `MAX_AUDIT_ENTRIES` | `10000` | Maximum audit log entries to retain |
| `ALERT_WEBHOOK_URL` | - | Optional webhook URL for alerts |

### Basic Configuration

```typescript
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
```

## Tools Reference

### get-security-metrics

Get real-time security metrics including violations, layer performance, and tool statistics.

**Parameters:**
- `includeEvents` (boolean, optional): Include recent security events (default: false)
- `includeLayerStats` (boolean, optional): Include per-layer statistics (default: true)
- `includeToolStats` (boolean, optional): Include per-tool statistics (default: true)
- `topPatternsLimit` (number, optional): Number of top blocked patterns (default: 10)

**Example:**
```json
{
  "includeEvents": true,
  "includeLayerStats": true,
  "topPatternsLimit": 5
}
```

**Response:**
```json
{
  "timestamp": "2024-01-15T10:30:00.000Z",
  "uptime": "2h 15m 30s",
  "summary": {
    "totalEvents": 1500,
    "totalViolations": 45,
    "violationsByType": {
      "SQL_INJECTION": 20,
      "PATH_TRAVERSAL": 15,
      "COMMAND_INJECTION": 10
    },
    "violationsBySeverity": {
      "HIGH": 5,
      "MEDIUM": 25,
      "LOW": 15
    }
  },
  "topBlockedPatterns": [
    { "type": "SQL_INJECTION", "count": 20 },
    { "type": "PATH_TRAVERSAL", "count": 15 }
  ],
  "layers": {
    "1": { "totalRequests": 1500, "blocked": 5, "avgLatencyMs": 2.5 },
    "2": { "totalRequests": 1495, "blocked": 30, "avgLatencyMs": 8.2 }
  }
}
```

### get-audit-log

Query audit log entries with filtering options.

**Parameters:**
- `startTime` (string, optional): Start time (ISO 8601)
- `endTime` (string, optional): End time (ISO 8601)
- `type` (enum, optional): request | response | security_event | system
- `level` (enum, optional): debug | info | warn | error
- `tool` (string, optional): Filter by tool name
- `correlationId` (string, optional): Filter by correlation ID
- `success` (boolean, optional): Filter by success status
- `limit` (number, optional): Max entries to return (default: 100)
- `offset` (number, optional): Pagination offset (default: 0)
- `includeStats` (boolean, optional): Include statistics (default: false)

**Example:**
```json
{
  "type": "security_event",
  "level": "warn",
  "limit": 50,
  "includeStats": true
}
```

### configure-alerts

Manage alert rules and view history.

**Parameters:**
- `action` (enum, required): list | add | update | delete | history | stats
- `ruleId` (string, optional): Rule ID for update/delete
- `rule` (object, optional): Rule configuration for add/update
- `historyLimit` (number, optional): History entries to return (default: 50)

**Add Rule Example:**
```json
{
  "action": "add",
  "rule": {
    "name": "High Violation Rate",
    "enabled": true,
    "condition": {
      "metric": "violations",
      "operator": ">",
      "threshold": 10,
      "windowMs": 60000
    },
    "severity": "warning",
    "channels": ["console", "memory"],
    "cooldownMs": 300000
  }
}
```

**Available Metrics:**
- `violations` - Total security violations
- `rate_limit_hits` - Rate limit exceeded events
- `error_rate` - Error rate (0-1)
- `latency_p99` - 99th percentile latency (ms)

### export-metrics

Export metrics in various formats for external consumption.

**Parameters:**
- `format` (enum, optional): prometheus | json | summary (default: prometheus)
- `includeAuditStats` (boolean, optional): Include audit statistics (default: true)
- `includeAlertStats` (boolean, optional): Include alert statistics (default: true)

**Prometheus Format:**
```
# HELP mcp_security_violations_total Total number of security violations
# TYPE mcp_security_violations_total counter
mcp_security_violations_total 45

# HELP mcp_layer_latency_p99_ms P99 latency by layer in milliseconds
# TYPE mcp_layer_latency_p99_ms gauge
mcp_layer_latency_p99_ms{layer="1"} 5
mcp_layer_latency_p99_ms{layer="2"} 25
```

**Summary Format:**
```
╔══════════════════════════════════════════════════════════════╗
║              MCP SECURITY MONITORING SUMMARY                 ║
╚══════════════════════════════════════════════════════════════╝

📊 Server Uptime: 2h 15m 30s
🕐 Report Time: 2024-01-15T10:30:00.000Z

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECURITY EVENTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Total Events: 1500
Total Violations: 45

Violations by Type:
  • SQL_INJECTION: 20
  • PATH_TRAVERSAL: 15
  • COMMAND_INJECTION: 10
```

## Prometheus Integration

### Scrape Configuration

Add to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'mcp-security'
    static_configs:
      - targets: ['localhost:9090']
    metrics_path: '/metrics'
    scrape_interval: 15s
```

### Grafana Dashboard

Import the provided dashboard or create panels for:

- **Security Overview**: Total events, violations, block rate
- **Layer Performance**: Per-layer latency percentiles
- **Tool Statistics**: Calls per tool, success rates
- **Alerts**: Active alerts, trigger frequency

## Example Prompts

- "Show me the security metrics summary"
- "Query audit logs for security events in the last hour"
- "Add an alert for high violation rate"
- "Export metrics in Prometheus format"
- "List all configured alert rules"

## Claude Desktop Integration

Add to your Claude Desktop config (`~/.config/Claude/claude_desktop_config.json` on Linux, `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "monitoring": {
      "command": "node",
      "args": ["dist/index.js"],
      "cwd": "/path/to/cookbook/monitoring-server",
      "env": {
        "VERBOSE_LOGGING": "false",
        "METRICS_RETENTION_MS": "3600000"
      }
    }
  }
}
```

## Security Analysis

### What This Demonstrates

1. **Metrics Don't Leak Sensitive Data**
   - No request payloads in metrics
   - Audit logs sanitize sensitive fields
   - Correlation IDs don't expose internal state

2. **Audit Logs Are Tamper-Evident**
   - Structured format with timestamps
   - Correlation IDs link related entries
   - Append-only storage pattern

3. **Alert Integration Is Secure**
   - No secrets in alert payloads
   - Webhook URLs from environment only
   - Rate-limited alert channels

4. **Performance Impact Is Minimal**
   - In-memory metrics collection
   - Efficient histogram implementation
   - Configurable retention periods

### Common Issues

**Metrics not appearing**
- Check that the server is running and tools are being called
- Demo data is seeded on startup for testing

**Audit log too large**
- Adjust `MAX_AUDIT_ENTRIES` environment variable
- Query with filters to reduce response size

**Alerts not firing**
- Check rule is enabled: `configure-alerts action: "list"`
- Verify cooldown period hasn't triggered
- Check threshold values match expected ranges

## Testing

```bash
# Run all tests
npm test

# Watch mode
npm run test:watch
```

## License

MIT - Part of the MCP Security Framework cookbook examples.
