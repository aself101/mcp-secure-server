# API Wrapper Server

An MCP server demonstrating safe wrapping of third-party REST APIs with domain restrictions, rate limiting, and response validation.

## Overview

This cookbook shows how to securely wrap external APIs using the `mcp-security` framework. It demonstrates:

- **Domain Restrictions**: Only allowed API domains can be accessed
- **Per-Tool Rate Limiting**: Each tool has its own rate limit based on cost/risk
- **Response Size Limits**: Prevents oversized responses from consuming resources
- **Input Validation**: Zod schemas validate all inputs before processing
- **Error Handling**: Safe error messages without information leakage

### APIs Used (Free, No Auth Required)

| API | Domain | Purpose |
|-----|--------|---------|
| [Open-Meteo](https://open-meteo.com) | api.open-meteo.com | Weather forecasts |
| [Frankfurter](https://frankfurter.app) | api.frankfurter.app | Currency exchange rates |
| [Hacker News](https://hn.algolia.com/api) | hn.algolia.com | Tech news headlines |

## Security Features Demonstrated

### Layer 2 - Content Validation
- SSRF prevention (hardcoded API domains, no user-controlled URLs)
- XSS sanitization in string inputs

### Layer 4 - Semantic Policies
- Per-tool rate limiting via `quotaConfig`
- Tool registry with side effect declarations
- Response size limits via `egressConfig`

### Layer 5 - Contextual Validation
- Domain allowlist enforcement
- Response content validation

## Installation

```bash
# From the cookbook directory
cd cookbook/api-wrapper-server

# Install dependencies
npm install

# Build TypeScript
npm run build
```

## Configuration

### Basic Configuration

```typescript
const server = new SecureMcpServer(
  { name: 'api-wrapper-server', version: '1.0.0' },
  {
    toolRegistry: [
      {
        name: 'weather-forecast',
        sideEffects: 'network',
        quotaConfig: { maxRequests: 10, windowMs: 60000 },
      },
    ],
    maxRequestsPerMinute: 30,
  }
);
```

### Advanced Configuration

```typescript
const server = new SecureMcpServer(
  { name: 'api-wrapper-server', version: '1.0.0' },
  {
    enableLogging: true,
    verboseLogging: true,

    toolRegistry: [
      {
        name: 'weather-forecast',
        sideEffects: 'network',
        maxArgsSize: 500,
        quotaConfig: { maxRequests: 10, windowMs: 60000 },
      },
      {
        name: 'currency-convert',
        sideEffects: 'network',
        maxArgsSize: 200,
        quotaConfig: { maxRequests: 5, windowMs: 60000 },
      },
      {
        name: 'news-headlines',
        sideEffects: 'network',
        maxArgsSize: 300,
        quotaConfig: { maxRequests: 3, windowMs: 60000 },
      },
    ],

    defaultPolicy: {
      allowNetwork: true,
      allowWrites: false,
    },

    maxRequestsPerMinute: 30,
    maxRequestsPerHour: 500,

    egressConfig: {
      maxResponseSize: 50 * 1024, // 50KB
      validateContent: true,
    },
  }
);
```

## Tools Reference

### weather-forecast

Get weather forecast for a city with 5-day predictions.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| city | string | Yes | City name (e.g., "London", "New York") |
| units | "metric" \| "imperial" | No | Temperature units (default: metric) |

**Supported Cities:** New York, London, Paris, Tokyo, Sydney, Los Angeles, Chicago, Berlin, Madrid, Rome, Beijing, Mumbai, Dubai, Singapore, Toronto, San Francisco, Seattle, Miami, Boston, Denver

**Example:**
```json
{
  "city": "London",
  "units": "metric"
}
```

**Response:**
```json
{
  "city": "London",
  "coordinates": { "latitude": 51.5074, "longitude": -0.1278 },
  "timezone": "Europe/London",
  "current": {
    "temperature": "15°C",
    "humidity": "72%",
    "conditions": "Partly cloudy",
    "windSpeed": "12 km/h"
  },
  "forecast": [
    { "date": "2024-01-15", "high": "16°C", "low": "8°C", "conditions": "Overcast" }
  ]
}
```

**Rate Limit:** 10 requests/minute

---

### currency-convert

Convert between currencies using real-time exchange rates.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| from | string | Yes | Source currency code (ISO 4217) |
| to | string | Yes | Target currency code (ISO 4217) |
| amount | number | Yes | Amount to convert (max: 1 billion) |

**Example:**
```json
{
  "from": "USD",
  "to": "EUR",
  "amount": 100
}
```

**Response:**
```json
{
  "from": "USD",
  "to": "EUR",
  "amount": 100,
  "result": 91.85,
  "rate": 0.9185,
  "date": "2024-01-15",
  "formatted": {
    "input": "100 USD",
    "output": "91.85 EUR"
  }
}
```

**Rate Limit:** 5 requests/minute

---

### news-headlines

Get tech news headlines from Hacker News.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| category | "front_page" \| "ask_hn" \| "show_hn" \| "jobs" | No | News category (default: front_page) |
| query | string | No | Search query to filter stories |
| limit | number | No | Max articles (1-10, default: 10) |

**Example:**
```json
{
  "category": "front_page",
  "query": "rust",
  "limit": 5
}
```

**Response:**
```json
{
  "category": "front_page",
  "query": "rust",
  "count": 5,
  "articles": [
    {
      "id": "12345678",
      "title": "Rust 2.0 Released",
      "url": "https://blog.rust-lang.org/...",
      "author": "rustacean",
      "points": 542,
      "comments": 128,
      "published": "2024-01-15T10:30:00Z"
    }
  ]
}
```

**Rate Limit:** 3 requests/minute

## Security Analysis

### What Attacks Are Prevented

| Attack Vector | Prevention Method | Layer |
|---------------|-------------------|-------|
| SSRF to AWS metadata | Hardcoded API domains | Design |
| SSRF to internal network | No user-controlled URLs | Design |
| API rate abuse | Per-tool quota config | Layer 4 |
| Large response DoS | 50KB response limit | Layer 4 |
| XSS in city names | String sanitization | Utility |
| SQL injection in currency | Input validation | Utility |
| Invalid currency codes | ISO 4217 validation | Utility |

### Security Demo

Try these attack scenarios (they will be blocked):

```bash
# Attempt to exhaust rate limit
for i in {1..15}; do
  echo "Request $i"
  # Send news-headlines request (limit: 3/min)
done
# Result: Requests 4+ blocked by Layer 4

# XSS in city name - sanitized
{ "city": "<script>alert(1)</script>", "units": "metric" }
# Result: XSS characters stripped, city not found error

# Invalid currency code (SQL injection attempt)
{ "from": "'; DROP TABLE--", "to": "EUR", "amount": 100 }
# Result: Invalid currency code error
```

## Performance

### Benchmarks

| Metric | Value |
|--------|-------|
| Cold start | ~200ms |
| Avg request latency | 150-500ms (API dependent) |
| Memory usage | ~50MB |
| Max throughput | 30 req/min (global limit) |

### Layer Timing (Typical)

| Layer | Time |
|-------|------|
| Layer 1 (Structure) | <1ms |
| Layer 2 (Content) | <2ms |
| Layer 4 (Semantics) | <1ms |
| External API call | 100-400ms |

## Common Issues

### "City not found" Error

The weather tool only supports a predefined list of major cities. For other locations, consider:
- Using a geocoding API to get coordinates
- Extending the `CITY_COORDINATES` map

### Rate Limit Exceeded

Each tool has its own rate limit:
- `weather-forecast`: 10/min
- `currency-convert`: 5/min
- `news-headlines`: 3/min

Wait for the window to reset (1 minute) before retrying.

### API Timeout

External APIs have a 10-second timeout. If you see timeout errors:
- Check your internet connection
- The external API may be experiencing issues
- Try again later

## Claude Desktop Integration

Add to your Claude Desktop config (`~/.config/claude-desktop/config.json` on Linux, `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "api-wrapper": {
      "command": "node",
      "args": ["dist/index.js"],
      "cwd": "/path/to/mcp-security/cookbook/api-wrapper-server"
    }
  }
}
```

Then restart Claude Desktop. The tools will be available:
- `weather-forecast` - Get weather for major cities
- `currency-convert` - Convert between currencies
- `news-headlines` - Get Hacker News headlines

## Testing

```bash
# Run all tests
npm test

# Run with coverage
npm run test:coverage

# Watch mode
npm run test:watch
```

### Test Coverage

- Integration tests: Valid API calls, error handling, schema validation
- Security tests: Input validation, XSS prevention, injection attempts

## Development

```bash
# Watch mode for development
npm run dev

# Build
npm run build

# Start server
npm start
```

## License

MIT
