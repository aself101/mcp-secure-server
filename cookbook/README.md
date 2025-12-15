# MCP Cookbook

Example MCP servers built with the [mcp-security](https://github.com/anthropics/mcp-security) framework. These servers demonstrate how to build secure MCP tools for real-world APIs.

## Servers

| Server | Description | Auth Required |
|--------|-------------|---------------|
| **advanced-validation-server** | Layer 5 custom validators (PII detection, geofencing, business hours) | None |
| **api-wrapper-server** | Safe REST API wrapping with domain restrictions and rate limiting | None |
| **cli-wrapper-server** | Safe CLI tool wrapping with command injection prevention | None |
| **database-server** | Safe database operations with SQL injection prevention | None |
| **filesystem-server** | Secure file system access with path traversal prevention | None |
| **image-gen-server** | Unified image generation across 5 providers (BFL, Google, Ideogram, OpenAI, Stability) | 5 API keys |
| **kenpom-server** | College basketball analytics from KenPom | Email + Password |
| **monitoring-server** | Observability with metrics, audit logging, and alerts | None |
| **nba-server** | NBA stats, live scores, and player data | None |

## Quick Start

### 1. Install Dependencies

```bash
cd cookbook
npm install
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env with your API keys
```

### 3. Build

```bash
npm run build
```

### 4. Add to Claude Desktop

Add to your Claude Desktop config (`~/.config/claude/claude_desktop_config.json` on Linux, `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "advanced-validation": {
      "command": "node",
      "args": ["cookbook/advanced-validation-server/dist/index.js"],
      "cwd": "/path/to/mcp-security"
    },
    "api-wrapper": {
      "command": "node",
      "args": ["cookbook/api-wrapper-server/dist/index.js"],
      "cwd": "/path/to/mcp-security"
    },
    "cli-wrapper": {
      "command": "node",
      "args": ["cookbook/cli-wrapper-server/dist/index.js"],
      "cwd": "/path/to/mcp-security"
    },
    "database": {
      "command": "node",
      "args": ["cookbook/database-server/dist/index.js"],
      "cwd": "/path/to/mcp-security"
    },
    "filesystem": {
      "command": "node",
      "args": ["cookbook/filesystem-server/dist/index.js"],
      "cwd": "/path/to/mcp-security"
    },
    "image-gen": {
      "command": "node",
      "args": ["cookbook/image-gen-server/dist/index.js"],
      "cwd": "/path/to/mcp-security"
    },
    "kenpom": {
      "command": "node",
      "args": ["cookbook/kenpom-server/dist/index.js"],
      "cwd": "/path/to/mcp-security"
    },
    "monitoring": {
      "command": "node",
      "args": ["cookbook/monitoring-server/dist/index.js"],
      "cwd": "/path/to/mcp-security"
    },
    "nba": {
      "command": "node",
      "args": ["cookbook/nba-server/dist/index.js"],
      "cwd": "/path/to/mcp-security"
    }
  }
}
```

## Advanced Validation Server

Demonstrates Layer 5 custom validators for building application-specific security rules.

### Custom Validators

| Validator | Type | Description |
|-----------|------|-------------|
| `pii-detector` | Response | Blocks responses containing SSN, credit cards, emails, phones |
| `business-hours` | Request | Restricts expensive operations to business hours |
| `geofencing` | Request | Blocks requests from specified countries |
| `egress-tracker` | Response | Tracks cumulative data sent per session |
| `anomaly-detector` | Request | Detects unusual request patterns |

### Tools

| Tool | Validator Demo | Description |
|------|---------------|-------------|
| `financial-query` | PII Detector | Query mock financial data with sensitive info |
| `batch-process` | Business Hours | Run expensive batch operations |
| `export-data` | Egress Tracker | Export large datasets |
| `api-call` | Geofencing | Make geo-restricted API calls |

### Example Prompts

- "Query customer info for cust-001" (blocked - contains PII)
- "Run batch-process generate-reports" (blocked outside business hours)
- "Export users dataset with limit 5000" (tracked for egress)

## API Wrapper Server

Safe wrapping of third-party REST APIs with domain restrictions and rate limiting.

### Tools

| Tool | Description |
|------|-------------|
| `weather-forecast` | Get weather forecast for major cities |
| `currency-convert` | Convert between currencies using real-time rates |
| `news-headlines` | Get tech news from Hacker News |

### Example Prompts

- "What's the weather in London?"
- "Convert 100 USD to EUR"
- "Show me the latest tech news"

## CLI Wrapper Server

Safe wrapping of command-line tools with command injection prevention.

### Tools

| Tool | Description |
|------|-------------|
| `git-status` | Git repository operations (status, branch, log, diff, show) |
| `image-resize` | ImageMagick image resizing |
| `pdf-metadata` | PDF info extraction |
| `encode-video` | FFmpeg video encoding |

### Example Prompts

- "Show me the git status of /home/user/my-project"
- "Resize the image at /tmp/photo.jpg to 800x600"
- "Get metadata from /home/user/docs/report.pdf"
- "Encode /tmp/video.mp4 to webm format"

## Image Generation Server

Unified interface for 5 image generation providers.

### Tools

| Tool | Description |
|------|-------------|
| `generate-image` | Text-to-image generation |
| `edit-image` | Edit/inpaint with mask |
| `upscale-image` | Upscale image resolution |
| `create-variation` | Create image variations |
| `remove-background` | Remove image background |
| `replace-background` | Replace background |
| `describe-image` | Get image description |
| `list-models` | List available models |

### Example Prompts

- "Generate an image of a sunset over mountains using Stability AI"
- "List all available models for image generation"
- "Upscale this image using Ideogram"

## KenPom Server

College basketball analytics and efficiency ratings.

### Tools

| Tool | Description |
|------|-------------|
| `get-ratings` | Team efficiency ratings |
| `get-program-ratings` | All-time program rankings |
| `get-efficiency` | Offensive/defensive efficiency |
| `get-four-factors` | Shooting, TO, rebounding, FT |
| `get-team-stats` | 20+ team statistics |
| `get-schedule` | Team game-by-game results |
| `get-scouting-report` | 70+ detailed team stats |
| `get-player-stats` | Individual player metrics |
| `get-conference-standings` | Conference standings |
| `get-fan-match` | Daily game predictions |

### Example Prompts

- "Get the current KenPom ratings"
- "Show me Duke's schedule for 2024"
- "Get the scouting report for Kansas"
- "What are the four factors for the ACC?"

## Monitoring Server

Observability and monitoring for MCP deployments.

### Tools

| Tool | Description |
|------|-------------|
| `get-security-metrics` | Real-time security metrics, violations, layer performance |
| `get-audit-log` | Query audit entries with filtering and pagination |
| `configure-alerts` | Manage alert rules (add, update, delete, history) |
| `export-metrics` | Export in Prometheus, JSON, or summary format |

### Resources

| URI | Description |
|-----|-------------|
| `monitoring://config` | Server configuration and capabilities |
| `monitoring://health` | Health check with metrics summary |

### Example Prompts

- "Show me the security metrics summary"
- "Query audit logs for security events in the last hour"
- "Add an alert for high violation rate"
- "Export metrics in Prometheus format"
- "List all configured alert rules"

## NBA Server

NBA stats, live scores, and player data from public APIs.

### Tools

| Tool | Description |
|------|-------------|
| `get-player-stats` | Player career stats |
| `get-player-game-log` | Player game-by-game |
| `get-player-info` | Player bio and info |
| `get-team-roster` | Current team roster |
| `get-team-game-log` | Team game-by-game |
| `get-league-leaders` | Top players by stat |
| `get-standings` | Conference standings |
| `get-box-score` | Game box score |
| `get-play-by-play` | Game play-by-play |
| `get-live-scoreboard` | Today's live scores |
| `get-live-box-score` | Real-time box score |
| `find-player` | Search players by name |

### Example Prompts

- "Get LeBron James career stats"
- "Show today's NBA scores"
- "Who are the league leaders in points?"
- "Get the Lakers roster"

## Security

All servers use the mcp-security framework which provides:

- **5-layer validation pipeline**: Structure, Content, Behavior, Semantics, Contextual
- **Rate limiting**: Configurable per-minute and per-hour limits
- **Attack pattern detection**: SQL injection, XSS, path traversal, etc.
- **Error sanitization**: Prevents information leakage

## Development

### Run a single server

```bash
# After building
npm run image-gen
npm run kenpom
npm run nba
```

### Project Structure

```
cookbook/
├── package.json              # Monorepo root
├── tsconfig.json             # Shared TypeScript config
├── .env.example              # Environment template
├── advanced-validation-server/  # Layer 5 custom validators demo
├── api-wrapper-server/       # REST API wrapper MCP server (domain restrictions)
├── cli-wrapper-server/       # CLI wrapper MCP server (command injection prevention)
├── database-server/          # Database MCP server (SQL injection prevention)
├── filesystem-server/        # Filesystem MCP server (path traversal prevention)
├── image-gen-server/         # Image generation MCP server
├── kenpom-server/            # KenPom MCP server
├── monitoring-server/        # Observability MCP server (metrics, audit, alerts)
└── nba-server/               # NBA MCP server
```
