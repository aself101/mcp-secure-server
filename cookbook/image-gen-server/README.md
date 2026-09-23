# Image Generation MCP Server

A secure MCP server providing unified access to 5 image generation providers: BFL (Flux), Google (Imagen), Ideogram, OpenAI (GPT Image), and Stability AI.

## Overview

This cookbook demonstrates how to build a multi-provider API wrapper with the MCP Security Framework. It showcases:

- **Layer 3**: High-throughput rate limiting (100 req/min)
- **Layer 4**: Network side effect declarations
- **Layer 4**: Large argument handling (up to 10KB for images)
- **Provider Abstraction**: Unified interface across 5 providers
- **Credential Security**: Per-provider API key management

## Security Features Demonstrated

| Feature | Layer | Description |
|---------|-------|-------------|
| Rate Limiting | L3, L4 | 100 req/min, 1000 req/hr |
| Side Effect Declaration | L4 | All tools declare `network` side effects |
| Argument Size Limits | L4 | Up to 10KB for image data |
| Credential Protection | Config | Separate API keys per provider |
| No Write Operations | L4 | Read-only (generates to memory, not disk) |

## Installation

```bash
cd cookbook/image-gen-server
npm install
npm run build
```

## Configuration

### Environment Variables

```bash
# Copy example config
cp .env.example .env
# Add your API keys
```

| Variable | Required | Description |
|----------|----------|-------------|
| `BFL_API_KEY` | For BFL | Black Forest Labs (Flux) API key |
| `GOOGLE_GENAI_API_KEY` | For Google | Google AI (Imagen) API key |
| `IDEOGRAM_API_KEY` | For Ideogram | Ideogram API key |
| `OPENAI_API_KEY` | For OpenAI | OpenAI (GPT Image) API key |
| `STABILITY_API_KEY` | For Stability | Stability AI API key |

## Supported Providers

| Provider | Generation | Edit | Upscale | Background | Describe |
|----------|------------|------|---------|------------|----------|
| BFL (Flux) | Yes | - | - | - | - |
| Google (Imagen) | Yes | - | - | - | - |
| Ideogram | Yes | Yes | Yes | Yes | Yes |
| OpenAI (GPT Image) | Yes | Yes | - | - | - |
| Stability AI | Yes | Yes | Yes | Yes | - |

## Tools Reference

### generate-image

Generate images from text prompts.

**Parameters:**
- `provider` (enum, required): bfl, google, ideogram, openai, stability
- `prompt` (string, required): Text description (max 2000 chars)
- `model` (string, optional): Provider-specific model name
- `width` (number, optional): Image width in pixels
- `height` (number, optional): Image height in pixels
- `aspectRatio` (string, optional): e.g., "16:9", "1:1"
- `negativePrompt` (string, optional): What to avoid
- `style` (string, optional): Style preset
- `count` (number, optional): Number of images (1-4)

**Example:**
```json
{
  "provider": "openai",
  "prompt": "A serene mountain landscape at sunset",
  "model": "gpt-image-2.5-flare",
  "aspectRatio": "16:9"
}
```

### edit-image

Edit an image using inpainting with an optional mask.

**Parameters:**
- `provider` (enum, required): ideogram, openai, stability
- `image` (string, required): Image URL or base64 data
- `prompt` (string, required): Description of the edit
- `mask` (string, optional): Mask image (white = edit area)

### upscale-image

Upscale an image to higher resolution.

**Parameters:**
- `provider` (enum, required): ideogram, stability
- `image` (string, required): Image URL or base64 data
- `scale` (number, optional): Upscale factor

### remove-background

Remove the background from an image (Stability AI).

**Parameters:**
- `image` (string, required): Image URL or base64 data

### replace-background

Replace the background of an image.

**Parameters:**
- `provider` (enum, required): ideogram, stability
- `image` (string, required): Image URL or base64 data
- `prompt` (string, required): Description of new background

### describe-image

Get a text description of an image (Ideogram).

**Parameters:**
- `image` (string, required): Image URL or base64 data

### list-models

List available models for image generation.

**Parameters:**
- `provider` (enum, optional): Filter by provider

## Security Analysis

### Content Moderation

Each provider has built-in content moderation:
- Prompts are checked for policy violations
- Generated images are filtered
- NSFW content is blocked

### Rate Limiting

High-throughput configuration for image generation:
- **Per-minute**: 100 requests
- **Per-hour**: 1000 requests

### API Key Security

- Keys stored in environment variables
- Never logged or exposed in responses
- Per-provider isolation

## Claude Desktop Integration

```json
{
  "mcpServers": {
    "image-gen": {
      "command": "node",
      "args": ["dist/index.js"],
      "cwd": "/path/to/cookbook/image-gen-server",
      "env": {
        "OPENAI_API_KEY": "sk-...",
        "STABILITY_API_KEY": "sk-..."
      }
    }
  }
}
```

## Running Tests

```bash
npm test
npm run test:coverage
```

## License

MIT - Part of the MCP Security Framework cookbook examples.
