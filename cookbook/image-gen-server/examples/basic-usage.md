# Basic Usage Examples

This document shows common usage patterns for the Image Generation MCP server.

## Generating Images

### Simple image generation with OpenAI

```text
Tool: generate-image
Arguments: {
  "provider": "openai",
  "prompt": "A cozy cabin in the mountains during winter"
}
```

Response:
```json
{
  "success": true,
  "provider": "openai",
  "model": "dall-e-3",
  "images": [
    {
      "url": "https://oaidalleapiprodscus.blob.core.windows.net/...",
      "revisedPrompt": "A cozy wooden cabin..."
    }
  ]
}
```

### Generate with specific dimensions

```text
Tool: generate-image
Arguments: {
  "provider": "stability",
  "prompt": "Abstract art with vibrant colors",
  "width": 1024,
  "height": 1024
}
```

### Generate with aspect ratio

```text
Tool: generate-image
Arguments: {
  "provider": "ideogram",
  "prompt": "Panoramic cityscape at night",
  "aspectRatio": "16:9"
}
```

### Generate multiple images

```text
Tool: generate-image
Arguments: {
  "provider": "bfl",
  "prompt": "Futuristic vehicle design",
  "count": 4
}
```

## Listing Available Models

### List all models

```text
Tool: list-models
Arguments: {}
```

Response:
```json
{
  "models": {
    "bfl": ["flux-pro", "flux-dev"],
    "google": ["imagen-3"],
    "ideogram": ["V_2", "V_2_TURBO"],
    "openai": ["dall-e-3", "dall-e-2"],
    "stability": ["sd3-large", "sd3-medium"]
  }
}
```

### List models for specific provider

```text
Tool: list-models
Arguments: { "provider": "openai" }
```

## Editing Images

### Inpainting with OpenAI

```text
Tool: edit-image
Arguments: {
  "provider": "openai",
  "image": "https://example.com/my-image.png",
  "prompt": "Replace the sky with a sunset"
}
```

### Edit with mask

```text
Tool: edit-image
Arguments: {
  "provider": "stability",
  "image": "https://example.com/photo.jpg",
  "mask": "https://example.com/mask.png",
  "prompt": "Add a vintage car in the masked area"
}
```

## Upscaling Images

### Basic upscale

```text
Tool: upscale-image
Arguments: {
  "provider": "stability",
  "image": "https://example.com/low-res.jpg"
}
```

### Upscale with specific scale

```text
Tool: upscale-image
Arguments: {
  "provider": "ideogram",
  "image": "https://example.com/image.png",
  "scale": 2
}
```

## Background Operations

### Remove background

```text
Tool: remove-background
Arguments: {
  "image": "https://example.com/portrait.jpg"
}
```

Response:
```json
{
  "success": true,
  "image": "data:image/png;base64,..."
}
```

### Replace background

```text
Tool: replace-background
Arguments: {
  "provider": "stability",
  "image": "https://example.com/portrait.jpg",
  "prompt": "A tropical beach at sunset"
}
```

## Image Description

### Get description of an image

```text
Tool: describe-image
Arguments: {
  "image": "https://example.com/mystery-image.jpg"
}
```

Response:
```json
{
  "description": "A golden retriever sitting in a field of flowers..."
}
```

## Workflow Example: Create Marketing Asset

1. Generate the base image:
```text
Tool: generate-image
Arguments: {
  "provider": "openai",
  "prompt": "Professional product photo of a coffee mug on a desk",
  "aspectRatio": "1:1"
}
```

2. Upscale for print quality:
```text
Tool: upscale-image
Arguments: {
  "provider": "stability",
  "image": "[url from step 1]",
  "scale": 2
}
```

3. Create variations for A/B testing:
```text
Tool: create-variation
Arguments: {
  "image": "[url from step 2]"
}
```
