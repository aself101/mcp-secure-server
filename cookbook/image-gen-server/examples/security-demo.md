# Security Demonstration

This document demonstrates security features of the Image Generation MCP server.

## Content Moderation

### Policy violation detection

```text
Tool: generate-image
Arguments: {
  "provider": "openai",
  "prompt": "[inappropriate content]"
}
```

**Result: BLOCKED by Provider**
```json
{
  "error": "Content policy violation",
  "message": "Your request was rejected as a result of our safety system"
}
```

All providers enforce content policies:
- OpenAI: Comprehensive content filter
- Stability AI: NSFW filter
- Google: SafeSearch integration
- Ideogram: Content moderation
- BFL: Usage policies

## Rate Limiting

### Request quota enforcement

After exceeding 100 requests per minute:

```text
Tool: generate-image
Arguments: { "provider": "openai", "prompt": "test" }
```

**Result: BLOCKED**
```json
{
  "error": "Rate limit exceeded",
  "message": "Maximum 100 requests per minute exceeded",
  "retryAfter": 30
}
```

### Per-tool quotas

Some tools may have individual limits:
```json
{
  "error": "Tool quota exceeded",
  "message": "upscale-image limited to 20/min",
  "tool": "upscale-image"
}
```

## Input Validation

### Invalid provider

```text
Tool: generate-image
Arguments: { "provider": "invalid", "prompt": "test" }
```

**Result: BLOCKED**
```json
{
  "error": "Validation failed",
  "message": "Provider must be one of: bfl, google, ideogram, openai, stability"
}
```

### Prompt too long

```text
Tool: generate-image
Arguments: {
  "provider": "openai",
  "prompt": "A".repeat(3000)
}
```

**Result: BLOCKED**
```json
{
  "error": "Validation failed",
  "message": "Prompt exceeds maximum length of 2000 characters"
}
```

### Invalid image count

```text
Tool: generate-image
Arguments: {
  "provider": "openai",
  "prompt": "test",
  "count": 10
}
```

**Result: BLOCKED**
```json
{
  "error": "Validation failed",
  "message": "Count must be between 1 and 4"
}
```

## Argument Size Limits

### Oversized base64 image

```text
Tool: edit-image
Arguments: {
  "provider": "stability",
  "image": "[very large base64 string > 10KB]",
  "prompt": "edit"
}
```

**Result: BLOCKED**
```json
{
  "error": "Argument too large",
  "message": "Arguments exceed maximum size of 10000 bytes"
}
```

## Credential Protection

### API keys never exposed

Errors never include credentials:

**Internal Error:**
```text
401 Unauthorized: Invalid API key sk-abc123...
```

**Exposed Error:**
```json
{
  "error": "Authentication failed",
  "message": "Invalid API key for provider: openai"
}
```

### Environment isolation

Each provider's credentials are isolated:
- `OPENAI_API_KEY` only used for OpenAI
- `STABILITY_API_KEY` only used for Stability
- No credential sharing between providers

## Network Security

### Side effect declaration

All image tools declare network side effects:

```typescript
toolRegistry: [
  { name: 'generate-image', sideEffects: 'network' },
  { name: 'edit-image', sideEffects: 'network' },
  { name: 'upscale-image', sideEffects: 'network' },
]
```

### HTTPS enforcement

All provider API calls use HTTPS:
- OpenAI: api.openai.com
- Stability: api.stability.ai
- Google: generativelanguage.googleapis.com
- Ideogram: api.ideogram.ai
- BFL: api.bfl.ml

## URL Validation

### Image URL validation

```text
Tool: edit-image
Arguments: {
  "provider": "openai",
  "image": "file:///etc/passwd",
  "prompt": "edit"
}
```

**Result: BLOCKED**
```json
{
  "error": "Invalid image URL",
  "message": "Only HTTP/HTTPS URLs are allowed"
}
```

### Malicious URL patterns

```text
Tool: edit-image
Arguments: {
  "provider": "openai",
  "image": "http://localhost:8080/internal",
  "prompt": "edit"
}
```

**Result: Depends on provider**
- Some providers block localhost
- SSRF protection at provider level

## Summary

| Security Feature | Implementation |
|-----------------|----------------|
| Content Moderation | Provider-enforced policies |
| Rate Limiting | 100/min, 1000/hr |
| Input Validation | Zod schemas on all inputs |
| Credential Security | Environment variables, isolated |
| Size Limits | 10KB max for image arguments |
| Side Effects | All network tools declared |
| URL Validation | HTTP/HTTPS only |
| Error Sanitization | No internal details exposed |
