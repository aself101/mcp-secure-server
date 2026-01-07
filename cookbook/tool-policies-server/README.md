# Tool Policies Server

Demonstrates **config-driven tool policies** for context-aware security validation. Tool policies are loaded from a JSON configuration file, enabling different security levels per tool to reduce false positives while maintaining protection where it matters.

## The Problem

Security patterns that detect attacks like command injection (`| cat /etc/passwd`) or SQL injection (`' OR 1=1 --`) can cause **false positives** when applied to documentation tools.

For example, a note-taking tool might legitimately store:
- Shell command examples: `ls -la | grep pattern`
- SQL documentation: `SELECT * FROM users WHERE active = 1`
- Event handler docs: `<button onclick="handleClick()">`

These would trigger security warnings at full validation level, but they're perfectly safe when stored as documentation.

## The Solution: Config-Driven Tool Policies

The MCP Security Framework v2.0 supports loading tool policies from a JSON configuration file. This provides:

- **Pattern matching** - Use glob patterns to apply policies to groups of tools
- **Base policies** - Define reusable policy templates
- **Inheritance** - Extend base policies with custom overrides
- **Relaxed fields** - Specify which parameters get relaxed validation

### Security Levels

| Level | Description | Patterns Checked |
|-------|-------------|------------------|
| **EXECUTION** | Command execution, file access | All patterns (most restrictive) |
| **QUERY** | Database queries, API calls | SQL/NoSQL injection + base checks |
| **STORAGE** | Documentation, notes | XSS, deserialization only |
| **DISPLAY** | Read-only display | Minimal (XSS, deserialization) |

## Quick Start

```bash
cd cookbook/tool-policies-server
npm install
npm run build
npm start
```

## Configuration File

Tool policies are defined in `tool-policies.json`:

```json
{
  "version": "2.0",

  "basePolicies": {
    "storage-content": {
      "level": "STORAGE",
      "relaxedFields": ["content", "title"],
      "description": "Base policy for tools that store text content"
    },
    "display-readonly": {
      "level": "DISPLAY",
      "description": "Base policy for read-only query tools"
    }
  },

  "patterns": [
    { "match": "search-*", "policy": "display-readonly" },
    { "match": "get-*", "policy": "display-readonly" },
    { "match": "list-*", "policy": "display-readonly" }
  ],

  "tools": {
    "save-note": {
      "level": "STORAGE",
      "relaxedFields": ["content", "title"],
      "description": "Saves documentation notes - content may contain code examples"
    },
    "execute-command": {
      "level": "EXECUTION",
      "description": "Command execution tool - full validation required"
    },
    "query-data": {
      "level": "QUERY",
      "description": "Database query tool - SQL/NoSQL injection checks enabled"
    }
  },

  "defaultLevel": "EXECUTION"
}
```

### Schema Reference

| Field | Type | Description |
|-------|------|-------------|
| `version` | `"2.0"` | Required schema version |
| `basePolicies` | object | Reusable policy templates |
| `patterns` | array | Glob patterns for tool matching |
| `tools` | object | Explicit per-tool policies |
| `defaultLevel` | string | Fallback level for unknown tools |

### Pattern Matching

Patterns use [minimatch](https://github.com/isaacs/minimatch) glob syntax:

```json
{
  "patterns": [
    { "match": "get_*", "policy": "display-readonly" },
    { "match": "*_issues", "policy": { "level": "DISPLAY" } },
    { "match": "{save,create}_*", "policy": "storage-content" }
  ]
}
```

**Resolution order:**
1. Explicit tool definitions (highest priority)
2. Pattern matching (first match wins)
3. `defaultLevel` from config
4. `EXECUTION` level (secure default)

### Inheritance

Policies can extend base policies:

```json
{
  "basePolicies": {
    "base-storage": {
      "level": "STORAGE",
      "relaxedFields": ["content"]
    }
  },
  "tools": {
    "my-tool": {
      "extends": "base-storage",
      "relaxedFields": ["extra_field"],
      "description": "Inherits STORAGE, merges relaxedFields"
    }
  }
}
```

## Usage in Code

### Loading Configuration

```typescript
import { initializeToolPolicies, getToolPolicy } from 'mcp-secure-server';
import { readFile } from 'node:fs/promises';

// Load from file
const content = await readFile('./tool-policies.json', 'utf-8');
const config = JSON.parse(content);
initializeToolPolicies(config);

// Check resolved policy
const policy = getToolPolicy('save-note');
console.log(policy.level); // 'STORAGE'
```

### Environment Variable

You can also set `TOOL_POLICIES_PATH` to specify a custom config location:

```bash
export TOOL_POLICIES_PATH=/path/to/my-policies.json
npm start
```

### Runtime Registration

For dynamic policies, use `registerToolPolicy`:

```typescript
import { registerToolPolicy } from 'mcp-secure-server';

registerToolPolicy('dynamic-tool', {
  level: 'STORAGE',
  relaxedFields: ['content'],
  description: 'Registered at runtime'
});
```

### Query Functions

```typescript
import {
  getToolPolicy,
  getToolsByLevel,
  isRelaxedField,
  getToolPoliciesConfig
} from 'mcp-secure-server';

// Get resolved policy for a tool
const policy = getToolPolicy('save-note');
console.log(policy.level); // 'STORAGE'

// Get all tools at a level
const storageLevelTools = getToolsByLevel('STORAGE');

// Check if a field has relaxed validation
isRelaxedField('save-note', 'content'); // true
isRelaxedField('save-note', 'project'); // false

// Access the loaded config
const config = getToolPoliciesConfig();
console.log(config?.version); // '2.0'
```

## Tools in This Server

| Tool | Level | Purpose |
|------|-------|---------|
| `save-note` | STORAGE | Save documentation with code examples |
| `search-notes` | DISPLAY | Read-only note search |
| `execute-command` | EXECUTION | Demo of full validation (doesn't execute) |
| `query-data` | QUERY | Database queries with SQL injection checks |
| `get-policy-info` | DISPLAY | Inspect current policy configuration |

## Testing

```bash
npm test
```

The tests demonstrate:
- Config file loading
- Policy resolution order
- Pattern matching
- Inheritance with extends
- Relaxed field configuration

## Pattern Behavior by Level

### STORAGE Level (Documentation)

These patterns are **allowed** at STORAGE level:

```
# Shell examples in docs
ls -la | grep pattern
cmd1 && cmd2 || cmd3

# Event handler documentation
<button onclick="handleClick()">

# SQL examples in docs
SELECT * FROM users WHERE id = 1
```

### EXECUTION Level (Full Validation)

These patterns are **blocked** at EXECUTION level:

```
# Command injection
; rm -rf /
| cat /etc/passwd
$(whoami)

# Path traversal
../../../etc/passwd

# SQL injection
' OR 1=1 --
'; DROP TABLE users; --
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    MCP Request                              │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  Config Loading (startup)                                   │
│  ┌─────────────────────────────────────────────────────────┐│
│  │ 1. Load tool-policies.json                              ││
│  │ 2. Parse and validate against v2.0 schema               ││
│  │ 3. Resolve inheritance chains                           ││
│  │ 4. Index patterns for fast matching                     ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  Layer 2: Content Validation                                │
│  ┌─────────────────────────────────────────────────────────┐│
│  │ 1. Extract tool name from request                       ││
│  │ 2. Resolve policy (explicit → patterns → default)       ││
│  │ 3. Get pattern categories for security level            ││
│  │ 4. Validate only against allowed patterns               ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  Pattern Categories by Level                                │
│                                                             │
│  DISPLAY:    XSS, Deserialization                          │
│  STORAGE:    XSS, Deserialization                          │
│  QUERY:      + SQL, NoSQL injection                         │
│  EXECUTION:  + Command injection, Path traversal, etc.      │
└─────────────────────────────────────────────────────────────┘
```

## Best Practices

1. **Use a config file**: Centralize policies in `tool-policies.json` for easy auditing and version control.

2. **Define base policies**: Create reusable templates for common security patterns.

3. **Use patterns**: Apply policies to groups of tools with glob patterns (e.g., `get_*` for all read-only tools).

4. **Default to EXECUTION**: The `defaultLevel: "EXECUTION"` ensures unknown tools get full validation.

5. **Be specific with relaxedFields**: Only relax validation on fields that actually contain user content.

6. **Document your policies**: Include descriptions so developers understand why a tool has a particular level.

## License

MIT
