# Tool Policies Server

Demonstrates **context-aware security validation** using tool policies. Different tools have different security levels, reducing false positives while maintaining protection where it matters.

## The Problem

Security patterns that detect attacks like command injection (`| cat /etc/passwd`) or SQL injection (`' OR 1=1 --`) can cause **false positives** when applied to documentation tools.

For example, a note-taking tool might legitimately store:
- Shell command examples: `ls -la | grep pattern`
- SQL documentation: `SELECT * FROM users WHERE active = 1`
- Event handler docs: `<button onclick="handleClick()">`

These would trigger security warnings at full validation level, but they're perfectly safe when stored as documentation.

## The Solution: Tool Security Levels

The MCP Security Framework classifies tools into four security levels:

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

## Usage

### Register Custom Tool Policies

```typescript
import { registerToolPolicy, getToolPolicy } from 'mcp-secure-server';

// Register a documentation tool with STORAGE level
registerToolPolicy('save-note', {
  level: 'STORAGE',
  relaxedFields: ['content', 'title'],
  description: 'Saves documentation notes'
});

// Check the policy
const policy = getToolPolicy('save-note');
console.log(policy.level); // 'STORAGE'
```

### Built-in Tool Policies

The framework includes policies for common tools:

```typescript
import { getToolPolicy } from 'mcp-secure-server';

// Validation tracker tools
getToolPolicy('save_features_list').level; // 'STORAGE'
getToolPolicy('query_issues').level;       // 'DISPLAY'
getToolPolicy('add_issue_note').level;     // 'STORAGE'

// Database tools
getToolPolicy('query-users').level;        // 'QUERY'
getToolPolicy('create-order').level;       // 'EXECUTION'

// Unknown tools default to EXECUTION (safest)
getToolPolicy('unknown-tool').level;       // 'EXECUTION'
```

### Relaxed Fields

Some tools have specific fields that use relaxed validation:

```typescript
import { isRelaxedField } from 'mcp-secure-server';

// The 'content' field in add_issue_note uses STORAGE rules
isRelaxedField('add_issue_note', 'content'); // true
isRelaxedField('add_issue_note', 'project'); // false
```

### Get Tools by Level

```typescript
import { getToolsByLevel } from 'mcp-secure-server';

const storageLevelTools = getToolsByLevel('STORAGE');
// ['save_features_list', 'update_status', 'add_issue_note', ...]

const executionLevelTools = getToolsByLevel('EXECUTION');
// ['create-order', 'batch-process', 'delete_project', ...]
```

## Tools in This Server

| Tool | Level | Purpose |
|------|-------|---------|
| `save-note` | STORAGE | Save documentation with code examples |
| `search-notes` | DISPLAY | Read-only note search |
| `execute-command` | EXECUTION | Demo of full validation (doesn't execute) |
| `query-data` | QUERY | Database queries with SQL injection checks |
| `get-policy-info` | - | Inspect current policy configuration |

## Testing

```bash
npm test
```

The tests demonstrate:
- Policy registration and retrieval
- Relaxed field configuration
- Content patterns safe at different levels
- Built-in tool policy verification

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
│  Layer 2: Content Validation                                │
│  ┌─────────────────────────────────────────────────────────┐│
│  │ 1. Extract tool name from request                       ││
│  │ 2. Look up tool policy (defaults to EXECUTION)          ││
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

1. **Default to EXECUTION**: Unknown tools automatically use EXECUTION level for safety.

2. **Use STORAGE for documentation tools**: Note-taking, issue tracking, and comment tools should use STORAGE level.

3. **Use QUERY for database tools**: Any tool that builds queries should have SQL injection checks.

4. **Be specific with relaxedFields**: Only relax validation on fields that actually contain user content.

5. **Document your policies**: Include descriptions so developers understand why a tool has a particular level.

## License

MIT
