# Security Policy & Threat Model

This document describes the security architecture, threat model, and responsible disclosure process for the MCP Security Framework.

## Table of Contents

- [Threat Model](#threat-model)
- [Security Architecture](#security-architecture)
- [Attack Surface Analysis](#attack-surface-analysis)
- [Mitigation Strategies](#mitigation-strategies)
- [Security Assumptions](#security-assumptions)
- [Known Limitations](#known-limitations)
- [Reporting Vulnerabilities](#reporting-vulnerabilities)
- [Security Checklist](#security-checklist)

---

## Threat Model

### Overview

The MCP Security Framework protects Model Context Protocol (MCP) servers from malicious inputs originating from AI agents, compromised clients, or adversarial users. The framework assumes a **zero-trust** approach where all inputs are considered potentially hostile.

### Threat Actors

| Actor | Capability | Motivation | Risk Level |
|-------|------------|------------|------------|
| **Malicious AI Agent** | Crafted prompts, encoded payloads, multi-step attacks | Data exfiltration, system access, privilege escalation | HIGH |
| **Compromised Client** | Full control over MCP messages, timing attacks | Lateral movement, persistence, data theft | HIGH |
| **Adversarial User** | Prompt injection via AI, indirect attacks | Unauthorized access, denial of service | MEDIUM |
| **Network Attacker** | Man-in-the-middle, message tampering | Credential theft, session hijacking | MEDIUM |
| **Insider Threat** | Knowledge of system internals | Data leakage, backdoor installation | MEDIUM |

### Attack Vectors

#### 1. Injection Attacks

**Threat**: Attackers inject malicious code/commands through MCP tool arguments.

| Attack Type | Example | Severity | Detection Layer |
|-------------|---------|----------|-----------------|
| Command Injection | `$(rm -rf /)`, `` `whoami` `` | CRITICAL | Layer 2 |
| SQL Injection | `' OR 1=1; DROP TABLE--` | HIGH | Layer 2 |
| NoSQL Injection | `{"$where": "..."}` | HIGH | Layer 2 |
| XSS | `<script>alert(1)</script>` | HIGH | Layer 2 |
| LDAP Injection | `*)(uid=*))(|(uid=*` | HIGH | Layer 2 |
| XPath Injection | `' or '1'='1` | HIGH | Layer 2 |

#### 2. Path Traversal

**Threat**: Attackers access files outside intended directories.

| Attack Type | Example | Severity | Detection Layer |
|-------------|---------|----------|-----------------|
| Basic Traversal | `../../../etc/passwd` | HIGH | Layer 2 |
| Encoded Traversal | `%2e%2e%2f%2e%2e%2f` | HIGH | Layer 2 |
| Null Byte Injection | `file.txt%00.jpg` | HIGH | Layer 2 |
| Unicode Normalization | `..%c0%af..%c0%af` | HIGH | Layer 2 |

#### 3. Server-Side Request Forgery (SSRF)

**Threat**: Attackers make the server access internal resources or cloud metadata.

| Target | Example | Severity | Detection Layer |
|--------|---------|----------|-----------------|
| AWS Metadata | `http://169.254.169.254/latest/meta-data/` | CRITICAL | Layer 2 |
| GCP Metadata | `http://metadata.google.internal/` | CRITICAL | Layer 2 |
| Azure Metadata | `http://169.254.169.254/metadata/` | CRITICAL | Layer 2 |
| Localhost | `http://127.0.0.1:8080/admin` | HIGH | Layer 2 |
| Private Networks | `http://10.0.0.1/internal` | HIGH | Layer 2 |

#### 4. Deserialization Attacks

**Threat**: Attackers exploit insecure deserialization to achieve remote code execution.

| Platform | Marker | Severity | Detection Layer |
|----------|--------|----------|-----------------|
| Java | `rO0ABXNy` (base64), `aced0005` (hex) | CRITICAL | Layer 2 |
| PHP | `O:8:"stdClass":` | CRITICAL | Layer 2 |
| Python | `cos\nsystem` (pickle) | CRITICAL | Layer 2 |
| .NET | `AAEAAADxxxxxxxx` (BinaryFormatter) | CRITICAL | Layer 2 |
| Ruby | `Marshal.load`, `BAh...` (base64) | HIGH | Layer 2 |
| Log4Shell | `${jndi:ldap://...}` | CRITICAL | Layer 2 |
| YAML | `!!python/object/apply`, `!!js/function` | HIGH | Layer 2 |

#### 4a. CSS Injection

**Threat**: Attackers inject malicious CSS to execute code or exfiltrate data.

| Attack Type | Example | Severity | Detection Layer |
|-------------|---------|----------|-----------------|
| CSS Expressions | `expression(alert(1))` | CRITICAL | Layer 2 |
| CSS Import | `@import url(http://evil.com)` | HIGH | Layer 2 |
| IE Behaviors | `behavior: url(...)` | HIGH | Layer 2 |
| XBL Binding | `-moz-binding: url(...)` | HIGH | Layer 2 |
| URL JavaScript | `url(javascript:...)` | CRITICAL | Layer 2 |

#### 4b. Secret/Credential Detection

**Threat**: Accidental exposure of secrets and credentials in requests.

| Secret Type | Pattern | Severity | Detection Layer |
|-------------|---------|----------|-----------------|
| AWS Access Key | `AKIA[0-9A-Z]{16}` | HIGH | Layer 2 |
| AWS Secret Key | `aws_secret_access_key=...` | HIGH | Layer 2 |
| Google API Key | `AIza[0-9A-Za-z\-_]{35}` | MEDIUM | Layer 2 |
| Stripe Secret | `sk_live_[0-9a-zA-Z]{24,}` | HIGH | Layer 2 |
| GitHub Token | `ghp_[A-Za-z0-9]{36,}` | HIGH | Layer 2 |
| Slack Token | `xox[aboprs]-...` | HIGH | Layer 2 |
| JWT (alg=none) | `"alg": "none"` | HIGH | Layer 2 |

#### 5. Denial of Service

**Threat**: Attackers exhaust server resources to degrade or prevent service.

| Attack Type | Example | Severity | Detection Layer |
|-------------|---------|----------|-----------------|
| Rate Flooding | >30 requests/minute | HIGH | Layer 3 |
| Burst Attack | >10 requests in 10 seconds | HIGH | Layer 3 |
| Automated Timing | Requests at consistent intervals (low variance) | MEDIUM | Layer 3 |
| Probing/Recon | Methods like `test*`, `scan*`, `*admin*` | LOW | Layer 3 |
| Message Size | >50KB payload | HIGH | Layer 1 |
| ReDoS | Crafted regex input | HIGH | Layer 2 |
| Billion Laughs | XML entity expansion | CRITICAL | Layer 2 |
| Memory Exhaustion | Large decoded strings | HIGH | Layer 2 |

#### 6. Protocol Attacks

**Threat**: Attackers exploit protocol-level vulnerabilities.

| Attack Type | Example | Severity | Detection Layer |
|-------------|---------|----------|-----------------|
| Invalid JSON-RPC | Missing `jsonrpc: "2.0"` | HIGH | Layer 1 |
| Method Tampering | Unauthorized method access | HIGH | Layer 1/4 |
| CRLF Injection | `\r\n\r\nHTTP/1.1 200 OK` | HIGH | Layer 2 |
| Prototype Pollution | `{"__proto__": {"admin": true}}` | HIGH | Layer 2 |

#### 7. Data Exfiltration

**Threat**: Attackers steal sensitive data through responses.

| Attack Type | Example | Severity | Detection Layer |
|-------------|---------|----------|-----------------|
| PII Leakage | SSN, credit cards in response | HIGH | Layer 5 |
| Secret Exposure | API keys, tokens | CRITICAL | Layer 5 |
| Error Information | Stack traces, internal paths | MEDIUM | Error Sanitizer |

---

## Security Architecture

### Defense-in-Depth Model

```text
                    ┌─────────────────────────────────────────────────────┐
                    │                   MCP CLIENT                        │
                    └─────────────────────────────────────────────────────┘
                                            │
                                            ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│                         SECURE TRANSPORT LAYER                                │
│  • Message interception    • Error sanitization    • Audit logging            │
└───────────────────────────────────────────────────────────────────────────────┘
                                            │
                    ┌───────────────────────┼───────────────────────┐
                    │                       │                       │
                    ▼                       │                       │
┌─────────────────────────────┐             │             ┌─────────────────────┐
│      LAYER 1: STRUCTURE     │             │             │   REQUEST NORMALIZER │
│  • JSON-RPC 2.0 format      │◄────────────┴────────────►│  • Format detection  │
│  • Size limits (50KB)       │                           │  • ID generation     │
│  • Encoding validation      │                           │  • SDK compatibility │
│  • Parameter count (100)    │                           └─────────────────────┘
└─────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────┐
│      LAYER 2: CONTENT       │─────────────────────────────────────────────────┐
│  • 19 attack pattern groups │                                                 │
│  • Canonicalization         │        ┌─────────────────────────────────────┐ │
│  • Multi-encoding detection │        │        PATTERN CATEGORIES           │ │
│  • Input size limits (2MB)  │        │  • pathTraversal  • xss            │ │
└─────────────────────────────┘        │  • sql           • command         │ │
                    │                   │  • ssrf          • nosql           │ │
                    ▼                   │  • deserialization • xml           │ │
┌─────────────────────────────┐        │  • crlf          • lolbins         │ │
│      LAYER 3: BEHAVIOR      │        │  • graphql       • bufferOverflow  │ │
│  • Rate limiting (30/min)   │        │  • script        • encoding        │ │
│  • Burst detection (10/10s) │        │  • css           • csv             │ │
│  • Pattern analysis         │        │  • svg           • secrets         │ │
│  • Hourly limits (500/hr)   │        └─────────────────────────────────────┘ │
└─────────────────────────────┘                                                 │
                    │                   ◄────────────────────────────────────────┘
                    ▼
┌─────────────────────────────┐
│      LAYER 4: SEMANTICS     │
│  • Tool registry contracts  │        ┌─────────────────────────────────────┐
│  • Resource access policies │        │         TOOL REGISTRY               │
│  • Per-tool quotas          │───────►│  • Argument validation              │
│  • Side effect declarations │        │  • Size limits                      │
│  • Egress limits            │        │  • Quota enforcement                │
└─────────────────────────────┘        └─────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────┐
│     LAYER 5: CONTEXTUAL     │
│  • Custom validators        │        ┌─────────────────────────────────────┐
│  • Domain restrictions      │        │        CONTEXT STORE                │
│  • OAuth validation         │───────►│  • Cross-request state              │
│  • Response filtering       │        │  • Session management               │
│  • Global rules             │        │  • TTL-based expiration             │
└─────────────────────────────┘        └─────────────────────────────────────┘
                    │
                    ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│                             MCP SERVER                                        │
│                    (Protected by 5-layer validation)                          │
└───────────────────────────────────────────────────────────────────────────────┘
```

### Security Components

| Component | Responsibility | Location |
|-----------|----------------|----------|
| `SecureMcpServer` | Main entry point, pipeline orchestration | `mcp-secure-server.ts` |
| `SecureTransport` | Message interception, error handling (stdio) | `transport/secure-transport.ts` |
| `createSecureHttpServer` | HTTP transport with 5-layer validation | `transport/http-server.ts` |
| `createSecureHttpHandler` | HTTP request handler for custom servers | `transport/http-server.ts` |
| `ValidationPipeline` | Layer sequencing, result aggregation | `utils/validation-pipeline.ts` |
| `ErrorSanitizer` | Information disclosure prevention | `utils/error-sanitizer.ts` |
| `RequestNormalizer` | Input format standardization | `utils/request-normalizer.ts` |
| `SecurityLogger` | Audit trail, metrics collection | `utils/security-logger.ts` |

---

## Attack Surface Analysis

### Input Points

| Entry Point | Data Type | Validation Layers | Risk |
|-------------|-----------|-------------------|------|
| `method` | String | 1, 3 | MEDIUM |
| `params` | Object | 1, 2, 4 | HIGH |
| `params.arguments` | Object | 2, 4 | HIGH |
| `params.name` | String | 2, 4 | MEDIUM |
| `params.uri` | String | 2, 4 | HIGH |
| `id` | String/Number | 1 | LOW |

### Output Points

| Exit Point | Data Type | Protection | Risk |
|------------|-----------|------------|------|
| Tool responses | Any | Layer 5 response validators | HIGH |
| Error messages | String | ErrorSanitizer | MEDIUM |
| Resource content | Buffer/String | Layer 4 egress limits | HIGH |

### Trust Boundaries

```text
┌──────────────────────────────────────────────────────────────┐
│                    UNTRUSTED ZONE                            │
│                                                              │
│  ┌────────────────┐    ┌────────────────┐                   │
│  │   AI Agent     │    │   MCP Client   │                   │
│  │  (Claude, etc) │    │   (Desktop)    │                   │
│  └───────┬────────┘    └───────┬────────┘                   │
│          │                     │                             │
│          └──────────┬──────────┘                             │
│                     │                                        │
└─────────────────────│────────────────────────────────────────┘
                      │
                      │  TRUST BOUNDARY
                      │  (All input validated)
                      ▼
┌──────────────────────────────────────────────────────────────┐
│                    VALIDATION ZONE                           │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              MCP Security Framework                   │   │
│  │         (5 Layers + Support Components)               │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
└──────────────────────────────────────────────────────────────┘
                      │
                      │  TRUST BOUNDARY
                      │  (Validated requests only)
                      ▼
┌──────────────────────────────────────────────────────────────┐
│                    TRUSTED ZONE                              │
│                                                              │
│  ┌────────────────┐    ┌────────────────┐                   │
│  │   MCP Server   │    │   File System  │                   │
│  │   (Your App)   │    │   Database     │                   │
│  └────────────────┘    └────────────────┘                   │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

---

## Mitigation Strategies

### Layer 1: Structure Validation

| Threat | Mitigation | Configuration |
|--------|------------|---------------|
| Oversized messages | Size limit enforcement | `maxMessageSize: 50000` |
| Parameter flooding | Count limits | `maxParamCount: 20` |
| Method name abuse | Length limits | `maxMethodLength: 100` |
| Protocol violations | JSON-RPC 2.0 validation | Always enabled |

### Layer 2: Content Validation

| Threat | Mitigation | Implementation |
|--------|------------|----------------|
| Injection attacks | Pattern-based detection | 19 attack categories, 200+ patterns |
| Encoding evasion | Multi-layer canonicalization | URL, HTML, Unicode, hex decoding |
| ReDoS | Input size limits | `MAX_CONTENT_INPUT_SIZE: 2MB` |
| Memory exhaustion | Decode size limits | `MAX_URL_DECODE_INPUT_SIZE: 1MB` |

### Layer 3: Behavior Validation

| Threat | Mitigation | Configuration |
|--------|------------|---------------|
| Brute force | Rate limiting | `maxRequestsPerMinute: 30` |
| DoS | Burst detection | `burstThreshold: 10` (10 requests in 10 seconds) |
| Sustained attacks | Hourly limits | `maxRequestsPerHour: 500` |
| Automation | Timing analysis | Detects low-variance request intervals |
| Reconnaissance | Method probing detection | Flags `test*`, `scan*`, `admin*` patterns |

### Layer 4: Semantic Validation

| Threat | Mitigation | Configuration |
|--------|------------|---------------|
| Unauthorized tool use | Tool registry | Explicit tool allowlist |
| Data theft | Egress limits | `maxEgressBytes: 100000` |
| Path escape | Resource policies | `rootDirs`, `denyGlobs` |
| Quota abuse | Per-tool limits | `quotaPerMinute`, `quotaPerHour` |

### Layer 5: Contextual Validation

| Threat | Mitigation | Implementation |
|--------|------------|----------------|
| Domain abuse | Domain restrictions | `blockedDomains`, `allowedDomains` |
| OAuth attacks | URL validation | Scheme and domain validation |
| Data leakage | Response validators | PII detection, sanitization |
| Custom threats | Extensible validators | `addValidator()`, `addGlobalRule()` |

---

## Security Assumptions

### What We Assume Is Secure

1. **Transport Layer**: The underlying transport (stdio, HTTP) is secure
2. **Runtime Environment**: Node.js runtime is not compromised
3. **Configuration**: Security configuration is not tampered with
4. **Dependencies**: MCP SDK and Zod are trusted

### What We Do NOT Assume

1. **AI Agent Behavior**: AI agents may generate malicious requests
2. **Client Integrity**: MCP clients may be compromised
3. **User Input**: All user-influenced data is potentially hostile
4. **Network Security**: Man-in-the-middle attacks are possible

### Security Invariants

| Invariant | Enforcement | Violation Response |
|-----------|-------------|-------------------|
| All requests validated | ValidationPipeline | Request blocked |
| No internal errors exposed | ErrorSanitizer | Generic error returned |
| Rate limits enforced | BehaviorValidationLayer | Request blocked |
| Resource access controlled | SemanticValidationLayer | Access denied |

---

## Known Limitations

### Detection Gaps

| Gap | Description | Mitigation Recommendation |
|-----|-------------|---------------------------|
| Zero-day patterns | New attack patterns not yet cataloged | Enable verbose logging, monitor for anomalies |
| Semantic attacks | Context-dependent malicious behavior | Use Layer 5 custom validators |
| Encrypted payloads | Attacks within encrypted data | Decrypt and validate at application layer |
| Time-of-check attacks | Race conditions in multi-step flows | Use atomic operations where possible |

### Performance Trade-offs

| Trade-off | Impact | Configuration |
|-----------|--------|---------------|
| Pattern matching | ~5-20ms per request | Disable specific pattern groups if needed |
| Canonicalization | Memory overhead | Adjust `MAX_URL_DECODE_INPUT_SIZE` |
| Rate tracking | Memory for counters | Configure `maxSessions` |

### False Positive Risks

| Pattern | False Positive Scenario | Mitigation |
|---------|------------------------|------------|
| SQL keywords | Legitimate text containing `SELECT` | Context-aware validation |
| Path sequences | Legitimate relative paths | Configure `rootDirs` |
| Script tags | HTML content in responses | Use allowlists for content types |

---

## Reporting Vulnerabilities

### Responsible Disclosure

If you discover a security vulnerability in the MCP Security Framework:

1. **Do NOT** disclose publicly until fixed
2. **Report**: Open a [GitHub Security Advisory](https://github.com/aself101/mcp-secure-server/security/advisories/new)
3. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Suggested fix (if any)

### Response Timeline

| Stage | Timeline |
|-------|----------|
| Acknowledgment | Within 48 hours |
| Initial Assessment | Within 7 days |
| Fix Development | Within 30 days for critical issues |
| Public Disclosure | After fix is released |

### Security Updates

Security updates are released as patch versions (e.g., `0.9.1`) and announced through:
- GitHub Security Advisories
- npm deprecation notices for vulnerable versions
- CHANGELOG.md entries

---

## Security Checklist

### Before Deployment

- [ ] Review default configuration for your environment
- [ ] Configure appropriate rate limits for expected traffic
- [ ] Set up resource policies (`rootDirs`, `denyGlobs`)
- [ ] Register all tools with appropriate constraints
- [ ] Enable logging for security events
- [ ] Test with attack payloads from test suite

### Runtime Monitoring

- [ ] Monitor security logs for blocked requests
- [ ] Track rate limit violations
- [ ] Review periodic security reports
- [ ] Alert on CRITICAL severity events

### Maintenance

- [ ] Keep dependencies updated (`npm audit`)
- [ ] Review security advisories for MCP SDK
- [ ] Update attack patterns periodically
- [ ] Review and rotate any secrets/tokens

---

## Appendix: Violation Types Reference

### Generic Violations

| Violation Type | Severity | Description |
|----------------|----------|-------------|
| `UNKNOWN` | MEDIUM | Unknown or unclassified violation |
| `VALIDATION_ERROR` | MEDIUM | General validation failure |
| `INTERNAL_ERROR` | HIGH | Internal processing error |
| `POLICY_VIOLATION` | HIGH | Generic policy violation |

### Layer 1: Structure Violations

| Violation Type | Severity | Description |
|----------------|----------|-------------|
| `INVALID_MESSAGE` | CRITICAL | Null, undefined, or non-object message |
| `INVALID_PROTOCOL` | HIGH | Invalid JSON-RPC 2.0 structure |
| `INVALID_METHOD` | HIGH | Invalid or disallowed method name |
| `INVALID_SCHEMA` | HIGH | Message fails schema validation |
| `SIZE_LIMIT_EXCEEDED` | HIGH | Message exceeds size limit |
| `STRING_LIMIT_EXCEEDED` | HIGH | String parameter exceeds length limit |
| `PARAM_LIMIT_EXCEEDED` | HIGH | Too many parameters in request |
| `MISSING_REQUIRED_PARAM` | HIGH | Required parameter missing |
| `MALFORMED_MESSAGE` | HIGH | Message structure is malformed |

### Layer 2: Content Violations

| Violation Type | Severity | Description |
|----------------|----------|-------------|
| `DANGEROUS_ENCODING` | HIGH | Null bytes or dangerous unicode detected |
| `SUSPICIOUS_ENCODING` | MEDIUM | Unusual encoding patterns detected |
| `ENCODING_EVASION` | HIGH | Encoding used to bypass detection |
| `PATH_TRAVERSAL` | HIGH | Directory escape attempt |
| `COMMAND_INJECTION` | CRITICAL | Shell command execution attempt |
| `SQL_INJECTION` | HIGH | Database query manipulation |
| `NOSQL_INJECTION` | HIGH | NoSQL database attacks |
| `GRAPHQL_INJECTION` | HIGH | GraphQL introspection/abuse |
| `XSS_ATTEMPT` | HIGH | Cross-site scripting |
| `SCRIPT_INJECTION` | HIGH | Python/Node script injection |
| `CSS_INJECTION` | HIGH | Malicious CSS injection |
| `CRLF_INJECTION` | HIGH | HTTP header injection |
| `SSRF_ATTEMPT` | CRITICAL | Server-side request forgery |
| `BUFFER_OVERFLOW_ATTEMPT` | CRITICAL | Buffer overflow patterns (NOP sleds, format strings) |
| `DESERIALIZATION_INJECTION` | CRITICAL | Unsafe deserialization |
| `PROTOTYPE_POLLUTION` | CRITICAL | JavaScript prototype manipulation |
| `XML_ENTITY_ATTACK` | CRITICAL | XXE or Billion Laughs |
| `LOLBINS_EXECUTION` | CRITICAL | Living-off-the-land binary abuse |
| `CSV_INJECTION` | HIGH | CSV formula injection |
| `SVG_INJECTION` | HIGH | Malicious SVG content |
| `SECRET_EXPOSURE` | HIGH | API keys, tokens, credentials in request |
| `DANGEROUS_DATA_URI` | HIGH | Malicious data URI scheme |
| `BASE64_INJECTION` | HIGH | Malicious base64-encoded content |
| `NESTED_DATA_URI` | HIGH | Nested data URI evasion attempt |
| `SUSPICIOUS_TEST_DATA` | LOW | Suspicious test/debug data patterns |
| `EXCESSIVE_NESTING` | MEDIUM | Deeply nested object structure |

### Layer 3: Behavior Violations

| Violation Type | Severity | Description |
|----------------|----------|-------------|
| `REQUEST_FLOODING` | HIGH | Excessive request volume |
| `RATE_LIMIT_EXCEEDED` | HIGH | Too many requests per time window |
| `BURST_ACTIVITY` | HIGH | Suspicious request burst |
| `OVERSIZED_MESSAGE` | MEDIUM | Suspiciously large message |
| `AUTOMATED_TIMING` | MEDIUM | Automated timing pattern detected |
| `SUSPICIOUS_METHOD` | LOW | Probing/reconnaissance method pattern |
| `OVERSIZED_PARAMS` | MEDIUM | Parameters exceed size threshold |
| `EXCESSIVE_PARAM_COUNT` | MEDIUM | Too many parameters |
| `PARAM_SERIALIZATION_ERROR` | MEDIUM | Parameter serialization failed |

### Layer 4: Semantic Violations

| Violation Type | Severity | Description |
|----------------|----------|-------------|
| `QUOTA_EXCEEDED` | HIGH | Tool usage quota exceeded |
| `TOOL_NOT_ALLOWED` | HIGH | Tool not in registry |
| `INVALID_TOOL_ARGUMENTS` | HIGH | Tool arguments fail validation |
| `TOOL_EGRESS_LIMIT` | MEDIUM | Tool egress limit exceeded |
| `ARGS_EGRESS_LIMIT` | MEDIUM | Argument size exceeds egress limit |
| `ARG_SERIALIZATION_ERROR` | MEDIUM | Argument serialization failed |
| `SIDE_EFFECT_NOT_ALLOWED` | HIGH | Tool side effect not permitted |
| `RESOURCE_POLICY_VIOLATION` | HIGH | Unauthorized resource access |
| `RESOURCE_EGRESS_LIMIT` | MEDIUM | Resource response exceeds limit |
| `CHAIN_VIOLATION` | HIGH | Tool chaining rule violation |
| `INVALID_MCP_METHOD` | HIGH | Invalid MCP method call |

### Layer 5: Contextual Violations

| Violation Type | Severity | Description |
|----------------|----------|-------------|
| `DOMAIN_RESTRICTION_VIOLATION` | MEDIUM | Blocked domain access |
| `BLOCKED_DOMAIN` | HIGH | Domain on blocklist |
| `DOMAIN_NOT_ALLOWED` | MEDIUM | Domain not on allowlist |
| `DANGEROUS_URL_SCHEME` | HIGH | javascript:, vbscript:, data: schemes |
| `SENSITIVE_DATA_EXPOSURE` | HIGH | PII or secrets in response |
| `VALIDATOR_ERROR` | MEDIUM | Custom validator error |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 0.9.0 | 2025-12 | Initial security documentation |

---

*This document is part of the MCP Security Framework. For usage documentation, see [README.md](README.md).*
