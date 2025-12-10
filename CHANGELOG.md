# Changelog

All notable changes to the MCP Security Framework will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.0] - 2025-12-10

### Added
- **Layer 5 (Contextual Validation) now enabled by default** - Full 5-layer security pipeline
- Domain restriction support (blocklist and allowlist)
- OAuth URL validation with dangerous scheme blocking
- Response content validation for sensitive data detection
- Custom validator registration with priority ordering
- Global rules for cross-cutting security policies
- Context store for cross-request state with TTL support
- New exports: `ContextualValidationLayer`, `ContextualConfigBuilder`, `createContextualLayer`
- Comprehensive Layer 5 integration tests (38 new tests)

### Changed
- Default security pipeline now includes 5 layers (was 4)
- Consolidated `MCPSecurityMiddleware`, `EnhancedMCPSecurityMiddleware`, and `SecureMcpServer` into single `SecureMcpServer` class
- Logging now opt-in (quiet by default for production)
- Flattened options structure (no more `{ security: {...} }` nesting)
- 488 tests passing (was 464)

### Removed
- **Breaking**: `MCPSecurityMiddleware` and `EnhancedMCPSecurityMiddleware` exports removed
- Dead exports from package.json (`./middleware`, `./enhanced`)

### Fixed
- ESLint errors and warnings (122 issues resolved)
- Unnecessary try/catch wrapper in security-logger.js

## [0.7.1] - 2025-12-09

### Added
- Prototype pollution detection (P1/P2 pentest findings)
- XML entity attack detection (XXE, Billion Laughs - P3/P4 pentest findings)
- SSRF detection with cloud metadata endpoint protection (AWS, GCP, Azure, DigitalOcean, Oracle Cloud)
- Private network and loopback address blocking (RFC1918)
- Dangerous URI scheme detection (file://, gopher://, dict://, ldap://, ftp://, smb://)
- NoSQL injection detection (MongoDB operators, ObjectId)
- Deserialization attack detection (Java, PHP, Python pickle, YAML, .NET, Ruby Marshal, JNDI/Log4Shell)
- CSV injection detection
- LOLBins (Living Off The Land Binaries) detection
- GraphQL introspection and deep query detection
- Null/undefined message handling in Layer 1
- Multi-layer integration tests for defense-in-depth validation
- Quota timing edge case tests

### Changed
- Updated @modelcontextprotocol/sdk to v1.24.3 (security fix for DNS rebinding)
- Improved Unicode canonicalization for attack detection
- Enhanced test coverage from 346 to 450 tests

### Fixed
- Unhandled promise rejections for null/undefined messages
- Repository URL in package.json corrected to GitLab

### Removed
- ~7,860 lines of dead code (unused files, archive folder)
- Unused dependencies (cors, express, pino, zod)

## [0.7.0] - 2025-12-01

### Added
- Layer 2 refactoring with modular validators
- Configuration-driven attack pattern system
- SecureTransport wrapper for transport-level validation
- SecureMcpServer as drop-in replacement for McpServer

### Fixed
- Unicode/canonicalization edge cases
- Memory leak in request history tracking

### Changed
- Production ready with validation score improvements
- Improved error sanitization

## [0.6.0] - 2025-11-15

### Added
- Layer 5 (Contextual Validation) with custom validator registration
- OAuth/domain restriction support
- Response validation capabilities
- Priority-based rule ordering

### Changed
- Enhanced Layer 4 semantic validation
- Improved quota management with time-window tracking

## [0.5.0] - 2025-11-01

### Added
- Layer 4 (Semantic Validation) with tool contract enforcement
- Resource access policies
- Quota management with configurable limits
- Session tracking with TTL

### Changed
- Improved rate limiting algorithms in Layer 3

## [0.4.0] - 2025-10-15

### Added
- Layer 3 (Behavior Validation) with rate limiting
- Burst detection algorithms
- Request pattern analysis

## [0.3.0] - 2025-10-01

### Added
- Layer 2 (Content Validation) with injection detection
- Path traversal protection
- Command injection detection
- SQL injection prevention
- XSS protection
- CRLF injection prevention

## [0.2.0] - 2025-09-15

### Added
- Layer 1 (Structure Validation)
- JSON-RPC 2.0 format validation
- Request size limits
- Encoding validation
- Dangerous Unicode character detection

## [0.1.0] - 2025-09-01

### Added
- Initial project structure
- Basic MCP middleware architecture
- ValidationPipeline framework
- ErrorSanitizer for safe error responses
- SecurityLogger for audit logging
