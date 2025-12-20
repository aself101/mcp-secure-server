## [1.0.1](https://github.com/aself101/mcp-secure-server/compare/v1.0.0...v1.0.1) (2025-12-20)

### Reverts

* restore mcp-secure-server package name ([c1ce99e](https://github.com/aself101/mcp-secure-server/commit/c1ce99ecd2cd47dd171468a87ea8da8e31706335))

## [1.0.0](https://github.com/aself101/mcp-secure-server/compare/v0.9.2...v1.0.0) (2025-12-20)

### ⚠ BREAKING CHANGES

* Package renamed from mcp-secure-server to secure-mcp-server

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>

### Features

* rename package to secure-mcp-server ([95892a8](https://github.com/aself101/mcp-secure-server/commit/95892a827567c82df509b517295f26102713f681))

## [0.9.2](https://github.com/aself101/mcp-secure-server/compare/v0.9.1...v0.9.2) (2025-12-20)

### Bug Fixes

* **npm:** add publishConfig with public access ([0d4db2c](https://github.com/aself101/mcp-secure-server/commit/0d4db2c26e3ea897d8b5859f13e626833ee09de8))

## [0.9.1](https://github.com/aself101/mcp-secure-server/compare/v0.9.0...v0.9.1) (2025-12-20)

### Bug Fixes

* **ci:** add public access flag for npm publish ([6f7ea8a](https://github.com/aself101/mcp-secure-server/commit/6f7ea8a2b08bb660b7978fa3850f0455ae206e61))

## [0.9.0](https://github.com/aself101/mcp-secure-server/compare/v0.8.0...v0.9.0) (2025-12-20)

### Features

* **cookbook:** add advanced-validation-server demonstrating Layer 5 custom validators ([9bc84b2](https://github.com/aself101/mcp-secure-server/commit/9bc84b27cbca81f864b773bdf3ff482176353cee))
* **cookbook:** add monitoring-server for production observability ([5b8ffbd](https://github.com/aself101/mcp-secure-server/commit/5b8ffbdbcb949548039a310bcdd4a08b1cf75eac))
* **security:** add response validation to tool handlers ([3216c6e](https://github.com/aself101/mcp-secure-server/commit/3216c6e4b0748c7d87ea813940a1a763cf0b3131))
* **security:** implement extended chaining rules with glob patterns ([62b165f](https://github.com/aself101/mcp-secure-server/commit/62b165fff4378f6b97a833bd1f9875d7efeea8c4))
* **security:** restore method chaining validation to Layer 4 ([195bdbf](https://github.com/aself101/mcp-secure-server/commit/195bdbf2f61198f5236c62c600a8758d0c78920f))
* **security:** wire CSV, SVG, and secrets pattern detection ([7032d67](https://github.com/aself101/mcp-secure-server/commit/7032d6746f932385acfac6c6d1f7e2d28db5d956))
* **transport:** add HTTP transport with createSecureHttpServer and createSecureHttpHandler ([b927d4f](https://github.com/aself101/mcp-secure-server/commit/b927d4f959d45891ba080f063b8c86297a0408de))

### Bug Fixes

* **ci:** exclude cookbook from test execution ([d8af9ef](https://github.com/aself101/mcp-secure-server/commit/d8af9ef367c8df0ac76cc3551e3c3a532c634573))
* **ci:** use working release workflow with NODE_AUTH_TOKEN ([6327bf1](https://github.com/aself101/mcp-secure-server/commit/6327bf1fb8f637194e792aa40885650650856ba2))
* **cookbook:** fix advanced-validation-server tool registration ([f1e1d55](https://github.com/aself101/mcp-secure-server/commit/f1e1d55eb91fe1af975b7763df357f1d641dab29))
* **docs:** add npm version badge to README ([26aa8d7](https://github.com/aself101/mcp-secure-server/commit/26aa8d78ff0b1f31c32bd0c67e53d0581ce76d34))
* **security:** extend CSV DDE payload detection to JSON-embedded attacks ([2db706c](https://github.com/aself101/mcp-secure-server/commit/2db706c4d184cbbadcf3732a30db82bef32c5ec7))
* **security:** extend CSV injection detection to JSON-embedded payloads ([b36053e](https://github.com/aself101/mcp-secure-server/commit/b36053ebbf32a80a9eb6d41bec192f8d4bb48de4))
* **security:** reduce false positives in CSV injection detection ([fc6de80](https://github.com/aself101/mcp-secure-server/commit/fc6de80a4289a85d04812e18cb243138d197a64f))
* **transport:** address HTTP security audit findings ([d3e32db](https://github.com/aself101/mcp-secure-server/commit/d3e32dbe2a8522d2494b38682fe0abbb7230aee1))
* trigger npm publish retry ([3616a75](https://github.com/aself101/mcp-secure-server/commit/3616a7558642865e63d4768f3a73bd1d598ed451))
* use scoped package name @okstory/mcp-secure-server ([8ecc472](https://github.com/aself101/mcp-secure-server/commit/8ecc472ed4dbe5b452c677fefe31741b2ba1214d))

### Documentation

* **api:** add comprehensive JSDoc to public exports ([762d977](https://github.com/aself101/mcp-secure-server/commit/762d9775752601693d187d9bcfc7abce78f34bfd))
* **cookbook:** mark CRM server as skipped - redundant with database-server ([455fe05](https://github.com/aself101/mcp-secure-server/commit/455fe055c3b6ff26b81c4a5cc0ef90a5d1da538e))
* **readme:** add chaining rules to Full Configuration Reference ([1c27f35](https://github.com/aself101/mcp-secure-server/commit/1c27f3561731efa9a724ba18f682e39705c3102f))
* remove marketing language from documentation ([f51fe00](https://github.com/aself101/mcp-secure-server/commit/f51fe008c3774596bef195c28eb913c86960d22e))
* update project description - clarify we're a server, not middleware ([04d4641](https://github.com/aself101/mcp-secure-server/commit/04d4641ec0630af577f9ec9d4c6c298e829bc256))
* update test count and add JSDoc to SecureTransport ([34e50ca](https://github.com/aself101/mcp-secure-server/commit/34e50ca0c760419a3f103b86445083cb9bc41257))

### Code Refactoring

* **security:** reduce mcp-secure-server.ts from 553 to 327 lines ([0e130ff](https://github.com/aself101/mcp-secure-server/commit/0e130ff75aaaccf591e55a1ee0e296fa44853678))
* **security:** remove unused semantic sessions and simplify validation ([5df62ef](https://github.com/aself101/mcp-secure-server/commit/5df62ef9fc1e9294c1898218cd648386aec5aa31))

## [0.9.3](https://github.com/aself101/mcp-secure-server/compare/v0.9.2...v0.9.3) (2025-12-20)

### Bug Fixes

* use scoped package name @okstory/mcp-secure-server ([8ecc472](https://github.com/aself101/mcp-secure-server/commit/8ecc472ed4dbe5b452c677fefe31741b2ba1214d))

## [0.9.2](https://github.com/aself101/mcp-secure-server/compare/v0.9.1...v0.9.2) (2025-12-20)

### Bug Fixes

* trigger npm publish retry ([3616a75](https://github.com/aself101/mcp-secure-server/commit/3616a7558642865e63d4768f3a73bd1d598ed451))

## [0.9.1](https://github.com/aself101/mcp-secure-server/compare/v0.9.0...v0.9.1) (2025-12-20)

### Bug Fixes

* **docs:** add npm version badge to README ([26aa8d7](https://github.com/aself101/mcp-secure-server/commit/26aa8d78ff0b1f31c32bd0c67e53d0581ce76d34))

## [0.9.0](https://github.com/aself101/mcp-secure-server/compare/v0.8.0...v0.9.0) (2025-12-20)

### Features

* **cookbook:** add advanced-validation-server demonstrating Layer 5 custom validators ([9bc84b2](https://github.com/aself101/mcp-secure-server/commit/9bc84b27cbca81f864b773bdf3ff482176353cee))
* **cookbook:** add monitoring-server for production observability ([5b8ffbd](https://github.com/aself101/mcp-secure-server/commit/5b8ffbdbcb949548039a310bcdd4a08b1cf75eac))
* **security:** add response validation to tool handlers ([3216c6e](https://github.com/aself101/mcp-secure-server/commit/3216c6e4b0748c7d87ea813940a1a763cf0b3131))
* **security:** implement extended chaining rules with glob patterns ([62b165f](https://github.com/aself101/mcp-secure-server/commit/62b165fff4378f6b97a833bd1f9875d7efeea8c4))
* **security:** restore method chaining validation to Layer 4 ([195bdbf](https://github.com/aself101/mcp-secure-server/commit/195bdbf2f61198f5236c62c600a8758d0c78920f))
* **security:** wire CSV, SVG, and secrets pattern detection ([7032d67](https://github.com/aself101/mcp-secure-server/commit/7032d6746f932385acfac6c6d1f7e2d28db5d956))
* **transport:** add HTTP transport with createSecureHttpServer and createSecureHttpHandler ([b927d4f](https://github.com/aself101/mcp-secure-server/commit/b927d4f959d45891ba080f063b8c86297a0408de))

### Bug Fixes

* **ci:** exclude cookbook from test execution ([d8af9ef](https://github.com/aself101/mcp-secure-server/commit/d8af9ef367c8df0ac76cc3551e3c3a532c634573))
* **cookbook:** fix advanced-validation-server tool registration ([f1e1d55](https://github.com/aself101/mcp-secure-server/commit/f1e1d55eb91fe1af975b7763df357f1d641dab29))
* **security:** extend CSV DDE payload detection to JSON-embedded attacks ([2db706c](https://github.com/aself101/mcp-secure-server/commit/2db706c4d184cbbadcf3732a30db82bef32c5ec7))
* **security:** extend CSV injection detection to JSON-embedded payloads ([b36053e](https://github.com/aself101/mcp-secure-server/commit/b36053ebbf32a80a9eb6d41bec192f8d4bb48de4))
* **security:** reduce false positives in CSV injection detection ([fc6de80](https://github.com/aself101/mcp-secure-server/commit/fc6de80a4289a85d04812e18cb243138d197a64f))
* **transport:** address HTTP security audit findings ([d3e32db](https://github.com/aself101/mcp-secure-server/commit/d3e32dbe2a8522d2494b38682fe0abbb7230aee1))

### Documentation

* **api:** add comprehensive JSDoc to public exports ([762d977](https://github.com/aself101/mcp-secure-server/commit/762d9775752601693d187d9bcfc7abce78f34bfd))
* **cookbook:** mark CRM server as skipped - redundant with database-server ([455fe05](https://github.com/aself101/mcp-secure-server/commit/455fe055c3b6ff26b81c4a5cc0ef90a5d1da538e))
* **readme:** add chaining rules to Full Configuration Reference ([1c27f35](https://github.com/aself101/mcp-secure-server/commit/1c27f3561731efa9a724ba18f682e39705c3102f))
* remove marketing language from documentation ([f51fe00](https://github.com/aself101/mcp-secure-server/commit/f51fe008c3774596bef195c28eb913c86960d22e))
* update project description - clarify we're a server, not middleware ([04d4641](https://github.com/aself101/mcp-secure-server/commit/04d4641ec0630af577f9ec9d4c6c298e829bc256))
* update test count and add JSDoc to SecureTransport ([34e50ca](https://github.com/aself101/mcp-secure-server/commit/34e50ca0c760419a3f103b86445083cb9bc41257))

### Code Refactoring

* **security:** reduce mcp-secure-server.ts from 553 to 327 lines ([0e130ff](https://github.com/aself101/mcp-secure-server/commit/0e130ff75aaaccf591e55a1ee0e296fa44853678))
* **security:** remove unused semantic sessions and simplify validation ([5df62ef](https://github.com/aself101/mcp-secure-server/commit/5df62ef9fc1e9294c1898218cd648386aec5aa31))

# Changelog

All notable changes to the MCP Security Framework will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.0] - 2025-12-10

### Added
- **Full TypeScript rewrite** - Complete migration from JavaScript to TypeScript with strict mode
- **Zero `any` usage** - All dynamic data uses type guards instead of any
- **Type guards** - `isSeverity()`, `isViolationType()`, `isError()`, `getErrorMessage()` for runtime type validation
- **Type exports** - All types (Severity, ViolationType, ValidationResult, etc.) available for consumers
- **Build pipeline** - TypeScript compilation with `npm run build`, declarations, and source maps
- **ESLint TypeScript support** - Configured @typescript-eslint/parser for proper linting
- **ReDoS protection** - Bounded regex quantifiers to prevent denial-of-service
- **Prototype pollution protection** - Context store validates keys against pollution attempts
- New tests for request normalizer edge cases (19 tests)
- New tests for semantic policies edge cases (28 tests)
- Mutation tests for severity levels (18 tests)
- Boundary value tests for limits (20 tests)

### Changed
- Test count increased to 707 (was 488)
- Test coverage improved to 86%
- Package exports now point to dist/ directory
- Strict TypeScript configuration (noUncheckedIndexedAccess, strictNullChecks)
- README expanded to 1,037 lines with comprehensive documentation

### Fixed
- Package.json exports now correctly point to compiled output
- ESLint configuration now properly parses TypeScript files
- Type definitions auto-generated (removed manual index.d.ts)
- README type examples now match actual exports

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
- Validation score improvements
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
