# Repository Guidelines

## Project Structure & Module Organization
Source lives in `src/`, where `index.ts` re-exports the secure server, `security/` contains the layered middleware and transports, and `types/` stores shared definitions. Tests mirror this layout under `test/unit`, `test/integration`, and `test/performance`. Docs sit in `docs/`, examples in `cookbook/`, and builds in `dist/` (never edit generated files).

## Build, Test, and Development Commands
- `npm run build` – runs `tsc` and refreshes `dist/`.
- `npm test` – executes the entire Vitest suite; required before any PR.
- `npm run test:unit|test:integration|test:performance` – scope runs to the feature you are touching.
- `npm run test:watch` / `npm run test:coverage` – watch locally and regenerate the ≥86% coverage report before releases.
- `npm run minimal-server` – boots `cookbook/minimal-server/minimal-test-server.ts` for manual probing.
- `npm run lint` – enforces the shared ESLint configuration across `src/`.

## Coding Style & Naming Conventions
Write TypeScript (ES modules, Node ≥18) with 2-space indentation and relative imports. Classes/interfaces are `PascalCase`, functions/variables `camelCase`, constants `UPPER_SNAKE_CASE`, and filenames should state the layer they implement (`layer3-behavior.ts`, `secure-transport.ts`). Keep modules ≈300 LOC per `docs/AI-preferences.md`, reuse utilities, and rely on `npm run lint` to enforce ESLint + `@typescript-eslint`.

## Layer Implementation Notes
Validation layers extend `ValidationLayerBase`, implement `validate(message, context)` with the standard `{ passed, allowed, severity, reason, violationType }` shape, must flow through `ValidationPipeline`, sanitize errors with `ErrorSanitizer`, source attack patterns from `src/security/layers/layer-utils/content/dangerous-patterns.ts`, and expose options via `SecureMcpServer`.

## Testing Guidelines
Vitest drives every suite; keep specs `*.test.ts`/`*.test.js` inside the matching `test/<suite>/` folder so targeted runs stay fast. Validator or limit updates must ship with regression tests plus payload fixtures in `cookbook/test-data/`. Maintain ≥85% coverage via `npm run test:coverage`, note gaps in the PR, and cite `npm run minimal-server` when verifying transports.

## Commit & Pull Request Guidelines
Commits use the Conventional Commit style in history (`feat(security): …`, `fix(transport): …`, `refactor(security): …`); keep subjects imperative and under ~72 characters. Every PR should link the motivating issue, summarize the change, list the commands executed, and flag security or cookbook impact. Update docs when altering limits, transports, or defaults, and attach screenshots/logs only when they clarify behavior.

## Security & Configuration Tips
Default limits/policies in `src/security/constants.ts` deny outbound network and writes; any change needs matching documentation and rationale in the PR. Keep verbose logging disabled outside targeted tests so sensitive payloads stay private. Review `SECURITY.md` and surface new knobs through `src/security/mcp-secure-server.ts` before merging layer or transport changes.
