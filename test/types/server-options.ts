/**
 * Type-level guard for SecureMcpServer options, compiled by `npm run check:types`
 * against the package's own published declarations.
 *
 * 0.0.26-security documented `contextual.maxContextEntries` in the README, and
 * Layer 5 honoured it at runtime, but `SecureMcpServerOptions.contextual` is
 * typed from a second, hand-maintained copy of the Layer 5 options
 * (src/types/layers.ts) that the field was never added to, so the README
 * example failed with TS2353. This file pins the documented shapes and
 * derives a parity check between the two copies, so a key added to the
 * builder's config but not to the public options fails the build.
 */
import { SecureMcpServer, ContextualConfigBuilder, createSecureHttpServer } from 'mcp-secure-server';
import type { SecureMcpServerOptions } from 'mcp-secure-server';

new SecureMcpServer({ name: 'types-fixture', version: '1.0.0' }, {
  contextual: {
    enabled: true,
    domainRestrictions: { enabled: true, blockedDomains: ['evil.com'], allowedDomains: [] },
    oauthValidation: { enabled: true, allowedDomains: ['oauth.example.com'], blockDangerousSchemes: true },
    rateLimiting: { enabled: true, limit: 20, windowMs: 60000 },
    maxContextEntries: 10000
  }
});

new SecureMcpServer({ name: 'types-fixture', version: '1.0.0' }, {
  contextual: { rateLimiting: { enabled: true, limit: 2 } }
});

const server = new SecureMcpServer({ name: 'types-fixture', version: '1.0.0' });
createSecureHttpServer(server, { trustProxy: ['uniquelocal', '10.0.0.0/8'] });
createSecureHttpServer(server, { trustProxy: 1 });
// @ts-expect-error -- `true` (Express's "trust every hop") is rejected at the type level too
createSecureHttpServer(server, { trustProxy: true });

type PublicContextual = NonNullable<SecureMcpServerOptions['contextual']>;
type BuilderContextual = ReturnType<ContextualConfigBuilder['build']>;
type MissingFromPublic = Exclude<keyof BuilderContextual, keyof PublicContextual>;
const parity: [MissingFromPublic] extends [never] ? true : { missingFromPublicOptions: MissingFromPublic } = true;
void parity;
