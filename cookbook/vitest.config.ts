import { defineConfig } from 'vitest/config';

// Runs every example's own vitest config as a project, so `npm test` here (or
// `npm run test:cookbook` from the package root) covers the whole cookbook in
// one command. The cookbook was excluded from the root suite in d8af9ef
// (2025-12) because CI's root `npm ci` never installed its dependencies; it
// stays out of the root config for the same reason and is gated separately.
export default defineConfig({
  test: {
    projects: ['*-server'],
  },
});
