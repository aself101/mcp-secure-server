import { defineConfig } from 'vitest/config';
import path from 'path';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    setupFiles: ['./test/setup/global-setup.js'],
    exclude: [
      '**/node_modules/**',
      '**/dist/**',
      'cookbook/**',
      // Claude Code agent worktrees (.claude/worktrees/agent-*) are full checkouts of other
      // commits; collecting their tests ran a stale copy of the suite alongside this one.
      '.claude/**'
    ],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      include: ['src/**/*.ts'],
      exclude: [
        'test/**',
        'test-servers/**',
        'ssl-certs/**',
        'logs/**',
        'test-data/**',
        'cookbook/**',
        'dist/**',
        '**/*.d.ts',
        '**/types/**'
      ]
    },
    testTimeout: 10000,
    hookTimeout: 10000
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
      '@tests': path.resolve(__dirname, './test')
    }
  }
});