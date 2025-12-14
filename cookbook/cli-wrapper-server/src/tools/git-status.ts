/**
 * Git Status Tool
 *
 * Safe wrapper for git commands with:
 * - Subcommand allowlist (status, branch, log only)
 * - Working directory validation
 * - Timeout enforcement
 */

import { z } from 'zod';
import {
  executeCommand,
  validatePath,
  validateCommand,
  getAllowlist,
  isDirectory,
} from '../utils/index.js';

export const gitStatusSchema = z.object({
  repoPath: z
    .string()
    .min(1)
    .max(500)
    .describe('Path to the git repository'),
  subcommand: z
    .enum(['status', 'branch', 'log', 'diff', 'show'])
    .default('status')
    .describe('Git subcommand to execute'),
  args: z
    .array(z.string().max(100))
    .max(10)
    .optional()
    .describe('Additional arguments (limited)'),
});

export type GitStatusArgs = z.infer<typeof gitStatusSchema>;

export interface GitStatusResult {
  content: Array<{ type: 'text'; text: string }>;
}

// Allowed directories for git operations
const ALLOWED_REPO_DIRS = [
  process.cwd(),
  '/home',
  '/Users',
  '/tmp',
];

export async function gitStatus(args: GitStatusArgs): Promise<GitStatusResult> {
  const { repoPath, subcommand, args: extraArgs = [] } = args;

  // Validate repository path
  const pathValidation = validatePath(repoPath, {
    allowedDirs: ALLOWED_REPO_DIRS,
    mustExist: true,
    followSymlinks: true,
  });

  if (!pathValidation.valid) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          error: 'Invalid repository path',
          message: pathValidation.error,
        }, null, 2),
      }],
    };
  }

  // Verify it's a directory
  if (!isDirectory(pathValidation.normalizedPath)) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          error: 'Invalid repository path',
          message: 'Path is not a directory',
        }, null, 2),
      }],
    };
  }

  // Check if it's a git repository
  const gitDirCheck = await executeCommand('git', ['rev-parse', '--git-dir'], {
    cwd: pathValidation.normalizedPath,
    timeout: 5000,
  });

  if (gitDirCheck.exitCode !== 0) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          error: 'Not a git repository',
          message: 'The specified path is not a git repository',
          path: pathValidation.normalizedPath,
        }, null, 2),
      }],
    };
  }

  // Build full argument list
  const fullArgs = [subcommand, ...extraArgs];

  // Validate command against allowlist
  const gitAllowlist = getAllowlist('git');
  if (!gitAllowlist) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          error: 'Configuration error',
          message: 'Git allowlist not found',
        }, null, 2),
      }],
    };
  }

  const commandValidation = validateCommand('git', fullArgs, gitAllowlist);
  if (!commandValidation.valid) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          error: 'Command validation failed',
          message: commandValidation.error,
        }, null, 2),
      }],
    };
  }

  // Execute the git command
  const result = await executeCommand('git', fullArgs, {
    cwd: pathValidation.normalizedPath,
    timeout: 10000, // 10 second timeout
    maxOutput: 100 * 1024, // 100KB max output
    allowedDirs: ALLOWED_REPO_DIRS,
  });

  if (result.timedOut) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          error: 'Command timed out',
          message: 'Git command exceeded 10 second timeout',
          subcommand,
        }, null, 2),
      }],
    };
  }

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        success: result.exitCode === 0,
        subcommand,
        repoPath: pathValidation.normalizedPath,
        output: result.stdout || result.stderr,
        exitCode: result.exitCode,
        durationMs: result.durationMs,
      }, null, 2),
    }],
  };
}
