/**
 * Safe Command Execution Utility
 *
 * Executes CLI commands with:
 * - No shell spawning (prevents injection)
 * - Timeout enforcement
 * - Working directory restrictions
 * - Output capture and limits
 */

import { spawn } from 'child_process';
import { resolve, normalize } from 'path';

export interface CommandResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  timedOut: boolean;
  durationMs: number;
}

export interface ExecuteOptions {
  /** Working directory for the command */
  cwd?: string;
  /** Timeout in milliseconds (default: 30000) */
  timeout?: number;
  /** Maximum output size in bytes (default: 1MB) */
  maxOutput?: number;
  /** Environment variables to pass */
  env?: Record<string, string>;
  /** Allowed working directories (for validation) */
  allowedDirs?: string[];
}

const DEFAULT_TIMEOUT = 30000; // 30 seconds
const DEFAULT_MAX_OUTPUT = 1024 * 1024; // 1MB

/**
 * Execute a command safely without shell interpolation
 *
 * IMPORTANT: This function uses spawn() with shell: false to prevent
 * command injection. Arguments are passed directly to the process,
 * not through a shell interpreter.
 */
export async function executeCommand(
  command: string,
  args: string[],
  options: ExecuteOptions = {}
): Promise<CommandResult> {
  const {
    cwd,
    timeout = DEFAULT_TIMEOUT,
    maxOutput = DEFAULT_MAX_OUTPUT,
    env,
    allowedDirs,
  } = options;

  // Validate working directory if specified
  if (cwd && allowedDirs && allowedDirs.length > 0) {
    const normalizedCwd = normalize(resolve(cwd));
    const isAllowed = allowedDirs.some((dir) => {
      const normalizedDir = normalize(resolve(dir));
      return normalizedCwd.startsWith(normalizedDir);
    });
    if (!isAllowed) {
      return {
        stdout: '',
        stderr: `Working directory not allowed: ${cwd}`,
        exitCode: 1,
        timedOut: false,
        durationMs: 0,
      };
    }
  }

  const startTime = Date.now();

  return new Promise((resolvePromise) => {
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    let outputLimitReached = false;

    // ============================================================================
    // SAFE: spawn() with shell: false
    // ============================================================================
    // This is the CORRECT way to execute commands. The command and arguments
    // are passed directly to the OS, NOT through a shell interpreter.
    //
    // UNSAFE alternative (NEVER DO THIS):
    // exec(`${command} ${args.join(' ')}`) // Shell interprets special chars!
    // spawn(command, args, { shell: true }) // Same problem
    //
    // With shell: false, even if args contain "; rm -rf /" it's treated as
    // a literal string argument, not as shell commands.
    // ============================================================================
    const child = spawn(command, args, {
      cwd,
      env: env ? { ...process.env, ...env } : process.env,
      shell: false, // CRITICAL: Never use shell
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    const timeoutId = setTimeout(() => {
      timedOut = true;
      child.kill('SIGTERM');
      // Give it a moment to terminate gracefully
      setTimeout(() => {
        if (!child.killed) {
          child.kill('SIGKILL');
        }
      }, 1000);
    }, timeout);

    child.stdout?.on('data', (data: Buffer) => {
      if (stdout.length + data.length <= maxOutput) {
        stdout += data.toString();
      } else if (!outputLimitReached) {
        outputLimitReached = true;
        stdout += data.toString().slice(0, maxOutput - stdout.length);
        stdout += '\n... [output truncated]';
      }
    });

    child.stderr?.on('data', (data: Buffer) => {
      if (stderr.length + data.length <= maxOutput) {
        stderr += data.toString();
      } else if (!outputLimitReached) {
        outputLimitReached = true;
        stderr += data.toString().slice(0, maxOutput - stderr.length);
        stderr += '\n... [output truncated]';
      }
    });

    child.on('close', (code) => {
      clearTimeout(timeoutId);
      resolvePromise({
        stdout: stdout.trim(),
        stderr: stderr.trim(),
        exitCode: code ?? (timedOut ? 124 : 1),
        timedOut,
        durationMs: Date.now() - startTime,
      });
    });

    child.on('error', (err) => {
      clearTimeout(timeoutId);
      resolvePromise({
        stdout: '',
        stderr: `Command execution failed: ${err.message}`,
        exitCode: 1,
        timedOut: false,
        durationMs: Date.now() - startTime,
      });
    });
  });
}

/**
 * Check if a command exists in PATH
 */
export async function commandExists(command: string): Promise<boolean> {
  const result = await executeCommand('which', [command], { timeout: 5000 });
  return result.exitCode === 0;
}
