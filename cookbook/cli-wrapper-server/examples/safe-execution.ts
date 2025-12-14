/**
 * Safe Command Execution Example
 *
 * Demonstrates the CORRECT way to execute CLI commands safely.
 */

import { spawn } from 'child_process';

/**
 * SAFE: spawn() with shell: false
 *
 * Arguments are passed directly to the process as an array.
 * Even if an argument contains shell metacharacters like "; rm -rf /",
 * they are treated as literal strings, not shell commands.
 */
function safeExecute(command: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      shell: false, // CRITICAL: Never use shell
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';

    child.stdout?.on('data', (data) => {
      stdout += data.toString();
    });

    child.stderr?.on('data', (data) => {
      stderr += data.toString();
    });

    child.on('close', (code) => {
      if (code === 0) {
        resolve(stdout);
      } else {
        reject(new Error(stderr || `Exit code: ${code}`));
      }
    });

    child.on('error', reject);
  });
}

// Example usage
async function main() {
  // Safe: User input is passed as argument, not interpolated into command
  const userInput = 'my-feature-branch'; // Could be from user

  try {
    // This is SAFE even if userInput contains "; rm -rf /"
    const result = await safeExecute('git', ['branch', '--list', userInput]);
    console.log('Result:', result);
  } catch (error) {
    console.error('Error:', error);
  }

  // Demonstrate that injection is harmless
  const maliciousInput = '; rm -rf /';
  try {
    // The semicolon is treated as a literal character in the branch name
    // It will just fail to find a branch with that name
    const result = await safeExecute('git', ['branch', '--list', maliciousInput]);
    console.log('Injection attempt result:', result || '(no matching branch)');
  } catch (error) {
    console.error('Expected error:', error);
  }
}

main();
