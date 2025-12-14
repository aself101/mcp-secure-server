/**
 * Allowlist Validation Example
 *
 * Demonstrates how to validate commands and arguments against allowlists.
 * This provides defense-in-depth on top of safe execution.
 */

interface AllowedCommand {
  command: string;
  allowedSubcommands?: string[];
  blockedPatterns?: RegExp[];
  maxArgs?: number;
}

// Define what's allowed
const GIT_ALLOWLIST: AllowedCommand = {
  command: 'git',
  allowedSubcommands: ['status', 'branch', 'log', 'diff', 'show'],
  blockedPatterns: [
    /[;&|`$]/, // Shell metacharacters
    /\$\(/, // Command substitution
    /--exec/, // Dangerous git options
    /--upload-pack/,
    /--receive-pack/,
  ],
  maxArgs: 20,
};

/**
 * Validate a command before execution
 */
function validateCommand(
  command: string,
  args: string[],
  allowlist: AllowedCommand
): { valid: boolean; error?: string } {
  // Check command name
  if (command !== allowlist.command) {
    return { valid: false, error: `Command '${command}' not allowed` };
  }

  // Check argument count
  if (allowlist.maxArgs && args.length > allowlist.maxArgs) {
    return { valid: false, error: `Too many arguments (max: ${allowlist.maxArgs})` };
  }

  // Check subcommand
  if (allowlist.allowedSubcommands && args.length > 0) {
    if (!allowlist.allowedSubcommands.includes(args[0])) {
      return {
        valid: false,
        error: `Subcommand '${args[0]}' not allowed. Allowed: ${allowlist.allowedSubcommands.join(', ')}`,
      };
    }
  }

  // Check for blocked patterns in all arguments
  if (allowlist.blockedPatterns) {
    for (const arg of args) {
      for (const pattern of allowlist.blockedPatterns) {
        if (pattern.test(arg)) {
          return { valid: false, error: `Argument contains blocked pattern: ${arg}` };
        }
      }
    }
  }

  return { valid: true };
}

// Example usage
function main() {
  // Valid command
  let result = validateCommand('git', ['status'], GIT_ALLOWLIST);
  console.log('git status:', result);
  // { valid: true }

  // Valid with options
  result = validateCommand('git', ['log', '--oneline', '-10'], GIT_ALLOWLIST);
  console.log('git log --oneline -10:', result);
  // { valid: true }

  // Blocked: wrong subcommand
  result = validateCommand('git', ['push', 'origin', 'main'], GIT_ALLOWLIST);
  console.log('git push:', result);
  // { valid: false, error: "Subcommand 'push' not allowed" }

  // Blocked: shell metacharacter
  result = validateCommand('git', ['status', '; rm -rf /'], GIT_ALLOWLIST);
  console.log('git status with injection:', result);
  // { valid: false, error: "Argument contains blocked pattern" }

  // Blocked: command substitution
  result = validateCommand('git', ['status', '$(whoami)'], GIT_ALLOWLIST);
  console.log('git status with command substitution:', result);
  // { valid: false, error: "Argument contains blocked pattern" }

  // Blocked: wrong command entirely
  result = validateCommand('rm', ['-rf', '/'], GIT_ALLOWLIST);
  console.log('rm -rf /:', result);
  // { valid: false, error: "Command 'rm' not allowed" }
}

main();
