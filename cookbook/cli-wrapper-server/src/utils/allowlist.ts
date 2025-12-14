/**
 * Command and Argument Allowlist Validation
 *
 * Validates that commands and arguments match predefined allowlists.
 * This provides defense-in-depth on top of the mcp-security framework's
 * Layer 2 command injection detection.
 */

export interface AllowedCommand {
  /** The command name (e.g., 'git', 'convert') */
  command: string;
  /** Allowed subcommands or first arguments (e.g., ['status', 'branch', 'log']) */
  allowedSubcommands?: string[];
  /** Allowed argument patterns (regex) */
  allowedArgPatterns?: RegExp[];
  /** Blocked argument patterns (regex) - checked first */
  blockedArgPatterns?: RegExp[];
  /** Maximum number of arguments */
  maxArgs?: number;
  /** Require specific arguments to be present */
  requiredArgs?: string[];
}

export interface CommandValidationResult {
  valid: boolean;
  error?: string;
  sanitizedArgs?: string[];
}

// Common dangerous patterns that should always be blocked
const DANGEROUS_PATTERNS = [
  /[;&|`$]/, // Shell metacharacters
  /\$\(/, // Command substitution
  /\$\{/, // Variable expansion
  />\s*\//, // Redirect to root
  /<\s*\//, // Read from root
  /\|\|/, // OR operator
  /&&/, // AND operator
  /\n/, // Newlines (command separation)
  /\r/, // Carriage returns
];

/**
 * Validate a command against the allowlist
 */
export function validateCommand(
  command: string,
  args: string[],
  allowedCommand: AllowedCommand
): CommandValidationResult {
  // Check command matches
  if (command !== allowedCommand.command) {
    return {
      valid: false,
      error: `Command '${command}' is not allowed. Expected: ${allowedCommand.command}`,
    };
  }

  // Check max args
  if (allowedCommand.maxArgs !== undefined && args.length > allowedCommand.maxArgs) {
    return {
      valid: false,
      error: `Too many arguments. Maximum: ${allowedCommand.maxArgs}, provided: ${args.length}`,
    };
  }

  // Check required args
  if (allowedCommand.requiredArgs) {
    for (const required of allowedCommand.requiredArgs) {
      if (!args.includes(required)) {
        return {
          valid: false,
          error: `Required argument missing: ${required}`,
        };
      }
    }
  }

  // Check subcommand (first argument) if specified
  if (allowedCommand.allowedSubcommands && args.length > 0) {
    const subcommand = args[0];
    if (!allowedCommand.allowedSubcommands.includes(subcommand)) {
      return {
        valid: false,
        error: `Subcommand '${subcommand}' is not allowed. Allowed: ${allowedCommand.allowedSubcommands.join(', ')}`,
      };
    }
  }

  // Validate each argument
  const sanitizedArgs: string[] = [];
  for (const arg of args) {
    // Check for dangerous patterns (always blocked)
    for (const pattern of DANGEROUS_PATTERNS) {
      if (pattern.test(arg)) {
        return {
          valid: false,
          error: `Argument contains dangerous characters: ${arg}`,
        };
      }
    }

    // Check blocked patterns from config
    if (allowedCommand.blockedArgPatterns) {
      for (const pattern of allowedCommand.blockedArgPatterns) {
        if (pattern.test(arg)) {
          return {
            valid: false,
            error: `Argument matches blocked pattern: ${arg}`,
          };
        }
      }
    }

    // Check allowed patterns from config (if specified)
    if (allowedCommand.allowedArgPatterns && allowedCommand.allowedArgPatterns.length > 0) {
      const matchesAllowed = allowedCommand.allowedArgPatterns.some((pattern) =>
        pattern.test(arg)
      );
      if (!matchesAllowed) {
        return {
          valid: false,
          error: `Argument does not match any allowed pattern: ${arg}`,
        };
      }
    }

    sanitizedArgs.push(arg);
  }

  return {
    valid: true,
    sanitizedArgs,
  };
}

/**
 * Create an allowlist for common CLI tools
 */
export const COMMON_ALLOWLISTS: Record<string, AllowedCommand> = {
  git: {
    command: 'git',
    allowedSubcommands: ['status', 'branch', 'log', 'diff', 'show', 'rev-parse'],
    maxArgs: 20,
    blockedArgPatterns: [
      /^-c\s/, // Arbitrary config
      /--exec/, // Execute commands
      /--upload-pack/, // Remote execution
      /--receive-pack/, // Remote execution
    ],
  },

  convert: {
    command: 'convert',
    maxArgs: 50,
    allowedArgPatterns: [
      /^-resize$/, // Resize flag
      /^\d+x\d+!?$/, // Dimensions
      /^-quality$/, // Quality flag
      /^\d{1,3}$/, // Quality value 0-100
      /^-strip$/, // Strip metadata
      /^-auto-orient$/, // Auto orient
      /^[a-zA-Z0-9_\-./]+\.(png|jpg|jpeg|gif|webp|bmp|tiff)$/i, // File paths
    ],
    blockedArgPatterns: [
      /^-write$/, // Write to arbitrary files
      /^msl:/, // MSL scripts (code execution)
      /^ephemeral:/, // Ephemeral images
      /^label:/, // Can execute code
      /^caption:/, // Can execute code
      /^\|/, // Pipe
      /^https?:\/\//, // URL fetch (SSRF)
    ],
  },

  pdfinfo: {
    command: 'pdfinfo',
    maxArgs: 5,
    allowedArgPatterns: [
      /^[a-zA-Z0-9_\-./]+\.pdf$/i, // PDF file paths only
      /^-enc$/, // Encoding flag
      /^UTF-8$/, // Encoding value
    ],
  },

  ffmpeg: {
    command: 'ffmpeg',
    maxArgs: 50,
    allowedArgPatterns: [
      /^-i$/, // Input flag
      /^-y$/, // Overwrite
      /^-n$/, // Don't overwrite
      /^-c:v$/, // Video codec
      /^-c:a$/, // Audio codec
      /^-b:v$/, // Video bitrate
      /^-b:a$/, // Audio bitrate
      /^-r$/, // Frame rate
      /^-s$/, // Size
      /^-t$/, // Duration
      /^-ss$/, // Start time
      /^-to$/, // End time
      /^-vf$/, // Video filter
      /^-af$/, // Audio filter
      /^-preset$/, // Encoding preset
      /^-crf$/, // Constant rate factor
      /^\d+$/, // Numbers
      /^\d+:\d+:\d+$/, // Time format
      /^\d+x\d+$/, // Dimensions
      /^\d+[kKmM]?$/, // Bitrate values
      /^(ultrafast|superfast|veryfast|faster|fast|medium|slow|slower|veryslow)$/, // Presets
      /^(libx264|libx265|libvpx|aac|mp3|copy)$/, // Codecs
      /^scale=\d+:\d+$/, // Scale filter
      /^[a-zA-Z0-9_\-./]+\.(mp4|mkv|avi|mov|webm|mp3|wav|aac|flac)$/i, // Media files
    ],
    blockedArgPatterns: [
      /^-filter_complex$/, // Complex filters can be dangerous
      /^https?:\/\//, // URL fetch (SSRF)
      /^concat:/, // File concatenation (can read arbitrary files)
      /^-f\s*lavfi$/, // lavfi format can execute code
    ],
  },
};

/**
 * Get an allowlist for a specific command
 */
export function getAllowlist(command: string): AllowedCommand | undefined {
  return COMMON_ALLOWLISTS[command];
}
