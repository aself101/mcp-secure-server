import { describe, expect, it } from 'vitest';
import { z as z3 } from 'zod/v3';
import { z as z4 } from 'zod';
import { ErrorSanitizer } from '../../../src/security/utils/error-sanitizer.js';

const sanitizer = new ErrorSanitizer({ enableSecurityLogging: false });
const schema = z => {
  const summary = z.object({
    exploration_maps: z.array(z.object({
      metadata: z.object({ explorer_name: z.string(), framework: z.string() }),
    })),
  });
  return z.object({ analysis_summary: z.union([summary, z.array(summary)]) });
};
const invalid = { analysis_summary: { exploration_maps: [{ metadata: {} }] } };
const rewrite = (issues, resultEnvelope = false) => {
  const message = `Input validation error: Invalid arguments for tool validate_run: ${JSON.stringify(issues)}`;
  const envelope = resultEnvelope
    ? { result: { isError: true, content: [{ type: 'text', text: `MCP error -32602: ${message}` }], extra: 'kept' } }
    : { error: { code: -32602, message, data: { hint: 'kept' } } };
  return sanitizer.sanitizeOutgoingError({ jsonrpc: '2.0', id: 17, ...envelope });
};

describe.each([['Zod 3', z3], ['Zod 4', z4]])('%s union diagnostics', (_, z) => {
  it.each([false, true])('retains full nested paths (result envelope: %s)', resultEnvelope => {
    const parsed = schema(z).safeParse(invalid);
    expect(parsed.success).toBe(false);
    const response = rewrite(parsed.error.issues, resultEnvelope);
    const text = resultEnvelope ? response.result.content[0].text : response.error.message;
    expect(text).toContain('analysis_summary.exploration_maps.0.metadata.explorer_name:');
    expect(text).toContain('analysis_summary.exploration_maps.0.metadata.framework:');
    expect(text).not.toContain('expected array');
    expect(text).not.toContain('(expected string, received undefined)');
    expect(response.id).toBe(17);
    if (resultEnvelope) expect(response.result).toMatchObject({ isError: true, extra: 'kept' });
    else expect(response.error).toMatchObject({ code: -32602, data: { hint: 'kept' } });
  });

  it('preserves array indices for the array summary alternative', () => {
    const parsed = schema(z).safeParse({ analysis_summary: [invalid.analysis_summary] });
    const text = rewrite(parsed.error.issues).error.message;
    expect(text).toContain('analysis_summary.0.exploration_maps.0.metadata.framework:');
  });

  it('expands nested unions without duplicating or losing parent paths', () => {
    const nested = z.object({ outer: z.union([schema(z), z.string()]) });
    const parsed = nested.safeParse({ outer: invalid });
    const text = rewrite(parsed.error.issues).error.message;
    expect(text).toContain('outer.analysis_summary.exploration_maps.0.metadata.framework:');
    expect(text).not.toContain('outer.outer');
  });

  it('does not arbitrarily select an equally specific union alternative', () => {
    const parsed = z.object({ value: z.union([z.string(), z.number()]) }).safeParse({ value: null });
    expect(rewrite(parsed.error.issues).error.message).toContain('value: Invalid input');
  });
});

describe('malformed union diagnostics', () => {
  it.each([{ errors: [null] }, { unionErrors: [{ issues: [{}] }] }, { errors: [] }])(
    'retains the parent issue for %j', extra => {
      const response = rewrite([{ code: 'invalid_union', path: ['value'], message: 'Invalid input', ...extra }]);
      expect(response.error.message).toContain('value: Invalid input');
    },
  );

  it('bounds deeply nested union expansion', () => {
    let issue = { code: 'invalid_type', path: ['leaf'], message: 'Required', expected: 'string' };
    for (let i = 0; i < 30; i++) issue = { code: 'invalid_union', path: ['nested'], message: 'Invalid input', errors: [[issue]] };
    expect(rewrite([issue]).error.message).toContain('Invalid input');
  });
});
