/**
 * Zod Error Formatting Utilities
 *
 * Provides user-friendly error messages for Zod validation failures.
 */

import { ZodError, type ZodIssue } from 'zod';

export interface FormattedError {
  error: string;
  message: string;
  field?: string;
  details?: string[];
}

/**
 * Format a single Zod issue into a readable message
 */
function formatIssue(issue: ZodIssue): string {
  const path = issue.path.join('.');
  const prefix = path ? `${path}: ` : '';

  // Zod 4 issue shapes (the cookbook moved from zod 3 to ^4.1.13 with the
  // framework in 0.0.24-security): too_small/too_big carry `origin` (was
  // `type`), enum mismatches are `invalid_value` with `values` (was
  // `invalid_enum_value` / `options`), string formats are `invalid_format`
  // with `format` (was `invalid_string` / `validation`), and `invalid_type`
  // no longer reports what was received. Messages are unchanged.
  switch (issue.code) {
    case 'invalid_type':
      return `${prefix}Expected ${issue.expected}`;
    case 'too_small':
      if (issue.origin === 'string') {
        return `${prefix}Must be at least ${issue.minimum} character(s)`;
      }
      if (issue.origin === 'number') {
        return `${prefix}Must be at least ${issue.minimum}`;
      }
      if (issue.origin === 'array') {
        return `${prefix}Must have at least ${issue.minimum} item(s)`;
      }
      return `${prefix}Value is too small`;
    case 'too_big':
      if (issue.origin === 'string') {
        return `${prefix}Must be at most ${issue.maximum} character(s)`;
      }
      if (issue.origin === 'number') {
        return `${prefix}Must be at most ${issue.maximum}`;
      }
      if (issue.origin === 'array') {
        return `${prefix}Must have at most ${issue.maximum} item(s)`;
      }
      return `${prefix}Value is too large`;
    case 'invalid_value':
      return `${prefix}Invalid value. Expected one of: ${issue.values.map(String).join(', ')}`;
    case 'invalid_format':
      if (issue.format === 'email') {
        return `${prefix}Invalid email format`;
      }
      if (issue.format === 'regex') {
        return `${prefix}Invalid format`;
      }
      return `${prefix}Invalid string`;
    default:
      return `${prefix}${issue.message}`;
  }
}

/**
 * Format a ZodError into a user-friendly response
 */
export function formatZodError(error: ZodError): FormattedError {
  const issues = error.issues;
  const firstIssue = issues[0];
  const field = firstIssue?.path.join('.') || undefined;

  return {
    error: 'Validation failed',
    message: formatIssue(firstIssue),
    field,
    details: issues.length > 1 ? issues.map(formatIssue) : undefined,
  };
}

/**
 * Wrap an async handler to catch and format Zod errors
 */
export function withZodErrorHandling<T, R>(
  handler: (args: T) => Promise<R>
): (args: T) => Promise<R | { content: Array<{ type: 'text'; text: string }> }> {
  return async (args: T) => {
    try {
      return await handler(args);
    } catch (error) {
      if (error instanceof ZodError) {
        const formatted = formatZodError(error);
        return {
          content: [{ type: 'text', text: JSON.stringify(formatted, null, 2) }],
        };
      }
      throw error;
    }
  };
}
