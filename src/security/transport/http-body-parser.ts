/**
 * HTTP request body parsing utilities.
 * @module http-body-parser
 */

import type { IncomingMessage } from 'node:http';

/**
 * Parse JSON body from request with size limit and timeout.
 *
 * @param req - HTTP request
 * @param maxSize - Maximum body size in bytes
 * @param timeoutMs - Timeout in milliseconds
 * @returns Parsed JSON body
 * @throws Error if body exceeds size, times out, or is invalid JSON
 */
export async function parseJsonBody(
  req: IncomingMessage,
  maxSize: number,
  timeoutMs: number
): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let data = '';
    let size = 0;
    let completed = false;

    const timeout = setTimeout(() => {
      if (!completed) {
        completed = true;
        req.destroy();
        reject(new Error('Request timeout'));
      }
    }, timeoutMs);

    const cleanup = () => {
      clearTimeout(timeout);
      completed = true;
    };

    req.on('data', (chunk: Buffer) => {
      if (completed) return;

      size += chunk.length;
      if (size > maxSize) {
        cleanup();
        req.destroy();
        reject(new Error(`Body exceeds ${maxSize} bytes`));
        return;
      }
      data += chunk.toString();
    });

    req.on('end', () => {
      if (completed) return;
      cleanup();

      try {
        resolve(JSON.parse(data));
      } catch {
        reject(new Error('Invalid JSON'));
      }
    });

    req.on('error', (err) => {
      if (completed) return;
      cleanup();
      reject(err);
    });
  });
}
