/**
 * Write Log Tool
 * Append-only log writing with strict path restrictions
 */

import { z } from 'zod';
import * as fs from 'fs';
import * as path from 'path';
import { validatePath, createPathPolicy } from '../utils/index.js';

// 5,000 characters, not the 10KB this used to say: the server runs the 'standard'
// preset, whose Layer 1 maxStringLength (5,000 chars) refuses any longer string
// before this schema is consulted. One ceiling, stated where the tool declares it.
const MAX_MESSAGE_SIZE = 5000;

export const writeLogSchema = z.object({
  message: z
    .string()
    .min(1)
    .max(MAX_MESSAGE_SIZE)
    .describe('Log message to write'),
  level: z
    .enum(['debug', 'info', 'warn', 'error'])
    .default('info')
    .describe('Log level'),
});

export type WriteLogArgs = z.infer<typeof writeLogSchema>;

export interface WriteLogConfig {
  baseDir: string;
  logsDir: string;
}

function formatLogEntry(message: string, level: string): string {
  const timestamp = new Date().toISOString();
  return `[${timestamp}] [${level.toUpperCase()}] ${message}\n`;
}

export async function writeLog(args: WriteLogArgs, config: WriteLogConfig) {
  const { message, level } = args;
  const { baseDir, logsDir } = config;

  // Create a strict policy that ONLY allows the logs directory
  const logsPolicy = createPathPolicy([logsDir], []);

  // Validate that logsDir is valid
  const logsDirPath = path.resolve(baseDir, logsDir);

  // Ensure logs directory exists
  try {
    await fs.promises.mkdir(logsDirPath, { recursive: true });
  } catch (err) {
    const error = err as NodeJS.ErrnoException;
    if (error.code !== 'EEXIST') {
      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify(
              {
                error: 'Cannot create logs directory',
                message: 'Failed to create or access the logs directory',
              },
              null,
              2
            ),
          },
        ],
        isError: true,
      };
    }
  }

  // Generate log file name based on date
  const date = new Date().toISOString().split('T')[0];
  const logFileName = `app-${date}.log`;
  const logFilePath = path.join(logsDirPath, logFileName);

  // Validate the log file path
  const validation = validatePath(logFilePath, baseDir, logsPolicy);

  if (!validation.valid) {
    return {
      content: [
        {
          type: 'text' as const,
          text: JSON.stringify(
            {
              error: 'Invalid log path',
              message: validation.error,
            },
            null,
            2
          ),
        },
      ],
      isError: true,
    };
  }

  // Format and write the log entry
  const logEntry = formatLogEntry(message, level);

  try {
    await fs.promises.appendFile(logFilePath, logEntry, 'utf-8');

    return {
      content: [
        {
          type: 'text' as const,
          text: JSON.stringify(
            {
              success: true,
              level,
              message,
              file: logFileName,
              timestamp: new Date().toISOString(),
            },
            null,
            2
          ),
        },
      ],
    };
  } catch (err) {
    const error = err as NodeJS.ErrnoException;

    return {
      content: [
        {
          type: 'text' as const,
          text: JSON.stringify(
            {
              error: 'Write failed',
              message: `Failed to write log: ${error.message}`,
            },
            null,
            2
          ),
        },
      ],
      isError: true,
    };
  }
}
