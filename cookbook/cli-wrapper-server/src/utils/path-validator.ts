/**
 * Path Validation Utility
 *
 * Validates file and directory paths to prevent:
 * - Path traversal attacks
 * - Access to sensitive directories
 * - Symlink attacks
 */

import { resolve, normalize, extname, basename } from 'path';
import { existsSync, lstatSync, realpathSync } from 'fs';

export interface PathValidationResult {
  valid: boolean;
  normalizedPath: string;
  error?: string;
}

export interface PathValidationOptions {
  /** Allowed root directories */
  allowedDirs: string[];
  /** Allowed file extensions (e.g., ['.png', '.jpg']) */
  allowedExtensions?: string[];
  /** Whether the path must exist */
  mustExist?: boolean;
  /** Whether to follow symlinks for validation */
  followSymlinks?: boolean;
  /** Maximum path length */
  maxPathLength?: number;
}

const DEFAULT_MAX_PATH_LENGTH = 4096;

/**
 * Validate a file or directory path
 */
export function validatePath(
  inputPath: string,
  options: PathValidationOptions
): PathValidationResult {
  const {
    allowedDirs,
    allowedExtensions,
    mustExist = false,
    followSymlinks = true,
    maxPathLength = DEFAULT_MAX_PATH_LENGTH,
  } = options;

  // Check path length
  if (inputPath.length > maxPathLength) {
    return {
      valid: false,
      normalizedPath: '',
      error: `Path exceeds maximum length of ${maxPathLength} characters`,
    };
  }

  // Check for null bytes (used in some injection attacks)
  if (inputPath.includes('\0')) {
    return {
      valid: false,
      normalizedPath: '',
      error: 'Path contains null bytes',
    };
  }

  // Normalize and resolve the path
  let normalizedPath: string;
  try {
    normalizedPath = normalize(resolve(inputPath));
  } catch {
    return {
      valid: false,
      normalizedPath: '',
      error: 'Invalid path format',
    };
  }

  // Check if path is within allowed directories
  const isWithinAllowedDir = allowedDirs.some((dir) => {
    const normalizedDir = normalize(resolve(dir));
    return normalizedPath.startsWith(normalizedDir + '/') || normalizedPath === normalizedDir;
  });

  if (!isWithinAllowedDir) {
    return {
      valid: false,
      normalizedPath,
      error: 'Path is outside allowed directories',
    };
  }

  // Check file extension if specified
  if (allowedExtensions && allowedExtensions.length > 0) {
    const ext = extname(normalizedPath).toLowerCase();
    if (!allowedExtensions.includes(ext)) {
      return {
        valid: false,
        normalizedPath,
        error: `File extension not allowed. Allowed: ${allowedExtensions.join(', ')}`,
      };
    }
  }

  // Check existence if required
  if (mustExist) {
    if (!existsSync(normalizedPath)) {
      return {
        valid: false,
        normalizedPath,
        error: 'Path does not exist',
      };
    }

    // Follow symlinks and validate real path
    if (followSymlinks) {
      try {
        const realPath = realpathSync(normalizedPath);
        const isRealPathAllowed = allowedDirs.some((dir) => {
          const normalizedDir = normalize(resolve(dir));
          return realPath.startsWith(normalizedDir + '/') || realPath === normalizedDir;
        });

        if (!isRealPathAllowed) {
          return {
            valid: false,
            normalizedPath,
            error: 'Symlink target is outside allowed directories',
          };
        }
      } catch {
        return {
          valid: false,
          normalizedPath,
          error: 'Failed to resolve symlink',
        };
      }
    }
  }

  return {
    valid: true,
    normalizedPath,
  };
}

/**
 * Check if a path is a directory
 */
export function isDirectory(path: string): boolean {
  try {
    return existsSync(path) && lstatSync(path).isDirectory();
  } catch {
    return false;
  }
}

/**
 * Check if a path is a file
 */
export function isFile(path: string): boolean {
  try {
    return existsSync(path) && lstatSync(path).isFile();
  } catch {
    return false;
  }
}

/**
 * Get safe filename from path (removes directory traversal)
 */
export function getSafeFilename(path: string): string {
  return basename(normalize(path));
}
