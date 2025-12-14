/**
 * Tool exports for CLI wrapper server
 */

export {
  gitStatusSchema,
  gitStatus,
  type GitStatusArgs,
  type GitStatusResult,
} from './git-status.js';

export {
  imageResizeSchema,
  imageResize,
  type ImageResizeArgs,
  type ImageResizeResult,
} from './image-resize.js';

export {
  pdfMetadataSchema,
  pdfMetadata,
  type PdfMetadataArgs,
  type PdfMetadataResult,
} from './pdf-metadata.js';

export {
  encodeVideoSchema,
  encodeVideo,
  type EncodeVideoArgs,
  type EncodeVideoResult,
} from './encode-video.js';
