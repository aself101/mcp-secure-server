/**
 * Image inputs and outputs shared by the tools and providers.
 *
 * Tools accept an image as an https URL or a base64 data URI — what their
 * schemas document. Every provider receives it as a temporary file made by
 * `withImageFile`. A bare local path is refused: the provider libraries open
 * any readable image on disk and upload it, so passing paths through let a
 * caller (often an LLM steered by untrusted content) exfiltrate local images.
 */

import { mkdtemp, rm, writeFile } from 'fs/promises';
import { tmpdir } from 'os';
import path from 'path';
import { urlToBuffer, detectImageMime, MAX_DOWNLOAD_SIZE } from 'stability-ai-api/utils';

/**
 * Decode base64 image data, refusing — before decoding — anything whose
 * decoded size would exceed `maxBytes`. The default matches the 50 MB cap the
 * URL path gets from `urlToBuffer`, so neither input form is unbounded; the
 * framework's message-size limit is an outer envelope, not this guarantee.
 */
export function decodeBase64Image(data: string, maxBytes: number = MAX_DOWNLOAD_SIZE): Buffer {
  const decodedSize = Math.floor((data.length * 3) / 4);
  if (decodedSize > maxBytes) {
    throw new Error(`Image data exceeds ${maxBytes} bytes`);
  }
  return Buffer.from(data, 'base64');
}

const INPUT_CONTRACT = 'Image input must be an https URL or a base64 data URI (data:image/<type>;base64,...); local file paths are not accepted';

const DATA_URI = /^data:image\/([a-z0-9.+-]+);base64,(.*)$/is;

/**
 * Run `fn` with `image` as a local file path. A path is passed through; a
 * data URI or URL is written to a temporary file that is removed afterwards,
 * whether `fn` succeeds or throws.
 *
 * URLs are fetched with stability-ai-api's `urlToBuffer` rather than a bare
 * fetch: this server downloads URLs its callers hand it, and that helper
 * enforces HTTPS, refuses private/loopback/metadata addresses at check time
 * and again at connect time (DNS rebinding), re-validates every redirect and
 * caps the download at 50 MB.
 */
export async function withImageFile<T>(image: string, fn: (file: string) => Promise<T>): Promise<T> {
  const isData = /^data:/i.test(image);
  const isUrl = /^https?:\/\//i.test(image);
  if (!isData && !isUrl) throw new Error(INPUT_CONTRACT);

  let bytes: Buffer;
  let extension: string;
  if (isData) {
    const match = image.match(DATA_URI);
    if (!match) throw new Error('Unsupported data URI: expected data:image/<type>;base64,<data>');
    bytes = decodeBase64Image(match[2]);
    // The bytes decide, as on the URL path; the caller's label is a fallback.
    const sniffed = detectImageMime(bytes);
    extension = (sniffed ? sniffed.split('/')[1] : match[1].toLowerCase()).replace('jpeg', 'jpg');
  } else {
    bytes = await urlToBuffer(image);
    const mime = detectImageMime(bytes);
    extension = mime ? mime.split('/')[1].replace('jpeg', 'jpg') : 'png';
  }

  const dir = await mkdtemp(path.join(tmpdir(), 'image-gen-'));
  try {
    const file = path.join(dir, `input.${extension}`);
    await writeFile(file, bytes);
    return await fn(file);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

/** `withImageFile` for an optional input (a mask): absent stays absent. */
export async function withOptionalImageFile<T>(image: string | undefined, fn: (file: string | undefined) => Promise<T>): Promise<T> {
  return image === undefined ? fn(undefined) : withImageFile(image, fn);
}

/**
 * An MCP image content block for a provider result: a data URI keeps its own
 * MIME type (providers return JPEG and WebP as well as PNG); a bare base64
 * string is reported as PNG, as the tools always did.
 */
export function imageContent(img: string): { type: 'image'; data: string; mimeType: string } {
  const match = img.match(/^data:(image\/[a-z0-9.+-]+);base64,(.*)$/is);
  return match
    ? { type: 'image', data: match[2], mimeType: match[1].toLowerCase() }
    : { type: 'image', data: img, mimeType: 'image/png' };
}

/**
 * A provider result as the tools save and return it. Providers hand back a
 * data URI, bare base64, or a URL (bfl and ideogram return signed result
 * URLs). URLs are downloaded with the same SSRF-guarded helper as inputs —
 * the tools used a bare fetch with no size cap or timeout — and the MIME type
 * and file extension come from the bytes, since every image used to be saved
 * and labelled as PNG whatever it was.
 */
export async function resolveImageOutput(img: string): Promise<{ base64: string; mimeType: string; extension: string }> {
  let bytes: Buffer;
  const dataUri = img.match(/^data:[^;,]*;base64,(.*)$/is);
  if (dataUri) {
    bytes = decodeBase64Image(dataUri[1]);
  } else if (/^https?:\/\//i.test(img)) {
    bytes = await urlToBuffer(img);
  } else {
    bytes = decodeBase64Image(img);
  }
  const mimeType = detectImageMime(bytes) || 'image/png';
  const extension = mimeType.split('/')[1].replace('jpeg', 'jpg');
  return { base64: bytes.toString('base64'), mimeType, extension };
}
