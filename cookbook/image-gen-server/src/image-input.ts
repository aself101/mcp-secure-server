/**
 * Image inputs and outputs shared by the tools and providers.
 *
 * Tools accept an image as a local path, a base64 data URI, or an https URL.
 * Most provider libraries take those directly; openai-image-api 3.x edits
 * take file paths only, so `withImageFile` materializes the other two forms.
 */

import { mkdtemp, rm, writeFile } from 'fs/promises';
import { tmpdir } from 'os';
import path from 'path';
import { urlToBuffer, detectImageMime } from 'stability-ai-api/utils';

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
  if (!isData && !isUrl) return fn(image);

  let bytes: Buffer;
  let extension: string;
  if (isData) {
    const match = image.match(DATA_URI);
    if (!match) throw new Error('Unsupported data URI: expected data:image/<type>;base64,<data>');
    extension = match[1].toLowerCase() === 'jpeg' ? 'jpg' : match[1].toLowerCase();
    bytes = Buffer.from(match[2], 'base64');
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
    bytes = Buffer.from(dataUri[1], 'base64');
  } else if (/^https?:\/\//i.test(img)) {
    bytes = await urlToBuffer(img);
  } else {
    bytes = Buffer.from(img, 'base64');
  }
  const mimeType = detectImageMime(bytes) || 'image/png';
  const extension = mimeType.split('/')[1].replace('jpeg', 'jpg');
  return { base64: bytes.toString('base64'), mimeType, extension };
}
