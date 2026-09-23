/**
 * Image inputs for libraries that take file paths (openai-image-api 3.x edit),
 * and MCP image content blocks that report the real MIME type.
 */
import { describe, it, expect } from 'vitest';
import { existsSync, readFileSync } from 'fs';
import { withImageFile, imageContent, resolveImageOutput, decodeBase64Image } from '../src/image-input.js';

const PNG = Buffer.from('89504e470d0a1a0a0000000d49484452', 'hex');

describe('withImageFile', () => {
  // The tools document "Image URL or base64 data". A bare path used to reach
  // the provider libraries, which open any readable image on disk and upload
  // it (security review of this change); it is now refused.
  it.each(['./photo.png', '/etc/passwd', '~/.ssh/id_rsa', 'C:\\Users\\x\\a.png', 'file:///etc/hosts'])('refuses a local path or file URL: %s', async (input) => {
    let called = false;
    await expect(withImageFile(input, async f => { called = true; return f; })).rejects.toThrow(/https URL or a base64 data URI/);
    expect(called).toBe(false);
  });

  it('writes a data URI to a temporary file for the callback, then removes it', async () => {
    let seen = '';
    const bytes = await withImageFile(`data:image/png;base64,${PNG.toString('base64')}`, async f => {
      seen = f;
      expect(f.endsWith('.png')).toBe(true);
      return readFileSync(f);
    });
    expect(bytes.equals(PNG)).toBe(true);
    expect(existsSync(seen)).toBe(false);
  });

  it('names the temporary file by the bytes, not the data URI label (round-1 review, M-2)', async () => {
    const JPEG = Buffer.from('ffd8ffe000104a464946', 'hex');
    const name = await withImageFile(`data:image/png;base64,${JPEG.toString('base64')}`, async f => f);
    expect(name.endsWith('.jpg')).toBe(true);
  });

  it('removes the temporary file when the callback throws', async () => {
    let seen = '';
    await expect(withImageFile(`data:image/png;base64,${PNG.toString('base64')}`, async f => {
      seen = f;
      throw new Error('boom');
    })).rejects.toThrow('boom');
    expect(seen).not.toBe('');
    expect(existsSync(seen)).toBe(false);
  });

  it('refuses a data URI that is not base64 image data', async () => {
    await expect(withImageFile('data:text/plain,hello', async f => f)).rejects.toThrow(/data URI/);
  });

  it('downloads URLs through the SSRF-guarded fetch: plain http and private hosts are refused before any request', async () => {
    await expect(withImageFile('http://cdn.example/a.png', async f => f)).rejects.toThrow(/HTTPS/);
    await expect(withImageFile('https://127.0.0.1/a.png', async f => f)).rejects.toThrow(/internal|private|localhost/i);
  });
});

describe('imageContent', () => {
  it('takes the MIME type from the data URI', () => {
    expect(imageContent('data:image/webp;base64,AAAA')).toEqual({ type: 'image', data: 'AAAA', mimeType: 'image/webp' });
    expect(imageContent('data:image/jpeg;base64,BBBB')).toEqual({ type: 'image', data: 'BBBB', mimeType: 'image/jpeg' });
  });
  it('treats a bare base64 string as PNG, as before', () => {
    expect(imageContent('CCCC')).toEqual({ type: 'image', data: 'CCCC', mimeType: 'image/png' });
  });
});

describe('resolveImageOutput (provider results → bytes the tools save and return)', () => {
  const JPEG = Buffer.from('ffd8ffe000104a464946', 'hex');
  it('reads a data URI and takes the type from the bytes, not the label', async () => {
    const out = await resolveImageOutput(`data:image/png;base64,${JPEG.toString('base64')}`);
    expect(out).toEqual({ base64: JPEG.toString('base64'), mimeType: 'image/jpeg', extension: 'jpg' });
  });
  it('reads bare base64', async () => {
    expect(await resolveImageOutput(PNG.toString('base64'))).toEqual({ base64: PNG.toString('base64'), mimeType: 'image/png', extension: 'png' });
  });
  it('fetches a result URL through the SSRF-guarded download (http and private hosts refused before any request)', async () => {
    await expect(resolveImageOutput('http://delivery.example/x.png')).rejects.toThrow(/HTTPS/);
    await expect(resolveImageOutput('https://169.254.169.254/latest')).rejects.toThrow(/internal|private|metadata/i);
  });
});

describe('decodeBase64Image (size cap before decoding)', () => {
  it('decodes within the cap', () => {
    expect(decodeBase64Image(PNG.toString('base64'), 1024).equals(PNG)).toBe(true);
  });
  it('refuses base64 whose decoded size would exceed the cap, without decoding it', () => {
    expect(() => decodeBase64Image('A'.repeat(4000), 1000)).toThrow(/exceeds 1000 bytes/);
  });
  it('the data-URI and bare-base64 paths go through it (default cap is the URL path\'s 50 MB)', async () => {
    const huge = 'A'.repeat(Math.ceil((50 * 1024 * 1024 + 3) / 3) * 4);
    await expect(withImageFile(`data:image/png;base64,${huge}`, async f => f)).rejects.toThrow(/exceeds/);
    await expect(resolveImageOutput(huge)).rejects.toThrow(/exceeds/);
  });
});
