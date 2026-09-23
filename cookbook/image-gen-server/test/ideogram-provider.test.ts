/**
 * The Ideogram adapter's image inputs: https URL or base64 data URI only,
 * handed to ideogram-api as a temporary file.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { existsSync } from 'fs';

const calls: { method: string; params: any; existed: boolean }[] = [];
vi.mock('ideogram-api', () => ({
  IdeogramAPI: class {
    constructor(..._args: any[]) {}
    async edit(params: any) { calls.push({ method: 'edit', params, existed: existsSync(params.image) && existsSync(params.mask) }); return { data: [{ url: 'https://ideogram.example/r.png' }] }; }
    async upscale(params: any) { calls.push({ method: 'upscale', params, existed: existsSync(params.image) }); return { data: [] }; }
    async replaceBackground(params: any) { calls.push({ method: 'replaceBackground', params, existed: existsSync(params.image) }); return { data: [] }; }
    async describe(params: any) { calls.push({ method: 'describe', params, existed: existsSync(params.image) }); return { descriptions: [{ text: 'a cat' }] }; }
  },
}));

const { IdeogramProvider } = await import('../src/providers/ideogram.js');
const PNG = Buffer.from('89504e470d0a1a0a0000000d49484452', 'hex');
const uri = `data:image/png;base64,${PNG.toString('base64')}`;

describe('IdeogramProvider image inputs', () => {
  beforeEach(() => {
    calls.length = 0;
    process.env.IDEOGRAM_API_KEY = 'test';
  });

  it('refuses a local path for every image-taking operation, without calling the library', async () => {
    const p = new IdeogramProvider();
    for (const op of [
      () => p.edit({ image: '/etc/hosts', prompt: 'x', mask: uri }),
      () => p.edit({ image: uri, prompt: 'x', mask: './mask.png' }),
      () => p.upscale({ image: './in.png' }),
      () => p.replaceBackground('~/a.png', 'beach'),
      () => p.describe('/Users/someone/Pictures/a.png'),
    ]) await expect(op()).rejects.toThrow(/https URL or a base64 data URI/);
    expect(calls).toEqual([]);
  });

  it('hands the library temporary files that exist during the call', async () => {
    const p = new IdeogramProvider();
    await p.edit({ image: uri, prompt: 'x', mask: uri });
    await p.upscale({ image: uri });
    await p.replaceBackground(uri, 'beach');
    expect(await p.describe(uri)).toBe('a cat');
    expect(calls.map(c => [c.method, c.existed])).toEqual([['edit', true], ['upscale', true], ['replaceBackground', true], ['describe', true]]);
  });
});
