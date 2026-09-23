/**
 * The Stability adapter against stability-ai-api 1.x.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { existsSync } from 'fs';

const JPEG = Buffer.from('ffd8ffe000104a464946', 'hex');
const calls: { method: string; args: any[]; existed?: boolean }[] = [];
let replaceResult: any = { image: JPEG };

vi.mock('stability-ai-api', async (importOriginal) => {
  const real: any = await importOriginal();
  return {
    ...real,
    StabilityAPI: class {
      constructor(..._args: any[]) {}
      async generateUltra(...args: any[]) { calls.push({ method: 'generateUltra', args }); return { image: JPEG }; }
      async generateCore(...args: any[]) { calls.push({ method: 'generateCore', args }); return { image: JPEG }; }
      async generateSD3(...args: any[]) { calls.push({ method: 'generateSD3', args }); return { image: JPEG }; }
      async replaceBackgroundAndRelight(...args: any[]) { calls.push({ method: 'replaceBackgroundAndRelight', args, existed: existsSync(args[0]) }); return replaceResult; }
      async inpaint(...args: any[]) { calls.push({ method: 'inpaint', args, existed: existsSync(args[0]) && existsSync(args[2].mask) }); return { image: JPEG }; }
      async upscaleFast(...args: any[]) { calls.push({ method: 'upscaleFast', args, existed: existsSync(args[0]) }); return { image: JPEG }; }
      async removeBackground(...args: any[]) { calls.push({ method: 'removeBackground', args, existed: existsSync(args[0]) }); return { image: JPEG }; }
    },
  };
});

const { StabilityProvider } = await import('../src/providers/stability.js');

describe('StabilityProvider (stability-ai-api 1.x)', () => {
  beforeEach(() => {
    calls.length = 0;
    replaceResult = { image: JPEG };
    process.env.STABILITY_API_KEY = 'sk-test';
  });

  it('maps sd3-large to sd3.5-large, which Stability re-routes it to server-side, and reports that model', async () => {
    const out = await new StabilityProvider().generate({ prompt: 'p', model: 'sd3-large' } as any);
    expect(calls[0].method).toBe('generateSD3');
    expect(calls[0].args[0].model).toBe('sd3.5-large');
    expect(out.model).toBe('sd3.5-large');
  });

  it('sends the SD 3.5 variants through generateSD3 by name', async () => {
    await new StabilityProvider().generate({ prompt: 'p', model: 'sd3.5-flash' } as any);
    expect(calls[0]).toMatchObject({ method: 'generateSD3', args: [{ model: 'sd3.5-flash' }] });
  });

  it('labels images by their bytes, not as PNG', async () => {
    const out = await new StabilityProvider().generate({ prompt: 'p' } as any);
    expect(out.images).toEqual([`data:image/jpeg;base64,${JPEG.toString('base64')}`]);
  });

  it('refuses a local path for every image-taking operation, without calling the library', async () => {
    const p = new StabilityProvider();
    for (const op of [
      () => p.edit({ image: '/etc/hosts', prompt: 'x' }),
      () => p.upscale({ image: './in.png' }),
      () => p.removeBackground('~/a.png'),
      () => p.replaceBackground('/tmp/a.png', 'a beach'),
    ]) await expect(op()).rejects.toThrow(/https URL or a base64 data URI/);
    expect(calls).toEqual([]);
  });

  it('hands the library a temporary file for a data URI (image and mask)', async () => {
    const p = new StabilityProvider();
    const uri = `data:image/jpeg;base64,${JPEG.toString('base64')}`;
    await p.edit({ image: uri, prompt: 'x', mask: uri });
    await p.upscale({ image: uri });
    await p.removeBackground(uri);
    expect(calls.map(c => [c.method, c.existed])).toEqual([['inpaint', true], ['upscaleFast', true], ['removeBackground', true]]);
  });

  it('returns no image, rather than a bogus one, when replace-background yields a task', async () => {
    replaceResult = { id: 'task-1', status: 'in-progress' };
    const out = await new StabilityProvider().replaceBackground(`data:image/jpeg;base64,${JPEG.toString('base64')}`, 'a beach');
    expect(out.images).toEqual([]);
    expect(calls[0].args[1]).toEqual({ background_prompt: 'a beach' });
  });
});
