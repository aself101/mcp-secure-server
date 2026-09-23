/**
 * The OpenAI adapter against openai-image-api 3.x: edits must send the
 * caller's image (the pre-3.x adapter ignored it and generated a new image),
 * as a file path, since the library takes paths.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { existsSync, readFileSync } from 'fs';

const calls: { method: string; params: any; existed: Record<string, boolean>; bytes?: Buffer }[] = [];
vi.mock('openai-image-api', () => ({
  OpenAIImageAPI: class {
    async generateImage(params: any) {
      calls.push({ method: 'generateImage', params, existed: {} });
      return { created: 0, data: [{ b64_json: 'AAAA' }], output_format: 'webp' };
    }
    async generateImageEdit(params: any) {
      calls.push({
        method: 'generateImageEdit',
        params,
        existed: { image: existsSync(params.image), mask: params.mask ? existsSync(params.mask) : false },
        bytes: readFileSync(params.image),
      });
      return { created: 0, data: [{ b64_json: 'BBBB' }] };
    }
  },
}));

const { OpenAIProvider } = await import('../src/providers/openai.js');
const PNG = Buffer.from('89504e470d0a1a0a0000000d49484452', 'hex');

describe('OpenAIProvider (openai-image-api 3.x)', () => {
  beforeEach(() => {
    calls.length = 0;
    process.env.OPENAI_API_KEY = 'sk-test';
  });

  it('edit sends the caller\'s image and mask as files that exist during the call, then removes them', async () => {
    const provider = new OpenAIProvider();
    const dataUri = `data:image/png;base64,${PNG.toString('base64')}`;
    const out = await provider.edit({ image: dataUri, prompt: 'add a hat', mask: dataUri });
    expect(calls).toHaveLength(1);
    const [call] = calls;
    expect(call.method).toBe('generateImageEdit');
    expect(call.params.prompt).toBe('add a hat');
    expect(call.existed).toEqual({ image: true, mask: true });
    expect(call.bytes!.equals(PNG)).toBe(true);
    expect(existsSync(call.params.image)).toBe(false);
    expect(existsSync(call.params.mask)).toBe(false);
    expect(out.images).toEqual(['data:image/png;base64,BBBB']);
  });

  it('generate uses a GPT Image model and returns data URIs of the reported format', async () => {
    const out = await new OpenAIProvider().generate({ prompt: 'a cat', width: 1000, height: 600 } as any);
    expect(calls[0].params.model).toBe('gpt-image-2.5-flare');
    expect(calls[0].params.size).toBe('1008x608');
    expect(out.images).toEqual(['data:image/webp;base64,AAAA']);
  });

  it('refuses a DALL-E model instead of sending it (openai-image-api 3.x dropped them)', async () => {
    await expect(new OpenAIProvider().generate({ prompt: 'a cat', model: 'dall-e-3' } as any)).rejects.toThrow(/Unsupported OpenAI model/);
    expect(calls).toHaveLength(0);
  });

  it('no longer claims to create variations', () => {
    expect((new OpenAIProvider() as any).createVariation).toBeUndefined();
  });
});
