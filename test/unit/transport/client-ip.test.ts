import { describe, it, expect, vi, afterEach } from 'vitest';
import { createClientIpResolver, getClientIp, normalizeAddress, rateLimitKey } from '@/security/transport/client-ip.js';

const req = (headers: Record<string, string | string[]>, remoteAddress: string | undefined = '192.0.2.10') =>
  ({ headers, socket: { remoteAddress } });
const resolve = (trustProxy: unknown, headers: Record<string, string | string[]>, peer?: string) =>
  createClientIpResolver({ trustProxy: trustProxy as never, onWarning: false })(req(headers, peer));

afterEach(() => vi.restoreAllMocks());

describe('client IP resolution', () => {
  describe('default (trustProxy 0): forwarding headers are client-supplied and ignored', () => {
    it('ignores X-Forwarded-For and X-Real-IP', () => {
      expect(resolve(undefined, { 'x-forwarded-for': '203.0.113.7', 'x-real-ip': '203.0.113.8' })).toBe('192.0.2.10');
    });

    it('a rotating X-Forwarded-For maps every request to one key', () => {
      const keys = new Set([1, 2, 3].map(i => resolve(0, { 'x-forwarded-for': `198.51.100.${i}` })));
      expect([...keys]).toEqual(['192.0.2.10']);
    });

    it('returns "unknown" when the socket has no address', () => {
      expect(createClientIpResolver({ onWarning: false })({ headers: {}, socket: {} })).toBe('unknown');
      expect(createClientIpResolver({ onWarning: false })({ headers: {} })).toBe('unknown');
    });
  });

  describe('hop count', () => {
    const chain = '203.0.113.195, 70.41.3.18, 150.172.238.178';

    it('1 hop is the rightmost entry; 2 hops the second from the right', () => {
      expect(resolve(1, { 'x-forwarded-for': chain })).toBe('150.172.238.178');
      expect(resolve(2, { 'x-forwarded-for': chain })).toBe('70.41.3.18');
    });

    it('a client-prepended entry cannot displace the proxy-appended one', () => {
      expect(resolve(1, { 'x-forwarded-for': '1.2.3.4, 198.51.100.7' })).toBe('198.51.100.7');
    });

    it('fewer entries than hops keys on the socket peer, never the client-written leftmost entry', () => {
      expect(resolve(3, { 'x-forwarded-for': '1.2.3.4, 198.51.100.7' })).toBe('192.0.2.10');
    });

    it('no X-Forwarded-For keys on the socket peer; X-Real-IP is never read', () => {
      expect(resolve(1, { 'x-real-ip': '203.0.113.9' })).toBe('192.0.2.10');
    });

    it('joins repeated header values and skips empty entries', () => {
      expect(resolve(1, { 'x-forwarded-for': ['203.0.113.195', ' 70.41.3.18 , ,'] })).toBe('70.41.3.18');
      expect(resolve(2, { 'x-forwarded-for': ['203.0.113.195', ' 70.41.3.18 , ,'] })).toBe('203.0.113.195');
    });

    it('a non-IP entry at the trusted position keys on the peer', () => {
      expect(resolve(1, { 'x-forwarded-for': 'unknown' })).toBe('192.0.2.10');
      expect(resolve(1, { 'x-forwarded-for': 'x'.repeat(4000) })).toBe('192.0.2.10');
    });
  });

  describe('trusted proxy list', () => {
    const trusted = ['10.0.0.0/8'];

    it('walks right to left past trusted hops to the first untrusted address', () => {
      expect(resolve(trusted, { 'x-forwarded-for': 'spoof-ignored, 203.0.113.1' }, '10.0.0.1')).toBe('203.0.113.1');
      expect(resolve(trusted, { 'x-forwarded-for': '203.0.113.1, 10.0.0.5' }, '10.0.0.1')).toBe('203.0.113.1');
    });

    it('a request that reaches the server directly is keyed on its own address, whatever it forwards', () => {
      expect(resolve(trusted, { 'x-forwarded-for': '198.51.100.99' }, '203.0.113.50')).toBe('203.0.113.50');
    });

    it('padding the header cannot move the key past the proxy-appended entry', () => {
      const padded = '1.1.1.1, 2.2.2.2, 3.3.3.3, 203.0.113.1';
      expect(resolve(trusted, { 'x-forwarded-for': padded }, '10.0.0.1')).toBe('203.0.113.1');
    });

    it('a trusted peer with no forwarded entry keys on the peer', () => {
      expect(resolve(trusted, {}, '10.0.0.1')).toBe('10.0.0.1');
    });

    it('a non-IP entry keys on the last trusted hop', () => {
      expect(resolve(trusted, { 'x-forwarded-for': 'junk, 10.0.0.5' }, '10.0.0.1')).toBe('10.0.0.5');
    });

    it('accepts bare addresses and named ranges', () => {
      expect(resolve(['10.0.0.1'], { 'x-forwarded-for': '203.0.113.1' }, '10.0.0.1')).toBe('203.0.113.1');
      expect(resolve(['loopback'], { 'x-forwarded-for': '203.0.113.1' }, '127.0.0.1')).toBe('203.0.113.1');
      expect(resolve(['uniquelocal'], { 'x-forwarded-for': '203.0.113.1' }, 'fd00::1')).toBe('203.0.113.1');
    });

    it('an empty list trusts nothing', () => {
      expect(resolve([], { 'x-forwarded-for': '203.0.113.1' }, '10.0.0.1')).toBe('10.0.0.1');
    });
  });

  describe('normalization', () => {
    it('strips ports, so a port-appending proxy cannot mint a key per connection', () => {
      expect(resolve(1, { 'x-forwarded-for': '203.0.113.1:5555' })).toBe(resolve(1, { 'x-forwarded-for': '203.0.113.1:5556' }));
      expect(resolve(1, { 'x-forwarded-for': '203.0.113.1:5555' })).toBe('203.0.113.1');
    });

    it('unwraps IPv4-mapped IPv6 so dual-stack peers share the IPv4 key', () => {
      expect(resolve(0, {}, '::ffff:203.0.113.5')).toBe('203.0.113.5');
    });

    it.each([
      ['[2001:db8::1]:443', '2001:db8::1'],
      ['FE80::1%eth0', 'fe80::1'],
      ['  203.0.113.1  ', '203.0.113.1'],
      ['not-an-ip', null],
      ['203.0.113.1:abc', null],
      ['', null]
    ])('normalizeAddress(%j) = %j', (raw, expected) => {
      expect(normalizeAddress(raw)).toBe(expected);
    });
  });

  describe('IPv6 keys by /64', () => {
    it('addresses in one /64 share a key; different /64s do not', () => {
      expect(rateLimitKey('2001:db8:1:2::1')).toBe(rateLimitKey('2001:0db8:0001:0002:ffff:ffff:ffff:ffff'));
      expect(rateLimitKey('2001:db8:1:2::1')).not.toBe(rateLimitKey('2001:db8:1:3::1'));
      expect(rateLimitKey('2001:db8:1:2::1')).toBe('2001:db8:1:2::/64');
    });

    it('rotating within a /64 does not mint new keys, peer or forwarded', () => {
      const keys = new Set(['2001:db8::a', '2001:db8::b', '2001:db8::c'].map(p => resolve(0, {}, p)));
      expect([...keys]).toEqual(['2001:db8:0:0::/64']);
      expect(resolve(1, { 'x-forwarded-for': '2001:db8::a' })).toBe(resolve(1, { 'x-forwarded-for': '2001:db8::b' }));
    });

    it('expands edge forms', () => {
      expect(rateLimitKey('::1')).toBe('0:0:0:0::/64');
      expect(rateLimitKey('fe80::')).toBe('fe80:0:0:0::/64');
      expect(rateLimitKey('64:ff9b::192.0.2.1')).toBe('64:ff9b:0:0::/64');
      expect(rateLimitKey('203.0.113.1')).toBe('203.0.113.1');
    });
  });

  describe('validation at construction', () => {
    it.each([true, -1, 1.5, NaN, '1', Infinity, null, ['10.0.0.0/33'], ['not-an-ip'], ['constructor'], [5], ['10.0.0.0/8/1'], ['10.0.0.0/']])(
      'rejects %j', (value) => {
        expect(() => createClientIpResolver({ trustProxy: value as never })).toThrow(TypeError);
      });

    it('getClientIp validates too', () => {
      expect(() => getClientIp(req({}), { trustProxy: true as never })).toThrow(TypeError);
    });
  });

  describe('misconfiguration warnings', () => {
    const resolverWith = (trustProxy: unknown) => {
      const onWarning = vi.fn();
      return { onWarning, run: createClientIpResolver({ trustProxy: trustProxy as never, onWarning }) };
    };

    it('warns once when a private peer forwards X-Forwarded-For that is not trusted', () => {
      const { onWarning, run } = resolverWith(0);
      run(req({ 'x-forwarded-for': '203.0.113.1' }, '10.0.0.1'));
      run(req({ 'x-forwarded-for': '203.0.113.2' }, '10.0.0.1'));
      expect(onWarning).toHaveBeenCalledTimes(1);
      expect(onWarning.mock.calls[0]![0]).toMatch(/private address that trustProxy does not trust/);
    });

    it('does not warn for a public peer sending X-Forwarded-For (a directly exposed server)', () => {
      const { onWarning, run } = resolverWith(0);
      run(req({ 'x-forwarded-for': '198.51.100.1' }, '203.0.113.50'));
      expect(onWarning).not.toHaveBeenCalled();
    });

    it('a hop count above the real chain warns on honest traffic, so raising it cannot silence the signal', () => {
      const { onWarning, run } = resolverWith(5);
      run(req({ 'x-forwarded-for': '203.0.113.1' }, '10.0.0.1'));
      expect(onWarning).toHaveBeenCalledTimes(1);
      expect(onWarning.mock.calls[0]![0]).toMatch(/fewer X-Forwarded-For entries than trustProxy/);
    });

    it('a trusted proxy that sends no X-Forwarded-For warns', () => {
      const { onWarning, run } = resolverWith(['10.0.0.0/8']);
      run(req({ 'x-real-ip': '203.0.113.1' }, '10.0.0.1'));
      expect(onWarning).toHaveBeenCalledTimes(1);
    });

    it('a correct configuration is silent', () => {
      const { onWarning, run } = resolverWith(1);
      run(req({ 'x-forwarded-for': 'spoof, 203.0.113.1' }, '10.0.0.1'));
      expect(onWarning).not.toHaveBeenCalled();
    });

    it('defaults to process.emitWarning with a stable code; getClientIp never warns', () => {
      const emit = vi.spyOn(process, 'emitWarning').mockImplementation(() => {});
      getClientIp(req({ 'x-forwarded-for': '203.0.113.1' }, '10.0.0.1'));
      expect(emit).not.toHaveBeenCalled();
      createClientIpResolver()(req({ 'x-forwarded-for': '203.0.113.1' }, '10.0.0.1'));
      expect(emit).toHaveBeenCalledWith(expect.any(String), { code: 'MCP_SECURE_SERVER_TRUST_PROXY' });
    });
  });
});
