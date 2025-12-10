import { describe, it, expect, beforeEach } from 'vitest';
import ContentValidationLayer from '@/security/layers/layer2-content.js';

/**
 * SSRF Attack Detection Tests
 * Tests for Server-Side Request Forgery protection patterns
 * Coverage: network.js patterns (cloudMetadata, loopback, privateNetworks, dangerousSchemes)
 */

describe('SSRF Attack Detection', () => {
  let layer;

  beforeEach(() => {
    layer = new ContentValidationLayer({ debugMode: false });
  });

  describe('Cloud Metadata Endpoint Detection', () => {
    it('should block AWS metadata endpoint (169.254.169.254)', async () => {
      const message = createToolCallMessage({
        url: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.reason).toMatch(/ssrf|metadata|cloud|internal/i);
    });

    it('should block AWS metadata with path variations', async () => {
      const attacks = [
        'http://169.254.169.254/latest/meta-data/',
        'http://169.254.169.254/latest/user-data/',
        'http://169.254.169.254/latest/dynamic/instance-identity/document'
      ];

      for (const url of attacks) {
        const message = createToolCallMessage({ url });
        const result = await layer.validate(message, {});
        expect(result.passed).toBe(false);
      }
    });

    it('should block GCP metadata service', async () => {
      const message = createToolCallMessage({
        url: 'http://metadata.google.internal/computeMetadata/v1/'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
    });

    it('should block GCP metadata variations', async () => {
      const attacks = [
        'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/',
        'http://metadata.google.internal/computeMetadata/v1/project/project-id'
      ];

      for (const url of attacks) {
        const message = createToolCallMessage({ url });
        const result = await layer.validate(message, {});
        expect(result.passed).toBe(false);
      }
    });

    it('should block Azure IMDS endpoint', async () => {
      const message = createToolCallMessage({
        url: 'http://169.254.169.254/metadata/instance?api-version=2021-02-01'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
    });

    it('should block DigitalOcean metadata', async () => {
      const message = createToolCallMessage({
        url: 'http://169.254.169.254/metadata/v1/'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
    });

    it('should block Oracle Cloud metadata', async () => {
      const message = createToolCallMessage({
        url: 'http://169.254.169.254/opc/v1/instance/'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
    });
  });

  describe('Loopback Address Detection', () => {
    it('should block localhost URLs', async () => {
      const message = createToolCallMessage({
        url: 'http://localhost/admin'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
    });

    it('should block 127.0.0.1', async () => {
      const message = createToolCallMessage({
        url: 'http://127.0.0.1:8080/internal-api'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
    });

    it('should block IPv6 loopback [::1]', async () => {
      const message = createToolCallMessage({
        url: 'http://[::1]/admin'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
    });

    it('should block 0.0.0.0', async () => {
      const message = createToolCallMessage({
        url: 'http://0.0.0.0:3000/api'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
    });

    it('should block short loopback formats', async () => {
      const attacks = [
        'http://127.1/admin',
        'http://127.0.1/config'
      ];

      for (const url of attacks) {
        const message = createToolCallMessage({ url });
        const result = await layer.validate(message, {});
        expect(result.passed).toBe(false);
      }
    });
  });

  describe('Private Network Detection (RFC1918)', () => {
    it('should block 10.x.x.x range', async () => {
      const attacks = [
        'http://10.0.0.1/admin',
        'http://10.255.255.255/config',
        'http://10.10.10.10:8080/internal'
      ];

      for (const url of attacks) {
        const message = createToolCallMessage({ url });
        const result = await layer.validate(message, {});
        expect(result.passed).toBe(false);
      }
    });

    it('should block 172.16-31.x.x range', async () => {
      const attacks = [
        'http://172.16.0.1/admin',
        'http://172.20.10.5:9000/api',
        'http://172.31.255.255/internal'
      ];

      for (const url of attacks) {
        const message = createToolCallMessage({ url });
        const result = await layer.validate(message, {});
        expect(result.passed).toBe(false);
      }
    });

    it('should block 192.168.x.x range', async () => {
      const attacks = [
        'http://192.168.0.1/router',
        'http://192.168.1.1/config',
        'http://192.168.255.255:8080/internal'
      ];

      for (const url of attacks) {
        const message = createToolCallMessage({ url });
        const result = await layer.validate(message, {});
        expect(result.passed).toBe(false);
      }
    });
  });

  describe('Dangerous URI Schemes', () => {
    it('should block file:// scheme', async () => {
      const message = createToolCallMessage({
        url: 'file:///etc/passwd'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
    });

    it('should block gopher:// scheme', async () => {
      const message = createToolCallMessage({
        url: 'gopher://localhost:25/_HELO%20attacker'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
    });

    it('should block dict:// scheme', async () => {
      const message = createToolCallMessage({
        url: 'dict://localhost:11211/stats'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
    });

    it('should block ldap:// scheme', async () => {
      const message = createToolCallMessage({
        url: 'ldap://evil.com/cn=admin'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
    });

    it('should block ftp:// scheme', async () => {
      const message = createToolCallMessage({
        url: 'ftp://internal-server/sensitive-data'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
    });

    it('should block smb:// scheme', async () => {
      const message = createToolCallMessage({
        url: 'smb://internal-server/share'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
    });
  });

  describe('Internal Service Detection', () => {
    it('should block common admin ports', async () => {
      const attacks = [
        'http://internal.example.com:8080/admin',
        'http://backend:9090/metrics',
        'http://api-server:3000/health'
      ];

      for (const url of attacks) {
        const message = createToolCallMessage({ url });
        const result = await layer.validate(message, {});
        expect(result.passed).toBe(false);
      }
    });

    it('should block database ports', async () => {
      const attacks = [
        'http://db:3306/mysql',
        'http://postgres:5432/admin',
        'http://mongo:27017/test'
      ];

      for (const url of attacks) {
        const message = createToolCallMessage({ url });
        const result = await layer.validate(message, {});
        expect(result.passed).toBe(false);
      }
    });

    it('should block Kubernetes/Docker endpoints', async () => {
      const attacks = [
        'http://kubernetes.default.svc.cluster.local/api',
        'unix:///var/run/docker.sock'
      ];

      for (const url of attacks) {
        const message = createToolCallMessage({ url });
        const result = await layer.validate(message, {});
        expect(result.passed).toBe(false);
      }
    });
  });

  describe('SSRF Bypass Attempts', () => {
    it('should block hex-encoded IPs', async () => {
      const message = createToolCallMessage({
        url: 'http://0x7f000001/admin'  // 127.0.0.1 in hex
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
    });

    it('should block integer-encoded IPs', async () => {
      const message = createToolCallMessage({
        url: 'http://2130706433/admin'  // 127.0.0.1 as integer
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
    });

    it('should block URL-encoded loopback', async () => {
      // URL-encoded loopback address should be caught after canonicalization
      const message = createToolCallMessage({
        url: 'http://%31%32%37%2e%30%2e%30%2e%31/admin'  // 127.0.0.1 URL-encoded
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
    });
  });

  describe('Exfiltration Endpoints', () => {
    it('should block webhook URLs', async () => {
      const attacks = [
        'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXX',
        'https://discord.com/api/webhooks/123456789/abcdefghijk'
      ];

      for (const url of attacks) {
        const message = createToolCallMessage({ url });
        const result = await layer.validate(message, {});
        expect(result.passed).toBe(false);
      }
    });

    it('should block DNS exfiltration services', async () => {
      const message = createToolCallMessage({
        url: 'http://test.burpcollaborator.net/exfil'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
    });
  });

  describe('Legitimate URLs (Should Pass)', () => {
    it('should allow external public URLs', async () => {
      const message = createToolCallMessage({
        url: 'https://api.example.com/data'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(true);
    });

    it('should allow standard HTTPS endpoints', async () => {
      const safeUrls = [
        'https://github.com/api/v3/repos',
        'https://api.openai.com/v1/completions',
        'https://www.google.com/search'
      ];

      for (const url of safeUrls) {
        const message = createToolCallMessage({ url });
        const result = await layer.validate(message, {});
        expect(result.passed).toBe(true);
      }
    });

    it('should allow URLs with port 443', async () => {
      const message = createToolCallMessage({
        url: 'https://api.example.com:443/endpoint'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(true);
    });
  });
});

function createToolCallMessage(params = {}) {
  return {
    jsonrpc: '2.0',
    method: 'tools/call',
    id: 1,
    params: {
      name: 'http-request',
      arguments: params
    }
  };
}
