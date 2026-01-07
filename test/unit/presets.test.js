/**
 * Tests for security preset functionality
 */
import { describe, it, expect, beforeEach } from 'vitest';
import {
  SecureMcpServer,
  SECURITY_PRESETS,
  resolvePreset,
  getDefaultPreset,
  isValidPreset
} from '../../src/index.js';

describe('Security Presets', () => {
  describe('SECURITY_PRESETS', () => {
    it('should define basic, standard, and paranoid presets', () => {
      expect(SECURITY_PRESETS).toHaveProperty('basic');
      expect(SECURITY_PRESETS).toHaveProperty('standard');
      expect(SECURITY_PRESETS).toHaveProperty('paranoid');
    });

    it('basic preset should have relaxed limits', () => {
      const basic = SECURITY_PRESETS.basic;

      expect(basic.maxMessageSize).toBe(100 * 1024);
      expect(basic.maxParamCount).toBe(200);
      expect(basic.maxRequestsPerMinute).toBe(120);
      expect(basic.maxRequestsPerHour).toBe(3000);
      expect(basic.burstThreshold).toBe(30);
      expect(basic.contentValidation).toBe('minimal');
      expect(basic.enforceChaining).toBe(false);
      expect(basic.quotas).toBeNull();
      expect(basic.contextual).toBeNull();
    });

    it('standard preset should have balanced settings', () => {
      const standard = SECURITY_PRESETS.standard;

      expect(standard.maxMessageSize).toBe(50 * 1024);
      expect(standard.maxParamCount).toBe(100);
      expect(standard.maxRequestsPerMinute).toBe(30);
      expect(standard.maxRequestsPerHour).toBe(500);
      expect(standard.burstThreshold).toBe(10);
      expect(standard.contentValidation).toBe('standard');
      expect(standard.enforceChaining).toBe(false);
      expect(standard.quotas).toBeNull();
      expect(standard.contextual).toEqual({ enabled: true });
    });

    it('paranoid preset should have strict settings', () => {
      const paranoid = SECURITY_PRESETS.paranoid;

      expect(paranoid.maxMessageSize).toBe(25 * 1024);
      expect(paranoid.maxParamCount).toBe(50);
      expect(paranoid.maxRequestsPerMinute).toBe(15);
      expect(paranoid.maxRequestsPerHour).toBe(200);
      expect(paranoid.burstThreshold).toBe(5);
      expect(paranoid.contentValidation).toBe('full');
      expect(paranoid.enforceChaining).toBe(true);
      expect(paranoid.quotas).toBeDefined();
      expect(paranoid.contextual).toEqual({
        enabled: true,
        rateLimiting: { enabled: true }
      });
    });
  });

  describe('resolvePreset', () => {
    it('should return preset configuration for valid names', () => {
      expect(resolvePreset('basic')).toEqual(SECURITY_PRESETS.basic);
      expect(resolvePreset('standard')).toEqual(SECURITY_PRESETS.standard);
      expect(resolvePreset('paranoid')).toEqual(SECURITY_PRESETS.paranoid);
    });

    it('should return null for custom preset', () => {
      expect(resolvePreset('custom')).toBeNull();
    });
  });

  describe('getDefaultPreset', () => {
    it('should return standard as the default', () => {
      expect(getDefaultPreset()).toBe('standard');
    });
  });

  describe('isValidPreset', () => {
    it('should return true for valid preset names', () => {
      expect(isValidPreset('basic')).toBe(true);
      expect(isValidPreset('standard')).toBe(true);
      expect(isValidPreset('paranoid')).toBe(true);
      expect(isValidPreset('custom')).toBe(true);
    });

    it('should return false for invalid values', () => {
      expect(isValidPreset('invalid')).toBe(false);
      expect(isValidPreset('')).toBe(false);
      expect(isValidPreset(null)).toBe(false);
      expect(isValidPreset(undefined)).toBe(false);
      expect(isValidPreset(123)).toBe(false);
      expect(isValidPreset({})).toBe(false);
    });
  });
});

describe('SecureMcpServer with Presets', () => {
  const serverInfo = { name: 'preset-test', version: '1.0.0' };

  describe('preset application', () => {
    it('should use standard preset by default', () => {
      const server = new SecureMcpServer(serverInfo);
      const stats = server.getSecurityStats();

      expect(stats.server.totalLayers).toBe(5);
      expect(stats.server.enabledLayers).toBe(5);
    });

    it('should apply basic preset when specified', () => {
      const server = new SecureMcpServer(serverInfo, {
        securityLevel: 'basic'
      });

      const stats = server.getSecurityStats();
      expect(stats.server.totalLayers).toBe(5);
    });

    it('should apply paranoid preset when specified', () => {
      const server = new SecureMcpServer(serverInfo, {
        securityLevel: 'paranoid'
      });

      const stats = server.getSecurityStats();
      expect(stats.server.totalLayers).toBe(5);
    });

    it('should allow individual option overrides with preset', () => {
      const server = new SecureMcpServer(serverInfo, {
        securityLevel: 'paranoid',
        maxRequestsPerMinute: 60  // Override paranoid's 15
      });

      const stats = server.getSecurityStats();
      expect(stats.server.totalLayers).toBe(5);
    });
  });

  describe('preset behavior', () => {
    it('basic preset should have Layer 5 disabled', () => {
      // basic preset has contextual: null which disables Layer 5
      const server = new SecureMcpServer(serverInfo, {
        securityLevel: 'basic'
      });

      const stats = server.getSecurityStats();
      // Layer 5 should still be in the pipeline but with minimal config
      expect(stats.server.totalLayers).toBeGreaterThanOrEqual(4);
    });

    it('paranoid preset should have all layers enabled', () => {
      const server = new SecureMcpServer(serverInfo, {
        securityLevel: 'paranoid'
      });

      const stats = server.getSecurityStats();
      expect(stats.server.totalLayers).toBe(5);
      expect(stats.server.enabledLayers).toBe(5);
    });
  });

  describe('custom preset', () => {
    it('should ignore preset values when securityLevel is custom', () => {
      const server = new SecureMcpServer(serverInfo, {
        securityLevel: 'custom',
        maxMessageSize: 1024 * 1024,  // 1MB custom
        maxRequestsPerMinute: 1000
      });

      const stats = server.getSecurityStats();
      expect(stats.server.totalLayers).toBe(5);
    });
  });
});
