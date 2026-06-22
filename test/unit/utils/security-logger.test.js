// tests/unit/utils/security-logger.test.js
import { describe, it, expect, vi, beforeEach, afterEach, beforeAll, afterAll } from 'vitest';
import { SecurityLogger } from '../../../src/security/utils/security-logger.js';
import fs from 'fs';
import path from 'path';

// Test utilities
const TEST_LOGS_DIR = path.resolve(process.cwd(), 'test-logs');
const EXPECTED_LOG_FILES = [
  'security-decisions.log',
  'security-blocks.log', 
  'performance.log',
  'security-debug.log'
];

describe('SecurityLogger', () => {
  let logger;
  let originalCwd;
  let consoleSpy;

  beforeAll(() => {
    // Setup test environment
    originalCwd = process.cwd();
    
    // Create test logs directory
    if (!fs.existsSync(TEST_LOGS_DIR)) {
      fs.mkdirSync(TEST_LOGS_DIR, { recursive: true });
    }
  });

  afterAll(() => {
    // Cleanup test logs directory
    try {
      if (fs.existsSync(TEST_LOGS_DIR)) {
        fs.rmSync(TEST_LOGS_DIR, { recursive: true, force: true });
      }
    } catch (error) {
      console.warn('Could not cleanup test logs directory:', error.message);
    }
  });

  beforeEach(() => {
    consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    
    // Clean up any existing log files from previous tests
    const logsDir = path.resolve(process.cwd(), 'logs');
    if (fs.existsSync(logsDir)) {
      try {
        for (const file of EXPECTED_LOG_FILES) {
          const filePath = path.join(logsDir, file);
          if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
          }
        }
      } catch (error) {
        console.warn('Could not cleanup existing log files:', error.message);
      }
    }
  });

  afterEach(async () => {
    if (logger) {
      try {
        await logger.flush();
        // Small delay to ensure cleanup
        await new Promise(resolve => setTimeout(resolve, 100));
      } catch (error) {
        // Ignore cleanup errors
      }
    }
    vi.restoreAllMocks();
  });

  describe('Constructor & Initialization', () => {
    it('creates logger with default options', () => {
      logger = new SecurityLogger();
      
      expect(logger.logLevel).toBe('debug');
      expect(logger.requestCount).toBe(0);
      expect(logger.blockCount).toBe(0);
      expect(logger.layerStats).toBeInstanceOf(Map);
      expect(logger.streams).toBeInstanceOf(Map);
      expect(typeof logger.logger).toBe('object');
      expect(logger.logger).not.toBe(null);
    });

    it('respects custom options', () => {
      logger = new SecurityLogger({
        logLevel: 'warn',
        enableConsoleLogging: false
      });
      
      expect(logger.logLevel).toBe('warn');
      expect(logger.options.enableConsoleLogging).toBe(false);
    });

    it('creates logs directory if not exists', () => {
      logger = new SecurityLogger();
      
      const logsDir = path.resolve(process.cwd(), 'logs');
      expect(fs.existsSync(logsDir)).toBe(true);
    });

    it('initializes winston logger with correct transports', () => {
      logger = new SecurityLogger();
      
      expect(logger.logger.transports).toHaveLength(4);
      expect(logger.streams.size).toBe(4);
      
      // Check expected streams exist
      for (const filename of EXPECTED_LOG_FILES) {
        expect(logger.streams.has(filename)).toBe(true);
      }
    });
  });

  describe('Basic Logging Methods', () => {
    beforeEach(() => {
      logger = new SecurityLogger({ logLevel: 'debug' });
    });

    describe('logRequest', () => {
      it('logs request with basic message', async () => {
        const message = {
          jsonrpc: '2.0',
          method: 'tools/call',
          id: 'test-123',
          params: { name: 'calculator' }
        };

        logger.logRequest(message);
        
        expect(logger.requestCount).toBe(1);
        
        // Wait for async logging
        await new Promise(resolve => setTimeout(resolve, 50));
      });

      it('logs request with context', async () => {
        const message = { method: 'test' };
        const context = { 
          timestamp: Date.now(),
          source: 'test-suite' 
        };

        logger.logRequest(message, context);
        
        expect(logger.requestCount).toBe(1);
      });

      it('handles messages without params', async () => {
        const message = {
          jsonrpc: '2.0',
          method: 'resources/list',
          id: 'test-456'
        };

        expect(() => {
          logger.logRequest(message);
        }).not.toThrow();
        
        expect(logger.requestCount).toBe(1);
      });
    });

    describe('logSecurityDecision', () => {
      it('logs allowed decision', async () => {
        const decision = {
          passed: true,
          allowed: true,
          severity: 'LOW',
          reason: 'Valid request',
          violationType: 'NONE',
          confidence: 1.0,
          layerName: 'TestLayer'
        };
        
        const message = { method: 'test', id: 'allow-test' };

        await logger.logSecurityDecision(decision, message, 'TestLayer');
        
        expect(logger.layerStats.has('TestLayer')).toBe(true);
        const stats = logger.layerStats.get('TestLayer');
        expect(stats.passed).toBe(1);
        expect(stats.blocked).toBe(0);
      });

      it('logs blocked decision', async () => {
        const decision = {
          passed: false,
          allowed: false,
          severity: 'HIGH',
          reason: 'Path traversal detected',
          violationType: 'PATH_TRAVERSAL',
          confidence: 0.9,
          layerName: 'ContentLayer'
        };
        
        const message = { method: 'tools/call', id: 'block-test' };

        await logger.logSecurityDecision(decision, message, 'ContentLayer');
        
        expect(logger.blockCount).toBe(1);
        expect(logger.layerStats.has('ContentLayer')).toBe(true);
        const stats = logger.layerStats.get('ContentLayer');
        expect(stats.passed).toBe(0);
        expect(stats.blocked).toBe(1);
      });

      it('handles decision without layerName', async () => {
        const decision = {
          passed: true,
          allowed: true
        };
        
        const message = { method: 'test' };

        expect(async () => {
          await logger.logSecurityDecision(decision, message, 'FallbackLayer');
        }).not.toThrow();
      });

      it('creates attack analysis for blocked decisions', async () => {
        const decision = {
          passed: false,
          allowed: false,
          severity: 'CRITICAL',
          reason: 'SQL injection detected',
          violationType: 'SQL_INJECTION',
          confidence: 0.95,
          layerName: 'ContentLayer'
        };
        
        const message = { method: 'tools/call', id: 'sql-attack' };

        await logger.logSecurityDecision(decision, message, 'ContentLayer');
        
        // Should increment block count and create stats
        expect(logger.blockCount).toBe(1);
        expect(logger.layerStats.get('ContentLayer').blocked).toBe(1);
      });
    });

    describe('logPerformance', () => {
      it('logs performance metrics', () => {
        const message = { method: 'tools/call', id: 'perf-test' };
        const startTime = 100;
        const endTime = 125.5;

        expect(() => {
          logger.logPerformance(startTime, endTime, message);
        }).not.toThrow();
      });

      it('categorizes performance correctly', () => {
        const message = { method: 'test' };
        
        // Test different performance categories
        logger.logPerformance(0, 3, message);    // FAST
        logger.logPerformance(0, 15, message);   // MEDIUM  
        logger.logPerformance(0, 30, message);   // SLOW
      });
    });

    describe('logInfo', () => {
      it('logs info message', () => {
        expect(() => {
          logger.logInfo('Test info message');
        }).not.toThrow();
        
        expect(logger.requestCount).toBe(1);
      });
    });
  });

  describe('Statistics & Reporting', () => {
    beforeEach(() => {
      logger = new SecurityLogger();
    });

    it('tracks request statistics correctly', async () => {
      // Log some requests and decisions
      logger.logRequest({ method: 'test1' });
      logger.logRequest({ method: 'test2' });
      
      await logger.logSecurityDecision({
        passed: true,
        layerName: 'Layer1'
      }, { method: 'test1' }, 'Layer1');
      
      await logger.logSecurityDecision({
        passed: false,
        layerName: 'Layer2' 
      }, { method: 'test2' }, 'Layer2');

      const stats = logger.getStats();
      
      expect(stats.totalRequests).toBe(2);
      expect(stats.totalBlocked).toBe(1);
      expect(stats.blockRate).toBe('50.00');
      expect(stats.passRate).toBe('50.00');
    });

    it('generates recommendations based on stats', async () => {
      // Create high block rate scenario - need requests AND blocked decisions
      for (let i = 0; i < 10; i++) {
        // Log request first
        logger.logRequest({ method: `test-${i}`, id: `req-${i}` });
        
        // Then log a blocked decision for that request
        await logger.logSecurityDecision({
          passed: false,
          allowed: false,
          layerName: 'TestLayer'
        }, { method: `test-${i}` }, 'TestLayer');
      }

      const stats = logger.getStats();
      const recommendations = logger.generateRecommendations(stats);
      console.error(recommendations)
      // Should have 100% block rate (10 blocked out of 10 requests)
      expect(stats.blockRate).toBe('100.00');

    });

    it('generates report with correct structure', async () => {
      logger.logRequest({ method: 'test' });
      
      const report = await logger.generateReport();
      
      expect(report).toHaveProperty('summary');
      expect(report).toHaveProperty('timestamp');
      expect(report).toHaveProperty('testDuration');
      expect(report).toHaveProperty('logFiles');
      expect(report).toHaveProperty('recommendations');
    });
  });

  describe('File Operations', () => {
    beforeEach(() => {
      logger = new SecurityLogger();
    });

    it('verifies log files exist after logging', async () => {
      // Log something to trigger file creation
      logger.logRequest({ method: 'test' });
      await logger.forceFlush();
      
      // Wait for file system operations
      await new Promise(resolve => setTimeout(resolve, 100));
      
      expect(() => {
        logger.verifyLogFiles();
      }).not.toThrow();
    });

    it('creates expected log files', async () => {
      // Trigger logging to create files
      logger.logRequest({ method: 'test' });
      await logger.logSecurityDecision({
        passed: false,
        layerName: 'Test'
      }, { method: 'test' }, 'Test');
      
      await logger.forceFlush();
      await new Promise(resolve => setTimeout(resolve, 100));
      
      const logsDir = path.resolve(process.cwd(), 'logs');
      
      // Check at least some files were created
      let filesFound = 0;
      for (const filename of EXPECTED_LOG_FILES) {
        const filePath = path.join(logsDir, filename);
        if (fs.existsSync(filePath)) {
          filesFound++;
        }
      }
      
      expect(filesFound).toBeGreaterThan(0);
    });

    it('handles force flush without errors', async () => {
      logger.logRequest({ method: 'test' });
      
      await expect(logger.forceFlush()).resolves.not.toThrow();
      await expect(logger.flush()).resolves.not.toThrow();
    });
  });

  describe('Error Handling', () => {
    it('handles logging errors gracefully', () => {
      logger = new SecurityLogger();

      // Mock winston logger to throw error
      const mockError = new Error('Winston error');
      vi.spyOn(logger.logger, 'info').mockImplementation(() => {
        throw mockError;
      });

      // Should not throw - errors are handled silently
      expect(() => {
        logger.logRequest({ method: 'test' });
      }).not.toThrow();
    });

    it('handles invalid message objects', () => {
      logger = new SecurityLogger();
      
      // These should throw since the logger expects valid message objects
      expect(() => {
        logger.logRequest(null);
      }).toThrow();
      
      expect(() => {
        logger.logRequest(undefined);
      }).toThrow();
      
      // But empty objects and objects with missing fields should work
      expect(() => {
        logger.logRequest({});
      }).not.toThrow();
      
      expect(() => {
        logger.logRequest({ method: 'test' }); // Missing other fields
      }).not.toThrow();
      
      expect(() => {
        logger.logRequest({ 
          jsonrpc: '2.0',
          method: 'test',
          id: 'test-id'
          // Missing params - should be fine
        });
      }).not.toThrow();
    });

    it('degrades to no-op logging (does not crash) when the log directory cannot be created', () => {
      // A logger whose directory cannot be created (e.g. an unwritable
      // cwd-derived default like "/logs" when launched with cwd="/") must NOT
      // crash construction — logging infrastructure must never crash the app
      // (see DESIGN DECISIONS #1 in security-logger.ts).
      const existsSpy = vi.spyOn(fs, 'existsSync').mockReturnValue(false);
      const mkdirSpy = vi.spyOn(fs, 'mkdirSync').mockImplementation(() => {
        throw new Error('Permission denied');
      });
      const stderrSpy = vi.spyOn(process.stderr, 'write').mockReturnValue(true);

      let logger;
      expect(() => {
        logger = new SecurityLogger();
      }).not.toThrow();

      // The logger is usable and silently no-ops on logging calls.
      expect(() => {
        logger.logRequest({ method: 'test', id: 'x' }, { canonical: 'test' });
      }).not.toThrow();

      // The degraded state is OBSERVABLE, not silent: getStats reports it and a
      // one-time stderr warning is emitted (the visibility valve).
      const stats = logger.getStats();
      expect(stats.fileLoggingAvailable).toBe(false);
      expect(stats.writeErrors).toBe(0);
      expect(stats.lastWriteError).toBe(null);
      expect(stderrSpy).toHaveBeenCalled();
      expect(stderrSpy.mock.calls.some(([msg]) => /DISABLED/.test(String(msg)))).toBe(true);

      existsSpy.mockRestore();
      mkdirSpy.mockRestore();
      stderrSpy.mockRestore();
    });

    it('degrades (does not crash) when stream creation fails despite a valid directory', () => {
      // Directory is fine, but every fs.createWriteStream throws synchronously.
      // createFileTransport must catch, return null, and the logger must report
      // unavailable rather than crash or falsely report healthy.
      const existsSpy = vi.spyOn(fs, 'existsSync').mockReturnValue(true);
      const statSpy = vi
        .spyOn(fs, 'statSync')
        .mockReturnValue({ isDirectory: () => true });
      const cwsSpy = vi.spyOn(fs, 'createWriteStream').mockImplementation(() => {
        throw new Error('EMFILE: too many open files');
      });
      const stderrSpy = vi.spyOn(process.stderr, 'write').mockReturnValue(true);

      try {
        let logger;
        expect(() => {
          logger = new SecurityLogger({ logDir: path.join(TEST_LOGS_DIR, 'stream-fail') });
        }).not.toThrow();
        expect(() => {
          logger.logRequest({ method: 'test', id: 'x' }, { canonical: 'test' });
        }).not.toThrow();
        expect(logger.getStats().fileLoggingAvailable).toBe(false);
        // Degradation is observable on stderr, symmetric with the mkdir path.
        expect(stderrSpy.mock.calls.some(([msg]) => /DISABLED/.test(String(msg)))).toBe(true);
      } finally {
        existsSpy.mockRestore();
        statSpy.mockRestore();
        cwsSpy.mockRestore();
        stderrSpy.mockRestore();
      }
    });

    it('reports a healthy logging state when the directory is writable', () => {
      const l = new SecurityLogger({ logDir: path.join(TEST_LOGS_DIR, 'healthy') });
      const stats = l.getStats();
      expect(stats.fileLoggingAvailable).toBe(true);
      expect(stats.writeErrors).toBe(0);
      expect(stats.lastWriteError).toBe(null);
    });

    it('degrades (does not crash) when logDir points at an existing non-directory', () => {
      // A path that exists as a FILE cannot hold log files. existsSync alone
      // would report it usable; statSync().isDirectory() catches it.
      const filePath = path.join(TEST_LOGS_DIR, 'not-a-dir.txt');
      fs.writeFileSync(filePath, 'i am a file');
      const stderrSpy = vi.spyOn(process.stderr, 'write').mockReturnValue(true);

      try {
        let logger;
        expect(() => {
          logger = new SecurityLogger({ logDir: filePath });
        }).not.toThrow();
        expect(logger.getStats().fileLoggingAvailable).toBe(false);
        expect(stderrSpy.mock.calls.some(([msg]) => /not a\s+directory/i.test(String(msg)))).toBe(true);
      } finally {
        stderrSpy.mockRestore();
        fs.unlinkSync(filePath);
      }
    });
  });

  describe('Log directory resolution', () => {
    const originalEnv = process.env.LOG_DIR;

    afterEach(() => {
      if (originalEnv === undefined) {
        delete process.env.LOG_DIR;
      } else {
        process.env.LOG_DIR = originalEnv;
      }
    });

    it('uses the explicit logDir option', () => {
      const dir = path.join(TEST_LOGS_DIR, 'explicit');
      const l = new SecurityLogger({ logDir: dir });
      expect(l.getStats().logFiles.decisions).toBe(
        path.join(path.resolve(dir), 'security-decisions.log')
      );
    });

    it('falls back to the LOG_DIR env var when no option is given', () => {
      const dir = path.join(TEST_LOGS_DIR, 'from-env');
      process.env.LOG_DIR = dir;
      const l = new SecurityLogger();
      expect(l.getStats().logFiles.decisions).toBe(
        path.join(path.resolve(dir), 'security-decisions.log')
      );
    });

    it('prefers the explicit option over the LOG_DIR env var', () => {
      process.env.LOG_DIR = path.join(TEST_LOGS_DIR, 'env-loser');
      const dir = path.join(TEST_LOGS_DIR, 'option-winner');
      const l = new SecurityLogger({ logDir: dir });
      expect(l.getStats().logFiles.decisions).toBe(
        path.join(path.resolve(dir), 'security-decisions.log')
      );
    });

    it('defaults to <cwd>/logs when neither option nor env is set', () => {
      delete process.env.LOG_DIR;
      const l = new SecurityLogger();
      expect(l.getStats().logFiles.decisions).toBe(
        path.join(path.resolve(process.cwd(), 'logs'), 'security-decisions.log')
      );
    });

    it('resolves a relative logDir option to an absolute path', () => {
      delete process.env.LOG_DIR;
      const l = new SecurityLogger({ logDir: 'test-logs/relative-dir' });
      const decisions = l.getStats().logFiles.decisions;
      expect(path.isAbsolute(decisions)).toBe(true);
      expect(decisions).toBe(
        path.resolve('test-logs/relative-dir', 'security-decisions.log')
      );
    });

    it('falls back to the default when logDir is blank/whitespace', () => {
      delete process.env.LOG_DIR;
      const l = new SecurityLogger({ logDir: '   ' });
      expect(l.getStats().logFiles.decisions).toBe(
        path.join(path.resolve(process.cwd(), 'logs'), 'security-decisions.log')
      );
    });
  });

  describe('Utility Methods', () => {
    beforeEach(() => {
      logger = new SecurityLogger();
    });

    it('generates next request ID correctly', () => {
      expect(logger.nextRequestId()).toBe(1);
      expect(logger.nextRequestId()).toBe(2);
      expect(logger.nextRequestId()).toBe(3);
    });

    it('runs test logger without errors', () => {
      expect(() => {
        logger.testLogger();
      }).not.toThrow();
    });
  });

  describe('Performance', () => {
    it('handles high volume logging efficiently', async () => {
      logger = new SecurityLogger();
      
      const start = performance.now();
      
      // Log 100 requests quickly
      for (let i = 0; i < 100; i++) {
        logger.logRequest({ method: `test-${i}`, id: `req-${i}` });
      }
      
      const duration = performance.now() - start;
      
      expect(duration).toBeLessThan(1000); // Should complete in <1s
      expect(logger.requestCount).toBe(100);
    });

    it('handles large message objects', () => {
      logger = new SecurityLogger();
      
      const largeMessage = {
        method: 'tools/call',
        id: 'large-test',
        params: {
          data: 'x'.repeat(10000) // 10KB of data
        }
      };

      const start = performance.now();
      logger.logRequest(largeMessage);
      const duration = performance.now() - start;
      
      expect(duration).toBeLessThan(100); // Should handle large messages quickly
    });
  });

  describe('Integration Scenarios', () => {
    it('simulates full security pipeline logging', async () => {
      logger = new SecurityLogger();
      
      // Simulate a complete security validation pipeline
      const message = {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 'integration-test',
        params: {
          name: 'file-reader',
          arguments: { path: '../../../etc/passwd' }
        }
      };

      // 1. Log the incoming request
      logger.logRequest(message, { source: 'integration-test' });
      
      // 2. Log layer decisions
      await logger.logSecurityDecision({
        passed: true,
        layerName: 'StructureLayer'
      }, message, 'StructureLayer');
      
      await logger.logSecurityDecision({
        passed: false,
        allowed: false,
        severity: 'HIGH',
        reason: 'Path traversal detected',
        violationType: 'PATH_TRAVERSAL',
        layerName: 'ContentLayer'
      }, message, 'ContentLayer');
      
      // 3. Log performance
      logger.logPerformance(0, 15.2, message);
      
      // 4. Verify stats
      const stats = logger.getStats();
      expect(stats.totalRequests).toBe(1);
      expect(stats.totalBlocked).toBe(1);
      expect(stats.layerStats).toHaveProperty('StructureLayer');
      expect(stats.layerStats).toHaveProperty('ContentLayer');
    });
  });
});