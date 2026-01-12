/**
 * Security logger - Enhanced with detailed security decision logging and buffering fixes
 *
 * DESIGN DECISIONS:
 *
 * 1. Silent Catch Blocks (AUDIT-OK pattern)
 *    Logging infrastructure must NEVER crash the application. All logging operations
 *    are wrapped in try/catch with intentionally empty handlers. If logging fails,
 *    the application continues operating - losing a log entry is preferable to crashing.
 *
 * 2. Fire-and-Forget Flush Pattern (void this.forceFlush())
 *    Non-blocking async flushes using `void` operator. Security decisions and requests
 *    should not wait for disk I/O. The flush runs in background; errors are caught
 *    internally. This prioritizes request throughput over guaranteed log persistence.
 */

import winston from 'winston';
import fs from 'fs';
import path from 'path';
import { LOGGING } from '../constants.js';
import type {
  SecurityLoggerOptions,
  SecurityDecision,
  LoggableMessage,
  LogContext,
  LayerStats,
  SecurityStats,
  SecurityReport,
  LogFileResult
} from './security-logger-types.js';
import {
  formatRequestLogData,
  formatSecurityDecisionLogData,
  formatPerformanceLogData,
  isBlockedDecision,
  updateLayerStats
} from './log-formatters.js';

// Re-export types for backward compatibility
export type {
  SecurityLoggerOptions,
  SecurityDecision,
  LoggableMessage,
  LogContext,
  LayerStats,
  SecurityStats,
  SecurityReport,
  LogFileResult
} from './security-logger-types.js';

/** Log file paths */
const LOG_FILES = [
  'logs/security-decisions.log',
  'logs/security-blocks.log',
  'logs/performance.log',
  'logs/security-debug.log'
] as const;

class SecurityLogger {
  private _logLevel: string;
  private streams: Map<string, fs.WriteStream>;
  private logger: winston.Logger;
  private requestCount: number;
  private blockCount: number;
  private layerStats: Map<string, LayerStats>;
  private _options: SecurityLoggerOptions;

  constructor(options: SecurityLoggerOptions = {}) {
    this._options = options;
    this._logLevel = options.logLevel || 'debug';

    this.setupLogsDirectorySync();
    this.streams = new Map();

    this.logger = winston.createLogger({
      level: this._logLevel,
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json({ space: 2 })
      ),
      transports: [
        this.createFileTransport('security-decisions.log', 'info'),
        this.createFileTransport('security-blocks.log', 'warn'),
        this.createFileTransport('performance.log', 'debug'),
        this.createFileTransport('security-debug.log', 'debug')
      ]
    });

    this.requestCount = 0;
    this.blockCount = 0;
    this.layerStats = new Map();
    this.setupExitHandlers();
    this.testLogger();
  }

  get options(): SecurityLoggerOptions {
    return this._options;
  }

  get logLevel(): string {
    return this._logLevel;
  }

  private createFileTransport(filename: string, level: string): winston.transports.FileTransportInstance {
    const filePath = path.resolve(process.cwd(), 'logs', filename);
    const stream = fs.createWriteStream(filePath, {
      flags: 'a',
      encoding: 'utf8',
      mode: 0o666,
      autoClose: true,
      highWaterMark: 0
    });
    this.streams.set(filename, stream);

    return new winston.transports.File({
      filename: filePath,
      level: level,
      options: { flags: 'a', highWaterMark: 0 },
      tailable: true,
      handleExceptions: false,
      handleRejections: false,
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
      maxsize: LOGGING.MAX_FILE_SIZE,
      maxFiles: LOGGING.MAX_FILES,
      stream: stream
    });
  }

  private setupLogsDirectorySync(): void {
    if (!fs.existsSync('logs')) {
      fs.mkdirSync('logs', { recursive: true });
    }
  }

  private setupExitHandlers(): void {
    const gracefulExit = async (_signal: string): Promise<void> => {
      await this.forceFlush();
      process.exit(0);
    };

    process.on('SIGINT', () => {
      gracefulExit('SIGINT').catch(() => process.exit(1));
    });
    process.on('SIGTERM', () => {
      gracefulExit('SIGTERM').catch(() => process.exit(1));
    });
    process.on('exit', () => {
      try {
        this.flushStreamsSync();
      } catch (_err) {
        // AUDIT-OK: Silent fail on exit - process is terminating, no recovery possible
      }
    });
  }

  /**
   * Synchronously flush all streams - used during process exit
   */
  private flushStreamsSync(): void {
    for (const [_filename, stream] of this.streams) {
      // SAFETY: WriteStream has flush() and fd properties not typed on Stream base.
      // We check existence before use; assertion is safe for graceful shutdown.
      if (stream && typeof (stream as unknown as { flush?: () => void }).flush === 'function') {
        (stream as unknown as { flush: () => void }).flush();
      }
      if (stream && (stream as unknown as { fd?: number | null }).fd !== null &&
          (stream as unknown as { fd?: number }).fd !== undefined) {
        fs.fsyncSync((stream as unknown as { fd: number }).fd);
      }
    }
  }

  /**
   * Synchronously fsync all log files
   */
  private fsyncLogFiles(): void {
    for (const file of LOG_FILES) {
      try {
        const fd = fs.openSync(file, 'a');
        fs.fsyncSync(fd);
        fs.closeSync(fd);
      } catch (_err) {
        // AUDIT-OK: Silent fail - file may not exist yet during startup
      }
    }
  }

  nextRequestId(): number {
    this.requestCount++;
    return this.requestCount;
  }

  private testLogger(): void {
    try {
      this.logger.info('ENHANCED_LOGGER_INITIALIZATION', {
        event: 'LOGGER_INIT',
        message: 'Enhanced security logger with verbose decision tracking',
        timestamp: new Date().toISOString(),
        level: this._logLevel,
        features: ['verbose_decisions', 'attack_analysis', 'performance_tracking']
      });
    } catch (_error) {
      // AUDIT-OK: Logger init failure is non-fatal - app continues without logging
    }
  }

  logRequest(message: LoggableMessage, context: LogContext = {}): void {
    this.requestCount++;
    const logData = formatRequestLogData(message, context, this.requestCount);

    try {
      this.logger.info('MCP_REQUEST', logData);
      void this.forceFlush(); // Fire-and-forget: see design note at top of file
    } catch (_error) {
      // AUDIT-OK: Request logging failure must not block request processing
    }
  }

  logInfo(message: string): void {
    this.requestCount++;
    try {
      this.logger.debug('LOG_INFO', {
        event: 'LOG_INFO',
        requestId: this.requestCount,
        message
      });
    } catch (_error) {
      // AUDIT-OK: Info logging failure is non-fatal
    }
  }

  logError(message: string): void {
    this.requestCount++;
    try {
      this.logger.error('LOG_ERROR', {
        event: 'LOG_ERROR',
        requestId: this.requestCount,
        message
      });
      void this.forceFlush();
    } catch (_error) {
      // AUDIT-OK: Error logging failure must not cause cascading failures
    }
  }

  async logSecurityDecision(decision: SecurityDecision, message: LoggableMessage, layer: string): Promise<void> {
    const isBlocked = isBlockedDecision(decision);
    if (isBlocked) this.blockCount++;

    const layerName = decision.layerName || layer;
    updateLayerStats(this.layerStats, layerName, isBlocked);

    const logData = formatSecurityDecisionLogData(
      decision,
      message,
      layer,
      this.requestCount,
      this.blockCount
    );

    try {
      if (isBlocked) {
        this.logger.warn('SECURITY_BLOCK', logData);
        await this.forceFlush(); // Await for blocks - want these persisted
      } else {
        this.logger.info('SECURITY_ALLOW', logData);
        void this.forceFlush(); // Fire-and-forget for allowed requests
      }
    } catch (_error) {
      // AUDIT-OK: Security decision logging must not block request processing
    }
  }

  logPerformance(startTime: number, endTime: number, message: LoggableMessage): void {
    const logData = formatPerformanceLogData(startTime, endTime, message, this.requestCount);

    try {
      this.logger.debug('PERFORMANCE_ENHANCED', logData);
      void this.forceFlush();
    } catch (_error) {
      // AUDIT-OK: Performance logging is telemetry - failure is non-fatal
    }
  }

  getStats(): SecurityStats {
    const stats: SecurityStats = {
      totalRequests: this.requestCount,
      totalBlocked: this.blockCount,
      totalAllowed: this.requestCount - this.blockCount,
      blockRate: this.requestCount > 0
        ? (this.blockCount / this.requestCount * 100).toFixed(2)
        : '0.00',
      passRate: this.requestCount > 0
        ? ((this.requestCount - this.blockCount) / this.requestCount * 100).toFixed(2)
        : '100.00',
      layerStats: Object.fromEntries(this.layerStats),
      logLevel: this._logLevel,
      logFiles: {
        decisions: LOG_FILES[0],
        blocks: LOG_FILES[1],
        performance: LOG_FILES[2],
        debug: LOG_FILES[3]
      }
    };

    try {
      this.logger.info('ENHANCED_SECURITY_STATS', {
        event: 'STATS_REPORT',
        timestamp: new Date().toISOString(),
        stats
      });
    } catch (_error) {
      // AUDIT-OK: Stats logging failure doesn't affect stats calculation
    }

    return stats;
  }

  async generateReport(): Promise<SecurityReport> {
    const stats = this.getStats();
    const report: SecurityReport = {
      summary: stats,
      timestamp: new Date().toISOString(),
      testDuration: process.uptime(),
      logFiles: stats.logFiles,
      recommendations: this.generateRecommendations(stats)
    };

    try {
      const reportPath = path.join('logs', 'security-report.json');
      await fs.promises.writeFile(reportPath, JSON.stringify(report, null, 2));
      this.logger.info('ENHANCED_REPORT_GENERATED', {
        event: 'ENHANCED_REPORT_GENERATION',
        reportPath,
        timestamp: new Date().toISOString(),
        reportSummary: report.summary
      });
    } catch (_error) {
      // AUDIT-OK: Report file write failure - report object still returned to caller
    }
    return report;
  }

  private generateRecommendations(stats: SecurityStats): string[] {
    const recommendations: string[] = [];

    if (parseFloat(stats.blockRate) > 50) {
      recommendations.push("HIGH_BLOCK_RATE: Consider reviewing attack patterns - over 50% of requests blocked");
    }
    if (parseFloat(stats.blockRate) === 0) {
      recommendations.push("NO_BLOCKS: No attacks detected - validate security testing is comprehensive");
    }
    if (stats.totalRequests > 100) {
      recommendations.push("HIGH_VOLUME: Consider implementing rate limiting or caching for performance");
    }

    return recommendations;
  }

  verifyLogFiles(): Record<string, LogFileResult> {
    const results: Record<string, LogFileResult> = {};
    for (const filePath of LOG_FILES) {
      try {
        if (fs.existsSync(filePath)) {
          const fileStats = fs.statSync(filePath);
          results[filePath] = { exists: true, size: fileStats.size };
        } else {
          results[filePath] = { exists: false };
        }
      } catch (err) {
        results[filePath] = { exists: false, error: (err as Error).message };
      }
    }
    return results;
  }

  async forceFlush(): Promise<void> {
    try {
      // Flush winston transports
      for (const transport of this.logger.transports) {
        const transportAny = transport as unknown as { flush?: (callback: () => void) => void };
        if (typeof transportAny.flush === 'function') {
          await new Promise<void>(resolve => transportAny.flush!(resolve));
        }
      }
      // Flush streams and fsync log files
      this.flushStreamsSync();
      this.fsyncLogFiles();
    } catch (_error) {
      // AUDIT-OK: Flush errors during async flush - best-effort persistence
    }
  }

  async flush(): Promise<void> {
    return this.forceFlush();
  }
}

export { SecurityLogger };
