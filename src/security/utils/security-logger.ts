/**
 * Security logger - Enhanced with detailed security decision logging and buffering fixes
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

    process.on('SIGINT', () => gracefulExit('SIGINT'));
    process.on('SIGTERM', () => gracefulExit('SIGTERM'));
    process.on('exit', () => {
      try {
        this.flushStreamsSync();
      } catch (_err) {
        // Silent fail on exit - logging system is shutting down
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
        // Silent fail - file may not exist yet
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
      // Silent fail - logger initialization should not crash the application
    }
  }

  logRequest(message: LoggableMessage, context: LogContext = {}): void {
    this.requestCount++;
    const logData = formatRequestLogData(message, context, this.requestCount);

    try {
      this.logger.info('MCP_REQUEST', logData);
      this.forceFlush().catch(() => {});
    } catch (_error) {
      // Silent fail - request logging should not crash the application
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
      // Silent fail
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
        await this.forceFlush();
      } else {
        this.logger.info('SECURITY_ALLOW', logData);
        this.forceFlush().catch(() => {});
      }
    } catch (_error) {
      // Silent fail - decision logging should not crash the application
    }
  }

  logPerformance(startTime: number, endTime: number, message: LoggableMessage): void {
    const logData = formatPerformanceLogData(startTime, endTime, message, this.requestCount);

    try {
      this.logger.debug('PERFORMANCE_ENHANCED', logData);
      this.forceFlush().catch(() => {});
    } catch (_error) {
      // Silent fail
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
      // Silent fail
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
      // Silent fail - report generation should not crash the application
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
      // Silent fail - flush errors should not crash the application
    }
  }

  async flush(): Promise<void> {
    return this.forceFlush();
  }
}

export { SecurityLogger };
