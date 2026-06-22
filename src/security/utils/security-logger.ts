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

/**
 * After the first log-write failure, re-warn to stderr once every this many
 * additional failures. Keeps a sustained outage visible without flooding.
 */
const WRITE_ERROR_WARN_INTERVAL = 1000;

/** Log file names, relative to the resolved log directory */
const LOG_FILE_NAMES = [
  'security-decisions.log',
  'security-blocks.log',
  'performance.log',
  'security-debug.log'
] as const;

class SecurityLogger {
  private _logLevel: string;
  private streams: Map<string, fs.WriteStream>;
  private logger: winston.Logger;
  private requestCount: number;
  private blockCount: number;
  private layerStats: Map<string, LayerStats>;
  private _options: SecurityLoggerOptions;
  private readonly logDir: string;
  private readonly fileLoggingAvailable: boolean;
  private writeErrorCount: number;
  private lastWriteError: string | null;

  constructor(options: SecurityLoggerOptions = {}) {
    this._options = options;
    this._logLevel = options.logLevel || 'debug';
    this.logDir = SecurityLogger.resolveLogDir(options);
    this.streams = new Map();
    this.writeErrorCount = 0;
    this.lastWriteError = null;

    // The log directory must exist before transports open their streams.
    // If it cannot be created (e.g. an unwritable cwd-derived default like
    // "/logs" when launched with cwd="/"), degrade to no-op logging rather
    // than crash the host process — see DESIGN DECISIONS #1 above.
    const logDirReady = this.setupLogsDirectorySync();

    const transports = logDirReady
      ? [
          this.createFileTransport('security-decisions.log', 'info'),
          this.createFileTransport('security-blocks.log', 'warn'),
          this.createFileTransport('performance.log', 'debug'),
          this.createFileTransport('security-debug.log', 'debug')
        ].filter(
          (t): t is winston.transports.FileTransportInstance => t !== null
        )
      : [];

    // Truthful health: file logging is "available" only if at least one
    // transport actually opened. A ready directory whose streams all failed to
    // open is still degraded — getStats() must not report it as healthy.
    this.fileLoggingAvailable = transports.length > 0;

    // Symmetry with setupLogsDirectorySync's stderr warning: if the directory
    // was usable but every transport still failed to open, that degradation is
    // otherwise signalled only through getStats(). Surface it on stderr too.
    if (logDirReady && !this.fileLoggingAvailable) {
      SecurityLogger.warnToStderr(
        `SecurityLogger: no log transports could be opened in "${this.logDir}"; ` +
          `security audit logging is DISABLED.`
      );
    }

    this.logger = winston.createLogger({
      level: this._logLevel,
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json({ space: 2 })
      ),
      transports,
      // No usable file transport → suppress output entirely. A logger with
      // zero transports otherwise emits a noisy winston warning on every call.
      silent: transports.length === 0
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

  /**
   * Resolve the absolute log directory.
   * Resolution order: explicit option → LOG_DIR env → `<cwd>/logs`.
   */
  private static resolveLogDir(options: SecurityLoggerOptions): string {
    const fromOption =
      typeof options.logDir === 'string' ? options.logDir.trim() : '';
    const fromEnv = (process.env.LOG_DIR ?? '').trim();
    const explicit = fromOption.length > 0 ? fromOption : fromEnv;
    if (explicit.length > 0) {
      return path.resolve(explicit);
    }
    return path.resolve(process.cwd(), 'logs');
  }

  private createFileTransport(
    filename: string,
    level: string
  ): winston.transports.FileTransportInstance | null {
    try {
      const filePath = path.join(this.logDir, filename);
      const stream = fs.createWriteStream(filePath, {
        flags: 'a',
        encoding: 'utf8',
        mode: 0o666,
        autoClose: true,
        highWaterMark: 0
      });
      // A late write failure (disk full, perms revoked) surfaces as an async
      // 'error' event; without a handler that becomes an uncaught exception
      // that crashes the host. Record it (so the degraded state is observable
      // via getStats) rather than crash — losing a log line beats crashing.
      stream.on('error', (err: Error) => {
        // AUDIT-OK: see DESIGN DECISIONS #1 — logging must never crash the app.
        this.recordWriteError(err);
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
    } catch (_err) {
      // AUDIT-OK: one transport failing to open must not crash startup.
      return null;
    }
  }

  private setupLogsDirectorySync(): boolean {
    try {
      if (fs.existsSync(this.logDir)) {
        // A path that exists but is not a directory cannot hold log files;
        // treat it as unavailable so logging degrades cleanly to no-op rather
        // than reporting healthy while every write silently fails.
        if (!fs.statSync(this.logDir).isDirectory()) {
          SecurityLogger.warnToStderr(
            `SecurityLogger: log path "${this.logDir}" exists but is not a ` +
              `directory; security audit logging is DISABLED.`
          );
          return false;
        }
        return true;
      }
      fs.mkdirSync(this.logDir, { recursive: true });
      return true;
    } catch (_err) {
      // AUDIT-OK: log directory unavailable (e.g. unwritable cwd). Degrade to
      // no-op logging rather than crash — see DESIGN DECISIONS #1.
      SecurityLogger.warnToStderr(
        `SecurityLogger: log directory "${this.logDir}" is not writable ` +
          `(${(_err as Error)?.message ?? 'unknown error'}); ` +
          `security audit logging is DISABLED.`
      );
      return false;
    }
  }

  /**
   * Record an asynchronous log-write failure so the degraded state is
   * observable via getStats() instead of silently swallowed. Warns to stderr
   * on the first failure and then periodically while failures persist — a
   * sustained audit-logging outage (e.g. a full disk silencing the security
   * log, a classic anti-forensics move) must keep signalling, not go quiet
   * after one line, while still being throttled to avoid flooding stderr
   * (CWE-778).
   */
  private recordWriteError(err: Error): void {
    this.writeErrorCount++;
    this.lastWriteError = err?.message ?? 'unknown write error';
    if (
      this.writeErrorCount === 1 ||
      this.writeErrorCount % WRITE_ERROR_WARN_INTERVAL === 0
    ) {
      SecurityLogger.warnToStderr(
        `SecurityLogger: writing to log directory "${this.logDir}" failed ` +
          `(${this.lastWriteError}); ${this.writeErrorCount} write error(s) ` +
          `so far; security audit logging may be incomplete.`
      );
    }
  }

  /**
   * Emit an operator-facing diagnostic to stderr. stdout is reserved for the
   * MCP stdio protocol, so warnings must never go there. Never throws.
   */
  private static warnToStderr(message: string): void {
    try {
      process.stderr.write(`[mcp-secure-server] ${message}\n`);
    } catch {
      // AUDIT-OK: diagnostics must never crash the app — see DESIGN DECISIONS #1.
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
    for (const name of LOG_FILE_NAMES) {
      try {
        const fd = fs.openSync(path.join(this.logDir, name), 'a');
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
      // Actual runtime logging health — distinct from the enableLogging config
      // intent. False here means the audit trail is dark despite being enabled.
      fileLoggingAvailable: this.fileLoggingAvailable,
      writeErrors: this.writeErrorCount,
      lastWriteError: this.lastWriteError,
      logFiles: {
        decisions: path.join(this.logDir, LOG_FILE_NAMES[0]),
        blocks: path.join(this.logDir, LOG_FILE_NAMES[1]),
        performance: path.join(this.logDir, LOG_FILE_NAMES[2]),
        debug: path.join(this.logDir, LOG_FILE_NAMES[3])
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
      const reportPath = path.join(this.logDir, 'security-report.json');
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
    for (const name of LOG_FILE_NAMES) {
      const filePath = path.join(this.logDir, name);
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
