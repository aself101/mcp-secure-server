// security-logger.js - Enhanced with detailed security decision logging and buffering fixes
import winston from 'winston';
import fs from 'fs';
import path from 'path';
import { LOGGING } from '../constants.js';

class SecurityLogger {
    constructor(options = {}) {
        this.options = options;
        this.logLevel = options.logLevel || 'debug';
    
        this.setupLogsDirectorySync();
        
        this.streams = new Map();
            
        this.logger = winston.createLogger({
            level: this.logLevel,
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
    
    createFileTransport(filename, level) {
        const filePath = path.resolve(process.cwd(), 'logs', filename); 
        const stream = fs.createWriteStream(filePath, {
            flags: 'a',
            encoding: 'utf8',
            fd: null,
            mode: 0o666,
            autoClose: true,
            highWaterMark: 0
        });
        this.streams.set(filename, stream);
        
        return new winston.transports.File({ 
            filename: filePath,
            level: level,
            options: { 
                flags: 'a',
                highWaterMark: 0 
            },
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
    
    setupLogsDirectorySync() {
        try {
            if (!fs.existsSync('logs')) {
                fs.mkdirSync('logs', { recursive: true });
            }
        } catch (error) {
            throw error;
        }
    }
    
    setupExitHandlers() {
        const gracefulExit = async (signal) => {
            await this.forceFlush();
            process.exit(0);
        };

        process.on('SIGINT', () => gracefulExit('SIGINT'));
        process.on('SIGTERM', () => gracefulExit('SIGTERM'));
        process.on('exit', () => {
            try {
                for (const [filename, stream] of this.streams) {
                    if (stream && stream.flush) {
                        stream.flush();
                    }
                    if (stream && stream.fd !== null && stream.fd !== undefined) {
                        fs.fsyncSync(stream.fd);
                    }
                }
            } catch (err) {
                // Silent fail on exit - logging system is shutting down
            }
        });
    }
    
    nextRequestId() {
        this.requestCount++;
        return this.requestCount;
    }
    
    testLogger() {
        try {
            this.logger.info('ENHANCED_LOGGER_INITIALIZATION', {
                event: 'LOGGER_INIT',
                message: 'Enhanced security logger with verbose decision tracking',
                timestamp: new Date().toISOString(),
                level: this.logLevel,
                features: ['verbose_decisions', 'attack_analysis', 'performance_tracking']
            });
        } catch (error) {
            // Silent fail - logger initialization should not crash the application
        }
    }
    
    logRequest(message, context = {}) {
        this.requestCount++;
        
        const logData = {
            event: 'MCP_REQUEST',
            requestId: this.requestCount,
            method: message.method,
            timestamp: new Date().toISOString(),
            messageSize: JSON.stringify(message).length,
            hasParams: !!message.params,
            paramCount: message.params ? Object.keys(message.params).length : 0,
            context,
            messagePreview: (context?.canonical ?? JSON.stringify(message))
                                                    .substring(0, 300) + '...'
        };
        
        try {
            this.logger.info('MCP_REQUEST', logData);
            this.forceFlush().catch(() => {});
        } catch (error) {
            // Silent fail - request logging should not crash the application
        }
    }
    
    logInfo(message) {
        this.requestCount++;
        
        const logData = {
            event: 'LOG_INFO',
            requestId: this.requestCount,
            message
        };
        
        try {
            this.logger.debug('LOG_INFO', logData);
        } catch (error) {
            // Silent fail
        }
    }
    
    async logSecurityDecision(decision, message, layer) {
        const isBlocked = !decision.passed && !decision.allowed;
        
        if (isBlocked) this.blockCount++;
        
        const layerName = decision.layerName || layer;
        if (!this.layerStats.has(layerName)) {
            this.layerStats.set(layerName, { passed: 0, blocked: 0 });
        }
        const stats = this.layerStats.get(layerName);
        isBlocked ? stats.blocked++ : stats.passed++;
        
        const logData = {
            event: 'SECURITY_DECISION',
            requestId: this.requestCount,
            timestamp: new Date().toISOString(),
            layer: layerName,
            decision: isBlocked ? 'BLOCK' : 'ALLOW',
            passed: decision.passed,
            allowed: decision.allowed,
            severity: decision.severity || 'UNKNOWN',
            violationType: decision.violationType || 'NONE',
            reason: decision.reason || 'No reason provided',
            confidence: decision.confidence || 0,
            method: message.method,
            messageSize: JSON.stringify(message).length,
            ...(isBlocked && {
                attackAnalysis: {
                    attackType: decision.violationType,
                    riskLevel: decision.severity,
                    detectionLayer: layerName,
                    mitigationAction: 'REQUEST_BLOCKED'
                }
            }),    
            validationTime: decision.validationTime || 0,
            messagePreview: JSON.stringify(message).substring(0, 200) + '...',
            sessionStats: {
                totalRequests: this.requestCount,
                totalBlocked: this.blockCount,
                blockRate: ((this.blockCount / this.requestCount) * 100).toFixed(2) + '%'
            }
        };
        
        try {
            if (isBlocked) {
                this.logger.warn('SECURITY_BLOCK', logData);
                await this.forceFlush();
            } else {
                this.logger.info('SECURITY_ALLOW', logData);
                this.forceFlush().catch(() => {});
            }
        } catch (error) {
            // Silent fail - decision logging should not crash the application
        }
    }
    
    logPerformance(startTime, endTime, message) {
        const duration = endTime - startTime;
        const logData = {
            event: 'PERFORMANCE_METRIC',
            requestId: this.requestCount,
            method: message.method,
            timestamp: new Date().toISOString(),
            validationDuration: duration,
            performanceCategory: duration < 5 ? 'FAST' : duration < 20 ? 'ACCEPTABLE' : 'SLOW',
            thresholds: {
                fast: duration < 5,
                acceptable: duration < 20,
                slow: duration >= 20,
                critical: duration >= 50
            },
            messageSize: JSON.stringify(message).length,
            memoryUsage: process.memoryUsage(),
            uptime: process.uptime()
        };
        
        try {
            this.logger.debug('PERFORMANCE_ENHANCED', logData);
            this.forceFlush().catch(() => {});
        } catch (error) {
            // Silent fail
        }
    }
    
    getStats() {
        const stats = {
            totalRequests: this.requestCount,
            totalBlocked: this.blockCount,
            totalAllowed: this.requestCount - this.blockCount,
            blockRate: this.requestCount > 0 ? 
                (this.blockCount / this.requestCount * 100).toFixed(2) : 
                '0.00',
            passRate: this.requestCount > 0 ? 
                ((this.requestCount - this.blockCount) / this.requestCount * 100).toFixed(2) : 
                '100.00',
            layerStats: Object.fromEntries(this.layerStats),
            logLevel: this.logLevel,
            logFiles: {
                decisions: 'logs/security-decisions.log',
                blocks: 'logs/security-blocks.log', 
                performance: 'logs/performance.log',
                debug: 'logs/security-debug.log'
            }
        };
        
        try {
            this.logger.info('ENHANCED_SECURITY_STATS', {
                event: 'STATS_REPORT',
                timestamp: new Date().toISOString(),
                stats
            });
        } catch (error) {
            // Silent fail
        }
        
        return stats;
    }
    
    async generateReport() {
        const stats = this.getStats();
        const report = {
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
        } catch (error) {
            // Silent fail - report generation should not crash the application
        }
        return report;
    }
    
    generateRecommendations(stats) {
        const recommendations = [];

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
    
    verifyLogFiles() {
        const logFiles = [
            'logs/security-decisions.log',
            'logs/security-blocks.log',
            'logs/performance.log',
            'logs/security-debug.log'
        ];

        const results = {};
        for (const filePath of logFiles) {
            try {
                if (fs.existsSync(filePath)) {
                    const stats = fs.statSync(filePath);
                    results[filePath] = { exists: true, size: stats.size };
                } else {
                    results[filePath] = { exists: false };
                }
            } catch (error) {
                results[filePath] = { exists: false, error: error.message };
            }
        }
        return results;
    }
    
    async forceFlush() {
        try {
            for (const transport of this.logger.transports) {
                if (transport.flush) {
                    await new Promise(resolve => transport.flush(resolve));
                }
            }
            for (const [filename, stream] of this.streams) {
                if (stream && stream.flush) {
                    stream.flush();
                }
                if (stream && stream.fd !== null && stream.fd !== undefined) {
                    fs.fsyncSync(stream.fd);
                }
            }

            const logFiles = [
                'logs/security-decisions.log',
                'logs/security-blocks.log',
                'logs/performance.log',
                'logs/security-debug.log'
            ];

            for (const file of logFiles) {
                try {
                    const fd = fs.openSync(file, 'a');
                    fs.fsyncSync(fd);
                    fs.closeSync(fd);
                } catch (err) {
                    // Silent fail - file may not exist yet
                }
            }
        } catch (error) {
            // Silent fail - flush errors should not crash the application
        }
    }
    
    async flush() {
        return this.forceFlush();
    }
}

export { SecurityLogger };