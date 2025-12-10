/**
 * @fileoverview SecureMcpServer - Unified secure MCP server with built-in validation.
 * Consolidates MCPSecurityMiddleware, EnhancedMCPSecurityMiddleware, and SecureMcpServer.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { ValidationPipeline } from "./utils/validation-pipeline.js";
import { LIMITS, RATE_LIMITS } from './constants.js';
import StructureValidationLayer from "./layers/layer1-structure.js";
import ContentValidationLayer from "./layers/layer2-content.js";
import BehaviorValidationLayer from "./layers/layer3-behavior.js";
import SemanticsValidationLayer from "./layers/layer4-semantics.js";
import { InMemoryQuotaProvider } from "./layers/layer-utils/semantics/semantic-quotas.js";
import { defaultToolRegistry, defaultResourcePolicy } from "./utils/tool-registry.js";
import { ErrorSanitizer } from "./utils/error-sanitizer.js";
import { SecureTransport } from "./transport/index.js";
import { SecurityLogger } from "./utils/security-logger.js";

/**
 * Unified secure MCP server with built-in transport-level security validation.
 * All incoming messages are validated before reaching handlers.
 *
 * Logging is opt-in (quiet by default for production).
 */
class SecureMcpServer {
    /**
     * @param {object} serverInfo - Server name and version info
     * @param {object} [options] - Configuration options
     * @param {object} [options.server] - McpServer options passed to underlying SDK
     * @param {number} [options.maxMessageSize] - Maximum message size in bytes
     * @param {number} [options.maxRequestsPerMinute] - Rate limit per minute
     * @param {number} [options.maxRequestsPerHour] - Rate limit per hour
     * @param {number} [options.burstThreshold] - Max requests in 10-second window
     * @param {boolean} [options.enableLogging=false] - Enable security logging (opt-in)
     * @param {boolean} [options.verboseLogging=false] - Enable verbose decision logs
     * @param {boolean} [options.logPerformanceMetrics=false] - Enable timing stats
     * @param {string} [options.logLevel='info'] - Log level when logging enabled
     * @param {object} [options.toolRegistry] - Custom tool registry for Layer 4
     * @param {object} [options.resourcePolicy] - Custom resource policy for Layer 4
     */
    constructor(serverInfo, options = {}) {
        this._serverInfo = serverInfo;
        this._options = {
            // Limits
            maxMessageSize: options.maxMessageSize || LIMITS.MESSAGE_SIZE_MAX,
            maxRequestsPerMinute: options.maxRequestsPerMinute || RATE_LIMITS.REQUESTS_PER_MINUTE,
            maxRequestsPerHour: options.maxRequestsPerHour || RATE_LIMITS.REQUESTS_PER_HOUR,
            burstThreshold: options.burstThreshold || RATE_LIMITS.BURST_THRESHOLD,
            // Logging (OPT-IN - quiet by default)
            enableLogging: options.enableLogging || false,
            verboseLogging: options.verboseLogging || false,
            logPerformanceMetrics: options.logPerformanceMetrics || false,
            logLevel: options.logLevel || 'info',
            // Default policy for side effects (restrictive by default)
            defaultPolicy: options.defaultPolicy || {
                allowNetwork: false,
                allowWrites: false
            },
            ...options
        };

        // Core MCP server
        this._mcpServer = new McpServer(serverInfo, options.server || {});

        // Security components
        this._validationPipeline = this._createValidationPipeline(options);
        this._errorSanitizer = new ErrorSanitizer(ErrorSanitizer.createProductionConfig());

        // Optional logging (only created if enabled)
        this._securityLogger = this._options.enableLogging
            ? new SecurityLogger({ logLevel: this._options.logLevel })
            : null;

        // State tracking
        this._wrappedTransport = null;
        this._startTime = Date.now();
        this._requestHistory = [];
        this._requestIdByJsonrpcId = new Map();
    }

    /**
     * Create the 4-layer validation pipeline
     */
    _createValidationPipeline(options) {
        return new ValidationPipeline([
            new StructureValidationLayer({
                maxMessageSize: options.maxMessageSize || LIMITS.MESSAGE_SIZE_MAX,
                maxParamCount: LIMITS.PARAM_COUNT_MAX,
                maxStringLength: LIMITS.STRING_LENGTH_MAX
            }),
            new ContentValidationLayer(),
            new BehaviorValidationLayer({
                requestsPerMinute: options.maxRequestsPerMinute || RATE_LIMITS.REQUESTS_PER_MINUTE,
                requestsPerHour: options.maxRequestsPerHour || RATE_LIMITS.REQUESTS_PER_HOUR,
                burstThreshold: options.burstThreshold || RATE_LIMITS.BURST_THRESHOLD
            }),
            new SemanticsValidationLayer({
                toolRegistry: options.toolRegistry || defaultToolRegistry(),
                resourcePolicy: options.resourcePolicy || defaultResourcePolicy(),
                methodSpec: options.methodSpec,
                chainingRules: options.chainingRules,
                quotas: options.quotas,
                quotaProvider: options.quotaProvider || new InMemoryQuotaProvider({
                    clockSkewMs: options.clockSkewMs || 1000
                }),
                maxSessions: options.maxSessions || 5000,
                sessionTtlMs: options.sessionTtlMs || 30 * 60_000
            })
        ]);
    }

    // ==================== McpServer Delegation ====================

    async connect(transport) {
        this._wrappedTransport = this._wrapTransport(transport);
        return this._mcpServer.connect(this._wrappedTransport);
    }

    async close() {
        return this._mcpServer.close();
    }

    isConnected() {
        return this._mcpServer.isConnected();
    }

    tool(name, ...rest) {
        return this._mcpServer.tool(name, ...rest);
    }

    registerTool(name, config, callback) {
        return this._mcpServer.registerTool(name, config, callback);
    }

    resource(name, uriOrTemplate, ...rest) {
        return this._mcpServer.resource(name, uriOrTemplate, ...rest);
    }

    registerResource(name, uriOrTemplate, config, callback) {
        return this._mcpServer.registerResource(name, uriOrTemplate, config, callback);
    }

    prompt(name, ...rest) {
        return this._mcpServer.prompt(name, ...rest);
    }

    registerPrompt(name, config, callback) {
        return this._mcpServer.registerPrompt(name, config, callback);
    }

    async sendLoggingMessage(params, sessionId) {
        return this._mcpServer.sendLoggingMessage(params, sessionId);
    }

    sendResourceListChanged() {
        return this._mcpServer.sendResourceListChanged();
    }

    sendToolListChanged() {
        return this._mcpServer.sendToolListChanged();
    }

    sendPromptListChanged() {
        return this._mcpServer.sendPromptListChanged();
    }

    get server() {
        return this._mcpServer.server;
    }

    get mcpServer() {
        return this._mcpServer;
    }

    get validationPipeline() {
        return this._validationPipeline;
    }

    // ==================== Transport Wrapping ====================

    /**
     * Wraps a transport with security validation at the message level.
     * @param {object} transport - MCP transport (StdioServerTransport, etc.)
     * @returns {SecureTransport} Wrapped transport with security validation
     */
    _wrapTransport(transport) {
        const validator = async (message, context) => {
            const startTime = this._options.logPerformanceMetrics ? performance.now() : 0;
            const normalizedMessage = this._normalizeRequest(message);

            // Optional logging
            if (this._securityLogger) {
                let internalId = this._requestIdByJsonrpcId.get(normalizedMessage.id);
                if (!internalId) {
                    internalId = this._securityLogger.nextRequestId();
                    this._requestIdByJsonrpcId.set(normalizedMessage.id, internalId);
                }

                this._securityLogger.logRequest(normalizedMessage, {
                    timestamp: context.timestamp || Date.now(),
                    source: 'transport-level',
                    requestSize: JSON.stringify(message).length,
                    pipelineLayers: this._validationPipeline.getLayers(),
                    requestId: internalId
                });
            }

            // Run validation pipeline
            const result = await this._validationPipeline.validate(normalizedMessage, {
                timestamp: context.timestamp || Date.now(),
                transportLevel: true,
                originalMessage: message,
                logger: this._securityLogger,
                verbose: this._options.verboseLogging,
                requestId: normalizedMessage.id,
                policy: this._options.defaultPolicy
            });

            // Performance tracking
            if (this._options.logPerformanceMetrics && this._securityLogger) {
                const endTime = performance.now();
                result.validationTime = endTime - startTime;
                this._securityLogger.logPerformance(startTime, endTime, normalizedMessage);
            }

            // Log decision
            if (this._securityLogger) {
                this._securityLogger.logSecurityDecision(result, normalizedMessage, 'Transport');
            }

            this._trackRequest(normalizedMessage);
            return result;
        };

        return new SecureTransport(transport, validator, {
            errorSanitizer: this._errorSanitizer
        });
    }

    // ==================== Request Normalization ====================

    /**
     * Normalize different request formats into consistent structure
     * Handles: JSON-RPC messages, SDK request objects, HTTP requests
     */
    _normalizeRequest(request) {
        // Case 1: Already a JSON-RPC message
        if (request.jsonrpc && request.method) {
            return request;
        }

        // Case 2: Official SDK request object (CallToolRequest, etc.)
        if (request.method && request.params) {
            return {
                jsonrpc: "2.0",
                method: this._mapSdkMethod(request.method, request.params),
                params: request.params,
                id: request.id || Math.random().toString(36)
            };
        }

        // Case 3: HTTP request body
        if (request.body && typeof request.body === 'object') {
            return request.body;
        }

        // Case 4: Raw object - convert to JSON-RPC format
        return {
            jsonrpc: "2.0",
            method: request.method || "unknown",
            params: request.params || request,
            id: request.id || Math.random().toString(36)
        };
    }

    /**
     * Map SDK-specific request types to MCP methods
     */
    _mapSdkMethod(method, params) {
        const methodMap = {
            'tools/call': 'tools/call',
            'tools/list': 'tools/list',
            'resources/read': 'resources/read',
            'resources/list': 'resources/list',
            'prompts/get': 'prompts/get',
            'prompts/list': 'prompts/list',
            'initialize': 'initialize',
            'ping': 'ping'
        };
        return methodMap[method] || method;
    }

    _trackRequest(message) {
        this._requestHistory.push({
            timestamp: Date.now(),
            method: message.method,
            hasParams: !!message.params,
            messageSize: JSON.stringify(message).length
        });

        // Keep only recent history to prevent memory leaks
        if (this._requestHistory.length > 1000) {
            this._requestHistory = this._requestHistory.slice(-500);
        }
    }

    // ==================== Stats & Reporting ====================

    /**
     * Get security stats from all layers
     */
    getSecurityStats() {
        const behaviorLayer = this._validationPipeline.layers.find(
            layer => layer.constructor.name === 'BehaviorValidationLayer'
        );

        return {
            server: {
                uptime: Date.now() - this._startTime,
                totalLayers: this._validationPipeline.layers.length,
                enabledLayers: this._validationPipeline.layers.filter(l => l.isEnabled()).length,
                loggingEnabled: this._options.enableLogging
            },
            behaviorLayer: behaviorLayer ? behaviorLayer.getStats() : null,
            ...(this._securityLogger ? { logger: this._securityLogger.getStats() } : {})
        };
    }

    /**
     * Get verbose security report (requires logging enabled)
     */
    getVerboseSecurityReport() {
        if (!this._securityLogger) {
            return { error: 'Logging not enabled. Set enableLogging: true in options.' };
        }
        return this._securityLogger.getStats();
    }

    /**
     * Generate security report (requires logging enabled)
     */
    async generateSecurityReport() {
        if (!this._securityLogger) {
            return { error: 'Logging not enabled. Set enableLogging: true in options.' };
        }
        return await this._securityLogger.generateReport();
    }

    /**
     * Graceful shutdown with optional final report
     */
    async shutdown() {
        let finalReport = null;

        if (this._securityLogger) {
            finalReport = await this._securityLogger.generateReport();
            await this._securityLogger.flush();
        }

        // Cleanup behavior layer timers
        const behaviorLayer = this._validationPipeline.layers.find(
            layer => layer.constructor.name === 'BehaviorValidationLayer'
        );
        if (behaviorLayer && behaviorLayer.cleanup) {
            behaviorLayer.cleanup();
        }

        await this.close();
        return finalReport;
    }
}

export { SecureMcpServer };
