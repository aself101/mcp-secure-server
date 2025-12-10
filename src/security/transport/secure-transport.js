/**
 * @fileoverview Transport wrapper that validates all MCP messages before delivery.
 * Intercepts onmessage to run security validation, blocking malicious requests
 * with proper JSON-RPC error responses.
 */

export class SecureTransport {
    /**
     * @param {object} transport - MCP transport to wrap
     * @param {function} validator - Async function (message, context) => validationResult
     * @param {object} [options] - Optional configuration
     * @param {object} [options.errorSanitizer] - ErrorSanitizer instance for response sanitization
     */
    constructor(transport, validator, options = {}) {
        this._transport = transport;
        this._validator = validator;
        this._errorSanitizer = options.errorSanitizer || null;
        this._protocolOnMessage = null;
        this._protocolOnError = null;
        this._protocolOnClose = null;

        this._setupTransportCallbacks();
    }

    _setupTransportCallbacks() {
        this._transport.onmessage = (message, extra) => {
            return this._handleMessage(message, extra);
        };

        this._transport.onerror = (error) => {
            if (this._protocolOnError) {
                this._protocolOnError(error);
            }
        };

        this._transport.onclose = () => {
            if (this._protocolOnClose) {
                this._protocolOnClose();
            }
        };
    }

    async _handleMessage(message, extra) {
        const messageType = this._getMessageType(message);

        if (messageType === 'response') {
            this._forwardToProtocol(message, extra);
            return;
        }

        const validationResult = await this._validateMessage(message);

        if (!validationResult.allowed) {
            if (messageType === 'request') {
                await this._sendBlockedResponse(message.id, validationResult);
            }
            return;
        }

        this._forwardToProtocol(message, extra);
    }

    _getMessageType(message) {
        if (message.method !== undefined && message.id !== undefined) {
            return 'request';
        }
        if (message.method !== undefined && message.id === undefined) {
            return 'notification';
        }
        if (message.id !== undefined && (message.result !== undefined || message.error !== undefined)) {
            return 'response';
        }
        return 'unknown';
    }

    async _validateMessage(message) {
        try {
            const context = {
                timestamp: Date.now(),
                transportLevel: true
            };
            return await this._validator(message, context);
        } catch (_error) {
            return {
                allowed: false,
                passed: false,
                reason: 'Validation error',
                severity: 'CRITICAL',
                violationType: 'VALIDATION_ERROR'
            };
        }
    }

    async _sendBlockedResponse(requestId, validationResult) {
        let errorResponse;

        if (this._errorSanitizer) {
            errorResponse = this._errorSanitizer.createSanitizedErrorResponse(
                requestId,
                validationResult.reason || 'Request blocked by security policy',
                validationResult.severity || 'HIGH',
                validationResult.violationType || 'POLICY_VIOLATION'
            );
        } else {
            errorResponse = {
                jsonrpc: '2.0',
                id: requestId,
                error: {
                    code: -32602,
                    message: validationResult.reason || 'Request blocked by security policy'
                }
            };
        }

        try {
            await this._transport.send(errorResponse);
        } catch (error) {
            if (this._protocolOnError) {
                this._protocolOnError(new Error(`Failed to send blocked response: ${error.message}`));
            }
        }
    }

    _forwardToProtocol(message, extra) {
        if (this._protocolOnMessage) {
            this._protocolOnMessage(message, extra);
        }
    }

    get onmessage() {
        return this._protocolOnMessage;
    }

    set onmessage(handler) {
        this._protocolOnMessage = handler;
    }

    get onerror() {
        return this._protocolOnError;
    }

    set onerror(handler) {
        this._protocolOnError = handler;
    }

    get onclose() {
        return this._protocolOnClose;
    }

    set onclose(handler) {
        this._protocolOnClose = handler;
    }

    async start() {
        return this._transport.start();
    }

    async close() {
        return this._transport.close();
    }

    async send(message, options) {
        return this._transport.send(message, options);
    }

    get sessionId() {
        return this._transport.sessionId;
    }
}
