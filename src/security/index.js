/**
 * @fileoverview Security module exports for MCP servers.
 */

import { SecureMcpServer } from "./mcp-secure-server.js";
import { SecureTransport } from "./transport/index.js";
import ContextualValidationLayer, {
    ContextualConfigBuilder,
    createContextualLayer
} from "./layers/layer5-contextual.js";

export {
    SecureMcpServer,
    SecureTransport,
    // Layer 5 exports for advanced configuration
    ContextualValidationLayer,
    ContextualConfigBuilder,
    createContextualLayer
};
