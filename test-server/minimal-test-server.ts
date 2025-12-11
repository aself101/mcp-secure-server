// minimal-test-server.ts - Uses SecureMcpServer for automatic transport-level security
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { SecureMcpServer } from "../src/index.js";
import { z } from "zod";
import * as fs from 'fs/promises';

class CleanDebugServerWithVerboseLogging {
    private server: SecureMcpServer;

    constructor() {
        // SecureMcpServer automatically wraps transport with security validation
        // No manual validateToolCall() needed - all messages validated at transport level

        this.server = new SecureMcpServer(
            {
                name: "clean-debug-server-verbose",
                version: "0.3.0"
            },
            {
                // Logging (opt-in)
                enableLogging: true,
                logLevel: 'debug',
                logPerformanceMetrics: true,
                verboseLogging: true,
                // Rate limits
                maxRequestsPerMinute: 30,
                maxRequestsPerHour: 300,
                burstThreshold: 5,
                // Tool registry for Layer 4
                toolRegistry: [
                    { name: 'debug-calculator', sideEffects: 'none', maxArgsSize: 1000 },
                    { name: 'debug-file-reader', sideEffects: 'read', maxArgsSize: 1000 },
                    { name: 'debug-echo', sideEffects: 'none', maxArgsSize: 2000 },
                    { name: 'debug-database', sideEffects: 'read', maxArgsSize: 2000 },
                    { name: 'debug-http', sideEffects: 'network', maxArgsSize: 2000 },
                    { name: 'debug-parser', sideEffects: 'none', maxArgsSize: 10000 },
                    { name: 'debug-image', sideEffects: 'read', maxArgsSize: 1000 }
                ],
                // Policy permissions for side effects
                defaultPolicy: {
                    allowNetwork: true,  // Enable for debug-http tool
                    allowWrites: false
                }
            }
        );

        this.setupTools();
    }

    private setupTools(): void {
        // Calculator tool - pure business logic, security handled at transport level
        this.server.tool(
            "debug-calculator",
            "Simple calculator for testing",
            {
                expression: z.string().max(50).describe("Math expression")
            },
            async ({ expression }) => {
                const safeExpression = expression.replace(/[^0-9+\-*/.() ]/g, '');
                if (safeExpression !== expression) {
                    return { content: [{ type: "text", text: "Error: Invalid characters in expression" }] };
                }

                const result = Function(`"use strict"; return (${safeExpression})`)();

                if (!isFinite(result)) {
                    return { content: [{ type: "text", text: "Error: Result is not a valid number" }] };
                }

                return { content: [{ type: "text", text: `${expression} = ${result}` }] };
            }
        );

        // File reader tool - pure business logic
        this.server.tool(
            "debug-file-reader",
            "File reader for testing",
            {
                path: z.string().max(200).describe("File path")
            },
            async ({ path }) => {
                try {
                    const content = await fs.readFile(path, 'utf-8');
                    return {
                        content: [{
                            type: "text",
                            text: `File: ${path}\n\n${content.substring(0, 1000)}${content.length > 1000 ? '...' : ''}`
                        }]
                    };
                } catch (error) {
                    const message = error instanceof Error ? error.message : 'Unknown error';
                    return { content: [{ type: "text", text: `File Error: ${message}` }] };
                }
            }
        );

        // Echo tool - pure business logic
        this.server.tool(
            "debug-echo",
            "Echo tool for testing",
            {
                text: z.string().max(500).describe("Text to echo back")
            },
            async ({ text }) => {
                return { content: [{ type: "text", text: `Echo: ${text}` }] };
            }
        );

        // Database tool - pure business logic (ORM-like approach)
        this.server.tool(
            "debug-database",
            "Mock database operations using safe predefined queries",
            {
                operation: z.enum(['getUsers', 'getUser', 'searchProducts', 'countOrders']).describe("Predefined safe operation"),
                params: z.record(z.string(), z.any()).optional().describe("Operation parameters")
            },
            async ({ operation, params }) => {
                const p = params as Record<string, unknown> ?? {};
                const operations: Record<string, () => string> = {
                    getUsers: () => {
                        const limit = Math.min((p.limit as number) || 10, 100);
                        return `Executed: Users.findMany({ take: ${limit} })\nResult: [Mock: 3 users returned]`;
                    },
                    getUser: () => {
                        const id = (p.id as number) || 1;
                        return `Executed: Users.findUnique({ where: { id: ${id} } })\nResult: [Mock: User #${id} found]`;
                    },
                    searchProducts: () => {
                        const term = (p.term as string) || '';
                        return `Executed: Products.search({ query: "${term}" })\nResult: [Mock: 5 products matching "${term}"]`;
                    },
                    countOrders: () => {
                        return `Executed: Orders.count({ where: { status: "completed" } })\nResult: [Mock: 42 orders]`;
                    }
                };

                const result = operations[operation]?.() || 'Unknown operation';
                return { content: [{ type: "text", text: `Database Operation: ${operation}\n\n${result}` }] };
            }
        );

        // HTTP tool - pure business logic with URL whitelisting
        this.server.tool(
            "debug-http",
            "Mock HTTP request with URL validation (whitelist pattern)",
            {
                url: z.string().max(500).describe("URL to request"),
                method: z.enum(['GET', 'POST']).optional().describe("HTTP method")
            },
            async ({ url, method = 'GET' }) => {
                try {
                    const allowedDomains = ['api.github.com', 'httpbin.org', 'jsonplaceholder.typicode.com', 'example.com'];
                    const urlObj = new URL(url);
                    const isWhitelisted = allowedDomains.some(domain => urlObj.hostname.endsWith(domain));

                    if (!isWhitelisted) {
                        return { content: [{ type: "text", text: `Domain not whitelisted. Allowed: ${allowedDomains.join(', ')}` }] };
                    }

                    return {
                        content: [{
                            type: "text",
                            text: `HTTP ${method} ${urlObj.hostname}${urlObj.pathname}\nStatus: 200 OK\nMock Response: {"status": "success", "data": "..."}`
                        }]
                    };
                } catch (error) {
                    const message = error instanceof Error ? error.message : 'Unknown error';
                    return { content: [{ type: "text", text: `HTTP Error: ${message}` }] };
                }
            }
        );

        // Parser tool - pure business logic
        this.server.tool(
            "debug-parser",
            "JSON/XML parser with size limits",
            {
                data: z.string().max(5000).describe("JSON or XML string to parse (max 5KB)"),
                format: z.enum(['json', 'xml']).describe("Data format")
            },
            async ({ data, format }) => {
                try {
                    let result: string;
                    if (format === 'json') {
                        const parsed = JSON.parse(data) as Record<string, unknown>;
                        const keyCount = Object.keys(parsed).length;
                        result = `Parsed JSON (${keyCount} keys)\nSample: ${JSON.stringify(parsed).substring(0, 200)}...`;
                    } else {
                        if (!data.trim().startsWith('<') || !data.includes('>')) {
                            return { content: [{ type: "text", text: "Error: Invalid XML format" }] };
                        }
                        result = `Parsed XML\nRoot element detected\nSample: ${data.substring(0, 200)}...`;
                    }
                    return { content: [{ type: "text", text: result }] };
                } catch (error) {
                    const message = error instanceof Error ? error.message : 'Unknown error';
                    return { content: [{ type: "text", text: `Parser Error: ${message}` }] };
                }
            }
        );

        // Image tool - pure business logic with path validation
        this.server.tool(
            "debug-image",
            "Mock image processing with directory restrictions",
            {
                operation: z.enum(['resize', 'thumbnail', 'convert']).describe("Image operation"),
                filename: z.string().max(100).describe("Image filename (no paths)"),
                params: z.string().max(50).optional().describe("Operation parameters")
            },
            async ({ operation, filename, params }) => {
                if (filename.includes('/') || filename.includes('\\') || filename.includes('..')) {
                    return { content: [{ type: "text", text: "Error: Filename cannot contain path separators" }] };
                }

                const allowedDir = 'uploads/images/';
                return {
                    content: [{
                        type: "text",
                        text: `Image ${operation}: ${allowedDir}${filename}\nParams: ${params || 'default'}\nResult: Mock processed successfully`
                    }]
                };
            }
        );
    }

    private async createTestData(): Promise<void> {
        try {
            await fs.mkdir('test-data', { recursive: true });
            await fs.mkdir('logs', { recursive: true });
            await fs.writeFile('test-data/clean-safe.txt',
                'This is a clean safe test file for debugging.\nVerbose logging captures all security decisions at transport level.'
            );
        } catch {
            // Fail silently to avoid console pollution
        }
    }

    async start(): Promise<SecureMcpServer> {
        await this.createTestData();
        const transport = new StdioServerTransport();
        await this.server.connect(transport);
        return this.server;
    }

    getSecurityStats() {
        return this.server.getSecurityStats();
    }

    async generateSecurityReport() {
        return this.server.generateSecurityReport();
    }
}

// Direct execution - NO console output to avoid JSON pollution
const isMainModule = import.meta.url === `file://${process.argv[1]}`;

if (isMainModule) {
    async function main() {
        const server = new CleanDebugServerWithVerboseLogging();
        await server.start();

        // Keep server running
        process.stdin.resume();
    }

    main().catch(error => {
        console.error(error);
        process.exit(1);
    });
}

export { CleanDebugServerWithVerboseLogging };
