/**
 * API Wrapper MCP Server
 *
 * Demonstrates safe wrapping of third-party REST APIs with:
 * - Domain restrictions (Layer 5)
 * - Per-tool rate limiting (Layer 4)
 * - Response size limits (Layer 4)
 * - Input validation (Zod schemas)
 *
 * Uses free APIs that don't require authentication:
 * - Weather: Open-Meteo (https://open-meteo.com)
 * - Currency: Frankfurter (https://frankfurter.app)
 * - News: Hacker News API (https://hn.algolia.com)
 */

import 'dotenv/config';
import { SecureMcpServer } from 'mcp-secure-server';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import {
  weatherForecastSchema,
  weatherForecast,
  currencyConvertSchema,
  currencyConvert,
  newsHeadlinesSchema,
  newsHeadlines,
} from './tools/index.js';

// ============================================================================
// Security Configuration
// ============================================================================

const server = new SecureMcpServer(
  {
    name: 'api-wrapper-server',
    version: '1.0.0',
  },
  {
    // Security preset - standard for production API wrapper
    securityLevel: 'standard',
    // Logging configuration
    enableLogging: process.env.VERBOSE_LOGGING === 'true',
    verboseLogging: process.env.VERBOSE_LOGGING === 'true',

    // Tool registry with per-tool security policies
    toolRegistry: [
      {
        name: 'weather-forecast',
        sideEffects: 'network',
        maxArgsSize: 500,
        maxEgressBytes: 50 * 1024, // 50KB max response
        quotaPerMinute: 10, // Rate limit: 10 requests per minute
        quotaPerHour: 200,
      },
      {
        name: 'currency-convert',
        sideEffects: 'network',
        maxArgsSize: 200,
        maxEgressBytes: 10 * 1024, // 10KB max response
        quotaPerMinute: 5, // Rate limit: 5 requests per minute
        quotaPerHour: 100,
      },
      {
        name: 'news-headlines',
        sideEffects: 'network',
        maxArgsSize: 300,
        maxEgressBytes: 50 * 1024, // 50KB max response
        quotaPerMinute: 3, // Rate limit: 3 requests per minute
        quotaPerHour: 60,
      },
    ],

    // Default policy for all tools
    defaultPolicy: {
      allowNetwork: true,
      allowWrites: false,
    },

    // Global rate limits
    maxRequestsPerMinute: 30,
    maxRequestsPerHour: 500,
  }
);

// ============================================================================
// Tool Definitions
// ============================================================================

/**
 * Tool 1: weather-forecast
 * Fetches weather forecast for a city using Open-Meteo API
 * - Domain: api.open-meteo.com only
 * - Rate limit: 10/minute
 * - Max response: 50KB
 */
server.tool(
  'weather-forecast',
  'Get weather forecast for a city. Supports major world cities with 5-day forecasts including temperature, humidity, and conditions.',
  weatherForecastSchema.shape,
  async (args) => weatherForecast(args as Parameters<typeof weatherForecast>[0])
);

/**
 * Tool 2: currency-convert
 * Converts between currencies using Frankfurter API
 * - Domain: api.frankfurter.app only
 * - Rate limit: 5/minute
 * - Validates ISO 4217 currency codes
 */
server.tool(
  'currency-convert',
  'Convert between currencies using real-time exchange rates. Supports major world currencies with ISO 4217 codes.',
  currencyConvertSchema.shape,
  async (args) => currencyConvert(args as Parameters<typeof currencyConvert>[0])
);

/**
 * Tool 3: news-headlines
 * Fetches tech news from Hacker News API
 * - Domain: hn.algolia.com only
 * - Rate limit: 3/minute
 * - Strips HTML, limits to 10 articles
 */
server.tool(
  'news-headlines',
  'Get tech news headlines from Hacker News. Supports categories: front_page, ask_hn, show_hn, jobs. Optional search query.',
  newsHeadlinesSchema.shape,
  async (args) => newsHeadlines(args as Parameters<typeof newsHeadlines>[0])
);

// ============================================================================
// Server Startup
// ============================================================================

async function main() {
  const transport = new StdioServerTransport();
  // Type assertion needed due to MCP SDK version differences
  await server.connect(transport as Parameters<typeof server.connect>[0]);
  console.error('API Wrapper MCP Server running on stdio');
  console.error('Tools available: weather-forecast, currency-convert, news-headlines');
}

main().catch((error) => {
  console.error('Server failed to start:', error);
  process.exit(1);
});
