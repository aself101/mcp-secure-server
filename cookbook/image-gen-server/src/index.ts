/**
 * Image Generation MCP Server
 * Unified interface for 5 image generation providers
 */

import 'dotenv/config';
import { SecureMcpServer } from 'mcp-secure-server';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import { generateImageSchema, generateImage } from './tools/generate.js';
import {
  editImageSchema, editImage,
  removeBackgroundSchema, removeBackground,
  replaceBackgroundSchema, replaceBackground
} from './tools/edit.js';
import {
  upscaleImageSchema, upscaleImage,
  createVariationSchema, createVariation
} from './tools/upscale.js';
import {
  listModelsSchema, listModels,
  describeImageSchema, describeImage
} from './tools/list-models.js';

const server = new SecureMcpServer(
  {
    name: 'image-gen-server',
    version: '1.0.0'
  },
  {
    // Security preset - standard for API-based image generation
    securityLevel: 'standard',
    enableLogging: true,
    verboseLogging: true,
    toolRegistry: [
      { name: 'generate-image', sideEffects: 'network', maxArgsSize: 5000 },
      { name: 'edit-image', sideEffects: 'network', maxArgsSize: 10000 },
      { name: 'upscale-image', sideEffects: 'network', maxArgsSize: 10000 },
      { name: 'create-variation', sideEffects: 'network', maxArgsSize: 10000 },
      { name: 'remove-background', sideEffects: 'network', maxArgsSize: 10000 },
      { name: 'replace-background', sideEffects: 'network', maxArgsSize: 10000 },
      { name: 'describe-image', sideEffects: 'network', maxArgsSize: 10000 },
      { name: 'list-models', sideEffects: 'none', maxArgsSize: 500 }
    ],
    defaultPolicy: {
      allowNetwork: true,
      allowWrites: false
    },
    maxRequestsPerMinute: 100,
    maxRequestsPerHour: 1000
  }
);

// Generate image - all providers
server.tool(
  'generate-image',
  'Generate images from text prompts using various AI providers (BFL, Google, Ideogram, OpenAI, Stability)',
  generateImageSchema.shape,
  async (args) => generateImage(args)
);

// === TOOL #3: edit-image ===
server.tool(
  'edit-image',
  'Edit an image using inpainting with an optional mask',
  editImageSchema.shape,
  async (args) => editImage(args)
);

// === TOOL #4: upscale-image ===
server.tool(
  'upscale-image',
  'Upscale an image to higher resolution',
  upscaleImageSchema.shape,
  async (args) => upscaleImage(args)
);

// === TOOL #5: create-variation ===
server.tool(
  'create-variation',
  'Create variations of an existing image (OpenAI DALL-E 2 only)',
  createVariationSchema.shape,
  async (args) => createVariation(args)
);

// === TOOL #6: remove-background ===
server.tool(
  'remove-background',
  'Remove the background from an image (Stability AI)',
  removeBackgroundSchema.shape,
  async (args) => removeBackground(args)
);

// === TOOL #7: replace-background ===
server.tool(
  'replace-background',
  'Replace the background of an image with a new one',
  replaceBackgroundSchema.shape,
  async (args) => replaceBackground(args)
);

// === TOOL #8: describe-image ===
server.tool(
  'describe-image',
  'Get a text description of an image (Ideogram)',
  describeImageSchema.shape,
  async (args) => describeImage(args)
);

// List models - all providers
server.tool(
  'list-models',
  'List available models for image generation',
  listModelsSchema.shape,
  async (args) => listModels(args)
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('Image Generation MCP Server running on stdio');
}

main().catch(console.error);
