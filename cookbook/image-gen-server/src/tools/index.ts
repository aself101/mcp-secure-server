/**
 * Tool exports for Image Generation server
 */

export { generateImageSchema, generateImage } from './generate.js';

export {
  editImageSchema,
  editImage,
  removeBackgroundSchema,
  removeBackground,
  replaceBackgroundSchema,
  replaceBackground,
} from './edit.js';

export {
  upscaleImageSchema,
  upscaleImage,
} from './upscale.js';

export {
  listModelsSchema,
  listModels,
  describeImageSchema,
  describeImage,
} from './list-models.js';
