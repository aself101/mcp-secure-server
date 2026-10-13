/**
 * Integration Tests for API Wrapper Server
 *
 * Tests that all tools execute successfully with valid inputs
 * and basic functionality works end-to-end.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
  weatherForecast,
  currencyConvert,
  newsHeadlines,
  weatherForecastSchema,
  currencyConvertSchema,
  newsHeadlinesSchema,
} from '../src/tools/index.js';

// These tests call live public APIs (open-meteo, frankfurter, hn.algolia). They
// run only with COOKBOOK_LIVE=1, so the cookbook release gate is deterministic
// offline; several of them would otherwise pass offline only because a failed
// fetch happens to produce the error shape they assert.
const live = it.skipIf(!process.env.COOKBOOK_LIVE);

describe('API Wrapper Server Integration Tests', () => {
  describe('weather-forecast tool', () => {
    live('should return weather data for a valid city', async () => {
      const result = await weatherForecast({
        city: 'London',
        units: 'metric',
      });

      expect(result.content).toHaveLength(1);
      expect(result.content[0].type).toBe('text');

      const data = JSON.parse(result.content[0].text);
      expect(data.city).toBe('London');
      expect(data.current).toBeDefined();
      expect(data.current.temperature).toMatch(/°C$/);
      expect(data.forecast).toBeInstanceOf(Array);
      expect(data.forecast.length).toBeGreaterThan(0);
    }, 15000);

    live('should return weather in imperial units', async () => {
      const result = await weatherForecast({
        city: 'New York',
        units: 'imperial',
      });

      const data = JSON.parse(result.content[0].text);
      expect(data.current.temperature).toMatch(/°F$/);
    }, 15000);

    live('should return error for unknown city', async () => {
      const result = await weatherForecast({
        city: 'UnknownCityXYZ123',
        units: 'metric',
      });

      const data = JSON.parse(result.content[0].text);
      expect(data.error).toBe('City not found');
    });

    it('should validate schema correctly', () => {
      const validInput = { city: 'Paris', units: 'metric' as const };
      expect(() => weatherForecastSchema.parse(validInput)).not.toThrow();

      const invalidUnits = { city: 'Paris', units: 'kelvin' };
      expect(() => weatherForecastSchema.parse(invalidUnits)).toThrow();
    });
  });

  describe('currency-convert tool', () => {
    live('should convert USD to EUR', async () => {
      const result = await currencyConvert({
        from: 'USD',
        to: 'EUR',
        amount: 100,
      });

      expect(result.content).toHaveLength(1);
      const data = JSON.parse(result.content[0].text);
      expect(data.from).toBe('USD');
      expect(data.to).toBe('EUR');
      expect(data.amount).toBe(100);
      expect(data.result).toBeGreaterThan(0);
      expect(data.rate).toBeGreaterThan(0);
    }, 15000);

    live('should handle same currency conversion', async () => {
      const result = await currencyConvert({
        from: 'USD',
        to: 'USD',
        amount: 100,
      });

      const data = JSON.parse(result.content[0].text);
      expect(data.result).toBe(100);
      expect(data.rate).toBe(1);
    });

    live('should reject invalid currency code', async () => {
      const result = await currencyConvert({
        from: 'XXX',
        to: 'EUR',
        amount: 100,
      });

      const data = JSON.parse(result.content[0].text);
      expect(data.error).toBe('Invalid currency code');
    });

    it('should validate schema correctly', () => {
      const validInput = { from: 'USD', to: 'EUR', amount: 100 };
      expect(() => currencyConvertSchema.parse(validInput)).not.toThrow();

      const invalidAmount = { from: 'USD', to: 'EUR', amount: -100 };
      expect(() => currencyConvertSchema.parse(invalidAmount)).toThrow();

      const tooLargeAmount = { from: 'USD', to: 'EUR', amount: 10000000000 };
      expect(() => currencyConvertSchema.parse(tooLargeAmount)).toThrow();
    });
  });

  describe('news-headlines tool', () => {
    live('should return front page news', async () => {
      const result = await newsHeadlines({
        category: 'front_page',
        limit: 5,
      });

      expect(result.content).toHaveLength(1);
      const data = JSON.parse(result.content[0].text);
      expect(data.category).toBe('front_page');
      expect(data.articles).toBeInstanceOf(Array);
      expect(data.articles.length).toBeLessThanOrEqual(5);
    }, 15000);

    live('should search for specific topics', async () => {
      const result = await newsHeadlines({
        category: 'front_page',
        query: 'javascript',
        limit: 5,
      });

      const data = JSON.parse(result.content[0].text);
      expect(data.query).toBe('javascript');
    }, 15000);

    live('should enforce max limit of 10', async () => {
      const result = await newsHeadlines({
        category: 'front_page',
        limit: 10,
      });

      const data = JSON.parse(result.content[0].text);
      expect(data.articles.length).toBeLessThanOrEqual(10);
    }, 15000);

    it('should validate schema correctly', () => {
      const validInput = { category: 'ask_hn' as const, limit: 5 };
      expect(() => newsHeadlinesSchema.parse(validInput)).not.toThrow();

      const invalidCategory = { category: 'invalid' };
      expect(() => newsHeadlinesSchema.parse(invalidCategory)).toThrow();

      const tooManyArticles = { category: 'front_page' as const, limit: 100 };
      expect(() => newsHeadlinesSchema.parse(tooManyArticles)).toThrow();
    });
  });

  describe('Response format', () => {
    live('should return proper MCP content format', async () => {
      const result = await weatherForecast({ city: 'Tokyo', units: 'metric' });

      expect(result).toHaveProperty('content');
      expect(Array.isArray(result.content)).toBe(true);
      expect(result.content[0]).toHaveProperty('type', 'text');
      expect(result.content[0]).toHaveProperty('text');
    }, 15000);
  });
});
