/**
 * Geofencing Validator
 *
 * Restricts access based on geographic location (mock implementation).
 * In production, integrate with a real IP geolocation service.
 */

// Simple validation result type compatible with Layer 5
interface SimpleValidationResult {
  passed: boolean;
  severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  reason?: string;
  violationType?: string;
}

export interface GeofencingConfig {
  mode: 'allowlist' | 'blocklist';
  countries: string[];  // ISO 3166-1 alpha-2 codes
  mockLocation?: string; // For testing: 'US', 'CN', 'RU', etc.
}

interface ValidationContext {
  clientIp?: string;
  geoLocation?: {
    country: string;
    region?: string;
    city?: string;
  };
}

// Mock geolocation database for demo purposes
const MOCK_IP_LOCATIONS: Record<string, string> = {
  '192.168.1.1': 'US',
  '10.0.0.1': 'US',
  '8.8.8.8': 'US',
  '1.1.1.1': 'AU',
  '185.199.108.1': 'US',
  '31.13.24.1': 'IE',
  '203.0.113.1': 'CN',
  '198.51.100.1': 'RU',
  '185.220.100.1': 'DE',
};

export function getCountryFromIP(ip: string, mockLocation?: string): string {
  if (mockLocation) return mockLocation;
  return MOCK_IP_LOCATIONS[ip] || 'UNKNOWN';
}

export function createGeofencingValidator(config: GeofencingConfig) {
  return function geofencingValidator(
    _message: unknown,
    context: unknown
  ): SimpleValidationResult {
    const ctx = context as ValidationContext;

    // Determine country from context or mock
    let country: string;

    if (ctx.geoLocation?.country) {
      country = ctx.geoLocation.country;
    } else if (ctx.clientIp) {
      country = getCountryFromIP(ctx.clientIp, config.mockLocation);
    } else if (config.mockLocation) {
      country = config.mockLocation;
    } else {
      // No location info available - allow by default
      return { passed: true };
    }

    const isInList = config.countries.includes(country);

    if (config.mode === 'allowlist') {
      if (!isInList) {
        return {
          passed: false,
          severity: 'HIGH',
          reason: `Access denied: Country '${country}' not in allowlist`,
          violationType: 'GEOFENCING_VIOLATION'
        };
      }
    } else {
      // blocklist mode
      if (isInList) {
        return {
          passed: false,
          severity: 'HIGH',
          reason: `Access denied: Country '${country}' is blocked`,
          violationType: 'GEOFENCING_VIOLATION'
        };
      }
    }

    return { passed: true };
  };
}

export const COMMON_BLOCKLIST = ['CN', 'RU', 'KP', 'IR'];
export const US_ONLY_ALLOWLIST = ['US'];
export const WESTERN_ALLOWLIST = ['US', 'CA', 'GB', 'DE', 'FR', 'AU', 'NZ', 'IE', 'NL'];
