// Buffer overflow, data validation, encoding, secrets, CSS, and SVG patterns
/* eslint-disable no-useless-escape */

export const bufferOverflow = {
  repeatedChars: [
    { pattern: /A{500,}/g, name: 'Repeated A Characters', severity: 'CRITICAL' },
    { pattern: /X{500,}/g, name: 'Repeated X Characters', severity: 'CRITICAL' },
    { pattern: /0{1000,}/g, name: 'Repeated Zero Characters', severity: 'CRITICAL' },
    { pattern: /%{100,}/g, name: 'Repeated Percent Characters', severity: 'HIGH' }
  ],
  formatStrings: [
    { pattern: /[\x25][\x6E]{3,}/g, name: 'Format String %nnn (canonical)', severity: 'CRITICAL' },
    { pattern: /[\x25][\x73]{3,}/g, name: 'Format String %sss (canonical)', severity: 'HIGH' },
    { pattern: /[\x25][\x78]{3,}/g, name: 'Format String %xxx (canonical)', severity: 'HIGH' },
    { pattern: /[\x25][\x70]{3,}/g, name: 'Format String %ppp (canonical)', severity: 'HIGH' },
    { pattern: /%n{3,}/g, name: 'Format String %n (pre-canonical)', severity: 'CRITICAL' },
    { pattern: /%s{3,}/g, name: 'Format String %s (pre-canonical)', severity: 'HIGH' },
    { pattern: /%x{3,}/g, name: 'Format String %x (pre-canonical)', severity: 'HIGH' },
    { pattern: /%p{3,}/g, name: 'Format String %p (pre-canonical)', severity: 'HIGH' }
  ],
  nopSleds: [
    { pattern: /[\x90]{12,}/g, name: 'NOP Sled (12+ bytes)', severity: 'HIGH' },
    { pattern: /(?:\\x90){12,}/g, name: 'Escaped NOP Sled (12+)', severity: 'HIGH' },
    { pattern: /(?:%90){12,}/gi, name: 'URL-Encoded NOP Sled (12+)', severity: 'HIGH' },
    { pattern: /(?:\\\\x90){12,}/g, name: 'Double-Escaped NOP Sled (12+)', severity: 'HIGH' },
    { pattern: /[\x90]{6,}[\x31\x50\x68\xc0\xff\xeb\xe8\xe9]{6,}/g, name: 'Mixed Shellcode (Raw Bytes)', severity: 'CRITICAL' },
    { pattern: /[\x31\x50\x68\xc0\xff\xeb\xe8\xe9]{8,}/g, name: 'Opcode Density (Raw)', severity: 'HIGH' },
    { pattern: /(?:\\x(?:31|50|68|c0|ff|eb|e8|e9)){8,}/gi, name: 'Opcode Density (Escaped)', severity: 'HIGH' }
  ]
};

export const dataValidation = {
  testCredentials: [
    // Note: Removed overly-aggressive "Default Username" pattern that blocked legitimate client names
    // like "test" in clientInfo.name. Pattern /^(admin|root|test|demo|guest)$/i was too strict.
    { pattern: /(?:username|user|login)\s*[:=]\s*["']?(admin|root|test|demo|guest)["']?/i, name: 'Default Username in Field', severity: 'MEDIUM' },
    { pattern: /test123|admin123|password123|user123|demo123/i, name: 'Test Credentials', severity: 'MEDIUM' },
    { pattern: /(?:password|passwd|pwd)\s*[:=]\s*["']?(123456|password|qwerty|abc123|letmein)["']?/i, name: 'Weak Password in Field', severity: 'LOW' }
  ],
  sensitiveData: [
    { pattern: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g, name: 'Credit Card Pattern', severity: 'MEDIUM' },
    { pattern: /\b\d{3}-\d{2}-\d{4}\b/g, name: 'SSN Pattern', severity: 'MEDIUM' }
  ],
  mimeTypes: [
    'text/html', 'text/javascript', 'application/javascript',
    'application/x-javascript', 'text/jscript', 'text/vbscript',
    'text/css', 'application/x-css', 'text/x-css',
    'application/octet-stream', 'text/xml', 'application/xml'
  ]
};

export const encoding = {
  suspicious: [
    { pattern: /<script/i, name: 'Script Tag Start', severity: 'HIGH' },
    { pattern: /<\/script>/i, name: 'Script Tag End', severity: 'HIGH' },
    { pattern: /javascript:/i, name: 'JavaScript Protocol', severity: 'HIGH' },
    { pattern: /vbscript:/i, name: 'VBScript Protocol', severity: 'HIGH' },
    { pattern: /on\w+=/i, name: 'Event Handler', severity: 'MEDIUM' },
    { pattern: /<iframe/i, name: 'IFrame Tag', severity: 'MEDIUM' },
    { pattern: /<object/i, name: 'Object Tag', severity: 'MEDIUM' },
    { pattern: /<embed/i, name: 'Embed Tag', severity: 'MEDIUM' },
    { pattern: /eval\(/i, name: 'Eval Function', severity: 'HIGH' },
    { pattern: /function\(/i, name: 'Function Constructor', severity: 'MEDIUM' },
    { pattern: /settimeout\(/i, name: 'SetTimeout Function', severity: 'MEDIUM' },
  ]
};

export const secrets = {
  common: [
    { pattern: /\bAKIA[0-9A-Z]{16}\b/, name: 'AWS Access Key ID', severity: 'HIGH' },
    { pattern: /\b(?:ASIA|A3T[A-Z0-9])[A-Z0-9]{16}\b/, name: 'AWS Temp/Alt Key ID', severity: 'HIGH' },
    { pattern: /\baws_secret_access_key\b\s*[:=]\s*["']?[A-Za-z0-9\/+=]{40}["']?/i, name: 'AWS Secret Access Key', severity: 'HIGH' },
    { pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/, name: 'Google API Key', severity: 'MEDIUM' },
    { pattern: /\bsk_live_[0-9a-zA-Z]{24,}\b/, name: 'Stripe Secret Key', severity: 'HIGH' },
    { pattern: /\bghp_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{30,}\b/, name: 'GitHub Token', severity: 'HIGH' },
    { pattern: /\bxox[aboprs]-[A-Za-z0-9-]{10,}\b/, name: 'Slack Token', severity: 'HIGH' },
    { pattern: /\beyJ[A-Za-z0-9._-]{20,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}\b/, name: 'JWT', severity: 'MEDIUM' },
    { pattern: /"alg"\s*:\s*"none"/i, name: 'JWT alg=none', severity: 'HIGH' },
    { pattern: /"kid"\s*:\s*"\.\.\//i, name: 'JWT kid Path Traversal', severity: 'HIGH' }
  ]
};

export const css = {
  expressions: [
    { pattern: /expression\s*\(/gi, name: 'CSS Expression', severity: 'CRITICAL' },
    { pattern: /@import\s+url\s*\(/gi, name: 'CSS Import URL', severity: 'HIGH' },
    { pattern: /behavior\s*:/gi, name: 'IE Behavior Property', severity: 'HIGH' },
    { pattern: /binding\s*:/gi, name: 'XBL Binding', severity: 'HIGH' },
    { pattern: /-moz-binding\s*:/gi, name: 'Mozilla XBL Binding', severity: 'HIGH' }
  ],
  protocolInjection: [
    { pattern: /url\s*\(\s*javascript:/gi, name: 'CSS URL JavaScript', severity: 'CRITICAL' },
    { pattern: /url\s*\(\s*vbscript:/gi, name: 'CSS URL VBScript', severity: 'HIGH' }
  ]
};

export const svg = {
  vectors: [
    { pattern: /<svg[^>]*\b(onload|onbegin|onend|onrepeat)\s*=/i, name: 'SVG Event Handler', severity: 'HIGH' },
    { pattern: /<foreignObject[^>]*>/i, name: 'SVG ForeignObject', severity: 'HIGH' },
    { pattern: /\b(?:xlink:href|href)\s*=\s*["']\s*javascript:/i, name: 'SVG Href JavaScript', severity: 'CRITICAL' },
    { pattern: /\bsrcset\s*=\s*["'][^"']*javascript:/i, name: 'Srcset JavaScript', severity: 'HIGH' }
  ]
};

export const xml = {
  entityAttacks: [
    { pattern: /<!DOCTYPE\s+[^>]*>/i, name: 'XML DOCTYPE Declaration', severity: 'HIGH' },
    { pattern: /<!ENTITY\s+[^>]*>/i, name: 'XML ENTITY Declaration', severity: 'CRITICAL' },
    { pattern: /SYSTEM\s+["'][^"']*["']/i, name: 'XML External Entity (SYSTEM)', severity: 'CRITICAL' },
    { pattern: /PUBLIC\s+["'][^"']*["']/i, name: 'XML External Entity (PUBLIC)', severity: 'CRITICAL' },
    { pattern: /&[a-zA-Z0-9]+;.*&[a-zA-Z0-9]+;.*&[a-zA-Z0-9]+;/i, name: 'XML Entity Expansion Chain', severity: 'HIGH' },
    { pattern: /<!ELEMENT\s+[^>]*>/i, name: 'XML ELEMENT Declaration', severity: 'MEDIUM' },
    { pattern: /<!ATTLIST\s+[^>]*>/i, name: 'XML ATTLIST Declaration', severity: 'MEDIUM' }
  ],
  billionLaughs: [
    { pattern: /&lol\d*;/i, name: 'Billion Laughs Entity Reference', severity: 'CRITICAL' },
    { pattern: /<!ENTITY\s+lol/i, name: 'Billion Laughs Entity Definition', severity: 'CRITICAL' }
  ]
};
