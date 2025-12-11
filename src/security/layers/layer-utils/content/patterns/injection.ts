/**
 * XSS, SQL, Script, NoSQL, GraphQL, and Deserialization patterns
 */

import type { Severity } from '../../../../../types/index.js';

/** Attack pattern definition */
export interface AttackPattern {
  pattern: RegExp;
  name: string;
  severity: Severity;
}

/** Pattern category containing an array of attack patterns */
export type PatternCategory = AttackPattern[];

export const xss = {
  basicVectors: [
    { pattern: /<script[^>]*>/gi, name: 'Script Tag', severity: 'CRITICAL' },
    { pattern: /<\/script>/gi, name: 'Script Closing Tag', severity: 'CRITICAL' },
    { pattern: /javascript:/gi, name: 'JavaScript Protocol', severity: 'CRITICAL' },
    { pattern: /vbscript:/gi, name: 'VBScript Protocol', severity: 'HIGH' }
  ],
  eventHandlers: [
    { pattern: /on\w+\s*=/gi, name: 'Event Handler', severity: 'HIGH' },
    { pattern: /onclick\s*=/gi, name: 'OnClick Handler', severity: 'HIGH' },
    { pattern: /onerror\s*=/gi, name: 'OnError Handler', severity: 'HIGH' },
    { pattern: /onload\s*=/gi, name: 'OnLoad Handler', severity: 'HIGH' },
    { pattern: /onmouseover\s*=/gi, name: 'OnMouseOver Handler', severity: 'MEDIUM' }
  ],
  htmlElements: [
    { pattern: /<iframe[^>]*>/gi, name: 'IFrame Tag', severity: 'HIGH' },
    { pattern: /<object[^>]*>/gi, name: 'Object Tag', severity: 'HIGH' },
    { pattern: /<embed[^>]*>/gi, name: 'Embed Tag', severity: 'HIGH' },
    { pattern: /<applet[^>]*>/gi, name: 'Applet Tag', severity: 'HIGH' },
    { pattern: /<meta[^>]*>/gi, name: 'Meta Tag', severity: 'MEDIUM' },
    { pattern: /<link[^>]*>/gi, name: 'Link Tag', severity: 'MEDIUM' }
  ],
  advancedVectors: [
    { pattern: /srcdoc\s*=/gi, name: 'SrcDoc Attribute', severity: 'HIGH' },
    { pattern: /formaction\s*=/gi, name: 'FormAction Attribute', severity: 'MEDIUM' },
    { pattern: /data:\s*text\/html/gi, name: 'HTML Data URI', severity: 'HIGH' },
    { pattern: /data:\s*text\/javascript/gi, name: 'JavaScript Data URI', severity: 'CRITICAL' }
  ],
  jsExecution: [
    { pattern: /eval\s*\(/gi, name: 'Eval Function', severity: 'CRITICAL' },
    { pattern: /function\s*\(/gi, name: 'Function Constructor', severity: 'HIGH' },
    { pattern: /settimeout\s*\(/gi, name: 'SetTimeout Function', severity: 'HIGH' },
    { pattern: /setinterval\s*\(/gi, name: 'SetInterval Function', severity: 'HIGH' },
    { pattern: /requestanimationframe\s*\(/gi, name: 'RequestAnimationFrame', severity: 'MEDIUM' }
  ],
  domManipulation: [
    { pattern: /document\.write/gi, name: 'Document.Write', severity: 'HIGH' },
    { pattern: /document\.cookie/gi, name: 'Document.Cookie', severity: 'HIGH' },
    { pattern: /window\.location/gi, name: 'Window.Location', severity: 'HIGH' },
    { pattern: /location\.href/gi, name: 'Location.Href', severity: 'HIGH' }
  ],
  templateInjection: [
    { pattern: /\{\{.*\}\}/g, name: 'Template Literal', severity: 'MEDIUM' },
    { pattern: /\$\{.*\}/g, name: 'ES6 Template', severity: 'MEDIUM' },
    { pattern: /%\{.*\}/g, name: 'Ruby Template', severity: 'MEDIUM' }
  ],
  extraAttributes: [
    { pattern: /\bonanimation(?:start|end|iteration)\s*=/i, name: 'OnAnimation* Handler', severity: 'MEDIUM' },
    { pattern: /\bonauxclick\s*=/i, name: 'OnAuxClick Handler', severity: 'LOW' },
    { pattern: /\bonpointer(?:enter|over|down|up|leave)\s*=/i, name: 'Pointer Event Handler', severity: 'LOW' }
  ]
} as const satisfies Record<string, AttackPattern[]>;

export const sql = {
  basicInjection: [
    { pattern: /'\s*or\s*'1'\s*=\s*'1/gi, name: 'Classic OR Injection', severity: 'CRITICAL' },
    { pattern: /'\s*or\s*1\s*=\s*1/gi, name: 'Numeric OR Injection', severity: 'CRITICAL' },
    { pattern: /'\s*and\s*1\s*=\s*1/gi, name: 'AND Injection', severity: 'HIGH' },
    { pattern: /'\s*or\s*'a'\s*=\s*'a/gi, name: 'String OR Injection', severity: 'CRITICAL' },
    { pattern: /';\s*--/gi, name: 'Comment Injection', severity: 'HIGH' },
    { pattern: /union\s+select/gi, name: 'UNION SELECT', severity: 'CRITICAL' },
    { pattern: /union\s+all\s+select/gi, name: 'UNION ALL SELECT', severity: 'CRITICAL' }
  ],
  commandExecution: [
    { pattern: /exec\s*\(/gi, name: 'EXEC Command', severity: 'CRITICAL' },
    { pattern: /execute\s*\(/gi, name: 'EXECUTE Command', severity: 'CRITICAL' },
    { pattern: /sp_executesql/gi, name: 'SP_ExecuteSQL', severity: 'CRITICAL' },
    { pattern: /xp_cmdshell/gi, name: 'XP_CmdShell', severity: 'CRITICAL' }
  ],
  fileOperations: [
    { pattern: /load_file\s*\(/gi, name: 'LOAD_FILE Function', severity: 'HIGH' },
    { pattern: /into\s+outfile/gi, name: 'INTO OUTFILE', severity: 'HIGH' },
    { pattern: /into\s+dumpfile/gi, name: 'INTO DUMPFILE', severity: 'HIGH' }
  ],
  timeBasedAttacks: [
    { pattern: /waitfor\s+delay/gi, name: 'WAITFOR DELAY', severity: 'HIGH' },
    { pattern: /pg_sleep\s*\(/gi, name: 'PG_Sleep Function', severity: 'HIGH' },
    { pattern: /benchmark\s*\(/gi, name: 'BENCHMARK Function', severity: 'HIGH' },
    { pattern: /sleep\s*\(/gi, name: 'SLEEP Function', severity: 'HIGH' }
  ],
  informationGathering: [
    { pattern: /information_schema/gi, name: 'Information Schema', severity: 'MEDIUM' },
    { pattern: /sys\.tables/gi, name: 'System Tables', severity: 'MEDIUM' },
    { pattern: /mysql\.user/gi, name: 'MySQL User Table', severity: 'HIGH' },
    { pattern: /user\(\)/gi, name: 'USER() Function', severity: 'LOW' },
    { pattern: /version\(\)/gi, name: 'VERSION() Function', severity: 'LOW' },
    { pattern: /database\(\)/gi, name: 'DATABASE() Function', severity: 'LOW' },
    { pattern: /@@version/gi, name: 'Version Variable', severity: 'LOW' }
  ]
} as const satisfies Record<string, AttackPattern[]>;

export const script = {
  pythonInjection: [
    { pattern: /import\s+os/gi, name: 'Python OS Import', severity: 'HIGH' },
    { pattern: /import\s+subprocess/gi, name: 'Python Subprocess', severity: 'HIGH' },
    { pattern: /__import__\s*\(/gi, name: 'Python __import__', severity: 'HIGH' },
    { pattern: /os\.system\s*\(/gi, name: 'Python OS.System', severity: 'CRITICAL' },
    { pattern: /subprocess\./gi, name: 'Python Subprocess Call', severity: 'HIGH' }
  ],
  nodeInjection: [
    { pattern: /require\s*\(/gi, name: 'Node.js Require', severity: 'HIGH' },
    { pattern: /process\.env/gi, name: 'Process Environment', severity: 'MEDIUM' },
    { pattern: /child_process/gi, name: 'Child Process', severity: 'HIGH' },
    { pattern: /fs\.read/gi, name: 'File System Read', severity: 'MEDIUM' },
    { pattern: /fs\.write/gi, name: 'File System Write', severity: 'HIGH' }
  ],
  dynamicExecution: [
    { pattern: /getattr\s*\(/gi, name: 'GetAttr Function', severity: 'MEDIUM' },
    { pattern: /setattr\s*\(/gi, name: 'SetAttr Function', severity: 'HIGH' },
    { pattern: /delattr\s*\(/gi, name: 'DelAttr Function', severity: 'HIGH' },
    { pattern: /hasattr\s*\(/gi, name: 'HasAttr Function', severity: 'LOW' }
  ],
  prototypePollution: [
    { pattern: /\\?["']__proto__\\?["']\s*:/i, name: 'Prototype Pollution (__proto__)', severity: 'CRITICAL' },
    { pattern: /\\?["']constructor\\?["']\s*:\s*\{?\s*\\?["']?prototype/i, name: 'Constructor Prototype Pollution', severity: 'CRITICAL' },
    { pattern: /\bObject\.prototype\.[A-Za-z_]/i, name: 'Object.prototype Assignment', severity: 'CRITICAL' },
    { pattern: /\bprototype\s*\[\s*\\?["']/i, name: 'Prototype Bracket Access', severity: 'HIGH' }
  ],
  names: [
    { pattern: /\.(?:php\d*|phar|phtml|jsp|jspx|asp|aspx|cgi|pl|exe|dll)(?:\.[A-Za-z0-9]{1,8})?$/i, name: 'Executable or Script Extension', severity: 'HIGH' },
    { pattern: /\.[A-Za-z0-9]{1,6}\.(?:php|js|jsp|asp|aspx|cgi|pl)$/i, name: 'Double Extension', severity: 'HIGH' }
  ]
} as const satisfies Record<string, AttackPattern[]>;

export const nosql = {
  operators: [
    { pattern: /"\$where"\s*:/i, name: 'Mongo $where', severity: 'HIGH' },
    { pattern: /"\$(?:ne|gt|gte|lt|lte|in|nin|regex)"\s*:/i, name: 'Mongo Operator', severity: 'HIGH' },
    { pattern: /\bObjectId\s*\(/i, name: 'Mongo ObjectId in Query', severity: 'MEDIUM' },
    { pattern: /"\$[A-Za-z]+"s*:/i, name: 'Mongo Top-Level $ Operator', severity: 'HIGH' },
    { pattern: /"\$regex"\s*:\s*".*"\s*,\s*"\$options"\s*:\s*"[imsx]*"/i, name: 'Mongo $regex+$options', severity: 'HIGH' },
    { pattern: /"\$where"\s*:\s*".*"/i, name: 'Mongo $where Inline JavaScript', severity: 'HIGH' }
  ]
} as const satisfies Record<string, AttackPattern[]>;

export const graphql = {
  introspection: [
    { pattern: /__schema\b|__type\b|__typename\b/, name: 'GraphQL Introspection', severity: 'HIGH' },
    { pattern: /\bquery\s*\{\s*__schema/i, name: 'GraphQL Introspection Query', severity: 'HIGH' }
  ],
  costHints: [
    { pattern: /\b__directive\b|\b__typekind\b/i, name: 'GraphQL Meta Types', severity: 'MEDIUM' }
  ]
} as const satisfies Record<string, AttackPattern[]>;

export const deserialization = {
  markers: [
    { pattern: /\brO0AB[A-Za-z0-9+/=]{10,}/, name: 'Java Serialized (Base64)', severity: 'CRITICAL' },
    { pattern: /\bO:\d+:"[A-Za-z0-9_\\]+"\s*:\d+:\{/, name: 'PHP Object Serialization', severity: 'HIGH' },
    { pattern: /\bcos\\nsystem\\n|\bcposix\\nsystem\\n|(?:GLOBAL|REDUCE)\n/i, name: 'Python Pickle Primitives', severity: 'HIGH' },
    { pattern: /!!python\/object\/apply|!!js\/function/i, name: 'YAML Dangerous Tags', severity: 'HIGH' },
    { pattern: /\$\{jndi:(?:ldap|rmi|dns):\/\//i, name: 'JNDI/Log4Shell Probe', severity: 'CRITICAL' },
    { pattern: /\bAAEAAAD[0-9A-Za-z+/=]{16,}/, name: '.NET BinaryFormatter (Base64-like)', severity: 'CRITICAL' },
    { pattern: /\bMarshal\.load\b|\bBAh[0-9A-Za-z+/=]{10,}/i, name: 'Ruby Marshal', severity: 'HIGH' }
  ]
} as const satisfies Record<string, AttackPattern[]>;
