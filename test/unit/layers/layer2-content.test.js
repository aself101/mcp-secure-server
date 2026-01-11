import { describe, it, expect, beforeEach } from 'vitest';
import ContentValidationLayer from '@/security/layers/layer2-content.js';
import { createToolCallMessage } from '@tests/helpers/message-builders.js';

describe('Content Validation Layer', () => {
  let layer;

  beforeEach(() => {
    layer = new ContentValidationLayer({ debugMode: false });
  });

  describe('Path Traversal Detection', () => {
    it('should detect basic path traversal', async () => {
      const message = createToolCallMessage({ path: '../../../etc/passwd' });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('PATH_TRAVERSAL');
      expect(result.reason).toMatch(/path|file|travers|directory/i);
    });

    it('should detect URL-encoded path traversal', async () => {
      const message = createToolCallMessage({ path: '%2e%2e%2f%2e%2e%2fetc%2fpasswd' });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('PATH_TRAVERSAL');
    });

    it('should detect double-encoded path traversal', async () => {
      const message = createToolCallMessage({ path: '%252e%252e%252fetc%252fpasswd' });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('PATH_TRAVERSAL');
    });

    it('should detect fullwidth character path traversal', async () => {
      // Fullwidth dots and slash: U+FF0E, U+FF0F
      const message = createToolCallMessage({ path: '\uFF0E\uFF0E\uFF0F\uFF0E\uFF0E\uFF0Fetc\uFF0Fpasswd' });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('PATH_TRAVERSAL');
    });

    it('should detect URL-encoded null byte path traversal', async () => {
      // Null byte injection used to truncate file paths in vulnerable systems
      const message = createToolCallMessage({ path: '/etc/passwd%00.txt' });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('PATH_TRAVERSAL');
    });

    it('should detect null byte combined with path traversal', async () => {
      // Combined attack: traversal + null byte to bypass extension checks
      const message = createToolCallMessage({ path: '../../../etc/passwd%00.jpg' });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('PATH_TRAVERSAL');
    });

    it('should allow legitimate paths', async () => {
      const message = createToolCallMessage({ path: '/home/user/documents/file.txt' });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(true);
    });
  });

  describe('Context-Aware Sensitive File Detection', () => {
    it('should allow config.json without path context', async () => {
      // Just mentioning "tsconfig.json" or "config.json" without path traversal context should be allowed
      const message = createToolCallMessage({ file_path: 'tsconfig.json' });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(true);
    });

    it('should allow multiple config file references without path context', async () => {
      // Validation tracker scenario: file paths as data, not as access attempts
      const message = createToolCallMessage({
        recommendations: [
          { file_path: 'tsconfig.json', title: 'Fix types' },
          { file_path: 'eslint.config.json', title: 'Fix lint' },
          { file_path: 'package.json', title: 'Update deps' }
        ]
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(true);
    });

    it('should block config.json with path traversal context', async () => {
      // This is an actual attack: traversing to access config.json
      const message = createToolCallMessage({ path: '../../../config.json' });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('PATH_TRAVERSAL');
    });

    it('should block sensitive files with absolute path context', async () => {
      // Attempting to access /etc/passwd is clearly an attack
      const message = createToolCallMessage({ file: '/etc/passwd' });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('PATH_TRAVERSAL');
    });

    it('should block sensitive files with file:// protocol', async () => {
      const message = createToolCallMessage({ url: 'file:///etc/passwd' });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      // May be detected as SSRF (file:// scheme) or PATH_TRAVERSAL
      expect(['PATH_TRAVERSAL', 'SSRF_ATTEMPT']).toContain(result.violationType);
    });
  });

  describe('SQL Injection Detection', () => {
    it('should detect basic SQL injection', async () => {
      const message = createToolCallMessage({ query: "'; DROP TABLE users; --" });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      // May detect as COMMAND_INJECTION (rm -rf pattern) or SQL_INJECTION depending on pattern order
      expect(['SQL_INJECTION', 'COMMAND_INJECTION']).toContain(result.violationType);
    });

    it('should detect UNION-based SQL injection', async () => {
      const message = createToolCallMessage({ input: "' UNION SELECT * FROM passwords --" });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('SQL_INJECTION');
    });

    it('should detect OR-based authentication bypass', async () => {
      const message = createToolCallMessage({ username: "admin' OR '1'='1" });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('SQL_INJECTION');
    });

    it('should allow normal SQL-like words in context', async () => {
      const message = createToolCallMessage({ description: 'Select your favorite table from the menu' });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(true);
    });
  });

  describe('XSS Detection', () => {
    it('should detect basic script tags', async () => {
      const message = createToolCallMessage({ content: '<script>alert("xss")</script>' });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('XSS_ATTEMPT');
      expect(result.reason).toMatch(/xss|script|injection/i);
    });

    it('should detect event handler injection', async () => {
      const message = createToolCallMessage({ html: '<img src="x" onerror="alert(1)">' });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('XSS_ATTEMPT');
    });

    it('should detect javascript: protocol', async () => {
      const message = createToolCallMessage({ url: 'javascript:alert(document.cookie)' });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('XSS_ATTEMPT');
    });

    it('should detect Unicode-encoded XSS', async () => {
      const message = createToolCallMessage({ content: '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e' });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('XSS_ATTEMPT');
    });

    it('should allow normal HTML content', async () => {
      const message = createToolCallMessage({ content: '<p>Hello, <strong>world</strong>!</p>' });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(true);
    });
  });

  describe('Command Injection Detection', () => {
    it('should detect semicolon command chaining', async () => {
      const message = createToolCallMessage({ command: 'ls; rm -rf /' });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('COMMAND_INJECTION');
      expect(result.reason).toMatch(/command|injection|shell/i);
    });

    it('should detect pipe injection', async () => {
      const message = createToolCallMessage({ file: 'test.txt | cat /etc/passwd' });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      // May detect path traversal first due to /etc/passwd
      expect(['COMMAND_INJECTION', 'PATH_TRAVERSAL']).toContain(result.violationType);
    });

    it('should detect backtick command substitution', async () => {
      const message = createToolCallMessage({ name: '`whoami`' });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('COMMAND_INJECTION');
    });

    it('should detect $() command substitution', async () => {
      const message = createToolCallMessage({ input: '$(cat /etc/passwd)' });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      // May detect path traversal first due to /etc/passwd
      expect(['COMMAND_INJECTION', 'PATH_TRAVERSAL']).toContain(result.violationType);
    });
  });

  describe('Valid Message Handling', () => {
    it('should pass valid tool call messages', async () => {
      const message = createToolCallMessage({ name: 'John', age: 30 });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(true);
      expect(result.allowed).toBe(true);
    });

    it('should pass valid notifications', async () => {
      const message = {
        jsonrpc: '2.0',
        method: 'notifications/initialized'
      };
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(true);
    });
  });

  describe('Edge Cases', () => {
    it('should reject null messages', async () => {
      const result = await layer.validate(null, {});

      expect(result.passed).toBe(false);
      expect(result.severity).toBe('CRITICAL');
    });

    it('should reject undefined messages', async () => {
      const result = await layer.validate(undefined, {});

      expect(result.passed).toBe(false);
    });

    it('should reject empty objects', async () => {
      const result = await layer.validate({}, {});

      expect(result.passed).toBe(false);
    });
  });

  // Pentest Findings Regression Tests (2025-12-09)
  describe('Prototype Pollution Detection (P1/P2)', () => {
    it('should detect __proto__ pollution in object', async () => {
      const message = createToolCallMessage({ data: '{"__proto__": {"admin": true}}' });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('PROTOTYPE_POLLUTION');
      expect(result.reason).toMatch(/prototype.*pollution|__proto__/i);
    });

    it('should detect __proto__ in array payload', async () => {
      const message = createToolCallMessage({ items: '[{"__proto__": {"isAdmin": true}}]' });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('PROTOTYPE_POLLUTION');
    });

    it('should detect constructor.prototype pollution', async () => {
      const message = createToolCallMessage({ payload: '{"constructor": {"prototype": {"polluted": "yes"}}}' });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('PROTOTYPE_POLLUTION');
      expect(result.reason).toMatch(/prototype|constructor/i);
    });

    it('should detect Object.prototype assignment', async () => {
      const message = createToolCallMessage({ code: 'Object.prototype.isAdmin = true' });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('PROTOTYPE_POLLUTION');
    });

    it('should allow normal objects with constructor as string value', async () => {
      // This should pass - "constructor" as a key with a string value (not prototype pollution)
      const message = createToolCallMessage({ building: 'ABC Corp', type: 'constructor' });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(true);
    });

    it('should allow constructor in description text', async () => {
      const message = createToolCallMessage({ description: 'Call the constructor method' });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(true);
    });

    it('should allow constructor_name as key', async () => {
      const message = createToolCallMessage({ constructor_name: 'MyClass' });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(true);
    });

    it('should block nested constructor.prototype attack', async () => {
      const message = createToolCallMessage({
        nested: '{"nested": {"constructor": {"prototype": {"x": 1}}}}'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('PROTOTYPE_POLLUTION');
    });
  });

  describe('XML Entity Attack Detection (P3/P4)', () => {
    it('should detect DOCTYPE declarations', async () => {
      const message = createToolCallMessage({ xml: '<!DOCTYPE test [<!ENTITY x "y">]><root/>' });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('XML_ENTITY_ATTACK');
      expect(result.reason).toMatch(/xml|entity|doctype/i);
    });

    it('should detect ENTITY declarations', async () => {
      const message = createToolCallMessage({ data: '<!ENTITY xxe SYSTEM "file:///etc/passwd">' });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      // May detect SSRF (file:// scheme), path traversal (/etc/passwd), or XML entity attack
      expect(['XML_ENTITY_ATTACK', 'PATH_TRAVERSAL', 'SSRF_ATTEMPT']).toContain(result.violationType);
    });

    it('should detect Billion Laughs attack', async () => {
      // Single-line version to avoid CRLF detection triggering first
      const billionLaughs = '<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]><lolz>&lol2;</lolz>';
      const message = createToolCallMessage({ xml: billionLaughs });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('XML_ENTITY_ATTACK');
      expect(result.reason).toMatch(/xml|entity|doctype/i);
    });

    it('should detect external entity (SYSTEM)', async () => {
      const message = createToolCallMessage({ payload: '<!ENTITY xxe SYSTEM "http://evil.com/xxe">' });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('XML_ENTITY_ATTACK');
    });

    it('should detect external entity (PUBLIC)', async () => {
      const message = createToolCallMessage({ data: '<!ENTITY xxe PUBLIC "-//W3C//DTD XHTML 1.0//EN" "http://evil.com/xxe">' });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('XML_ENTITY_ATTACK');
    });

    it('should detect entity expansion chains', async () => {
      const message = createToolCallMessage({ content: '<root>&entity1;&entity2;&entity3;</root>' });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('XML_ENTITY_ATTACK');
    });

    it('should allow normal XML without entities', async () => {
      const message = createToolCallMessage({ xml: '<?xml version="1.0"?><root><item>value</item></root>' });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(true);
    });
  });

  describe('False Positive Tests - Legitimate Content', () => {
    it('should allow SQL-like words in legitimate product descriptions', async () => {
      const message = createToolCallMessage({
        description: 'SELECT your favorite table from our furniture catalog. We have wooden tables, metal tables, and more.'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(true);
    });

    it('should allow prototype/constructor in educational content', async () => {
      const message = createToolCallMessage({
        content: 'My constructor pattern uses prototype inheritance. This is a common JavaScript design pattern.'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(true);
    });

    it('should allow command-line documentation', async () => {
      const message = createToolCallMessage({
        docs: 'Run `npm install` in the terminal. Then run `npm test` to verify.'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(true);
    });

    it('should allow technical documentation with code examples', async () => {
      const message = createToolCallMessage({
        tutorial: 'The function returns true or false based on the condition. Use if/else for control flow.'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(true);
    });

    it('should allow "history" in documentation text', async () => {
      // This was triggering false positives for command injection
      const message = createToolCallMessage({
        summary: 'No version history documented. Check the release history for changes.',
        description: 'The version history shows the project evolution over time.'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(true);
    });

    it('should allow escaped newlines in JSON text content', async () => {
      const message = createToolCallMessage({
        text: 'Hello\nWorld',
        description: 'Line 1\nLine 2\nLine 3'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(true);
    });

    it('should allow multiline code strings', async () => {
      const message = createToolCallMessage({
        code: 'function hello() {\n  console.log("Hi");\n}'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(true);
    });

    it('should allow Windows line endings in text', async () => {
      const message = createToolCallMessage({
        windowsText: 'Line 1\r\nLine 2\r\nLine 3'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(true);
    });

    it('should allow file:// in documentation without path context', async () => {
      const message = createToolCallMessage({
        docs: 'Use file:///path/to/docs for local access'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(true);
    });

    it('should allow markdown tables with pipes', async () => {
      const message = createToolCallMessage({
        markdown: '| Header | Value |\n|--------|-------|\n| Name   | Test  |'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(true);
    });

    it('should block actual shell history access commands', async () => {
      const message = createToolCallMessage({
        command: 'history -c && rm ~/.bash_history'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('COMMAND_INJECTION');
    });

    it('should block CRLF with Set-Cookie header injection', async () => {
      const message = createToolCallMessage({
        header: 'X-Custom: value\r\nSet-Cookie: admin=true'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('CRLF_INJECTION');
    });

    it('should block URL-encoded CRLF injection', async () => {
      const message = createToolCallMessage({
        url: 'http://example.com/page%0d%0aSet-Cookie: evil=true'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('CRLF_INJECTION');
    });

    it('should block CRLF with Location header injection', async () => {
      const message = createToolCallMessage({
        redirect: 'innocent\r\nLocation: http://evil.com'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('CRLF_INJECTION');
    });
  });

  describe('Mixed Attack Vector Detection', () => {
    it('should detect file:// combined with SQL injection', async () => {
      const message = createToolCallMessage({
        query: "file:///etc/passwd' UNION SELECT * FROM users --"
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      // May detect as PATH_TRAVERSAL (file://), SQL_INJECTION, or SSRF
      expect(['PATH_TRAVERSAL', 'SQL_INJECTION', 'SSRF_ATTEMPT']).toContain(result.violationType);
    });

    it('should detect file:// protocol with command injection', async () => {
      const message = createToolCallMessage({
        url: 'file:///tmp/test; rm -rf /'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(['PATH_TRAVERSAL', 'COMMAND_INJECTION', 'SSRF_ATTEMPT']).toContain(result.violationType);
    });

    it('should detect path traversal combined with XSS', async () => {
      const message = createToolCallMessage({
        path: '../../../<script>alert(1)</script>'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(['PATH_TRAVERSAL', 'XSS_ATTEMPT']).toContain(result.violationType);
    });

    it('should detect SQL injection combined with prototype pollution', async () => {
      const message = createToolCallMessage({
        payload: '{"__proto__": {"query": "SELECT * FROM users"}}'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      // Prototype pollution is the primary concern here
      expect(result.violationType).toBe('PROTOTYPE_POLLUTION');
    });

    it('should detect multiple attack vectors in same request', async () => {
      const message = createToolCallMessage({
        file: '../../../etc/passwd',
        query: "'; DROP TABLE users; --",
        html: '<script>alert("xss")</script>'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      // Should detect at least one of the attack vectors
      expect(['PATH_TRAVERSAL', 'SQL_INJECTION', 'XSS_ATTEMPT', 'COMMAND_INJECTION']).toContain(result.violationType);
    });
  });
});
