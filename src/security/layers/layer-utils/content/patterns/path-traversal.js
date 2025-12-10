// Path traversal, command injection, and CRLF patterns
/* eslint-disable no-useless-escape */

export const pathTraversal = {
  patterns: [
    { pattern: /\.\.[\/\\]/g, name: 'Basic Path Traversal', severity: 'HIGH' },
    { pattern: /\.\.%2[fF]/gi, name: 'URL-Encoded Path Traversal', severity: 'HIGH' },
    { pattern: /\.\.%5[cC]/gi, name: 'URL-Encoded Backslash Traversal', severity: 'HIGH' },
    { pattern: /\.\.%252[fF]/gi, name: 'Double-Encoded Path Traversal', severity: 'HIGH' },
    { pattern: /%.{2}%.{2}%.{2}[fF]/gi, name: 'Triple-Encoded Path Traversal', severity: 'HIGH' },
    { pattern: /%2e%2e%2[fF]/gi, name: 'Fully URL-Encoded Traversal', severity: 'HIGH' },
    { pattern: /%2e%2e%5[cC]/gi, name: 'Fully URL-Encoded Backslash', severity: 'HIGH' },
    { pattern: /\.\.%c0%af/gi, name: 'UTF-8 Overlong Encoding', severity: 'CRITICAL' },
    { pattern: /\.\.%c1%9c/gi, name: 'UTF-8 Overlong Backslash', severity: 'CRITICAL' },
    { pattern: /\.{4,}[\/\\]{3,}/g, name: 'Extended Dot Traversal', severity: 'MEDIUM' },
    { pattern: /\.\.\\\.\.\\\.\.\\/gi, name: 'Windows Backslash Traversal', severity: 'HIGH' },
    { pattern: /\.\.\\\.\.\\\.\.\\\.\.\\.*windows/gi, name: 'Windows System Traversal', severity: 'CRITICAL' }
  ],
  unixSystemFiles: [
    { pattern: /\/etc\/passwd/i, name: 'Unix Password File', severity: 'CRITICAL' },
    { pattern: /\/etc\/shadow/i, name: 'Unix Shadow File', severity: 'CRITICAL' },
    { pattern: /\/etc\/hosts/i, name: 'Unix Hosts File', severity: 'HIGH' },
    { pattern: /\/etc\/group/i, name: 'Unix Groups File', severity: 'HIGH' },
    { pattern: /\/etc\/sudoers/i, name: 'Sudo Configuration', severity: 'CRITICAL' },
    { pattern: /\/\.ssh\//i, name: 'SSH Directory', severity: 'CRITICAL' },
    { pattern: /\/\.env/i, name: 'Environment File', severity: 'HIGH' },
    { pattern: /\/proc\/self\/environ/i, name: 'Process Environment', severity: 'HIGH' },
    { pattern: /\/proc\/self\/maps/i, name: 'Process Memory Maps', severity: 'MEDIUM' },
    { pattern: /\/proc\/version/i, name: 'Kernel Version', severity: 'LOW' },
    { pattern: /\/proc\/cpuinfo/i, name: 'CPU Information', severity: 'LOW' },
    { pattern: /\/proc\/meminfo/i, name: 'Memory Information', severity: 'LOW' },
    { pattern: /\/dev\/random/i, name: 'Random Device', severity: 'MEDIUM' },
    { pattern: /\/dev\/urandom/i, name: 'Urandom Device', severity: 'MEDIUM' }
  ],
  macosSystemFiles: [
    { pattern: /\/private\/etc\/master\.passwd/i, name: 'macOS Master Password File', severity: 'CRITICAL' },
    { pattern: /\/var\/db\/shadow\/hash\//i, name: 'macOS Shadow Hash', severity: 'CRITICAL' },
    { pattern: /\/var\/db\/dslocal\/nodes\/Default\/users\//i, name: 'macOS User Database', severity: 'CRITICAL' },
    { pattern: /\/Library\/Keychains\//i, name: 'macOS System Keychain', severity: 'CRITICAL' },
    { pattern: /\/System\/Library\/Keychains\//i, name: 'macOS System Certificates', severity: 'CRITICAL' },
    { pattern: /\/Library\/Application Support\/com\.apple\.TCC\//i, name: 'macOS TCC Database', severity: 'CRITICAL' },
    { pattern: /\/Library\/Preferences\/SystemConfiguration\//i, name: 'macOS Network Configuration', severity: 'HIGH' },
    { pattern: /\/private\/var\/db\/ConfigurationProfiles\//i, name: 'macOS Configuration Profiles', severity: 'HIGH' },
    { pattern: /\/Users\/.*\/Library\/Keychains\//i, name: 'macOS User Keychain', severity: 'HIGH' },
    { pattern: /\/Users\/.*\/\.bash_history/i, name: 'macOS Bash History', severity: 'MEDIUM' },
    { pattern: /\/Users\/.*\/\.zsh_history/i, name: 'macOS Zsh History', severity: 'MEDIUM' },
    { pattern: /\/Users\/.*\/Library\/Safari\//i, name: 'macOS Safari Data', severity: 'MEDIUM' },
    { pattern: /\/Users\/.*\/Library\/Cookies\//i, name: 'macOS User Cookies', severity: 'MEDIUM' },
    { pattern: /\/dev\/disk[0-9]/i, name: 'macOS Disk Device', severity: 'HIGH' },
    { pattern: /\/dev\/rdisk[0-9]/i, name: 'macOS Raw Disk Device', severity: 'HIGH' }
  ],
  windowsAbsolutePaths: [],
  windowsSystemFiles: [],
  sensitiveFiles: [
    { pattern: /id_rsa/i, name: 'RSA Private Key', severity: 'CRITICAL' },
    { pattern: /id_dsa/i, name: 'DSA Private Key', severity: 'CRITICAL' },
    { pattern: /id_ecdsa/i, name: 'ECDSA Private Key', severity: 'CRITICAL' },
    { pattern: /id_ed25519/i, name: 'Ed25519 Private Key', severity: 'CRITICAL' },
    { pattern: /private\.key/i, name: 'Private Key File', severity: 'CRITICAL' },
    { pattern: /server\.key/i, name: 'Server Key File', severity: 'CRITICAL' },
    { pattern: /\.pem$/i, name: 'PEM Certificate/Key', severity: 'HIGH' },
    { pattern: /\.pfx$/i, name: 'PFX Certificate', severity: 'HIGH' },
    { pattern: /\.p12$/i, name: 'PKCS12 Certificate', severity: 'HIGH' },
    { pattern: /config\.json/i, name: 'JSON Configuration', severity: 'MEDIUM' },
    { pattern: /config\.yaml/i, name: 'YAML Configuration', severity: 'MEDIUM' },
    { pattern: /config\.yml/i, name: 'YML Configuration', severity: 'MEDIUM' },
    { pattern: /\.htaccess/i, name: 'Apache Config', severity: 'MEDIUM' },
    { pattern: /\.htpasswd/i, name: 'Apache Password File', severity: 'HIGH' },
    { pattern: /web\.config/i, name: 'IIS Configuration', severity: 'MEDIUM' },
    { pattern: /database\.yml/i, name: 'Database Configuration', severity: 'HIGH' },
    { pattern: /\.aws\/credentials/i, name: 'AWS Credentials', severity: 'CRITICAL' },
    { pattern: /\.docker\/config\.json/i, name: 'Docker Configuration', severity: 'MEDIUM' },
    { pattern: /\.npmrc/i, name: 'NPM Configuration', severity: 'MEDIUM' },
    { pattern: /\.gitconfig/i, name: 'Git Configuration', severity: 'LOW' },
    { pattern: /\/\.ssh\/authorized_keys/i, name: 'SSH Authorized Keys', severity: 'HIGH' },
    { pattern: /\/\.ssh\/known_hosts/i, name: 'SSH Known Hosts', severity: 'MEDIUM' },
  ]
};

export const command = {
  basicInjection: [
    { pattern: /rm\s+-rf/gi, name: 'Recursive Delete', severity: 'CRITICAL' },
    { pattern: /&\s*rm\s+/gi, name: 'Chained Delete', severity: 'CRITICAL' },
    { pattern: /;\s*rm\s+/gi, name: 'Sequential Delete', severity: 'CRITICAL' },
    { pattern: /\|\s*rm\s+/gi, name: 'Piped Delete', severity: 'CRITICAL' },
    { pattern: /sudo\s+/gi, name: 'Sudo Execution', severity: 'HIGH' },
    { pattern: /chmod\s+777/gi, name: 'Permission Override', severity: 'HIGH' },
    { pattern: /;\s*[a-zA-Z]/gi, name: 'Command Separator Injection', severity: 'HIGH' },
    { pattern: /&&\s*[a-zA-Z]/gi, name: 'AND Command Chain', severity: 'HIGH' },
    { pattern: /\|\|\s*[a-zA-Z]/gi, name: 'OR Command Chain', severity: 'HIGH' },
    { pattern: /\|\s*[a-zA-Z]/gi, name: 'Pipe Command Chain', severity: 'MEDIUM' },
  ],
  networkOperations: [
    { pattern: /wget\s+http/gi, name: 'Wget Download', severity: 'HIGH' },
    { pattern: /curl\s+http/gi, name: 'Curl Request', severity: 'HIGH' },
    { pattern: /nc\s+-/gi, name: 'Netcat Connection', severity: 'HIGH' },
    { pattern: /\bcurl\b.*\s-(?:fsS?L|o|-O|-k)\s+https?:\/\//i, name: 'Curl Remote Fetch', severity: 'MEDIUM' },
    { pattern: /\btftp\b.*\s-i\s+[A-Za-z0-9\.\-]+/i, name: 'TFTP Transfer', severity: 'HIGH' },
    { pattern: /\bscp\b\s+-[pr]?\s+\S+@\S+:/i, name: 'SCP Exfil', severity: 'HIGH' }
  ],
  shellAccess: [
    { pattern: /bash\s+-i/gi, name: 'Interactive Bash', severity: 'CRITICAL' },
    { pattern: /\/bin\/sh/gi, name: 'Shell Access', severity: 'CRITICAL' },
    { pattern: /powershell/gi, name: 'PowerShell', severity: 'HIGH' },
    { pattern: /cmd\.exe/gi, name: 'Command Prompt', severity: 'HIGH' }
  ],
  executionWrappers: [
    { pattern: /system\s*\(/gi, name: 'System Call', severity: 'CRITICAL' },
    { pattern: /exec\s*\(/gi, name: 'Exec Call', severity: 'CRITICAL' },
    { pattern: /shell_exec/gi, name: 'Shell Exec', severity: 'CRITICAL' },
    { pattern: /passthru/gi, name: 'Passthru Function', severity: 'HIGH' }
  ],
  markers: [
    { pattern: /^host\s*:\s*.+/im, name: 'Host Header Present In Input', severity: 'MEDIUM' },
    { pattern: /^host\s*:\s*(?:localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)/im, name: 'Host -> Loopback', severity: 'HIGH' },
    { pattern: /^host\s*:\s*[^:\s]+:(?:80|443|22|25|3306|6379)/im, name: 'Host Suspicious Port', severity: 'MEDIUM' }
  ],
  fileOperations: [
    { pattern: /\bcat\s+/gi, name: 'Cat File Read', severity: 'MEDIUM' },
    { pattern: /\bmore\s+/gi, name: 'More File Read', severity: 'MEDIUM' },
    { pattern: /\bless\s+/gi, name: 'Less File Read', severity: 'MEDIUM' },
    { pattern: /\bhead\s+/gi, name: 'Head File Read', severity: 'MEDIUM' },
    { pattern: /\btail\s+/gi, name: 'Tail File Read', severity: 'MEDIUM' },
    { pattern: /\bfind\s+/gi, name: 'Find Command', severity: 'MEDIUM' },
    { pattern: /\bgrep\s+/gi, name: 'Grep Search', severity: 'LOW' },
  ],
  systemInfo: [
    { pattern: /\bps\s+/gi, name: 'Process List', severity: 'MEDIUM' },
    { pattern: /\btop\s*/gi, name: 'Top Process Monitor', severity: 'MEDIUM' },
    { pattern: /\bwhoami\s*/gi, name: 'User Identity', severity: 'MEDIUM' },
    { pattern: /\bid\s*(?:[;&|]|$)/gi, name: 'User ID Info', severity: 'MEDIUM' },
    { pattern: /\buname\s+/gi, name: 'System Info', severity: 'MEDIUM' },
    { pattern: /\benv\s*/gi, name: 'Environment Variables', severity: 'HIGH' },
    { pattern: /\bhistory\s*/gi, name: 'Command History', severity: 'MEDIUM' },
  ],
};

export const crlf = {
  basicInjection: [
    { pattern: /%0d%0a/gi, name: 'URL-Encoded CRLF', severity: 'HIGH' },
    { pattern: /%0a/gi, name: 'URL-Encoded LF', severity: 'MEDIUM' },
    { pattern: /%0d/gi, name: 'URL-Encoded CR', severity: 'MEDIUM' },
    { pattern: /\\r\\n/gi, name: 'Escaped CRLF', severity: 'HIGH' },
    { pattern: /\\n/gi, name: 'Escaped LF', severity: 'MEDIUM' },
    { pattern: /\\r/gi, name: 'Escaped CR', severity: 'MEDIUM' },
    { pattern: /\r\n/g, name: 'Literal CRLF', severity: 'HIGH' },
    { pattern: /\n.*(?:location|set-cookie|content-type):/gi, name: 'LF Header Injection', severity: 'MEDIUM' }
  ],
  doubleEncoded: [
    { pattern: /%250d%250a/gi, name: 'Double-Encoded CRLF', severity: 'HIGH' },
    { pattern: /%25250d%25250a/gi, name: 'Triple-Encoded CRLF', severity: 'HIGH' },
    { pattern: /%2e%2e%250d%250a/gi, name: 'Mixed Double-Encoded', severity: 'HIGH' }
  ],
  httpHeaders: [
    { pattern: /(?:%0d%0a|\\r\\n|\r\n).*set-cookie\s*:/gi, name: 'CRLF Cookie Injection', severity: 'CRITICAL' },
    { pattern: /(?:%0d%0a|\\r\\n|\r\n).*location\s*:/gi, name: 'CRLF Location Header', severity: 'CRITICAL' },
    { pattern: /(?:%0d%0a|\\r\\n|\r\n).*content-type\s*:/gi, name: 'CRLF Content-Type', severity: 'HIGH' },
    { pattern: /(?:%0d%0a|\\r\\n|\r\n).*content-length\s*:/gi, name: 'CRLF Content-Length', severity: 'HIGH' },
    { pattern: /(?:%0d%0a|\\r\\n|\r\n).*cache-control\s*:/gi, name: 'CRLF Cache-Control', severity: 'HIGH' },
    { pattern: /(?:%0d%0a|\\r\\n|\r\n).*authorization\s*:/gi, name: 'CRLF Authorization Header', severity: 'CRITICAL' },
    { pattern: /(?:%0d%0a|\\r\\n|\r\n).*access-control-allow-origin\s*:/gi, name: 'CRLF CORS Header', severity: 'HIGH' }
  ],
  responseSplitting: [
    { pattern: /(?:%0d%0a|\\r\\n|\r\n).*(?:%0d%0a|\\r\\n|\r\n).*<script/gi, name: 'Response Splitting XSS', severity: 'CRITICAL' },
    { pattern: /(?:%0d%0a|\\r\\n|\r\n).*(?:%0d%0a|\\r\\n|\r\n).*<html/gi, name: 'Response Splitting HTML', severity: 'HIGH' },
    { pattern: /(?:%0d%0a|\\r\\n|\r\n).*(?:%0d%0a|\\r\\n|\r\n).*javascript:/gi, name: 'Response Splitting JavaScript', severity: 'CRITICAL' },
    { pattern: /(?:%0d%0a|\\r\\n|\r\n){2,}/gi, name: 'Double CRLF (Body Split)', severity: 'HIGH' }
  ],
  utfOverlong: [
    { pattern: /%c0%ae%c0%ae%c0%af/gi, name: 'UTF-8 Overlong CRLF', severity: 'CRITICAL' },
    { pattern: /%e0%80%8a/gi, name: 'UTF-8 Overlong LF', severity: 'HIGH' },
    { pattern: /%e0%80%8d/gi, name: 'UTF-8 Overlong CR', severity: 'HIGH' }
  ],
  logInjection: [
    { pattern: /(?:%0d%0a|\\r\\n|\r\n).*\[.*\]\s*(?:error|info|debug|warn)/gi, name: 'Log Entry Injection', severity: 'MEDIUM' },
    { pattern: /(?:%0d%0a|\\r\\n|\r\n).*\d{4}-\d{2}-\d{2}/gi, name: 'Log Timestamp Injection', severity: 'MEDIUM' }
  ]
};
