/**
 * SSRF, LOLBins, and CSV injection patterns
 */
/* eslint-disable no-useless-escape */

import type { AttackPattern } from './injection.js';

export const ssrf = {
  endpoints: [
    { pattern: /https?:\/\/(?:169\.254\.169\.254|metadata\.google\.internal)(?:[/:?]|$)/i, name: 'Cloud Metadata Endpoint', severity: 'CRITICAL' },
    { pattern: /https?:\/\/(?:localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)(?:[/:?]|$)/i, name: 'Loopback Target', severity: 'HIGH' },
    { pattern: /https?:\/\/(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})(?:[/:?]|$)/i, name: 'RFC1918 Target', severity: 'HIGH' },
    { pattern: /\b(?:file|gopher|smb|ftp|ldap|ldaps|dict|dns):\/\//i, name: 'Dangerous URI Scheme', severity: 'HIGH' },
    { pattern: /https?:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/_-]+/i, name: 'Slack Webhook', severity: 'MEDIUM' },
    { pattern: /https?:\/\/(?:discord\.com|discordapp\.com)\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/i, name: 'Discord Webhook', severity: 'MEDIUM' },
    { pattern: /https?:\/\/outlook\.office\.com\/webhook\/[A-Za-z0-9/_-]+/i, name: 'Teams Webhook', severity: 'MEDIUM' },
    { pattern: /https?:\/\/(?:169\.254\.169\.254|fd00:ec2::254)(?:[/:?]|$)/i, name: 'AWS/ECS Metadata', severity: 'CRITICAL' },
    { pattern: /https?:\/\/(?:169\.254\.169\.254|instance-data)(?:[/:?]|$)/i, name: 'Azure IMDS', severity: 'CRITICAL' },
    { pattern: /https?:\/\/\[(?:fe80:[0-9a-f:%]+)\]/i, name: 'IPv6 Link-Local Target', severity: 'HIGH' },
    { pattern: /\b(?:file|gopher|smb|ftp|ldap|ldaps|dict|dns|mailto|data):\/\//i, name: 'Dangerous URI Scheme', severity: 'HIGH' },
    { pattern: /https?:\/\/(?:localtest|vcap|lvh)\.me/i, name: 'SSRF Bypass Domain', severity: 'HIGH' }
  ],
  cloudMetadata: [
    { pattern: /https?:\/\/169\.254\.169\.254(?:[/:?]|$)/i, name: 'AWS Metadata Service', severity: 'CRITICAL' },
    { pattern: /https?:\/\/(?:instance-data|metadata)\.ec2\.(?:internal|amazonaws\.com)(?:[/:?]|$)/i, name: 'AWS Metadata Domain', severity: 'CRITICAL' },
    { pattern: /https?:\/\/metadata\.google\.internal(?:[/:?]|$)/i, name: 'GCP Metadata Service', severity: 'CRITICAL' },
    { pattern: /https?:\/\/metadata(?:\.googleapis)?\.com(?:[/:?]|$)/i, name: 'GCP Metadata Domain', severity: 'CRITICAL' },
    { pattern: /https?:\/\/169\.254\.169\.254\/metadata\/instance(?:[/:?]|$)/i, name: 'Azure Metadata Service', severity: 'CRITICAL' },
    { pattern: /https?:\/\/169\.254\.169\.254\/metadata\/v1(?:[/:?]|$)/i, name: 'DigitalOcean Metadata', severity: 'CRITICAL' },
    { pattern: /https?:\/\/169\.254\.169\.254\/opc\/v[12](?:[/:?]|$)/i, name: 'Oracle Cloud Metadata', severity: 'CRITICAL' }
  ],
  loopback: [
    { pattern: /https?:\/\/(?:localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)(?:[:\/?]|$)/i, name: 'Loopback Address', severity: 'HIGH' },
    { pattern: /https?:\/\/(?:0x7f000001|0x0\.0x0\.0x0\.0x1|017700000001)(?:[:\/?]|$)/i, name: 'Encoded Loopback', severity: 'HIGH' },
    { pattern: /https?:\/\/(?:127\.1|127\.0\.1)(?:[:\/?]|$)/i, name: 'Short Loopback', severity: 'HIGH' }
  ],
  privateNetworks: [
    { pattern: /https?:\/\/10\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:[:\/?]|$)/i, name: 'Private Network 10.x.x.x', severity: 'HIGH' },
    { pattern: /https?:\/\/172\.(?:1[6-9]|2[0-9]|3[01])\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:[:\/?]|$)/i, name: 'Private Network 172.16-31.x.x', severity: 'HIGH' },
    { pattern: /https?:\/\/192\.168\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:[:\/?]|$)/i, name: 'Private Network 192.168.x.x', severity: 'HIGH' }
  ],
  specialAddresses: [
    { pattern: /https?:\/\/169\.254\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:[:\/?]|$)/i, name: 'Link-Local Address', severity: 'HIGH' },
    { pattern: /https?:\/\/2(?:2[4-9]|3[0-9])\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:[:\/?]|$)/i, name: 'Multicast Address', severity: 'MEDIUM' },
    { pattern: /https?:\/\/\[(?:::1|::ffff:127\.0\.0\.1|fe80::|fc00::)\](?:[:\/?]|$)/i, name: 'IPv6 Local Address', severity: 'HIGH' }
  ],
  dangerousSchemes: [
    { pattern: /\bfile:\/\/[^\s]*/i, name: 'File URI Scheme', severity: 'CRITICAL' },
    { pattern: /\bftp:\/\/[^\s]*/i, name: 'FTP URI Scheme', severity: 'HIGH' },
    { pattern: /\bgopher:\/\/[^\s]*/i, name: 'Gopher URI Scheme', severity: 'HIGH' },
    { pattern: /\bdict:\/\/[^\s]*/i, name: 'Dict URI Scheme', severity: 'HIGH' },
    { pattern: /\bldaps?:\/\/[^\s]*/i, name: 'LDAP URI Scheme', severity: 'HIGH' },
    { pattern: /\bsmb:\/\/[^\s]*/i, name: 'SMB URI Scheme', severity: 'HIGH' },
    { pattern: /\btftp:\/\/[^\s]*/i, name: 'TFTP URI Scheme', severity: 'HIGH' },
    { pattern: /\btelnet:\/\/[^\s]*/i, name: 'Telnet URI Scheme', severity: 'HIGH' },
    { pattern: /\bssh:\/\/[^\s]*/i, name: 'SSH URI Scheme', severity: 'HIGH' },
    { pattern: /\bjdbc:[^\s]*/i, name: 'JDBC URI Scheme', severity: 'HIGH' }
  ],
  internalServices: [
    { pattern: /https?:\/\/[^\/\s]+:(?:8080|8443|9090|9200|5601|3000|8088|8888)(?:[\/\?]|$)/i, name: 'Common Admin Port', severity: 'HIGH' },
    { pattern: /https?:\/\/[^\/\s]+:(?:3306|5432|1433|1521|27017|6379|11211)(?:[\/\?]|$)/i, name: 'Database Port', severity: 'HIGH' },
    { pattern: /https?:\/\/[^\/\s]+:(?:2375|2376|2377|4243|4244|6443|10250|10255)(?:[\/\?]|$)/i, name: 'Container/K8s Port', severity: 'CRITICAL' },
    { pattern: /https?:\/\/(?:admin|internal|intranet|staging|dev|test|localhost|backend|api-internal|db|database)(?:\.[a-z0-9.-]+)?(?:[:\/?]|$)/i, name: 'Internal Hostname', severity: 'HIGH' }
  ],
  cloudServices: [
    { pattern: /https?:\/\/kubernetes\.default\.svc\.cluster\.local(?:[:\/?]|$)/i, name: 'Kubernetes API', severity: 'CRITICAL' },
    { pattern: /https?:\/\/[^\/\s]*\.kubernetes\.io(?:[:\/?]|$)/i, name: 'Kubernetes Domain', severity: 'HIGH' },
    { pattern: /unix:\/\/\/var\/run\/docker\.sock/i, name: 'Docker Socket', severity: 'CRITICAL' },
    { pattern: /https?:\/\/[^\/\s]*:8500(?:[\/\?]|$)/i, name: 'Consul API', severity: 'HIGH' },
    { pattern: /https?:\/\/[^\/\s]*:8200(?:[\/\?]|$)/i, name: 'Vault API', severity: 'HIGH' }
  ],
  exfiltrationEndpoints: [
    { pattern: /https?:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9\/_-]+/i, name: 'Slack Webhook', severity: 'MEDIUM' },
    { pattern: /https?:\/\/(?:discord\.com|discordapp\.com)\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/i, name: 'Discord Webhook', severity: 'MEDIUM' },
    { pattern: /https?:\/\/api\.telegram\.org\/bot\d+/i, name: 'Telegram Bot API', severity: 'MEDIUM' },
    { pattern: /https?:\/\/(?:pastebin\.com|hastebin\.com|paste\.ee|dpaste\.de|0bin\.net)(?:[\/\?]|$)/i, name: 'Pastebin Service', severity: 'MEDIUM' },
    { pattern: /https?:\/\/(?:transfer\.sh|file\.io|anonfiles\.com|ufile\.io)(?:[\/\?]|$)/i, name: 'File Sharing Service', severity: 'MEDIUM' },
    { pattern: /https?:\/\/[^\/\s]*\.(?:burpcollaborator\.net|interact\.sh|canarytokens\.com)(?:[\/\?]|$)/i, name: 'DNS Exfiltration Service', severity: 'HIGH' }
  ],
  encodingBypass: [
    { pattern: /https?:\/\/0x[a-f0-9]{8}(?:[:\/?]|$)/i, name: 'Hex Encoded IP', severity: 'HIGH' },
    { pattern: /https?:\/\/0[0-7]{9,12}(?:[:\/?]|$)/i, name: 'Octal Encoded IP', severity: 'HIGH' },
    { pattern: /https?:\/\/[0-9]{8,10}(?:[:\/?]|$)/i, name: 'Integer Encoded IP', severity: 'HIGH' },
    { pattern: /https?:\/\/[^\/\s]*%[0-9a-f]{2}[^\/\s]*(?:[:\/?]|$)/i, name: 'URL Encoded Hostname', severity: 'MEDIUM' },
    { pattern: /https?:\/\/[^\/\s]*[\u0080-\uffff][^\/\s]*(?:[:\/?]|$)/i, name: 'Unicode Hostname', severity: 'MEDIUM' }
  ],
  redirectServices: [
    { pattern: /https?:\/\/(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|short\.link|rebrand\.ly|ow\.ly|buff\.ly)\/[^\s]*$/i, name: 'URL Shortener', severity: 'MEDIUM' },
    { pattern: /https?:\/\/[^\/\s]*\/(?:redirect|r|go|link|url|redir)[\?\&][^\s]*$/i, name: 'Redirect Endpoint', severity: 'MEDIUM' }
  ]
} as const satisfies Record<string, AttackPattern[]>;

export const lolbins = {
  tools: [
    { pattern: /\bpowershell(?:\.exe)?\b.*\s-(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}/i, name: 'PowerShell EncodedCommand', severity: 'CRITICAL' },
    { pattern: /\bIEX\s*\(\s*(?:IWR|Invoke-?WebRequest|Invoke-?Expression)/i, name: 'PowerShell IEX+IWR', severity: 'CRITICAL' },
    { pattern: /\bcertutil(?:\.exe)?\b.*-urlcache\b.*-split\b.*-f\b/i, name: 'Certutil Download', severity: 'HIGH' },
    { pattern: /\bbitsadmin(?:\.exe)?\b.*\/transfer\b/i, name: 'BITSAdmin Transfer', severity: 'HIGH' },
    { pattern: /\bmshta(?:\.exe)?\b/i, name: 'MSHTA Execution', severity: 'HIGH' },
    { pattern: /\brundll32(?:\.exe)?\b.*(?:javascript:|http)/i, name: 'Rundll32 Script/URL', severity: 'HIGH' },
    { pattern: /\bregsvr32(?:\.exe)?\b.*\s\/i:\s*https?:\/\//i, name: 'Regsvr32 Scriptlet', severity: 'HIGH' },
    { pattern: /\bwmic\b.*process\s+call\s+create/i, name: 'WMIC Process Create', severity: 'HIGH' },
    { pattern: /\bmsiexec(?:\.exe)?\b.*\s\/i\s+https?:\/\//i, name: 'MSI Remote Install', severity: 'HIGH' },
    { pattern: /\b(?:bash|sh)\s+-c\s+/i, name: 'Shell -c', severity: 'HIGH' },
    { pattern: /\/dev\/tcp\/[A-Za-z0-9\.\-]+\/\d+/i, name: 'Bash TCP Exfil', severity: 'HIGH' },
    { pattern: /\bmkfifo\b.*\|\s*(?:sh|bash)\s*-i\s*\|\s*(?:nc|ncat|netcat)\b/i, name: 'FIFO + NC Reverse Shell', severity: 'CRITICAL' },
    { pattern: /\bInstallUtil(?:\.exe)?\b.*\s\/logfile=/i, name: 'InstallUtil Abuse', severity: 'HIGH' },
    { pattern: /\brundll32(?:\.exe)?\b.*\s+javascript:/i, name: 'Rundll32 JavaScript Execution', severity: 'HIGH' }
  ]
} as const satisfies Record<string, AttackPattern[]>;

export const csv = {
  formula: [
    { pattern: /[\u0009\u0020]*[=+\-@]/, name: 'CSV Formula Sigil', severity: 'HIGH' },
    { pattern: /[\u0009\u0020]*["']?[=+\-@].*/i, name: 'CSV Formula (Quoted)', severity: 'HIGH' }
  ],
  payloads: [
    { pattern: /=["']?cmd\|/i, name: 'CSV CMD Pipe', severity: 'HIGH' }
  ]
} as const satisfies Record<string, AttackPattern[]>;
