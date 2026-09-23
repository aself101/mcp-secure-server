/**
 * The size of a value as JSON, in UTF-8 bytes — the unit every size limit in
 * this package is documented in (maxMessageSize, maxParamBytes,
 * suspiciousMessageSize, maxArgsSize, maxEgressBytes).
 *
 * Until 0.0.23-security each check measured `JSON.stringify(x).length`, which
 * is UTF-16 code units and under-counts non-ASCII by up to 3x: 9,000 CJK
 * characters measured ~9,100 against a real ~27,000 bytes. Every enforcing
 * size check and every reported size now goes through this one function, so
 * a fix to the measurement cannot again reach some checks and miss others.
 *
 * @throws when the value cannot be serialized (circular reference, BigInt)
 */
export function serializedByteLength(value: unknown): number {
  return Buffer.byteLength(JSON.stringify(value) ?? '', 'utf8');
}
