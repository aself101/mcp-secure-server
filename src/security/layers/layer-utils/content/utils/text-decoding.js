// Text and URI decoding utilities

export const normalizeWhitespace = (input) => {
    return input
        .replace(/[\u00A0\u1680\u2000-\u200A\u202F\u205F\u3000]/g, ' ') // Various Unicode spaces
        .replace(/[\u2028\u2029]/g, '\n')   // Line/paragraph separators
        .replace(/[\u0009\u000B\u000C]/g, ' '); // Tab, vertical tab, form feed
}

export const decodeSingleUrlEncoding = (input) => {
    let decoded = input;
    let changesMade = false;

    // Target the specific dangerous characters that are commonly URL encoded in attacks
    const singleEncodingMap = {
        '%3C': '<',    // Less than (script tags)
        '%3c': '<',    // Case insensitive
        '%3E': '>',    // Greater than (script tags)
        '%3e': '>',    // Case insensitive
        '%22': '"',    // Double quote (attribute attacks)
        '%27': "'",    // Single quote (attribute attacks)
        '%2F': '/',    // Forward slash (path attacks)
        '%2f': '/',    // Case insensitive
        '%5C': '\\',   // Backslash (path attacks)
        '%5c': '\\',   // Case insensitive
        '%20': ' ',    // Space (common in attacks)
        '%28': '(',    // Left parenthesis (function calls)
        '%29': ')',    // Right parenthesis (function calls)
        '%3B': ';',    // Semicolon (command injection)
        '%3b': ';',    // Case insensitive
        '%26': '&',    // Ampersand (entity references)
        '%3D': '=',    // Equals (assignment attacks)
        '%3d': '=',    // Case insensitive
        '%2B': '+',    // Plus (sometimes used in attacks)
        '%2b': '+',    // Case insensitive
        '%7C': '|',    // Pipe (command chaining)
        '%7c': '|'     // Case insensitive
    };

    // Apply the single encoding conversions
    for (const [encoded, decoded_char] of Object.entries(singleEncodingMap)) {
        if (decoded.includes(encoded)) {
            const beforeReplace = decoded;
            decoded = decoded.replaceAll(encoded, decoded_char);
            if (decoded !== beforeReplace) changesMade = true;
        }
    }

    return decoded;
}

// Strict, spec-like polyfill (throws URIError on bad input)
export function decodeURIComponentStrict(input) {
    if (input == null) throw new TypeError('decodeURIComponentStrict: input is null/undefined');
    const hex = (c) => {
        const code = c.charCodeAt(0);
        // '0'-'9'
        if (code >= 48 && code <= 57)  return code - 48;
        // 'A'-'F'
        if (code >= 65 && code <= 70)  return code - 55;
        // 'a'-'f'
        if (code >= 97 && code <= 102) return code - 87;
        return -1;
    };

    // Decode consecutive %HH groups into a byte run, then UTF-8 decode that run
    let out = '';
    for (let i = 0; i < input.length; ) {
        const ch = input[i];
        if (ch !== '%') {
            out += ch;
            i += 1;
            continue;
        }

        // Collect a contiguous run of %HH into bytes[]
        const bytes = [];
        while (i < input.length && input[i] === '%') {
            if (i + 2 >= input.length) throw new URIError('Malformed URI: incomplete percent escape');
            const h1 = hex(input[i + 1]);
            const h2 = hex(input[i + 2]);
            if (h1 < 0 || h2 < 0) throw new URIError('Malformed URI: non-hex percent escape');
            bytes.push((h1 << 4) | h2);
            i += 3;
        }
        out += utf8DecodeStrict(bytes);
    }
    return out;
}

// Best-effort variant: decodes valid sequences, preserves malformed ones
export function decodeURIComponentSafe(input) {
    try {
        return decodeURIComponentStrict(input);
    } catch {
        // Strict decode failed - do partial decoding of valid sequences
        return decodeURIPartial(input);
    }
}

// Decode valid percent-encoded sequences, preserve invalid ones
function decodeURIPartial(input) {
    let result = '';
    let i = 0;

    while (i < input.length) {
        if (input[i] === '%' && i + 2 < input.length) {
            const hex = input.slice(i + 1, i + 3);
            if (/^[0-9A-Fa-f]{2}$/.test(hex)) {
                // Valid hex sequence - try to decode it
                try {
                    const decoded = decodeURIComponent(input.slice(i, i + 3));
                    result += decoded;
                    i += 3;
                    continue;
                } catch {
                    // Even valid hex can fail (e.g., incomplete UTF-8)
                    result += input[i];
                    i++;
                    continue;
                }
            }
        }
        // Not a valid percent sequence - preserve as-is
        result += input[i];
        i++;
    }

    return result;
}

// Strict UTF-8 byte decoder (rejects overlongs, surrogates, out-of-range)
function utf8DecodeStrict(bytes) {
    let res = '';
    for (let i = 0; i < bytes.length; ) {
        const b1 = bytes[i++];

        if (b1 <= 0x7F) {
            res += String.fromCharCode(b1);
            continue;
        }

        // 2-byte: 0xC2–0xDF
        if (b1 >= 0xC2 && b1 <= 0xDF) {
            const b2 = mustCont(bytes, i++);
            const cp = ((b1 & 0x1F) << 6) | (b2 & 0x3F);
            res += String.fromCharCode(cp);
            continue;
        }

        // 3-byte
        if (b1 === 0xE0) {
            const b2 = mustIn(bytes, i++, 0xA0, 0xBF); // no overlong
            const b3 = mustCont(bytes, i++);
            const cp = ((b1 & 0x0F) << 12) | ((b2 & 0x3F) << 6) | (b3 & 0x3F);
            res += String.fromCharCode(cp);
            continue;
        }
        if ((b1 >= 0xE1 && b1 <= 0xEC) || (b1 >= 0xEE && b1 <= 0xEF)) {
            const b2 = mustCont(bytes, i++);
            const b3 = mustCont(bytes, i++);
            const cp = ((b1 & 0x0F) << 12) | ((b2 & 0x3F) << 6) | (b3 & 0x3F);
            res += String.fromCharCode(cp);
            continue;
        }
        if (b1 === 0xED) {
            const b2 = mustIn(bytes, i++, 0x80, 0x9F); // forbid surrogates
            const b3 = mustCont(bytes, i++);
            const cp = ((b1 & 0x0F) << 12) | ((b2 & 0x3F) << 6) | (b3 & 0x3F);
            res += String.fromCharCode(cp);
            continue;
        }

        // 4-byte
        if (b1 === 0xF0) {
            const b2 = mustIn(bytes, i++, 0x90, 0xBF); // no overlong
            const b3 = mustCont(bytes, i++);
            const b4 = mustCont(bytes, i++);
            const cp = ((b1 & 0x07) << 18) | ((b2 & 0x3F) << 12) | ((b3 & 0x3F) << 6) | (b4 & 0x3F);
            res += String.fromCodePoint(cp);
            continue;
        }
        if (b1 >= 0xF1 && b1 <= 0xF3) {
            const b2 = mustCont(bytes, i++);
            const b3 = mustCont(bytes, i++);
            const b4 = mustCont(bytes, i++);
            const cp = ((b1 & 0x07) << 18) | ((b2 & 0x3F) << 12) | ((b3 & 0x3F) << 6) | (b4 & 0x3F);
            res += String.fromCodePoint(cp);
            continue;
        }
        if (b1 === 0xF4) {
            const b2 = mustIn(bytes, i++, 0x80, 0x8F); // <= U+10FFFF
            const b3 = mustCont(bytes, i++);
            const b4 = mustCont(bytes, i++);
            const cp = ((b1 & 0x07) << 18) | ((b2 & 0x3F) << 12) | ((b3 & 0x3F) << 6) | (b4 & 0x3F);
            res += String.fromCodePoint(cp);
            continue;
        }

        throw new URIError('Malformed URI: invalid UTF-8 leading byte');
    }
    return res;

    function mustCont(arr, idx) {
        if (idx >= arr.length) throw new URIError('Malformed URI: truncated UTF-8 sequence');
        const b = arr[idx];
        if ((b & 0xC0) !== 0x80) throw new URIError('Malformed URI: expected continuation byte');
        return b;
    }
    function mustIn(arr, idx, lo, hi) {
        if (idx >= arr.length) throw new URIError('Malformed URI: truncated UTF-8 sequence');
        const b = arr[idx];
        if (b < lo || b > hi) throw new URIError('Malformed URI: invalid continuation range');
        return b;
    }
}
