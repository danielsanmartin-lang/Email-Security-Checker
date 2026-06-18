// Sanitize untrusted strings before inserting via innerHTML to prevent XSS.
// Implementación sin DOM: funciona en navegador y en Node (tests), y escapa también
// comillas (seguro para contextos de atributo como data-tooltip/title).
const _HTML_ESCAPES = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
};
export function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str).replace(/[&<>"']/g, ch => _HTML_ESCAPES[ch]);
}

/**
 * Extrae el valor de un registro TXT de la respuesta DoH.
 * El campo `data` puede venir como varias cadenas entrecomilladas concatenadas
 * (p. ej. `"v=spf1 ..." "..."`) o con comillas simples. Concatena todas las partes.
 */
export function extractTxtValue(data) {
    if (!data) return '';
    const matches = [...data.matchAll(/"([^"\\]*(?:\\.[^"\\]*)*)"/g)];
    if (matches.length > 0) return matches.map(m => m[1]).join('');
    return data.replace(/"/g, '');
}

export function parseSPF(raw) {
    if (!raw) return [];
    const tokens = raw.split(/\s+/);
    const entries = [];
    for (const token of tokens) {
        if (token === 'v=spf1') {
            entries.push({ prefix: '', type: 'v', value: 'spf1', qualifier: '' });
            continue;
        }
        let qualifier = '+';
        let t = token;
        if (/^[+\-~?]/.test(t)) { qualifier = t[0]; t = t.substring(1); }
        
        if (t.startsWith('include:')) {
            entries.push({ prefix: qualifier, type: 'include', value: t.substring(8), qualifier });
        } else if (t.startsWith('a:')) {
            entries.push({ prefix: qualifier, type: 'a', value: t.substring(2), qualifier });
        } else if (t.startsWith('mx:')) {
            entries.push({ prefix: qualifier, type: 'mx', value: t.substring(3), qualifier });
        } else if (t.startsWith('ip4:')) {
            entries.push({ prefix: qualifier, type: 'ip4', value: t.substring(4), qualifier });
        } else if (t.startsWith('ip6:')) {
            entries.push({ prefix: qualifier, type: 'ip6', value: t.substring(4), qualifier });
        } else if (t.startsWith('redirect=')) {
            entries.push({ prefix: qualifier, type: 'redirect', value: t.substring(9), qualifier });
        } else if (t.startsWith('exists:')) {
            entries.push({ prefix: qualifier, type: 'exists', value: t.substring(7), qualifier });
        } else if (t === 'a') {
            entries.push({ prefix: qualifier, type: 'a', value: '(self)', qualifier });
        } else if (t === 'mx') {
            entries.push({ prefix: qualifier, type: 'mx', value: '(self)', qualifier });
        } else if (t === 'all') {
            entries.push({ prefix: qualifier, type: 'all', value: '', qualifier });
        } else if (t === 'ptr') {
            entries.push({ prefix: qualifier, type: 'ptr', value: '', qualifier });
        } else if (t.startsWith('ptr:')) {
            entries.push({ prefix: qualifier, type: 'ptr', value: t.substring(4), qualifier });
        }
    }
    return entries;
}

export function parseDMARC(raw) {
    if (!raw) return null;
    const result = {};
    const tags = raw.split(';').map(s => s.trim()).filter(Boolean);
    for (const tag of tags) {
        const eq = tag.indexOf('=');
        if (eq > 0) {
            result[tag.substring(0, eq).trim()] = tag.substring(eq + 1).trim();
        }
    }
    return result;
}

/** Parse RFC 8461 MTA-STS policy file (https://mta-sts.domain/.well-known/mta-sts.txt) */
export function parseMTASTSPolicy(text) {
    if (!text || typeof text !== 'string') return null;
    const result = { mx: [] };
    for (const line of text.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const colon = trimmed.indexOf(':');
        if (colon === -1) continue;
        const key = trimmed.substring(0, colon).trim().toLowerCase();
        const value = trimmed.substring(colon + 1).trim();
        if (key === 'mx') {
            result.mx.push(value);
        } else {
            result[key] = value;
        }
    }
    if (!result.version && !result.mode && result.mx.length === 0) return null;
    return result;
}

/**
 * Validate fetched MTA-STS policy: HTTP 200, version STSv1, mode enforce.
 * @param {{ httpStatus: number|null, parsed: object|null }} policyFetch
 */
export function validateMTASTSPolicy(policyFetch) {
    if (!policyFetch || policyFetch.httpStatus !== 200) {
        return {
            valid: false,
            reason: policyFetch?.httpStatus ? 'http_status' : 'fetch_failed',
            mode: policyFetch?.parsed?.mode
                ? String(policyFetch.parsed.mode).toLowerCase()
                : policyFetch?.mode || null
        };
    }
    const parsed = policyFetch.parsed;
    if (!parsed) {
        return { valid: false, reason: 'parse_error', mode: null };
    }
    const version = parsed.version ? String(parsed.version).toUpperCase() : '';
    if (version !== 'STSV1') {
        return {
            valid: false,
            reason: 'invalid_version',
            mode: parsed.mode ? String(parsed.mode).toLowerCase() : null
        };
    }
    const mode = parsed.mode ? String(parsed.mode).toLowerCase() : '';
    if (mode !== 'enforce') {
        return {
            valid: false,
            reason: mode ? 'mode_not_enforce' : 'missing_mode',
            mode: mode || null
        };
    }
    return { valid: true, reason: null, mode: 'enforce' };
}
