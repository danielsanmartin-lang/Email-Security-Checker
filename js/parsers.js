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

// Cada entry lleva `index` = su posición dentro del registro. Sin él no se puede
// detectar que hay mecanismos DESPUÉS de `all` (inalcanzables: el evaluador para en
// el primer match, RFC 7208 §5.1) ni distinguir el primer `all` de los siguientes.
export function parseSPF(raw) {
    if (!raw) return [];
    const tokens = raw.split(/\s+/);
    const entries = [];
    const push = (entry) => entries.push({ ...entry, index: entries.length });
    for (const token of tokens) {
        if (token === 'v=spf1') {
            push({ prefix: '', type: 'v', value: 'spf1', qualifier: '' });
            continue;
        }
        let qualifier = '+';
        let t = token;
        if (/^[+\-~?]/.test(t)) { qualifier = t[0]; t = t.substring(1); }
        
        if (t.startsWith('include:')) {
            push({ prefix: qualifier, type: 'include', value: t.substring(8), qualifier });
        } else if (t.startsWith('a:')) {
            push({ prefix: qualifier, type: 'a', value: t.substring(2), qualifier });
        } else if (t.startsWith('mx:')) {
            push({ prefix: qualifier, type: 'mx', value: t.substring(3), qualifier });
        } else if (t.startsWith('ip4:')) {
            push({ prefix: qualifier, type: 'ip4', value: t.substring(4), qualifier });
        } else if (t.startsWith('ip6:')) {
            push({ prefix: qualifier, type: 'ip6', value: t.substring(4), qualifier });
        } else if (t.startsWith('redirect=')) {
            push({ prefix: qualifier, type: 'redirect', value: t.substring(9), qualifier });
        } else if (t.startsWith('exists:')) {
            push({ prefix: qualifier, type: 'exists', value: t.substring(7), qualifier });
        } else if (t === 'a') {
            push({ prefix: qualifier, type: 'a', value: '(self)', qualifier });
        } else if (t === 'mx') {
            push({ prefix: qualifier, type: 'mx', value: '(self)', qualifier });
        } else if (t === 'all') {
            push({ prefix: qualifier, type: 'all', value: '', qualifier });
        } else if (t === 'ptr') {
            push({ prefix: qualifier, type: 'ptr', value: '', qualifier });
        } else if (t.startsWith('ptr:')) {
            push({ prefix: qualifier, type: 'ptr', value: t.substring(4), qualifier });
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

/** Extrae max_age (segundos) de una política MTA-STS parseada; null si ausente/ inválido. */
export function parseMaxAge(parsed) {
    if (!parsed || parsed.max_age == null) return null;
    const n = parseInt(String(parsed.max_age).trim(), 10);
    return Number.isFinite(n) ? n : null;
}

/**
 * Validate fetched MTA-STS policy: HTTP 200, version STSv1, mode enforce.
 * Nota: `max_age` NO afecta a la validez aquí (se expone como `maxAge` para que la
 * capa de scoring emita un aviso si falta o es muy bajo, sin invalidar la política).
 * @param {{ httpStatus: number|null, parsed: object|null }} policyFetch
 */
export function validateMTASTSPolicy(policyFetch) {
    const maxAge = parseMaxAge(policyFetch?.parsed);
    if (!policyFetch || policyFetch.httpStatus !== 200) {
        return {
            valid: false,
            reason: policyFetch?.httpStatus ? 'http_status' : 'fetch_failed',
            mode: policyFetch?.parsed?.mode
                ? String(policyFetch.parsed.mode).toLowerCase()
                : policyFetch?.mode || null,
            maxAge
        };
    }
    const parsed = policyFetch.parsed;
    if (!parsed) {
        return { valid: false, reason: 'parse_error', mode: null, maxAge };
    }
    const version = parsed.version ? String(parsed.version).toUpperCase() : '';
    if (version !== 'STSV1') {
        return {
            valid: false,
            reason: 'invalid_version',
            mode: parsed.mode ? String(parsed.mode).toLowerCase() : null,
            maxAge
        };
    }
    const mode = parsed.mode ? String(parsed.mode).toLowerCase() : '';
    if (mode !== 'enforce') {
        return {
            valid: false,
            reason: mode ? 'mode_not_enforce' : 'missing_mode',
            mode: mode || null,
            maxAge
        };
    }
    return { valid: true, reason: null, mode: 'enforce', maxAge };
}

// ===== Análisis de registro DKIM (fuerza de clave, algoritmo, revocación) =====

const _B64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/** Decodifica base64 a array de bytes (sin depender de atob/Buffer, portable navegador+Node). */
function _b64ToBytes(b64) {
    const clean = String(b64).replace(/[^A-Za-z0-9+/]/g, '');
    const bytes = [];
    let buffer = 0;
    let bits = 0;
    for (const ch of clean) {
        const val = _B64_ALPHABET.indexOf(ch);
        if (val < 0) continue;
        buffer = (buffer << 6) | val;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            bytes.push((buffer >> bits) & 0xff);
        }
    }
    return bytes;
}

function _readDerLen(bytes, i) {
    let len = bytes[i++];
    if (len & 0x80) {
        const n = len & 0x7f;
        len = 0;
        for (let k = 0; k < n; k++) len = (len << 8) | bytes[i++];
    }
    return { len, next: i };
}

/**
 * Devuelve la longitud en bits del módulo RSA a partir de un SubjectPublicKeyInfo DER.
 * Recorre: SEQ { SEQ(algId) , BITSTRING { SEQ { INTEGER(modulus), INTEGER(exp) } } }.
 * @returns {number|null} bits del módulo, o null si no se pudo parsear.
 */
export function rsaModulusBits(spkiBytes) {
    try {
        let i = 0;
        if (spkiBytes[i++] !== 0x30) return null; // SEQUENCE (SPKI)
        ({ next: i } = _readDerLen(spkiBytes, i));
        if (spkiBytes[i++] !== 0x30) return null; // SEQUENCE (AlgorithmIdentifier)
        const algInfo = _readDerLen(spkiBytes, i);
        i = algInfo.next + algInfo.len; // saltar el algoritmo
        if (spkiBytes[i++] !== 0x03) return null; // BIT STRING
        ({ next: i } = _readDerLen(spkiBytes, i));
        i += 1; // byte de bits no usados
        if (spkiBytes[i++] !== 0x30) return null; // SEQUENCE (RSAPublicKey)
        ({ next: i } = _readDerLen(spkiBytes, i));
        if (spkiBytes[i++] !== 0x02) return null; // INTEGER (modulus)
        let modLen;
        ({ len: modLen, next: i } = _readDerLen(spkiBytes, i));
        // Quitar el byte 0x00 de signo si está presente
        if (spkiBytes[i] === 0x00) modLen -= 1;
        return modLen > 0 ? modLen * 8 : null;
    } catch {
        return null;
    }
}

/**
 * Analiza un registro DKIM (v=DKIM1; k=...; p=...; t=...).
 * @returns {{ revoked: boolean, algorithm: string, keyBits: number|null, testing: boolean }}
 */
export function analyzeDKIMRecord(record) {
    const tags = {};
    for (const part of String(record || '').split(';')) {
        const eq = part.indexOf('=');
        if (eq > 0) tags[part.substring(0, eq).trim().toLowerCase()] = part.substring(eq + 1).trim();
    }
    const algorithm = (tags.k || 'rsa').toLowerCase();
    const flags = (tags.t || '').toLowerCase().split(':').map(s => s.trim());
    const testing = flags.includes('y');
    const p = tags.p !== undefined ? tags.p.replace(/\s+/g, '') : undefined;

    // p= vacío ⇒ clave revocada (RFC 6376 §3.6.1)
    if (p === '') {
        return { revoked: true, algorithm, keyBits: null, testing, malformed: false };
    }

    let keyBits = null;
    let malformed = false;
    if (p && algorithm === 'rsa') {
        keyBits = rsaModulusBits(_b64ToBytes(p));
    } else if (p && algorithm === 'ed25519') {
        // Ed25519 (RFC 8463): p= es la clave pública EN CRUDO (32 bytes), no un
        // SubjectPublicKeyInfo DER como en RSA. Su fuerza equivale a ~3000 bits de
        // RSA, así que no se le puede aplicar el umbral de "clave débil <1024".
        const bytes = _b64ToBytes(p);
        if (bytes.length === 32) {
            keyBits = 256;
        } else {
            malformed = true;
        }
    }
    return { revoked: false, algorithm, keyBits, testing, malformed };
}

/**
 * Valida los destinos de informe TLS-RPT (RFC 8460 §3): cada URI de `rua` debe ser
 * `mailto:` o `https://`. Un destino con otro esquema (o vacío) hace que los
 * informes de fallo TLS no lleguen a ninguna parte.
 * @param {string[]} ruaList
 * @returns {{ valid: string[], invalid: string[] }}
 */
export function validateTlsRptRua(ruaList) {
    const valid = [];
    const invalid = [];
    for (const raw of ruaList || []) {
        const uri = String(raw || '').trim();
        if (!uri) continue;
        if (/^mailto:[^@\s]+@[^\s]+$/i.test(uri) || /^https:\/\/\S+$/i.test(uri)) {
            valid.push(uri);
        } else {
            invalid.push(uri);
        }
    }
    return { valid, invalid };
}

/**
 * Comprueba que cada MX real está cubierto por la lista `mx:` de la política MTA-STS
 * (RFC 8461 §4.1). Un patrón puede ser un hostname exacto o un comodín `*.dominio`,
 * donde `*` sustituye EXACTAMENTE a una etiqueta.
 * Es el fallo más común de MTA-STS: la política se queda obsoleta tras un cambio de
 * proveedor y el correo entrante empieza a rebotar en los MTA que la aplican.
 * @param {string[]} policyMx  entradas `mx:` de la política
 * @param {string[]} mxHosts   hostnames MX reales publicados en DNS
 * @returns {{ uncovered: string[], covered: string[], unused: string[] }}
 */
export function checkMtaStsMxCoverage(policyMx, mxHosts) {
    const patterns = (policyMx || []).map(p => String(p).trim().toLowerCase().replace(/\.$/, '')).filter(Boolean);
    const hosts = (mxHosts || []).map(h => String(h).trim().toLowerCase().replace(/\.$/, '')).filter(Boolean);

    const matches = (pattern, host) => {
        if (pattern === host) return true;
        if (!pattern.startsWith('*.')) return false;
        const suffix = pattern.slice(1); // ".dominio"
        if (!host.endsWith(suffix)) return false;
        const label = host.slice(0, host.length - suffix.length);
        // El comodín cubre una sola etiqueta: "*.example.com" casa con "mx.example.com"
        // pero no con "a.mx.example.com" ni con "example.com".
        return label.length > 0 && !label.includes('.');
    };

    const covered = hosts.filter(h => patterns.some(p => matches(p, h)));
    const uncovered = hosts.filter(h => !patterns.some(p => matches(p, h)));
    const unused = patterns.filter(p => !hosts.some(h => matches(p, h)));
    return { uncovered, covered, unused };
}
