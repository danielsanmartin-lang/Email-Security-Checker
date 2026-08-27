// Shared utility helpers
import { escapeHtml } from './parsers.js';

/**
 * Marca un fragmento como HTML ya seguro (no se volverá a escapar al interpolarlo
 * dentro de un template html``). Úsalo solo con HTML que tú controlas.
 */
export class SafeHtml {
    constructor(value) {
        this.value = value == null ? '' : String(value);
    }
    toString() {
        return this.value;
    }
}

export function raw(value) {
    return new SafeHtml(value);
}

function renderValue(v) {
    if (v == null || v === false) return '';
    if (v instanceof SafeHtml) return v.value;
    if (Array.isArray(v)) return v.map(renderValue).join('');
    return escapeHtml(v);
}

/**
 * Tagged template que escapa AUTOMÁTICAMENTE cada interpolación (XSS-safe por defecto).
 * - Strings/números se escapan.
 * - Valores envueltos en raw()/SafeHtml o producidos por otro html`` no se re-escapan.
 * - Arrays se renderizan concatenando cada elemento con la misma regla.
 * Devuelve un SafeHtml; al asignarlo a innerHTML o a `${}` se coacciona a string vía toString().
 *
 * Ejemplo:
 *   el.innerHTML = html`<span>${userValue}</span>`;            // userValue escapado
 *   const row = html`<tr>${cells.map(c => html`<td>${c}</td>`)}</tr>`; // anidado seguro
 */
export function html(strings, ...values) {
    let out = strings[0];
    for (let i = 0; i < values.length; i++) {
        out += renderValue(values[i]) + strings[i + 1];
    }
    return new SafeHtml(out);
}


/**
 * Normaliza la entrada del usuario a un nombre de dominio limpio.
 * Acepta direcciones de correo, URLs con esquema, prefijo www y rutas.
 * @param {string} input
 * @returns {string} dominio en minúsculas sin esquema, www, ruta ni email local-part
 */
export function normalizeDomain(input) {
    if (!input) return '';
    let domain = String(input).trim().toLowerCase();
    if (domain.includes('@')) {
        domain = domain.substring(domain.indexOf('@') + 1);
    }
    domain = domain
        .replace(/^https?:\/\//, '')
        .replace(/\/.*$/, '')
        .replace(/:\d+$/, '')
        .replace(/^www\./, '');
    // IDN → punycode (ASCII). La API URL convierte automáticamente dominios con
    // acentos/no-ASCII (p. ej. "café.com" → "xn--caf-dma.com"). Disponible en
    // navegador y en Node. Si falla, se conserva el valor ya saneado.
    try {
        const host = new URL(`http://${domain}`).hostname;
        if (host) domain = host;
    } catch {
        /* entrada no parseable como URL: mantener el valor saneado */
    }
    // Quita el punto final del FQDN absoluto (habitual al copiar de dig/registros
    // DNS): el resto del pipeline ya lo tolera, pero isValidDomain lo rechazaría.
    domain = domain.replace(/\.+$/, '');
    return domain;
}

/**
 * Valida que una cadena tenga forma de nombre de dominio (ASCII/punycode) con al
 * menos un punto (un TLD). No comprueba existencia en DNS.
 * @param {string} domain
 * @returns {boolean}
 */
export function isValidDomain(domain) {
    if (!domain || typeof domain !== 'string') return false;
    if (domain.length > 253) return false;
    return /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i.test(domain);
}

/**
 * Valida un selector DKIM. Es una etiqueta DNS (o varias separadas por puntos, p. ej.
 * `mimecast20230101` o `s1024._dkim`), así que se admiten letras, dígitos, guion,
 * guion bajo y punto, sin empezar ni acabar por separador.
 * @param {string} selector
 * @returns {boolean}
 */
export function isValidDkimSelector(selector) {
    if (!selector || typeof selector !== 'string') return false;
    if (selector.length > 63) return false;
    return /^[a-z0-9](?:[a-z0-9._-]{0,61}[a-z0-9])?$/i.test(selector);
}

/**
 * Normaliza la entrada del campo DKIM: acepta uno o varios selectores separados por
 * comas (o espacios) y devuelve solo los que tienen forma válida, en minúsculas y
 * sin duplicados. Una entrada vacía o completamente inválida devuelve [].
 * @param {string} input
 * @returns {string[]}
 */
export function parseDkimSelectors(input) {
    if (!input) return [];
    const parts = String(input).split(/[,\s]+/).map(s => s.trim().toLowerCase()).filter(Boolean);
    return [...new Set(parts.filter(isValidDkimSelector))];
}

export function extractRootDomain(hostname) {
    if (!hostname) return '';
    const parts = hostname.split('.');
    if (parts.length <= 2) return hostname;
    const tld = parts[parts.length - 1];
    const sld = parts[parts.length - 2];
    // Explicit list of known compound TLDs (second-level domains that act as TLD)
    // Avoids the fragile length heuristic that breaks on e.g. ".info.tr", ".name.tr"
    const COMPOUND_TLDS = new Set([
        // United Kingdom
        'co.uk', 'org.uk', 'me.uk', 'net.uk', 'ac.uk', 'gov.uk', 'ltd.uk', 'plc.uk',
        // Australia
        'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'asn.au', 'id.au',
        // Brazil
        'com.br', 'net.br', 'org.br', 'edu.br', 'gov.br', 'mil.br',
        // Spain
        'com.es', 'org.es', 'nom.es', 'edu.es', 'gob.es',
        // Argentina
        'com.ar', 'net.ar', 'org.ar', 'edu.ar', 'gov.ar', 'mil.ar',
        // Mexico
        'com.mx', 'net.mx', 'org.mx', 'edu.mx', 'gob.mx',
        // Colombia
        'com.co', 'net.co', 'org.co', 'edu.co', 'gov.co', 'mil.co',
        // Peru
        'com.pe', 'net.pe', 'org.pe', 'edu.pe', 'gob.pe', 'mil.pe',
        // New Zealand
        'co.nz', 'net.nz', 'org.nz', 'geek.nz', 'gen.nz', 'ac.nz', 'govt.nz',
        // Singapore
        'com.sg', 'net.sg', 'org.sg', 'edu.sg', 'gov.sg',
        // Hong Kong
        'com.hk', 'net.hk', 'org.hk', 'edu.hk', 'gov.hk',
        // Japan
        'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp', 'ad.jp',
        // South Africa
        'co.za', 'org.za', 'net.za', 'edu.za', 'gov.za', 'ac.za',
        // India
        'co.in', 'net.in', 'org.in', 'edu.in', 'gov.in', 'ac.in', 'res.in',
        // Israel
        'co.il', 'net.il', 'org.il', 'ac.il', 'gov.il',
        // South Korea
        'co.kr', 'ne.kr', 'or.kr', 're.kr', 'pe.kr', 'ac.kr', 'go.kr',
        // Turkey
        'com.tr', 'net.tr', 'org.tr', 'edu.tr', 'gov.tr', 'info.tr', 'name.tr', 'biz.tr',
        // Portugal
        'com.pt', 'net.pt', 'org.pt', 'edu.pt', 'gov.pt',
        // Poland
        'com.pl', 'net.pl', 'org.pl', 'edu.pl', 'gov.pl',
        // China
        'com.cn', 'net.cn', 'org.cn', 'edu.cn', 'gov.cn', 'ac.cn',
        // Russia
        'com.ru', 'net.ru', 'org.ru', 'edu.ru', 'gov.ru',
        // Ukraine
        'com.ua', 'net.ua', 'org.ua', 'edu.ua', 'gov.ua',
        // Romania
        'com.ro', 'org.ro', 'net.ro', 'edu.ro', 'gov.ro',
        // Chile
        'com.cl', 'net.cl', 'org.cl', 'gov.cl',
        // Venezuela
        'com.ve', 'net.ve', 'org.ve', 'edu.ve', 'gov.ve',
    ]);
    const possibleCompound = `${sld}.${tld}`;
    if (COMPOUND_TLDS.has(possibleCompound)) {
        return parts.slice(-3).join('.');
    }
    // Fallback heuristic for unknown compound TLDs: short SLD (≤3 chars) + 2-char TLD
    if (tld.length === 2 && sld.length <= 3) {
        return parts.slice(-3).join('.');
    }
    return parts.slice(-2).join('.');
}
