/**
 * lookalike.js
 * Dominios parecidos al auditado (typosquatting): los que un atacante registraría para
 * que un correo de "acme-es.com" o "acrne.es" pase por uno de "acme.es".
 *
 * POR QUÉ IMPORTA PARA EL CORREO
 * El fraude de pago (BEC) rara vez suplanta el dominio real, que DMARC protege: usa uno
 * parecido. Lo que lo hace posible es que ese dominio pueda RECIBIR correo, para que la
 * víctima conteste. Por eso se mira el MX de cada variante, no si tiene web.
 *
 * NO PUNTÚA. Que un tercero registre un parecido no depende del dominio auditado, y
 * distinguir un registro defensivo del propio dominio de uno hostil es una heurística
 * (mismos MX o NS, o un SPF o DMARC que apuntan al auditado). Se informa, con esa
 * salvedad, y sin llamar "ajeno" a lo que solo no tiene un vínculo visible.
 *
 * ES PURO: genera candidatos y clasifica respuestas ya resueltas. Las consultas las
 * hace api.js (checkLookalikes).
 */
import { extractRootDomain, isSameOrSubdomain } from './utils.js';

// TLD a los que se prueba a cambiar el dominio. Genéricos y de uso común en fraude, más
// .es y .eu por el mercado de la herramienta.
const SWAP_TLDS = ['com', 'es', 'net', 'org', 'eu', 'co', 'io', 'info', 'biz', 'online'];

// Sustituciones que engañan a la vista en una bandeja de entrada.
const HOMOGLYPHS = [
    ['o', '0'], ['0', 'o'], ['l', '1'], ['1', 'l'], ['i', 'l'], ['l', 'i'],
    ['m', 'rn'], ['rn', 'm'], ['w', 'vv'], ['vv', 'w'], ['d', 'cl'], ['cl', 'd']
];

const LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const isValidLabel = (label) => LABEL_RE.test(label) && !label.includes('--');

/**
 * Variantes del dominio registrable, por orden de prioridad (las más usadas en fraude
 * primero), sin repetir, sin el original y como mucho `max`.
 * @returns {Array<{domain: string, technique: string}>}
 */
export function generateLookalikes(domain, { max = 80 } = {}) {
    const root = extractRootDomain(String(domain || '').toLowerCase().replace(/\.$/, ''));
    const dot = root.indexOf('.');
    if (dot <= 0) return [];
    const label = root.slice(0, dot);
    const suffix = root.slice(dot + 1);

    const out = [];
    const seen = new Set([root]);
    const push = (lbl, sfx, technique) => {
        if (!isValidLabel(lbl)) return;
        const candidate = `${lbl}.${sfx}`;
        if (seen.has(candidate)) return;
        seen.add(candidate);
        out.push({ domain: candidate, technique });
    };

    // 1. Mismo nombre, otro TLD: acme.es → acme.com
    for (const tld of SWAP_TLDS) if (tld !== suffix) push(label, tld, 'tld');
    // 2. El país metido en el nombre: acme.es → acme-es.com, acmees.com
    if (suffix !== 'com') {
        const flat = suffix.replace(/\./g, '');
        push(`${label}-${flat}`, 'com', 'combo');
        push(`${label}${flat}`, 'com', 'combo');
    }
    // 3. Homoglifos: acme → acrne
    for (const [from, to] of HOMOGLYPHS) {
        let i = label.indexOf(from);
        while (i !== -1) {
            push(label.slice(0, i) + to + label.slice(i + from.length), suffix, 'homoglyph');
            i = label.indexOf(from, i + 1);
        }
    }
    // 4. Omisión de una letra: acme → acm (solo en nombres de 4 o más)
    if (label.length >= 4) {
        for (let i = 0; i < label.length; i++) push(label.slice(0, i) + label.slice(i + 1), suffix, 'omission');
    }
    // 5. Dos letras contiguas cambiadas de orden: acme → amce
    for (let i = 0; i < label.length - 1; i++) {
        if (label[i] === label[i + 1]) continue;
        push(label.slice(0, i) + label[i + 1] + label[i] + label.slice(i + 2), suffix, 'transposition');
    }
    // 6. Una letra repetida: acme → accme
    for (let i = 0; i < label.length; i++) push(label.slice(0, i + 1) + label[i] + label.slice(i + 1), suffix, 'repetition');
    // 7. Un guion en medio: acme → ac-me
    for (let i = 1; i < label.length; i++) push(`${label.slice(0, i)}-${label.slice(i)}`, suffix, 'hyphenation');

    return out.slice(0, max);
}

const norm = (h) => String(h || '').toLowerCase().replace(/\.$/, '');

/**
 * Nombres a los que apuntan el SPF y el DMARC de una variante: el `redirect=` del SPF y
 * los dominios de las direcciones `rua`/`ruf` del DMARC. Si alguno es del dominio
 * auditado, la variante es suya: nadie delega su SPF entero ni manda sus informes DMARC a
 * otro. Los `include:` NO cuentan: incluir el SPF de un proveedor es lo normal, y
 * auditando a ese proveedor (google.com, salesforce.com) haría "propio" a cualquier
 * parecido que lo use.
 * @param {string[]} txtRecords TXT del ápex de la variante (valores ya sin comillas)
 * @param {string[]} dmarcRecords TXT de _dmarc.<variante>
 */
export function ownershipLinks(txtRecords = [], dmarcRecords = []) {
    const links = [];
    for (const txt of txtRecords) {
        if (!/^v=spf1\b/i.test(txt.trim())) continue;
        for (const m of txt.matchAll(/(?:^|\s)redirect=([^\s]+)/gi)) links.push(norm(m[1]));
    }
    for (const txt of dmarcRecords) {
        if (!/^v=DMARC1\b/i.test(txt.trim())) continue;
        for (const m of txt.matchAll(/mailto:[^@\s,;!]+@([^\s,;!]+)/gi)) links.push(norm(m[1]));
    }
    return [...new Set(links)];
}

// Un MX tiene que ser un nombre de host: "300 ~." (un truco de algunos aparcamientos de
// dominios) no entrega correo a ningún sitio.
export const isDeliverableMx = (host) => /^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(norm(host));

/**
 * Clasifica una variante ya resuelta.
 *   own        — probablemente del propio dominio (registro defensivo): sus MX son los
 *                del auditado o cuelgan de él, sus NS son los mismos, o su SPF o su DMARC
 *                apuntan al auditado (`links`, ver ownershipLinks)
 *   mx         — sin vínculo visible con el auditado y con MX: puede recibir correo
 *   registered — registrada, sin MX que entregue
 * @param {{ mx: string[], ns: string[], links?: string[] }} lookalike
 * @param {{ domain: string, mx: string[], ns: string[] }} baseline el dominio auditado
 */
export function classifyLookalike({ mx = [], ns = [], links = [] } = {}, baseline = {}) {
    const mxHosts = mx.map(norm).filter(isDeliverableMx);
    const nsHosts = ns.map(norm).filter(Boolean);
    const base = norm(baseline.domain);
    const baseMx = new Set((baseline.mx || []).map(norm));
    const baseNs = [...new Set((baseline.ns || []).map(norm))].sort();

    const underBase = (h) => !!base && isSameOrSubdomain(h, base);
    const sameMx = mxHosts.length > 0 && mxHosts.every(h => baseMx.has(h) || underBase(h));
    const sortedNs = [...new Set(nsHosts)].sort();
    const sameNs = sortedNs.length > 0 && (
        (sortedNs.length === baseNs.length && sortedNs.every((h, i) => h === baseNs[i]))
        || sortedNs.every(underBase)
    );
    const linked = links.some(underBase);
    if (sameMx || sameNs || linked) return 'own';
    return mxHosts.length ? 'mx' : 'registered';
}
