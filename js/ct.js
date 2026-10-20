// ct.js
// Certificate Transparency: qué nombres de un dominio aparecen en certificados públicos.
// Lo comparten el detector de awareness (subdominios delegados a un vendor), el hospedaje
// del correo (owa., webmail.… en un certificado), los subdominios con correo y los
// dominios parecidos (¿alguien ha sacado un certificado para él hace poco?).
//
// Dos fuentes públicas con CORS:
//   · crt.sh, la primaria. Inestable: devuelve 502 a menudo y es lenta con dominios
//     grandes.
//   · Certspotter (SSLMate), de respaldo. Sin clave admite muy pocas consultas por hora,
//     así que solo se usa cuando crt.sh falla o tarda.
//
// Las consultas viajan a esos terceros con el dominio como parámetro: no tocan ningún
// servidor del dominio auditado.
import { timeoutSignal, abortError, withSignal } from './utils.js';

const CT_TIMEOUT = 10000;
// Si crt.sh no ha contestado en este tiempo, se pregunta también a Certspotter y gana la
// primera respuesta con nombres. No antes: cada consulta a Certspotter gasta una cuota
// muy pequeña.
const CT_HEDGE_DELAY = 4000;
// Los logs CT son frágiles y con cuota: se cachea incluso la respuesta vacía.
const CT_CACHE_TTL = 60 * 60 * 1000;

const _namesCache = new Map();
const _namesInflight = new Map();

// crt.sh se cae a menudo (502) o se queda colgado hasta el tiempo límite. Tras un fallo
// se deja de preguntarle un rato y se va directo a Certspotter: si no, una caída costaba
// 10 s en cada consulta (y los dominios parecidos se miran en serie).
const CRTSH_COOLDOWN = 5 * 60 * 1000;
let _crtShDownUntil = 0;
const crtShUp = () => Date.now() >= _crtShDownUntil;
function _markCrtShDown() {
    _crtShDownUntil = Date.now() + CRTSH_COOLDOWN;
}

async function _fetchJson(url, signal) {
    const timeout = timeoutSignal(CT_TIMEOUT, signal);
    try {
        const res = await fetch(url, { signal: timeout.signal });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return await res.json();
    } finally {
        timeout.done();
    }
}

const cleanName = (n) => String(n).trim().toLowerCase();

// Solo certificados vigentes y sin duplicados: lo que importa es la infraestructura de
// hoy, y con dominios grandes la respuesta completa pesa megas.
async function _crtShNames(domain) {
    const json = await _fetchJson(`https://crt.sh/?q=%.${encodeURIComponent(domain)}&output=json&exclude=expired&deduplicate=Y`)
        .catch((err) => {
            _markCrtShDown();
            throw err;
        });
    const names = new Set();
    for (const entry of json) {
        if (entry.name_value) entry.name_value.split('\n').forEach(n => names.add(cleanName(n)));
        if (entry.common_name) names.add(cleanName(entry.common_name));
    }
    return [...names];
}

async function _certspotterNames(domain) {
    const json = await _fetchJson(`https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names`);
    const names = new Set();
    for (const entry of json) {
        for (const n of (entry.dns_names || [])) names.add(cleanName(n));
    }
    return [...names];
}

/**
 * crt.sh primero; Certspotter si crt.sh falla, devuelve vacío o tarda más de
 * CT_HEDGE_DELAY. Gana la primera respuesta con nombres; si ambas fallan o vienen vacías,
 * []. Nunca rechaza.
 */
function _queryCtNames(domain) {
    return new Promise((resolve) => {
        let done = false;
        let pending = 0;
        let spotterStarted = false;
        let timer = null;
        const finish = (names) => {
            if (done) return;
            done = true;
            clearTimeout(timer);
            resolve(names);
        };
        const onResult = (names) => {
            pending--;
            if (names && names.length) finish(names);
            else if (!spotterStarted) startSpotter();
            else if (pending === 0) finish([]);
        };
        const onError = () => onResult(null);
        const startSpotter = () => {
            if (spotterStarted || done) return;
            spotterStarted = true;
            pending++;
            _certspotterNames(domain).then(onResult, onError);
        };
        // Con crt.sh caído hace poco, directamente Certspotter.
        if (!crtShUp()) {
            startSpotter();
            return;
        }
        pending++;
        _crtShNames(domain).then(onResult, onError);
        timer = setTimeout(startSpotter, CT_HEDGE_DELAY);
    });
}

/**
 * Nombres DNS que aparecen en certificados vigentes de `domain` y sus subdominios, en
 * minúsculas (los comodines conservan su `*.`).
 *
 * Una consulta en vuelo se comparte entre quien la pida, y el resultado se cachea una
 * hora. `signal` retira a ESTE llamante; la consulta, que ya está pedida, termina y se
 * cachea. Con la señal ya cancelada no se pide nada.
 *
 * @param {string} domain
 * @param {{ signal?: AbortSignal }} [opts]
 * @returns {Promise<string[]>} nunca rechaza salvo por cancelación
 */
export function getCtNames(domain, { signal } = {}) {
    if (signal && signal.aborted) return Promise.reject(abortError());
    const key = cleanName(domain);
    const cached = _namesCache.get(key);
    if (cached && Date.now() - cached.ts < CT_CACHE_TTL) return Promise.resolve(cached.data);
    let pending = _namesInflight.get(key);
    if (!pending) {
        pending = _queryCtNames(key).then((data) => {
            _namesCache.set(key, { data, ts: Date.now() });
            _namesInflight.delete(key);
            return data;
        });
        _namesInflight.set(key, pending);
    }
    return withSignal(pending, signal);
}

/** Vacía la caché de nombres y olvida si crt.sh estaba caído (tests y refresco forzado). */
export function clearCtCache() {
    _namesCache.clear();
    _namesInflight.clear();
    _crtShDownUntil = 0;
}

// "C=US, O=Let's Encrypt, CN=R11" → "Let's Encrypt"
function _issuerOrg(issuerName) {
    // El valor puede ir entre comillas cuando lleva comas: O="DigiCert, Inc."
    const m = String(issuerName || '').match(/(?:^|,\s*)O=(?:"([^"]+)"|([^,]+))/);
    if (m) return (m[1] || m[2]).trim();
    const cn = String(issuerName || '').match(/(?:^|,\s*)CN=([^,]+)/);
    return cn ? cn[1].trim() : null;
}

/**
 * Certificados vigentes emitidos exactamente para `domain` (no para sus subdominios),
 * con su fecha de emisión y su emisor. Para los dominios parecidos: un certificado
 * recién sacado para un dominio que imita a otro y recibe correo es la preparación
 * típica de una campaña.
 *
 * crt.sh primero y Certspotter si falla. Rechaza si fallan las dos (el llamante lo
 * muestra como "no comprobado", que no es lo mismo que "sin certificados").
 *
 * @returns {Promise<Array<{ notBefore: string, issuer: string|null }>>} del más reciente al más antiguo
 */
export async function getCertIssuances(domain, { signal } = {}) {
    if (signal && signal.aborted) throw abortError();
    const name = cleanName(domain);
    let certs = null;
    if (crtShUp()) {
        try {
            const json = await _fetchJson(`https://crt.sh/?q=${encodeURIComponent(name)}&output=json&exclude=expired`, signal);
            certs = json.map(e => ({ notBefore: e.not_before, issuer: _issuerOrg(e.issuer_name) }));
        } catch {
            if (signal && signal.aborted) throw abortError();
            _markCrtShDown();
        }
    }
    if (!certs) {
        const json = await _fetchJson(`https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(name)}&expand=issuer`, signal);
        certs = json.map(e => ({ notBefore: e.not_before, issuer: (e.issuer && (e.issuer.friendly_name || _issuerOrg(e.issuer.name))) || null }));
    }
    return certs
        .filter(c => c.notBefore && !Number.isNaN(Date.parse(c.notBefore)))
        .sort((a, b) => Date.parse(b.notBefore) - Date.parse(a.notBefore));
}

// ===== Dominios parecidos con certificado =====
// Un certificado emitido hace poco para un dominio que imita al auditado y recibe correo
// es la preparación típica de una campaña (la web de phishing necesita HTTPS). Se miran
// pocos y en serie: las dos fuentes CT tienen cuota.
export const LOOKALIKE_CERT_MAX = 3;
export const RECENT_CERT_DAYS = 30;
const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * Marca qué dominios parecidos se van a comprobar (`cert: { status: 'checking' }`): los
 * primeros que reciben correo y no son del auditado. Se llama ANTES de pintar el panel,
 * para que esas filas digan "comprobando" en vez de nada.
 * @returns {Array} las entradas elegidas (las mismas referencias de `lookalike.found`)
 */
export function markLookalikeCertChecks(lookalike, max = LOOKALIKE_CERT_MAX) {
    const picked = ((lookalike && lookalike.found) || []).filter(f => f.kind === 'mx').slice(0, max);
    for (const f of picked) f.cert = { status: 'checking' };
    return picked;
}

/** Lee la lista de certificados vigentes de un parecido (del más reciente al más antiguo). */
export function lookalikeCertStatus(certs, now = Date.now()) {
    if (!certs.length) return { status: 'none' };
    const latest = certs[0];
    const days = Math.max(0, Math.floor((now - Date.parse(latest.notBefore)) / DAY_MS));
    return {
        status: days <= RECENT_CERT_DAYS ? 'recent' : 'active',
        notBefore: latest.notBefore,
        issuer: latest.issuer,
        days
    };
}

/**
 * Rellena `cert` en los parecidos marcados por markLookalikeCertChecks, uno detrás de
 * otro. Un fallo de las fuentes CT queda como 'unchecked' ("no comprobado"), que no es lo
 * mismo que 'none' (sin certificados vigentes). Modifica `lookalike` y lo devuelve.
 */
export async function checkLookalikeCerts(lookalike, { signal, now = Date.now() } = {}) {
    const picked = ((lookalike && lookalike.found) || []).filter(f => f.cert && f.cert.status === 'checking');
    for (const f of picked) {
        if (signal && signal.aborted) throw abortError();
        try {
            f.cert = lookalikeCertStatus(await getCertIssuances(f.domain, { signal }), now);
        } catch (e) {
            if (signal && signal.aborted) throw abortError();
            f.cert = { status: 'unchecked' };
        }
    }
    return lookalike;
}
