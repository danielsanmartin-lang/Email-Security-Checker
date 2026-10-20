// rdap.js
// Fecha de registro de un dominio por RDAP (RFC 9083), preguntando directamente al
// registro de su TLD, el que indica el bootstrap de IANA (RFC 9224). Sin intermediarios.
//
// Sirve para los dominios parecidos: uno registrado hace unas semanas que ya recibe correo
// es la señal más clara de una campaña en preparación, y en uno registrado hace años un
// certificado reciente suele ser una renovación.
//
// No todos los TLD publican RDAP: muchos ccTLD (.es, .de, .io, .eu, .it…) no están en el
// bootstrap. Entonces no se sabe, y se dice así. Las consultas van al registro con el
// nombre del parecido como parámetro: no tocan ningún servidor del dominio auditado.
import { timeoutSignal, abortError, withSignal } from './utils.js';

const BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';
const RDAP_TIMEOUT = 6000;
// La fecha de registro no cambia de un análisis a otro.
const RDAP_CACHE_TTL = 60 * 60 * 1000;
const DAY_MS = 24 * 60 * 60 * 1000;

// Registrado hace menos que esto: dominio nuevo.
export const NEW_DOMAIN_DAYS = 90;
// Se miran los parecidos que reciben correo, hasta este número. RDAP no tiene la cuota de
// los logs CT, pero cada registro limita las consultas por IP.
export const LOOKALIKE_AGE_MAX = 10;
const CONCURRENCY = 3;

let _bootstrap = null;
const _cache = new Map();

async function _fetchJson(url, signal) {
    const timeout = timeoutSignal(RDAP_TIMEOUT, signal);
    try {
        const res = await fetch(url, { signal: timeout.signal });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return await res.json();
    } finally {
        timeout.done();
    }
}

// TLD → URL base de su servicio RDAP (solo https). Trabajo compartido: lo pide el primero
// y lo aprovechan los demás, así que no se cancela con la señal de ninguno.
function _loadBootstrap() {
    if (!_bootstrap) {
        _bootstrap = _fetchJson(BOOTSTRAP_URL).then((json) => {
            const map = new Map();
            for (const [tlds, urls] of json.services || []) {
                const url = (urls || []).find(u => String(u).startsWith('https://'));
                if (!url) continue;
                for (const tld of tlds) map.set(String(tld).toLowerCase(), url.endsWith('/') ? url : `${url}/`);
            }
            return map;
        });
        // Un fallo no se queda cacheado: el siguiente análisis lo vuelve a intentar.
        _bootstrap.catch(() => { _bootstrap = null; });
    }
    return _bootstrap;
}

// El sufijo más largo que tenga servicio (RFC 9224 §4).
function _baseFor(map, name) {
    const labels = name.split('.');
    for (let i = 1; i < labels.length; i++) {
        const base = map.get(labels.slice(i).join('.'));
        if (base) return base;
    }
    return null;
}

/**
 * Fecha de registro de `domain` (ISO 8601), o null si no se sabe: el TLD no publica RDAP,
 * la respuesta no trae el evento o el registro no contesta. Solo rechaza si se cancela.
 * @returns {Promise<string|null>}
 */
export async function getRegistrationDate(domain, { signal } = {}) {
    if (signal && signal.aborted) throw abortError();
    const name = String(domain).trim().toLowerCase();
    const hit = _cache.get(name);
    if (hit && Date.now() - hit.at < RDAP_CACHE_TTL) return hit.date;
    let date = null;
    try {
        const base = _baseFor(await withSignal(_loadBootstrap(), signal), name);
        if (base) {
            const json = await _fetchJson(`${base}domain/${encodeURIComponent(name)}`, signal);
            const ev = (json.events || []).find(e => e.eventAction === 'registration');
            if (ev && !Number.isNaN(Date.parse(ev.eventDate))) date = ev.eventDate;
        }
    } catch {
        if (signal && signal.aborted) throw abortError();
        return null; // sin cachear: puede ser un fallo pasajero
    }
    _cache.set(name, { date, at: Date.now() });
    return date;
}

/** Vacía la caché de fechas y el bootstrap (tests). */
export function clearRdapCache() {
    _cache.clear();
    _bootstrap = null;
}

/**
 * Marca qué parecidos se van a fechar (`age: { status: 'checking' }`): los que reciben
 * correo, hasta LOOKALIKE_AGE_MAX. Se llama ANTES de pintar el panel, como
 * markLookalikeCertChecks.
 */
export function markLookalikeAgeChecks(lookalike, max = LOOKALIKE_AGE_MAX) {
    const picked = ((lookalike && lookalike.found) || []).filter(f => f.kind === 'mx').slice(0, max);
    for (const f of picked) f.age = { status: 'checking' };
    return picked;
}

/** Lee la fecha de registro: dominio nuevo, antiguo o sin fecha. */
export function lookalikeAgeStatus(registered, now = Date.now()) {
    if (!registered) return { status: 'unknown' };
    const days = Math.max(0, Math.floor((now - Date.parse(registered)) / DAY_MS));
    return { status: days <= NEW_DOMAIN_DAYS ? 'new' : 'old', registered, days };
}

/**
 * Rellena `age` en los parecidos marcados, de CONCURRENCY en CONCURRENCY. Modifica
 * `lookalike` y lo devuelve.
 */
export async function checkLookalikeAges(lookalike, { signal, now = Date.now() } = {}) {
    const queue = ((lookalike && lookalike.found) || []).filter(f => f.age && f.age.status === 'checking');
    const worker = async () => {
        while (queue.length) {
            if (signal && signal.aborted) throw abortError();
            const f = queue.shift();
            f.age = lookalikeAgeStatus(await getRegistrationDate(f.domain, { signal }), now);
        }
    };
    await Promise.all(Array.from({ length: CONCURRENCY }, worker));
    return lookalike;
}
