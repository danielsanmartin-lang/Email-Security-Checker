import { parseMTASTSPolicy, validateMTASTSPolicy, extractTxtValue, parseDMARC } from './parsers.js';
import { getSettings, resolverChain } from './settings.js';
import { isValidDomain, extractRootDomain, isSameOrSubdomain } from './utils.js';
import { treeWalkTargets, selectOrgDomain } from './dmarc.js';
import { classifyLookalike, ownershipLinks, isDeliverableMx } from './lookalike.js';

// ===== DNS Cache =====
const _dnsCache = new Map();
const DNS_CACHE_TTL = 5 * 60 * 1000; // 5 minutes
// Deduplicación de consultas en vuelo: si ya hay una petición idéntica pendiente,
// se reutiliza su promesa en vez de disparar otra a la red (un análisis pide, p. ej.,
// el TXT del ápex dos veces en paralelo desde getSPF y getAllTXT).
const _inflight = new Map();

export function clearDnsCache() {
    _dnsCache.clear();
    _inflight.clear();
    _servfailZones.clear();
    // NO se toca el semáforo: su contador es estado de transporte, no de caché. Ponerlo a
    // cero con peticiones vivas lo dejaría en negativo al liberarse y admitiría de más.
}

function _getCached(name, type) {
    const key = `${name}:${type}`;
    const cached = _dnsCache.get(key);
    if (cached && Date.now() - cached.ts < DNS_CACHE_TTL) return cached.data;
    if (cached) _dnsCache.delete(key);
    return null;
}

function _setCache(name, type, data) {
    const key = `${name}:${type}`;
    _dnsCache.set(key, { data, ts: Date.now() });
    // Prune old entries if cache grows too large
    if (_dnsCache.size > 500) {
        const now = Date.now();
        for (const [k, v] of _dnsCache) {
            if (now - v.ts > DNS_CACHE_TTL) _dnsCache.delete(k);
        }
    }
}

// ===== DNS Query with timeout and fallback =====
const DNS_TIMEOUT = 8000; // 8 seconds

// RCODEs concluyentes: 0 = NOERROR, 3 = NXDOMAIN ("no existe" es una respuesta
// válida). Cualquier otro Status (2 = SERVFAIL, 5 = REFUSED…) significa que el
// resolver NO pudo responder: tratarlo como "sin registros" produciría un falso
// diagnóstico (p. ej. "sin SPF/DMARC" en dominios con DNSSEC roto).
const DNS_CONCLUSIVE_STATUSES = [0, 3];
// RCODE 2 = SERVFAIL ("no he podido"), 5 = REFUSED ("no quiero"). La diferencia importa
// para el reintento: el primero suele ser un autoritativo saturado y a la segunda
// responde; el segundo es una negativa deliberada (política, RPZ, o una DNSBL que
// rechaza las consultas que le llegan vía resolver público — caso habitual en checkRBL)
// y volver a preguntar devuelve exactamente lo mismo.
const DNS_RCODE_SERVFAIL = 2;

// Un análisis completo dispara ~120 consultas DoH. Sin límite salían en picos de 40
// simultáneas, y los servidores autoritativos frágiles (medido en worldnic.com, que
// sirve gruporamos.com) responden SERVFAIL a una parte aleatoria de la ráfaga. El
// resolver público reenvía ese SERVFAIL y la consulta se pierde aunque el registro
// exista. Con un tope bajo, la misma zona responde a todo.
const MAX_CONCURRENT_DNS = 6;
// Espera antes del único reintento ante SERVFAIL. Corta a propósito: lo que se busca
// es dejar pasar el pico de la ráfaga, no esperar a que se recupere un servidor caído.
const SERVFAIL_RETRY_DELAY = 300;

// Zonas en las que un reintento YA falló: se deja de reintentar el resto de sus nombres
// durante un rato. El reintento existe para el tropiezo transitorio; contra una zona
// caída de verdad solo suma espera. Y suma en serie: el detector de awareness sondea 17
// selectores DKIM uno detrás de otro, así que sin este corte un dominio con el DNS roto
// se llevaba +5 s de reloj para no averiguar nada.
const SERVFAIL_ZONE_TTL = 30 * 1000;
const _servfailZones = new Map();

function _zoneIsKnownBroken(name) {
    const zone = extractRootDomain(name);
    const ts = _servfailZones.get(zone);
    if (ts === undefined) return false;
    if (Date.now() - ts < SERVFAIL_ZONE_TTL) return true;
    _servfailZones.delete(zone);
    return false;
}

// Semáforo FIFO. INVARIANTE: solo puede envolver la resolución de UNA consulta, nunca
// nada que espere a más DNS mientras lo retiene. `getSPFLookupTree` es recursiva y hace
// Promise.all sobre sus subárboles: si un padre retuviera un hueco mientras espera a sus
// hijos, con la piscina llena de padres nadie avanzaría (deadlock). Hoy todos los
// abanicos (árbol SPF, getSRV, getDANE, getIPAddresses, RBL en app.js) completan su
// queryDNS ANTES de lanzar la siguiente tanda, así que el invariante se cumple.
let _dnsActive = 0;
const _dnsQueue = [];

function _releaseDnsSlot() {
    _dnsActive--;
    const next = _dnsQueue.shift();
    if (next) {
        _dnsActive++;
        next();
    }
}

function _acquireDnsSlot() {
    if (_dnsActive < MAX_CONCURRENT_DNS) {
        _dnsActive++;
        return Promise.resolve();
    }
    return new Promise(resolve => _dnsQueue.push(resolve));
}

/** Ejecuta `fn` ocupando un hueco de la piscina. Ver el invariante de arriba. */
async function _withDnsSlot(fn) {
    await _acquireDnsSlot();
    try {
        return await fn();
    } finally {
        _releaseDnsSlot();
    }
}

async function _fetchDoH(url, headers) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), DNS_TIMEOUT);
    try {
        const res = await fetch(url, { headers, signal: controller.signal });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return await res.json();
    } finally {
        clearTimeout(timeoutId);
    }
}

// Los valores que vienen del dominio auditado se pasan como ARGUMENTOS de console,
// nunca interpolados en el primer parámetro: ese es la cadena de formato de la consola
// y un dominio con un "%s" dentro descolocaría el resto del mensaje.
async function _resolveDNS(name, type) {
    // El orden (y si hay respaldo) lo decide el usuario en el panel de ajustes.
    const providers = resolverChain(name, type);

    let badStatus = null;
    let sawServfail = false;
    for (const provider of providers) {
        let candidate;
        try {
            candidate = await _fetchDoH(provider.url, provider.headers);
        } catch (e) {
            console.warn('%s DoH failed for %s (%s)', provider.label, name, type, e);
            continue;
        }
        if (typeof candidate.Status === 'number' && !DNS_CONCLUSIVE_STATUSES.includes(candidate.Status)) {
            console.warn('%s DoH returned Status %s for %s (%s)', provider.label, candidate.Status, name, type);
            badStatus = candidate.Status;
            if (candidate.Status === DNS_RCODE_SERVFAIL) sawServfail = true;
            continue;
        }
        // Respuesta concluyente: cachear y devolver. Las respuestas de error no
        // se cachean, para no fijar un fallo transitorio durante 5 minutos.
        _setCache(name, type, candidate);
        return candidate;
    }

    if (badStatus !== null) {
        const e = new Error(`DNS resolvers could not resolve ${name} (${type}): RCODE ${badStatus}`);
        e.code = 'servfail';
        e.rcode = badStatus;
        // Solo un SERVFAIL de verdad justifica reintentar (ver DNS_RCODE_SERVFAIL).
        e.retryable = sawServfail;
        throw e;
    }
    const e = new Error(`DNS queries failed for ${name} (${type})`);
    e.code = 'network';
    throw e;
}

/**
 * Resuelve una consulta ocupando un hueco de la piscina, con UN reintento ante SERVFAIL.
 *
 * Solo se reintenta el `servfail`: significa que un resolver SÍ contestó, pero que la zona
 * no pudo servir la respuesta — casi siempre porque el autoritativo se atragantó con la
 * ráfaga, y en la siguiente pasada responde. Un `network` es un fallo de conectividad de
 * este navegador; reintentarlo al instante solo añade latencia al mismo error.
 *
 * El reintento vuelve a la COLA en vez de retener su hueco durante la espera: retenerlo
 * desperdiciaría capacidad justo cuando la piscina está saturada, que es exactamente
 * cuando aparecen estos SERVFAIL.
 */
async function _resolveWithRetry(name, type) {
    try {
        return await _withDnsSlot(() => _resolveDNS(name, type));
    } catch (e) {
        // Con resolver propio no se reintenta: quien lo configura lo hace para que el
        // dominio auditado no salga de su infraestructura, no para doblarle el tráfico.
        if (e.code !== 'servfail' || !e.retryable || getSettings().resolver === 'custom') throw e;
        if (_zoneIsKnownBroken(name)) throw e;
        await new Promise(r => setTimeout(r, SERVFAIL_RETRY_DELAY));
        try {
            return await _withDnsSlot(() => _resolveDNS(name, type));
        } catch (e2) {
            // Falló dos veces con espera de por medio: la zona no está tropezando, está
            // caída. Se anota para que el resto de nombres se rindan a la primera.
            if (e2.code === 'servfail') _servfailZones.set(extractRootDomain(name), Date.now());
            throw e2;
        }
    }
}

export async function queryDNS(name, type) {
    // Check cache first. Los aciertos de caché y de deduplicación salen ANTES del
    // semáforo: no cuestan red, así que encolarlos solo añadiría latencia.
    const cached = _getCached(name, type);
    if (cached) return cached;

    // Reutiliza una consulta idéntica ya en vuelo (evita duplicados concurrentes).
    const key = `${name}:${type}`;
    const pending = _inflight.get(key);
    if (pending) return pending;

    const promise = _resolveWithRetry(name, type).finally(() => _inflight.delete(key));
    _inflight.set(key, promise);
    return promise;
}

// DoH RCODE: 0 = NOERROR, 3 = NXDOMAIN (dominio inexistente).
// Devuelve false solo si el resolver confirma NXDOMAIN en el ápex del dominio.
export async function checkDomainExists(domain) {
    const data = await queryDNS(domain, 'NS');
    if (data && typeof data.Status === 'number' && data.Status === 3) return false;
    return true;
}

export async function getMX(domain) {
    return _parseMxAnswer(await queryDNS(domain, 'MX'));
}

// Respuesta DoH de un MX → hosts ordenados por prioridad (con .nullMx si es Null MX).
// Compartido por getMX y checkLookalikes.
function _parseMxAnswer(data) {
    const empty = [];
    if (!data.Answer) return empty;
    const raw = data.Answer
        .filter(a => a.type === 15 && a.data)
        .map(a => {
            const parts = a.data.trim().split(/\s+/);
            if (parts.length < 2) return null;
            return { priority: parseInt(parts[0], 10), host: parts[1].replace(/\.$/, '') };
        })
        .filter(Boolean);

    // Null MX (RFC 7505): un único registro "0 ." (host vacío tras quitar el punto)
    // declara explícitamente que el dominio NO recibe correo. Devolvemos un array
    // vacío marcado con .nullMx para que el análisis lo reconozca como configuración
    // correcta (dominios aparcados) en vez de auditar hosts vacíos.
    const nullMx = raw.length > 0 && raw.every(r => r.priority === 0 && r.host === '');
    const hosts = raw.filter(r => r.host !== '').sort((a, b) => a.priority - b.priority);
    if (nullMx) {
        hosts.nullMx = true;
    }
    return hosts;
}

export async function getSPF(domain) {
    const data = await queryDNS(domain, 'TXT');
    if (!data.Answer) return { record: null, records: [], multiple: false };
    const records = [];
    for (const a of data.Answer) {
        if (a.data) {
            const txt = extractTxtValue(a.data);
            if (txt.startsWith('v=spf1')) {
                records.push(txt);
            }
        }
    }
    const uniqueRecords = [...new Set(records)];
    return {
        record: uniqueRecords[0] || null,
        records: uniqueRecords,
        multiple: uniqueRecords.length > 1
    };
}

// Un registro DMARC empieza por la etiqueta v con el valor exacto DMARC1 (sensible a
// mayúsculas), y la ABNF admite espacios alrededor del "=" (RFC 9989 §4.7 y §4.8). Con
// startsWith('v=DMARC1') un `v = DMARC1;` válido se tomaba por "sin DMARC", y un
// `v=DMARC10` se colaba como si lo fuera.
const DMARC_RECORD_RE = /^v\s*=\s*DMARC1\s*(;|$)/;

export function isDmarcRecord(txt) {
    return DMARC_RECORD_RE.test(String(txt || ''));
}

export async function getDMARC(domain) {
    const data = await queryDNS(`_dmarc.${domain}`, 'TXT');
    if (!data.Answer) return { record: null, records: [], multiple: false };
    const records = [];
    for (const a of data.Answer) {
        if (a.data) {
            const txt = extractTxtValue(a.data);
            if (isDmarcRecord(txt)) {
                records.push(txt);
            }
        }
    }
    const uniqueRecords = [...new Set(records)];
    return {
        record: uniqueRecords[0] || null,
        records: uniqueRecords,
        multiple: uniqueRecords.length > 1
    };
}

const psdOf = (record) => {
    const psd = (parseDMARC(record) || {}).psd;
    return psd === 'y' || psd === 'n' ? psd : null;
};

/**
 * Descubre la política DMARC aplicable y el Dominio Organizativo con el DNS Tree Walk de
 * RFC 9989 §4.10, que sustituye a la Public Suffix List de RFC 7489. Se hace entero por
 * DoH —sin backend y sin una PSL embebida que envejecería— y sobre queryDNS, así que
 * hereda caché, deduplicación, semáforo y reintento.
 *
 * - Política (§4.10.1): la del propio dominio si publica UN registro válido; si no, la de
 *   su dominio organizativo; si no, la de su sufijo público (PSD).
 * - Varios registros en un mismo nombre se descartan todos (§4.10, paso 2).
 * - Un fallo de DNS en un ANCESTRO no se lee como "no hay registro": deja `incomplete`.
 *   El fallo en el propio dominio sí se propaga, como antes, para marcar DMARC como no
 *   disponible en vez de "sin DMARC".
 *
 * En un dominio organizativo típico cuesta una consulta más (`_dmarc.<tld>`), cacheada.
 *
 * @returns {Promise<{record, records, multiple, policyDomain, source, orgDomain,
 *   inherited, inheritedFrom, walked, incomplete}>}
 */
export async function discoverDmarcPolicy(domain) {
    const start = String(domain || '').toLowerCase().replace(/\.$/, '');
    const own = await getDMARC(start);
    const found = [];
    const walked = [{ name: start, status: own.multiple ? 'multiple' : (own.record ? 'record' : 'none') }];
    if (own.record && !own.multiple) found.push({ name: start, record: own.record, psd: psdOf(own.record) });

    let incomplete = false;
    const stopsHere = (entry) => !!entry && (entry.psd === 'y' || entry.psd === 'n');
    if (!stopsHere(found[0])) {
        const targets = treeWalkTargets(start);
        // Se lanzan en paralelo (son como mucho 7 y la piscina de 6 las ordena), pero se
        // INTERPRETAN en orden: lo que haya por encima de un psd=n/psd=y no cuenta.
        const answers = await Promise.allSettled(targets.map(t => getDMARC(t)));
        for (let i = 0; i < targets.length; i++) {
            const a = answers[i];
            if (a.status === 'rejected') {
                incomplete = true;
                walked.push({ name: targets[i], status: 'error' });
                continue;
            }
            const r = a.value;
            walked.push({ name: targets[i], status: r.multiple ? 'multiple' : (r.record ? 'record' : 'none') });
            if (r.record && !r.multiple) {
                const entry = { name: targets[i], record: r.record, psd: psdOf(r.record) };
                found.push(entry);
                if (stopsHere(entry)) break;
            }
        }
    }

    const orgDomain = selectOrgDomain(found, start);
    let applied = null;
    let source = null;
    if (own.record && !own.multiple) {
        applied = found[0];
        source = 'author';
    } else {
        applied = found.find(f => f.name === orgDomain && f.name !== start) || null;
        if (applied) {
            source = 'org';
        } else {
            applied = found.find(f => f.psd === 'y' && f.name !== start) || null;
            if (applied) source = 'psd';
        }
    }

    const inherited = source === 'org' || source === 'psd';
    return {
        record: applied ? applied.record : null,
        // Para pintar: los registros en conflicto del propio dominio, o el aplicado.
        records: own.multiple ? own.records : (applied ? [applied.record] : []),
        multiple: own.multiple,
        policyDomain: applied ? applied.name : null,
        source,
        orgDomain,
        inherited,
        inheritedFrom: inherited ? applied.name : null,
        walked,
        incomplete
    };
}


export const COMMON_DKIM_SELECTORS = ['google', 'default', 's1', 's2', 'k1', 'k2', 'm1', 'mail', 'selector1'];

/**
 * ¿Es un registro de clave DKIM? `v=` es OPCIONAL (RFC 6376 §3.6.1): muchas claves se
 * publican como `k=rsa; p=…` a secas, y exigir `v=DKIM1` las daba por inexistentes. Si
 * `v=` aparece, debe ser la primera etiqueta y valer DKIM1; si no, basta con una lista
 * de etiquetas que declare `p=` (la clave pública, vacía si está revocada).
 */
export function isDkimKeyRecord(txt) {
    const s = String(txt || '').trim();
    if (/^v\s*=/i.test(s)) return /^v\s*=\s*DKIM1\s*(;|$)/.test(s);
    return /(^|;)\s*p\s*=/i.test(s);
}

export function discoverDKIMSelectors(spfRaw) {
    if (!spfRaw) return [];
    const selectors = [];
    const lower = spfRaw.toLowerCase();
    
    if (lower.includes('_spf.google.com') || lower.includes('google.com')) {
        selectors.push('google');
    }
    if (lower.includes('outlook.com') || lower.includes('spf.protection.outlook.com')) {
        selectors.push('selector1', 'selector2');
    }
    if (lower.includes('mandrillapp.com')) {
        selectors.push('mandrill');
    }
    if (lower.includes('mcsv.net')) {
        selectors.push('k1', 'k2', 'k3');
    }
    if (lower.includes('sendgrid.net')) {
        selectors.push('smtp', 's1', 's2', 'k1');
    }
    if (lower.includes('mailgun.org')) {
        selectors.push('mg', 'k1', 'pic');
    }
    if (lower.includes('mktomail.com')) {
        selectors.push('m1');
    }
    if (lower.includes('hubspotemail.net') || lower.includes('hubspot.com')) {
        selectors.push('hs1', 'hs2');
    }
    if (lower.includes('salesforce.com')) {
        selectors.push('salesforce');
    }
    if (lower.includes('zoho.com') || lower.includes('zoho.eu')) {
        selectors.push('zmail');
    }
    
    return [...new Set(selectors)];
}

// `customSelector` acepta un selector suelto o una lista (el campo de la UI admite
// varios separados por coma). Si se indica alguno, se consulta SOLO esa lista: es una
// elección explícita del usuario, no un complemento a la detección best-effort.
export async function getDKIM(domain, customSelector = null, spfRaw = null, icesSelectors = []) {
    const custom = (Array.isArray(customSelector) ? customSelector : [customSelector]).filter(Boolean);
    let selectors = custom.length > 0 ? [...new Set(custom)] : COMMON_DKIM_SELECTORS;
    if (custom.length === 0 && spfRaw) {
        const discovered = discoverDKIMSelectors(spfRaw);
        selectors = [...new Set([...discovered, ...COMMON_DKIM_SELECTORS, ...icesSelectors])];
    } else if (custom.length === 0 && icesSelectors.length > 0) {
        selectors = [...new Set([...COMMON_DKIM_SELECTORS, ...icesSelectors])];
    }
    const results = [];
    const errors = [];
    const promises = selectors.map(async (selector) => {
        try {
            const data = await queryDNS(`${selector}._domainkey.${domain}`, 'TXT');
            if (data && data.Answer) {
                for (const a of data.Answer) {
                    // Solo los TXT: en una cadena CNAME el destino también viene en Answer.
                    if (a.type !== undefined && a.type !== 16) continue;
                    const txt = extractTxtValue(a.data);
                    if (isDkimKeyRecord(txt)) {
                        results.push({ selector, record: txt });
                    }
                }
            }
        } catch(e) {
            // `code` distingue "la zona del dominio auditado no responde" (servfail) de
            // "falló la conectividad de este navegador" (network). La UI dice cosas muy
            // distintas en cada caso: lo primero es un dato sobre el dominio, lo segundo
            // un problema nuestro.
            errors.push({ selector, error: e.message, code: e.code || 'network' });
        }
    });
    await Promise.allSettled(promises);
    // `attempted` permite decir "N de M sin comprobar": sin el total, un "9 selectores
    // fallaron" no dice si el sondeo fue casi completo o casi inútil.
    return { records: results, errors, attempted: selectors.length };
}

export async function getBIMI(domain) {
    try {
        const data = await queryDNS(`default._bimi.${domain}`, 'TXT');
        if (data && data.Answer) {
            for (const a of data.Answer) {
                const txt = extractTxtValue(a.data);
                if (txt.startsWith('v=BIMI1')) {
                    // Parseo por etiquetas: un `l=;` VACÍO no es lo mismo que ausente
                    // (declara explícitamente que el dominio declina participar en BIMI),
                    // y la regex anterior no podía distinguirlos.
                    const tags = {};
                    for (const part of txt.split(';')) {
                        const eq = part.indexOf('=');
                        if (eq > 0) tags[part.substring(0, eq).trim().toLowerCase()] = part.substring(eq + 1).trim();
                    }
                    const logo = tags.l || null;
                    // a= es el certificado VMC/CMC. Sin él, Gmail y Apple Mail no
                    // muestran el logo aunque el SVG sea correcto.
                    const vmc = tags.a || null;
                    const isHttps = (u) => /^https:\/\//i.test(String(u || ''));
                    return {
                        record: txt,
                        logo,
                        vmc,
                        declined: tags.l === '',
                        logoInsecure: !!logo && !isHttps(logo),
                        vmcInsecure: !!vmc && !isHttps(vmc)
                    };
                }
            }
        }
    } catch(e) {
        return { error: e.message };
    }
    return null;
}

// Mecanismos SPF con máscara CIDR opcional (RFC 7208 §5.3/§5.6). Cada uno consume
// un lookup DNS. Acepta a, mx, ptr con :dominio y /IPv4-cidr y //IPv6-cidr.
const SPF_LOOKUP_MECH = /^(a|mx|ptr)(:[^/\s]+)?(\/\d{1,2})?(\/\/\d{1,3})?$/;

// Tope de mecanismos hoja (a/mx/exists) que se resuelven de verdad para detectar
// "void lookups" (RFC 7208 §4.6.4: más de 2 consultas vacías ⇒ PermError). Cada sonda
// es una consulta DNS extra; la caché y la deduplicación en vuelo amortizan las
// repetidas, pero el tope evita que un SPF patológico dispare cientos de peticiones.
const SPF_VOID_PROBE_BUDGET = 20;
const SPF_VOID_PROBE_TYPES = new Set(['a', 'mx', 'exists']);

// ¿La consulta de este mecanismo es "void"? (NXDOMAIN o cero respuestas)
// Devuelve true | false | null (null = no se pudo determinar, no se cuenta).
async function _probeVoidLookup(type, target) {
    // Quita la máscara CIDR (`a:example.com/24`) antes de consultar.
    const name = String(target).split('/')[0].replace(/\.$/, '');
    if (!name || name === '(self)') return null;
    const answersOf = async (qtype) => {
        const data = await queryDNS(name, qtype);
        if (data && data.Status === 3) return 0; // NXDOMAIN
        return ((data && data.Answer) || []).length;
    };
    try {
        if (type === 'mx') return (await answersOf('MX')) === 0;
        // `a` resuelve A y AAAA: solo es void si NINGUNA devuelve datos.
        // `exists:` se evalúa siempre contra A (RFC 7208 §5.7).
        const a = await answersOf('A');
        if (a > 0) return false;
        if (type === 'exists') return true;
        const aaaa = await answersOf('AAAA');
        return aaaa === 0;
    } catch {
        return null;
    }
}

export async function getSPFLookupTree(domain, path = new Set(), depth = 0, ctx = { probeBudget: SPF_VOID_PROBE_BUDGET }) {
    // node.error es un CÓDIGO neutral de idioma ('depth_exceeded' | 'loop' |
    // 'query_failed' | 'no_spf_record'). node.errorDetail contiene el mensaje
    // técnico original (si aplica).
    const node = { domain, lookups: 0, children: [], error: null, errorDetail: null, record: null };
    if (depth > 10) {
        node.error = 'depth_exceeded';
        return node;
    }
    // Bucle real = el dominio aparece en su propia cadena de ANTEPASADOS. Un include
    // repetido entre ramas hermanas (p. ej. dos includes que a su vez incluyen
    // _spf.google.com) NO es un bucle: cada rama recibe su propia copia del path.
    if (path.has(domain)) {
        node.error = 'loop';
        return node;
    }
    const childPath = new Set([...path, domain]);

    try {
        const spfData = await getSPF(domain);
        const spf = spfData.record;
        if (!spf) {
            // Un include:/redirect= cuyo destino NO publica SPF es un PermError en la
            // evaluación real (RFC 7208 §5.2): el mecanismo no puede resolverse y toda
            // la comprobación falla. En el ápex (depth 0) significa simplemente que el
            // dominio no tiene SPF, que ya se informa por otra vía.
            if (depth > 0) node.error = 'no_spf_record';
            return node;
        }
        node.record = spf;

        // Primera pasada: contabiliza mecanismos hoja y recoge include/redirect.
        // Con un mecanismo `all` en el registro, `redirect=` se IGNORA (RFC 7208 §6.1): no
        // se evalúa, así que ni cuenta como lookup ni aporta su árbol.
        const tokens = spf.split(/\s+/).filter(Boolean);
        const hasAll = tokens.some(tok => /^[+\-~?]?all$/i.test(tok));
        const nested = [];
        for (const token of tokens) {
            let t = token.toLowerCase();
            if (/^[+\-~?]/.test(t)) t = t.substring(1);

            if (t.startsWith('include:')) {
                node.lookups++;
                nested.push({ type: 'include', target: t.substring(8) });
            } else if (t.startsWith('redirect=')) {
                if (hasAll) continue;
                node.lookups++;
                nested.push({ type: 'redirect', target: t.substring(9) });
            } else if (t.startsWith('exists:')) {
                node.lookups++;
                node.children.push({ type: 'exists', target: t.substring(7) });
            } else if (SPF_LOOKUP_MECH.test(t)) {
                node.lookups++;
                const mech = t.split(/[:/]/)[0];
                node.children.push({ type: mech, target: t.includes(':') ? t.substring(t.indexOf(':') + 1) : '(self)' });
            }
        }

        // Sondeo de void lookups: resuelve los mecanismos hoja de este nivel para saber
        // cuáles devuelven NXDOMAIN o cero respuestas. Se hace en paralelo y solo
        // mientras quede presupuesto compartido con el resto del árbol.
        const probes = node.children.filter(c => SPF_VOID_PROBE_TYPES.has(c.type) && c.target !== '(self)');
        const budgeted = probes.slice(0, Math.max(0, ctx.probeBudget));
        ctx.probeBudget -= budgeted.length;
        await Promise.all(budgeted.map(async (child) => {
            const isVoid = await _probeVoidLookup(child.type, child.target);
            if (isVoid !== null) child.void = isVoid;
        }));

        // Segunda pasada: resuelve todos los include/redirect del nivel EN PARALELO.
        const subtrees = await Promise.all(
            nested.map(n => getSPFLookupTree(n.target, childPath, depth + 1, ctx))
        );
        subtrees.forEach((child, i) => {
            node.children.push({ type: nested[i].type, target: nested[i].target, tree: child });
            node.lookups += child.lookups;
        });
    } catch (e) {
        node.error = 'query_failed';
        node.errorDetail = e.message;
    }

    return node;
}

// Resuelve todas las IPs (IPv4 e IPv6) de un host.
export async function getIPAddresses(host) {
    const ips = [];
    try {
        const [aData, aaaaData] = await Promise.all([
            queryDNS(host, 'A').catch(() => null),
            queryDNS(host, 'AAAA').catch(() => null)
        ]);
        if (aData && aData.Answer) {
            for (const a of aData.Answer) {
                if (a.type === 1 && a.data) ips.push(a.data);
            }
        }
        if (aaaaData && aaaaData.Answer) {
            for (const a of aaaaData.Answer) {
                if (a.type === 28 && a.data) ips.push(a.data);
            }
        }
    } catch (e) {
        console.warn('Failed to resolve IPs for %s', host, e);
    }
    return [...new Set(ips)];
}

// Compat: devuelve la primera IP (preferentemente IPv4).
export async function getIPAddress(host) {
    const ips = await getIPAddresses(host);
    return ips[0] || null;
}

/**
 * Invierte una IP al formato que exigen las consultas por IP: RBL, PTR (in-addr.arpa
 * / ip6.arpa) y el mapeo IP→ASN de Team Cymru. IPv4 se invierte por octetos; IPv6, por
 * nibbles. Devuelve null si la dirección no se puede interpretar.
 */
export function reverseIpForDns(ip) {
    if (typeof ip !== 'string' || !ip) return null;
    if (ip.includes(':')) return expandIPv6ForRbl(ip);
    const octets = ip.split('.');
    if (octets.length !== 4 || !octets.every(o => /^\d{1,3}$/.test(o) && Number(o) <= 255)) return null;
    return octets.reverse().join('.');
}

// Expande una dirección IPv6 a sus 32 nibbles en orden inverso (formato de query RBL/PTR).
function expandIPv6ForRbl(ip) {
    // Manejar la abreviatura "::"
    const [head, tail] = ip.split('::');
    const headGroups = head ? head.split(':').filter(Boolean) : [];
    const tailGroups = tail ? tail.split(':').filter(Boolean) : [];
    const missing = 8 - (headGroups.length + tailGroups.length);
    if (missing < 0) return null;
    const groups = [...headGroups, ...Array(ip.includes('::') ? missing : 0).fill('0'), ...tailGroups];
    if (groups.length !== 8) return null;
    // Cada grupo a 4 hex chars
    const fullHex = groups.map(g => g.padStart(4, '0')).join('');
    if (fullHex.length !== 32) return null;
    return fullHex.split('').reverse().join('.');
}

// Comprueba una IP contra una DNSBL.
// status: 'listed' | 'clean' | 'error'
//   - 'listed'  : respuesta 127.0.0.x (la IP está en la lista)
//   - 'clean'   : NXDOMAIN / sin respuesta (no listada)
//   - 'error'   : 127.255.255.x (resolver público bloqueado/cuota) o fallo de red →
//                 resultado NO concluyente. Muchas DNSBL (Spamhaus, SpamCop…) rechazan
//                 las consultas que llegan vía resolvers DoH públicos (Google/Cloudflare),
//                 por lo que estas comprobaciones son best-effort.
export async function checkRBL(ip, rblHost) {
    try {
        const reversed = reverseIpForDns(ip);
        if (!reversed) return { status: 'error', listed: false, rbl: rblHost };
        const queryName = `${reversed}.${rblHost}`;
        const data = await queryDNS(queryName, 'A');
        if (data && data.Answer && data.Answer.length > 0) {
            const codes = data.Answer.filter(a => a.type === 1 && a.data).map(a => a.data);
            // 127.255.255.x ⇒ código de error de la DNSBL (consulta rechazada / cuota / resolver público)
            if (codes.length && codes.every(c => c.startsWith('127.255.255.'))) {
                return { status: 'error', listed: false, rbl: rblHost, details: codes[0] };
            }
            const listedCode = codes.find(c => c.startsWith('127.') && !c.startsWith('127.255.255.'));
            if (listedCode) {
                return { status: 'listed', listed: true, rbl: rblHost, details: listedCode };
            }
            // Respuesta presente pero fuera de 127.0.0.0/8 ⇒ no concluyente
            return { status: 'error', listed: false, rbl: rblHost, details: codes[0] || null };
        }
    } catch (e) {
        // Fallo de red ⇒ no concluyente (NXDOMAIN no lanza: se trata como 'clean' abajo)
        return { status: 'error', listed: false, rbl: rblHost };
    }
    return { status: 'clean', listed: false, rbl: rblHost };
}

// ===== NEW: Advanced DNS queries for ICES detection =====

export async function getAllTXT(domain) {
    try {
        const data = await queryDNS(domain, 'TXT');
        if (!data.Answer) return [];
        return data.Answer
            .filter(a => a.type === 16)
            .map(a => extractTxtValue(a.data));
    } catch (e) {
        console.warn('Failed to get all TXT for %s', domain, e);
        return [];
    }
}

// `opts.direct` = false salta la petición directa desde el navegador (que deja la IP del
// auditor y el Origin de la app en los registros del dominio auditado) y va directamente
// al proxy, si está permitido.
export async function fetchMTASTSPolicyFile(domain, opts = {}) {
    const direct = opts.direct !== false;
    // La URL se construye con el dominio auditado, que es justo lo que hace esta
    // comprobación. Aun así se valida AQUÍ, en el punto del fetch: la función es
    // exportada y no debe depender de que quien la llame haya validado antes.
    if (!isValidDomain(domain)) {
        return {
            url: null, httpStatus: null, fetchOk: false, body: null, parsed: null,
            mode: null, valid: false,
            error: 'Invalid domain', validationReason: 'invalid_domain'
        };
    }
    const url = `https://mta-sts.${domain}/.well-known/mta-sts.txt`;
    const base = {
        url,
        httpStatus: null,
        fetchOk: false,
        body: null,
        parsed: null,
        mode: null,
        valid: false,
        error: null,
        validationReason: null
    };

    let res;
    let body;
    let usedUrl = url;

    // Un redirect en el endpoint de política es motivo de fallo (RFC 8461 §3.3):
    // los MTA reales NO siguen 3xx al obtener mta-sts.txt.
    const redirectFail = (httpStatus) => ({
        ...base,
        httpStatus: httpStatus || null,
        error: 'Policy endpoint returned a redirect (RFC 8461 §3.3 forbids following it)',
        validationReason: 'redirect_not_allowed'
    });

    try {
        if (!direct) throw new Error('Direct fetch disabled in settings');
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 8000);
        // redirect:'manual' expone el 3xx como respuesta opaca en vez de seguirlo.
        res = await fetch(url, {
            method: 'GET',
            cache: 'no-store',
            redirect: 'manual',
            referrerPolicy: 'no-referrer',
            signal: controller.signal
        });
        clearTimeout(timeoutId);
        if (res.type === 'opaqueredirect' || (res.status >= 300 && res.status < 400)) {
            return redirectFail(res.status);
        }
        body = await res.text();
    } catch (e) {
        // El proxy CORS público es OPT-IN: manda el dominio auditado a un tercero.
        // Sin él, la política simplemente queda sin evaluar (no penaliza la nota).
        if (!getSettings().allowCorsProxy) {
            return {
                ...base,
                error: e.name === 'AbortError'
                    ? 'Policy fetch timed out'
                    : 'Direct fetch failed (CORS/Network) and the public CORS proxy is disabled in settings',
                validationReason: 'fetch_failed'
            };
        }
        if (direct) console.warn('Direct fetch for MTA-STS failed (likely CORS or network error). Trying proxy fallback.', e);
        try {
            const proxyUrl = `https://api.allorigins.win/get?url=${encodeURIComponent(url)}`;
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 8000);
            const proxyRes = await fetch(proxyUrl, { signal: controller.signal });
            clearTimeout(timeoutId);
            if (!proxyRes.ok) throw new Error(`Proxy HTTP error: ${proxyRes.status}`);
            const data = await proxyRes.json();
            if (!data || !data.contents) throw new Error(`Empty contents from proxy`);
            // Usa el código HTTP REAL del origen (allorigins lo expone en status.http_code)
            // en vez de asumir 200: una política inexistente (404) o redirigida no debe
            // reportarse como obtenida con éxito.
            const httpCode = data.status && typeof data.status.http_code === 'number' ? data.status.http_code : 200;
            if (httpCode >= 300 && httpCode < 400) return redirectFail(httpCode);
            if (httpCode < 200 || httpCode >= 400) {
                return { ...base, httpStatus: httpCode, error: `Policy endpoint returned HTTP ${httpCode}`, validationReason: 'fetch_failed' };
            }
            body = data.contents;
            res = { ok: true, status: httpCode };
            usedUrl = `${url} (via CORS proxy)`;
        } catch (proxyErr) {
            const message = e.name === 'AbortError' || proxyErr.name === 'AbortError'
                ? 'Policy fetch timed out'
                : `Direct fetch failed (CORS/Network) and CORS proxy fallback failed: ${proxyErr.message}`;
            return {
                ...base,
                error: message,
                validationReason: 'fetch_failed'
            };
        }
    }

    try {
        const parsed = parseMTASTSPolicy(body);
        const mode = parsed?.mode ? String(parsed.mode).toLowerCase() : null;
        const policyFetch = {
            url: usedUrl,
            httpStatus: res.status,
            fetchOk: res.ok,
            body,
            parsed,
            mode,
            error: null
        };
        const validation = validateMTASTSPolicy(policyFetch);
        return {
            ...policyFetch,
            valid: validation.valid,
            validationReason: validation.reason
        };
    } catch (parseErr) {
        return {
            ...base,
            url: usedUrl,
            error: `Failed to parse policy: ${parseErr.message}`,
            validationReason: 'parse_error'
        };
    }
}

/**
 * ¿Resuelve `host` a alguna dirección? Solo por DoH: no toca el host.
 * @returns {Promise<'ok'|'missing'|'unknown'>} 'unknown' = no se pudo consultar
 */
async function probeHostResolves(host) {
    try {
        const a = await queryDNS(host, 'A');
        if ((a && a.Answer || []).some(r => r.type === 1)) return 'ok';
        if (a && a.Status === 3) return 'missing';
        const aaaa = await queryDNS(host, 'AAAA');
        if ((aaaa && aaaa.Answer || []).some(r => r.type === 28)) return 'ok';
        return 'missing';
    } catch {
        return 'unknown';
    }
}

/**
 * Política MTA-STS respetando la privacidad del auditor.
 *
 * Primero se comprueba POR DNS que `mta-sts.<dominio>` resuelva: si no, la política está
 * rota para cualquier MTA del mundo, y eso se concluye sin mandar una sola petición al
 * dominio auditado. Solo después se descarga, y únicamente si Ajustes lo permite: la
 * descarga directa deja en SUS registros la IP del auditor y el Origin de esta app, y
 * además casi siempre la bloquea CORS. Sin permiso, la política queda "no descargada"
 * (no evaluable, no penaliza).
 */
async function resolveMtaStsPolicy(domain) {
    const host = `mta-sts.${domain}`;
    const notFetched = (validationReason) => ({
        url: `https://${host}/.well-known/mta-sts.txt`, host, httpStatus: null, fetchOk: false, body: null,
        parsed: null, mode: null, valid: false, error: null, validationReason
    });
    if (await probeHostResolves(host) === 'missing') return notFetched('host_missing');
    const s = getSettings();
    if (!s.contactAuditedHosts && !s.allowCorsProxy) return notFetched('not_fetched');
    return fetchMTASTSPolicyFile(domain, { direct: !!s.contactAuditedHosts });
}

export async function getMTASTS(domain) {
    try {
        const data = await queryDNS(`_mta-sts.${domain}`, 'TXT');
        if (!data.Answer) return null;
        for (const a of data.Answer) {
            const txt = extractTxtValue(a.data);
            if (txt.startsWith('v=STSv1')) {
                const idMatch = txt.match(/id=([^;]+)/);
                const result = {
                    record: txt,
                    id: idMatch ? idMatch[1].trim() : null
                };
                result.policy = await resolveMtaStsPolicy(domain);
                return result;
            }
        }
    } catch (e) {
        console.warn('Failed to get MTA-STS for %s', domain, e);
    }
    return null;
}

export async function getTLSRPT(domain) {
    try {
        const data = await queryDNS(`_smtp._tls.${domain}`, 'TXT');
        if (!data.Answer) return null;
        for (const a of data.Answer) {
            const txt = extractTxtValue(a.data);
            if (txt.startsWith('v=TLSRPTv1')) {
                const ruaMatch = txt.match(/rua=([^;]+)/);
                const rua = ruaMatch ? ruaMatch[1].trim().split(',').map(s => s.trim()) : [];
                return { record: txt, rua };
            }
        }
    } catch (e) {
        console.warn('Failed to get TLS-RPT for %s', domain, e);
    }
    return null;
}

export async function getNS(domain) {
    try {
        const data = await queryDNS(domain, 'NS');
        if (!data.Answer) return [];
        return data.Answer
            .filter(a => a.type === 2)
            .map(a => a.data.replace(/\.$/, ''));
    } catch (e) {
        console.warn('Failed to get NS for %s', domain, e);
        return [];
    }
}

export async function getSRV(domain) {
    const srvRecords = {};
    const checks = [
        { key: 'autodiscover', record: `_autodiscover._tcp.${domain}` },
        { key: 'imaps', record: `_imaps._tcp.${domain}` },
        { key: 'submission', record: `_submission._tcp.${domain}` }
    ];
    
    await Promise.all(checks.map(async check => {
        try {
            const data = await queryDNS(check.record, 'SRV');
            if (data.Answer && data.Answer.length > 0) {
                srvRecords[check.key] = data.Answer
                    .filter(a => a.type === 33)
                    .map(a => {
                        const parts = a.data.split(' ');
                        return {
                            priority: parts[0],
                            weight: parts[1],
                            port: parts[2],
                            target: parts[3] ? parts[3].replace(/\.$/, '') : ''
                        };
                    });
            }
        } catch (e) {
            console.warn('Failed to query SRV for %s', check.record, e);
        }
    }));
    
    return srvRecords;
}

// Detecta si el dominio está firmado con DNSSEC.
//   signed          : hay registros DNSKEY (type 48) publicados en el ápex
//   ad              : el resolver marcó la respuesta como Authenticated Data (validada)
//   validationKnown : el resolver valida DNSSEC, así que un AD=false SIGNIFICA algo.
//                     Google, Cloudflare y Quad9 validan; de un resolver propio no se sabe.
// DNSKEY sin AD es una zona firmada cuya cadena de confianza no valida (falta el DS en
// la zona padre, o está rota): no protege nada, y el scoring lo distingue.
export async function getDNSSEC(domain) {
    const validationKnown = getSettings().resolver !== 'custom';
    try {
        const data = await queryDNS(domain, 'DNSKEY');
        const hasDnskey = !!(data && data.Answer && data.Answer.some(a => a.type === 48));
        const ad = !!(data && data.AD);
        return { signed: hasDnskey || ad, hasDnskey, ad, validationKnown };
    } catch (e) {
        return { signed: false, hasDnskey: false, ad: false, validationKnown, error: e.message };
    }
}

// Verifica la autorización de destinos DMARC EXTERNOS (RFC 9990 §4, antes RFC 7489 §7.1):
// si rua/ruf apunta fuera del dominio organizativo, el destino debe publicar
// `<dominio-de-la-política>._report._dmarc.<host-destino>` con un registro v=DMARC1, o
// los informes se descartan.
//   authorized: true | false | null (null = no se pudo comprobar / error de red)
//
// `policyDomain` es el dominio DONDE SE ENCONTRÓ la política (paso 3 del RFC: «prepend
// the domain name from which the policy was retrieved»). Al analizar un subdominio que
// hereda la política, ese nombre es el del dominio organizativo, no el del subdominio:
// consultar `<subdominio>._report._dmarc…` acusaba de "no autorizado" a un destino que sí
// lo estaba. `opts.orgDomain` es el dominio organizativo que ha dado el Tree Walk; sin él
// se estima con extractRootDomain.
export async function checkDMARCExternalAuth(policyDomain, uris, opts = {}) {
    const results = [];
    if (!uris || uris.length === 0) return results;
    const analyzed = String(policyDomain).toLowerCase().replace(/\.$/, '');
    // El RFC compara DOMINIOS ORGANIZATIVOS, no cadenas exactas: comparar literales
    // acusaba de "destino externo no autorizado" a quien manda sus informes a un
    // subdominio propio (rua=…@dmarc.suempresa.com), que es la práctica habitual.
    const analyzedOrg = opts.orgDomain
        ? String(opts.orgDomain).toLowerCase().replace(/\.$/, '')
        : extractRootDomain(analyzed);
    const seen = new Set();
    for (const uri of uris) {
        const m = String(uri).match(/^\s*mailto:[^@\s]+@([^\s!,;?]+)/i);
        if (!m) continue;
        const destDomain = m[1].toLowerCase().replace(/\.$/, '');
        // Dentro del dominio organizativo ⇒ no hace falta autorización. Se compara por
        // etiquetas (sufijo) y no con la heurística de dominio raíz.
        if (isSameOrSubdomain(destDomain, analyzedOrg)) continue;
        if (!opts.orgDomain && extractRootDomain(destDomain) === analyzedOrg) continue;
        if (seen.has(destDomain)) continue;
        seen.add(destDomain);
        try {
            const data = await queryDNS(`${analyzed}._report._dmarc.${destDomain}`, 'TXT');
            let authorized = false;
            let override = null;
            if (data && data.Answer) {
                for (const a of data.Answer) {
                    const txt = extractTxtValue(a.data);
                    // Paso 6: v=DMARC1 obligatorio y el primero (mismas reglas que el registro).
                    if (isDmarcRecord(txt)) {
                        authorized = true;
                        // Paso 9: el receptor puede reescribir el destino, pero solo hacia el
                        // mismo host; si no, ese rua no cuenta.
                        const rua = (parseDMARC(txt) || {}).rua;
                        if (rua) override = rua;
                        break;
                    }
                }
            }
            results.push({ uri, destDomain, authorized, ...(override ? { override } : {}) });
        } catch (e) {
            results.push({ uri, destDomain, authorized: null });
        }
    }
    return results;
}

// `validated` (no enumerable, para no alterar a quien recorre los hosts) guarda si cada
// respuesta TLSA llegó validada por DNSSEC: un TLSA sin validar no lo usa ningún MTA
// (RFC 7672 §2.2).
export async function getDANE(mxHosts) {
    const daneRecords = {};
    const validated = {};
    Object.defineProperty(daneRecords, 'validated', { value: validated, enumerable: false });
    if (!mxHosts || mxHosts.length === 0) return daneRecords;
    const validationKnown = getSettings().resolver !== 'custom';
    await Promise.all(mxHosts.map(async mx => {
        try {
            const data = await queryDNS(`_25._tcp.${mx}`, 'TLSA');
            if (data.Answer && data.Answer.length > 0) {
                daneRecords[mx] = data.Answer
                    .filter(a => a.type === 52 || a.type === 32768) // 52 is TLSA type
                    .map(a => a.data);
                if (validationKnown) validated[mx] = !!data.AD;
            }
        } catch (e) {
            console.warn('Failed to query DANE for _25._tcp.%s', mx, e);
        }
    }));
    return daneRecords;
}


// ===========================================================================
// Hospedaje del correo: sondas del eje "plataforma de buzón"
//
// El MX dice quién FILTRA el correo entrante. Estas sondas responden a la otra
// pregunta, la que el MX tapa cuando hay un gateway delante: dónde VIVEN los
// buzones. Todas van por `queryDNS`, así que heredan caché, semáforo de
// concurrencia y cadena de resolvers, y no necesitan tocar la CSP.
// ===========================================================================

/**
 * Resuelve `autodiscover.<dominio>`: el endpoint de autoconfiguración de Exchange.
 * Es el mejor indicador externo de dónde están los buzones — apunta a
 * `autodiscover.outlook.com` en M365 y a infraestructura propia en on-premise.
 *
 * OJO al interpretarlo: autodiscover es un protocolo de Microsoft. Su AUSENCIA es
 * lo normal en Google Workspace y NO debe leerse como indicio de on-premise.
 *
 * `status` separa "no existe" (un dato sobre el dominio) de "no se pudo consultar" (un
 * dato sobre nosotros). La diferencia es crítica: un fallo transitorio de DNS no debe
 * leerse jamás como ausencia de autodiscover, y de ahí como indicio de servidor propio.
 *
 * @returns {Promise<{cname: string|null, ips: string[], status: 'ok'|'nxdomain'|'unavailable'}>}
 */
export async function getAutodiscover(domain) {
    const host = `autodiscover.${domain}`;
    let cname = null;
    const ips = [];
    try {
        // Una sola consulta A basta: la cadena Answer trae el CNAME (type 5) y la
        // dirección final (type 1). Pedir CNAME por separado sería una consulta de más.
        const data = await queryDNS(host, 'A');
        for (const a of (data && data.Answer) || []) {
            if (a.type === 5 && a.data && !cname) cname = String(a.data).replace(/\.$/, '').toLowerCase();
            if (a.type === 1 && a.data) ips.push(a.data);
        }
    } catch (e) {
        console.warn('Failed to resolve autodiscover for %s', domain, e);
        return { cname: null, ips: [], status: 'unavailable' };
    }
    const status = (cname || ips.length) ? 'ok' : 'nxdomain';
    return { cname, ips: [...new Set(ips)], status };
}

// El nombre de un ASN no cambia entre consultas y muchas IPs comparten ASN: sin
// memoizar, un análisis repetiría la misma consulta una vez por IP.
const _asNameCache = new Map();

/**
 * Nombre de la organización dueña de un ASN, vía Team Cymru sobre DNS.
 * `AS8075.asn.cymru.com` TXT → "8075 | US | arin | … | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US"
 */
async function getASName(asn) {
    if (!asn) return null;
    if (_asNameCache.has(asn)) return _asNameCache.get(asn);
    let name = null;
    try {
        const data = await queryDNS(`AS${asn}.asn.cymru.com`, 'TXT');
        const txt = extractTxtValue(((data && data.Answer) || []).map(a => a.data).find(Boolean) || '');
        // El último campo del TXT es la descripción de la organización.
        const parts = txt.split('|').map(s => s.trim());
        if (parts.length >= 5 && parts[4]) name = parts[4];
    } catch (e) {
        console.warn('Failed to resolve AS name for AS%s', asn, e);
    }
    _asNameCache.set(asn, name);
    return name;
}

/**
 * Perfila una IP: a qué ASN pertenece, de quién es ese ASN y qué PTR tiene.
 *
 * El ASN es la señal más fuerte de infraestructura propia: cuando una empresa
 * anuncia sus propios rangos, el ASN lleva literalmente su nombre (AS_INDITEX,
 * ASMERCADONA). Se usa el mapeo IP→ASN de Team Cymru, que se sirve por DNS y por
 * tanto funciona igual que cualquier otra consulta de la herramienta.
 *
 * Degrada con elegancia: si Cymru no responde (algunos resolvers corporativos lo
 * filtran), se devuelven los campos a null y la clasificación simplemente pierde
 * esa señal en vez de fallar.
 *
 * @returns {Promise<{ip: string, asn: string|null, asName: string|null, prefix: string|null, cc: string|null, ptr: string|null}>}
 */
export async function getIpIntel(ip) {
    const out = { ip, asn: null, asName: null, prefix: null, cc: null, ptr: null };
    const reversed = reverseIpForDns(ip);
    if (!reversed) return out;
    const zone = ip.includes(':') ? 'origin6.asn.cymru.com' : 'origin.asn.cymru.com';
    const arpa = ip.includes(':') ? 'ip6.arpa' : 'in-addr.arpa';

    const [cymru, ptr] = await Promise.all([
        queryDNS(`${reversed}.${zone}`, 'TXT').catch(() => null),
        queryDNS(`${reversed}.${arpa}`, 'PTR').catch(() => null)
    ]);

    if (cymru && cymru.Answer) {
        // "204748 | 195.77.160.0/23 | ES | ripencc | 1996-12-02"
        const txt = extractTxtValue(cymru.Answer.map(a => a.data).find(Boolean) || '');
        const parts = txt.split('|').map(s => s.trim());
        if (parts[0]) out.asn = parts[0].split(/\s+/)[0]; // el campo puede traer varios ASN
        if (parts[1]) out.prefix = parts[1];
        if (parts[2]) out.cc = parts[2];
    }
    if (ptr && ptr.Answer) {
        const rec = ptr.Answer.find(a => a.type === 12 && a.data);
        if (rec) out.ptr = String(rec.data).replace(/\.$/, '').toLowerCase();
    }
    if (out.asn) out.asName = await getASName(out.asn);
    return out;
}

/**
 * Consulta selectores DKIM CONSERVANDO el destino del CNAME.
 *
 * `getDKIM` se queda solo con el TXT `v=DKIM1` y descarta la cadena, pero en M365
 * el CNAME es justo lo interesante: `selector1._domainkey.<dominio>` →
 * `selector1-<dominio>._domainkey.<TENANT>.onmicrosoft.com`. Ese destino demuestra
 * que existe un tenant de Microsoft 365 y hasta revela su nombre.
 *
 * Lo que NO demuestra: dónde están los buzones. Un tenant puede coexistir con un
 * Exchange local — que es precisamente el caso híbrido que interesa detectar.
 *
 * @returns {Promise<Array<{selector: string, cname: string|null, hasKey: boolean}>>}
 */
export async function getDkimSelectorChain(domain, selectors = ['selector1', 'selector2']) {
    const results = await Promise.all(selectors.map(async (selector) => {
        const out = { selector, cname: null, hasKey: false };
        try {
            // Misma consulta (nombre, tipo) que hace getDKIM para selector1: la caché
            // de queryDNS la sirve sin tráfico adicional.
            const data = await queryDNS(`${selector}._domainkey.${domain}`, 'TXT');
            for (const a of (data && data.Answer) || []) {
                if (a.type === 5 && a.data && !out.cname) {
                    out.cname = String(a.data).replace(/\.$/, '').toLowerCase();
                }
                if (a.type === 16 && isDkimKeyRecord(extractTxtValue(a.data))) out.hasKey = true;
            }
        } catch (e) {
            console.warn('Failed to resolve DKIM chain %s._domainkey.%s', selector, domain, e);
        }
        return out;
    }));
    return results;
}

/**
 * Resuelve los dominios parecidos generados por lookalike.js: cuáles están registrados,
 * cuáles pueden recibir correo (MX) y cuáles son, probablemente, del propio dominio.
 *
 * Usa queryDNS, así que respeta la piscina de consultas y la caché, y lo que se envía al
 * resolver es lo mismo que en el resto del análisis: nombres de dominio. NXDOMAIN es
 * "libre"; un SERVFAIL o un fallo de red no se da por registrado, se cuenta aparte.
 *
 * @param {Array<{domain, technique}>} candidates
 * @param {{ domain: string, mx: string[], ns: string[] }} baseline el dominio auditado
 * @returns {Promise<{ checked: number, found: Array, unresolved: number }>}
 */
export async function checkLookalikes(candidates, baseline) {
    let unresolved = 0;
    const found = [];
    await Promise.all(candidates.map(async (candidate, index) => {
        let data;
        try {
            data = await queryDNS(candidate.domain, 'MX');
        } catch {
            unresolved++;
            return;
        }
        if (data && data.Status === 3) return; // NXDOMAIN: libre
        const mx = _parseMxAnswer(data).map(r => r.host).filter(isDeliverableMx);
        // Sin MX que entregue no puede recibir correo: basta con saber que está registrada,
        // y no se gastan tres consultas más (con marcas muy imitadas son decenas).
        if (!mx.length) {
            found.push({ ...candidate, index, mx, ns: [], kind: 'registered' });
            return;
        }
        // Para reconocer los registros defensivos: sus NS, y adónde apuntan su SPF y su
        // DMARC. Un fallo en cualquiera de las tres solo deja la heurística con menos datos.
        const txtOf = (name) => queryDNS(name, 'TXT')
            .then(d => (d.Answer || []).filter(a => a.type === 16).map(a => extractTxtValue(a.data)))
            .catch(() => []);
        const [ns, txt, dmarc] = await Promise.all([getNS(candidate.domain), txtOf(candidate.domain), txtOf(`_dmarc.${candidate.domain}`)]);
        const links = ownershipLinks(txt, dmarc);
        found.push({ ...candidate, index, mx, ns, kind: classifyLookalike({ mx, ns, links }, baseline) });
    }));
    // Primero lo que puede recibir correo y no es del auditado; dentro de cada grupo, el
    // orden de prioridad del generador.
    const RANK = { mx: 0, registered: 1, own: 2 };
    found.sort((a, b) => (RANK[a.kind] - RANK[b.kind]) || (a.index - b.index));
    return { checked: candidates.length, found: found.map(({ index: _i, ...rest }) => rest), unresolved };
}
