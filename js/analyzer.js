import { KB } from './knowledge.js';
import { extractRootDomain } from './utils.js';
import { parseSPF, parseDMARC, analyzeDKIMRecord, validateTlsRptRua, checkMtaStsMxCoverage } from './parsers.js';

export function identifyMX(host, domain) {
    const h = host.toLowerCase();
    // First label of the MX hostname (e.g. "esa01" from "esa01.arquia.es")
    const firstLabel = h.split('.')[0];
    for (const entry of KB.mx) {
        if (entry.matchType === 'hostname_prefix') {
            // Match if the first hostname label starts with the pattern (e.g. "esa" matches "esa01", "esa1", "esa-gw")
            if (firstLabel.startsWith(entry.pattern)) return entry;
        } else {
            if (h.includes(entry.pattern)) return entry;
        }
    }
    if (domain) {
        const mxRoot = extractRootDomain(h);
        const domainRoot = extractRootDomain(domain.toLowerCase());
        // If MX root matches the analyzed domain root, it's the company's own mail server — not a SEG
        if (domainRoot && mxRoot && mxRoot === domainRoot) {
            return { name: host, type: 'self' };
        }
        // MX en un dominio distinto y NO reconocido por el diccionario.
        //
        // Antes esto se etiquetaba directamente como 'seg', y era un falso positivo
        // sistemático: paypal.com → "paypalcorp.com", acme.com → "acmegroup.net",
        // empresa.es → "empresa.com"… Cualquier dominio hermano, variante de ccTLD o
        // hosting no catalogado se anunciaba como un producto de seguridad cuyo
        // "nombre" era, en realidad, un dominio. Los SEG de verdad los reconoce el
        // diccionario ANTES de llegar aquí, así que el atajo no aportaba ninguna
        // detección real: solo fabricaba afirmaciones que no se pueden sostener.
        //
        // Ahora se devuelve lo único que se sabe con certeza —el correo entra por un
        // dominio externo no identificado— y la UI lo presenta como observación, no
        // como capa de seguridad detectada.
        if (domainRoot && mxRoot && mxRoot !== domainRoot) {
            return {
                name: mxRoot,
                type: 'unknown',
                external: true,
                sameBrand: isSameBrand(mxRoot, domainRoot)
            };
        }
    }
    return { name: host, type: 'unknown' };
}

/**
 * ¿Dos dominios raíz comparten nombre de marca? (paypal.com ↔ paypalcorp.com,
 * empresa.es ↔ empresa.com, acme.com ↔ acmegroup.net)
 * Se compara la etiqueta principal y basta con que una sea prefijo de la otra, con
 * un mínimo de 4 caracteres para no emparejar por casualidad etiquetas cortas
 * ("mx", "srv"). Es una pista para redactar el aviso, nunca una afirmación de
 * propiedad: sirve para decir "probablemente es infraestructura propia" en vez de
 * "dominio no reconocido".
 */
export function isSameBrand(rootA, rootB) {
    const label = (d) => String(d || '').toLowerCase().split('.')[0];
    const a = label(rootA);
    const b = label(rootB);
    if (!a || !b) return false;
    if (a === b) return true;
    const [short, long] = a.length <= b.length ? [a, b] : [b, a];
    return short.length >= 4 && long.startsWith(short);
}

// extractRootDomain vive en utils.js junto a normalizeDomain/isValidDomain: es una
// utilidad de nombres de dominio, no lógica de análisis, y api.js también la necesita
// (para no depender del analizador). Se re-exporta para no romper los imports previos.
export { extractRootDomain } from './utils.js';

export function identifySPFService(value) {
    if (!value || value === '(self)') return null;
    const v = value.toLowerCase();
    for (const entry of KB.spf) {
        if (v.includes(entry.pattern)) return entry;
    }
    
    if (v.includes('.')) {
        const cleanDomain = v.replace(/^(include:|a:|mx:|ptr:)/, '');
        const rootDomain = extractRootDomain(cleanDomain);
        return {
            name: rootDomain,
            category: 'unknown',
            cat_label: 'Desconocido',
            is_unknown: true,
            search_query: cleanDomain
        };
    }
    return null;
}

export function identifyDMARCReporter(uri) {
    const u = uri.toLowerCase();
    for (const entry of KB.dmarc_reporters) {
        if (u.includes(entry.pattern)) return entry.name;
    }
    return null;
}

// NEW: Identify ICES/SEG/other services from TXT verification tokens
export function identifyTXTVerifications(txtRecords) {
    if (!txtRecords || txtRecords.length === 0) return [];
    const found = [];
    const seen = new Set();
    for (const txt of txtRecords) {
        const lower = txt.toLowerCase();
        // Skip SPF and DMARC records (already analyzed elsewhere)
        if (lower.startsWith('v=spf1') || lower.startsWith('v=dmarc1')) continue;
        for (const entry of KB.txt_verification) {
            if (lower.includes(entry.pattern.toLowerCase()) && !seen.has(entry.name)) {
                seen.add(entry.name);
                found.push({
                    name: entry.name,
                    category: entry.category,
                    record: txt.length > 80 ? txt.substring(0, 77) + '...' : txt,
                    fullRecord: txt,
                    // Peso propio del token (si el diccionario lo define) y marca de
                    // "solo verificación de propiedad": un token TXT prueba que el
                    // dominio se vinculó al vendor, no que esté en el flujo de correo.
                    ...(entry.weight != null ? { weight: entry.weight } : {}),
                    ...(entry.verificationOnly ? { verificationOnly: true } : {})
                });
            }
        }
    }
    return found;
}

// NEW: Identify DNS provider from NS records
export function identifyNSProvider(nsRecords) {
    if (!nsRecords || nsRecords.length === 0) return null;
    for (const ns of nsRecords) {
        const lower = ns.toLowerCase();
        for (const entry of KB.ns_providers) {
            if (lower.includes(entry.pattern)) {
                return { name: entry.name, hint: entry.hint, ns };
            }
        }
    }
    return null;
}

// NEW: Analyze TLS-RPT reporting destinations
export function analyzeTLSRPT(tlsrpt) {
    if (!tlsrpt || !tlsrpt.rua || tlsrpt.rua.length === 0) return [];
    const reporters = [];
    for (const rua of tlsrpt.rua) {
        const lower = rua.toLowerCase();
        let identified = null;
        for (const entry of KB.tlsrpt_reporters) {
            if (lower.includes(entry.pattern)) {
                identified = entry.name;
                break;
            }
        }
        reporters.push({ uri: rua, reporter: identified });
    }
    return reporters;
}

// Recorre el árbol SPF (getSPFLookupTree) y devuelve TODOS los dominios objetivo
// de include/redirect en cualquier profundidad (cadena SPF aplanada).
/**
 * Recorre el árbol SPF y recoge los problemas que SOLO se ven resolviéndolo:
 *   - noRecord: destino de include/redirect que no publica SPF ⇒ PermError (RFC 7208 §5.2).
 *               Es el fallo silencioso más común: el registro "parece" correcto pero
 *               ningún receptor puede evaluarlo.
 *   - voids:    mecanismos a/mx/exists cuya consulta devuelve NXDOMAIN o vacío.
 *               Más de 2 ⇒ PermError (RFC 7208 §4.6.4).
 *   - loops:    include/redirect que vuelve sobre un antepasado de su propia cadena.
 * @returns {{ noRecord: string[], voids: string[], loops: string[] }}
 */
export function collectSpfTreeIssues(tree, acc = { noRecord: [], voids: [], loops: [] }) {
    if (!tree || !tree.children) return acc;
    for (const child of tree.children) {
        if (child.void === true) acc.voids.push(`${child.type}:${child.target}`);
        if (child.tree) {
            if (child.tree.error === 'no_spf_record') acc.noRecord.push(child.target);
            else if (child.tree.error === 'loop') acc.loops.push(child.target);
            collectSpfTreeIssues(child.tree, acc);
        }
    }
    return acc;
}

export function collectSpfDomains(tree, acc = []) {
    if (!tree || !tree.children) return acc;
    for (const child of tree.children) {
        if (child.target && child.target !== '(self)') {
            acc.push(child.target.toLowerCase());
        }
        if (child.tree) collectSpfDomains(child.tree, acc);
    }
    return acc;
}

const DEFAULT_SEG_WEIGHTS = { mx: 0.9, mta_sts: 0.8, txt: 0.7, spf: 0.6, spf_nested: 0.5, dkim: 0.6 };

function _segLevel(score) {
    if (score >= 0.85) return 'alta';
    if (score >= 0.55) return 'media';
    return 'baja';
}

/**
 * Detección ponderada multi-señal de capas de seguridad (SEG / ICES).
 * Agrega evidencia de: MX, SPF (incluye top-level y anidado), tokens TXT, lista mx
 * de la política MTA-STS y selectores DKIM del vendor. Combina con noisy-OR.
 *
 * @returns {{ segList: Array, icesList: Array }} cada entrada:
 *   { name, category, source, score, level, evidence: [{signal, value, weight}] }
 */
export function detectSecurityLayers(signals = {}) {
    const {
        domain = '',
        mxRecords = [],
        spfEntries = [],
        spfNestedDomains = [],
        txtVerifications = [],
        mtaStsMx = [],
        dkimSelectors = []
    } = signals;

    const W = { ...DEFAULT_SEG_WEIGHTS, ...(KB.seg_signal_weights || {}) };
    const map = new Map(); // key: `${category}:${name}` -> entry

    const add = (name, category, signal, value, weight) => {
        if (!name || (category !== 'seg' && category !== 'ices')) return;
        const key = `${category}:${name}`;
        let entry = map.get(key);
        if (!entry) {
            entry = { name, category, evidence: [] };
            map.set(key, entry);
        }
        // Dedupe por signal+value
        if (!entry.evidence.some(e => e.signal === signal && e.value === value)) {
            entry.evidence.push({ signal, value, weight });
        }
    };

    // 1. MX (correo entrante por el gateway)
    for (const mx of mxRecords) {
        const id = identifyMX(mx.host, domain);
        if (id.type === 'seg' || id.type === 'ices') add(id.name, id.type, 'mx', mx.host, W.mx);
    }

    // 2. MTA-STS: hostnames MX autorizados en la política
    for (const pattern of mtaStsMx) {
        const id = identifyMX(String(pattern).toLowerCase(), domain);
        if (id.type === 'seg' || id.type === 'ices') add(id.name, id.type, 'mta_sts', pattern, W.mta_sts);
    }

    // 3. SPF top-level (include / a / redirect)
    const topValues = [];
    for (const entry of spfEntries) {
        if (entry.type === 'include' || entry.type === 'a' || entry.type === 'redirect') {
            topValues.push((entry.value || '').toLowerCase());
            const svc = identifySPFService(entry.value);
            if (svc && (svc.category === 'seg' || svc.category === 'ices')) {
                add(svc.name, svc.category, 'spf', entry.value, W.spf);
            }
        }
    }

    // 4. SPF anidado (includes profundos no presentes en top-level)
    for (const d of spfNestedDomains) {
        if (topValues.includes(d)) continue;
        const svc = identifySPFService(d);
        if (svc && (svc.category === 'seg' || svc.category === 'ices')) {
            add(svc.name, svc.category, 'spf_nested', d, W.spf_nested);
        }
    }

    // 5. Tokens de verificación TXT (peso propio del token si el diccionario lo define)
    for (const v of txtVerifications) {
        if (v.category === 'seg' || v.category === 'ices') {
            add(v.name, v.category, 'txt', v.record, v.weight ?? W.txt);
        }
    }

    // 6. Selectores DKIM del vendor
    const dkimMap = KB.dkim_security_selectors || [];
    for (const sel of dkimSelectors) {
        const s = String(sel).toLowerCase();
        const hit = dkimMap.find(d => d.selector.toLowerCase() === s);
        if (hit) add(hit.name, hit.category, 'dkim', sel, W.dkim);
    }

    // Un SEG se define por estar EN el flujo de correo entrante (el MX apunta a él).
    // Estas señales confirman esa presencia; un token de verificación TXT NO.
    const IN_PATH_SIGNALS = new Set(['mx', 'mta_sts', 'spf', 'spf_nested', 'dkim']);
    // Identidad canónica del vendor: ignora paréntesis y sufijos genéricos para que un
    // mismo vendor con distinto nombre en cada diccionario ("Sophos" en el token TXT vs
    // "Sophos Email" en el MX; "Trend Micro" vs "Trend Micro Email Security") se
    // reconozca como el mismo y no se marque "sin confirmar" a un vendor cuyo MX SÍ lo confirma.
    const canonVendor = (name) => String(name).toLowerCase()
        .replace(/\([^)]*\)/g, ' ')
        .replace(/\b(email|security|messaging|gateway|essentials|ironport)\b/g, ' ')
        .replace(/[^a-z0-9]+/g, '');
    // Vendors cuyo MX real confirma presencia en el flujo de correo (por identidad canónica).
    const mxVendorCanon = new Set(
        mxRecords
            .map(mx => identifyMX(mx.host, domain))
            .filter(id => id.type === 'seg' || id.type === 'ices')
            .map(id => canonVendor(id.name))
            .filter(Boolean)
    );

    const segList = [];
    const icesList = [];
    for (const entry of map.values()) {
        let score = Math.round((1 - entry.evidence.reduce((acc, e) => acc * (1 - e.weight), 1)) * 100) / 100;
        const strongest = entry.evidence.reduce((a, b) => (b.weight > a.weight ? b : a), entry.evidence[0]);

        // Cross-check MX: si la ÚNICA evidencia de un SEG es un token de verificación
        // TXT (prueba de propiedad de dominio, no de flujo de correo) y ningún MX real
        // pertenece a ese vendor, la afirmación NO está confirmada → la degradamos a
        // "baja". Un gateway que no aparece en el MX no está filtrando el correo.
        // (Los ICES son API-based y no tocan el MX, por eso quedan excluidos.)
        const hasInPath = entry.evidence.some(e => IN_PATH_SIGNALS.has(e.signal));
        const canon = canonVendor(entry.name);
        const mxConfirmsVendor = canon !== '' && mxVendorCanon.has(canon);
        const unconfirmed = entry.category === 'seg' && !hasInPath && !mxConfirmsVendor;
        if (unconfirmed && score > 0.4) score = 0.4;

        const out = {
            name: entry.name,
            category: entry.category,
            source: strongest ? strongest.value : '',
            score,
            level: _segLevel(score),
            evidence: entry.evidence,
            ...(unconfirmed ? { unconfirmed: true } : {})
        };
        (entry.category === 'seg' ? segList : icesList).push(out);
    }
    segList.sort((a, b) => b.score - a.score);
    icesList.sort((a, b) => b.score - a.score);
    return { segList, icesList };
}

export function analyze(mxRecords, spfRaw, dmarcRaw, advancedData = {}) {
    const domain = advancedData.domain || '';
    const spfEntries = parseSPF(spfRaw);
    const dmarcParsed = parseDMARC(dmarcRaw);

    let provider = null;
    // providerSource es una estructura neutral de idioma: { key, arg }. La capa de
    // presentación (viewmodel) la traduce. Evita el patrón frágil de "sentinel" en español.
    let providerSource = null;
    // Detección de proveedor de correo (MX primero, luego SPF)
    for (const mx of mxRecords) {
        const id = identifyMX(mx.host, domain);
        if (id.type === 'provider' && !provider) {
            provider = id.name;
            providerSource = { key: 'evidence_mx', arg: mx.host };
        }
    }

    const spfServices = [];
    for (const entry of spfEntries) {
        if (entry.type === 'include' || entry.type === 'a' || entry.type === 'redirect') {
            const svc = identifySPFService(entry.value);
            if (svc) {
                if (!provider && svc.category === 'email') {
                    provider = svc.name;
                    providerSource = { key: 'evidence_spf', arg: entry.value };
                }
                spfServices.push({ ...svc, raw: entry.value });
            }
        }
    }

    const txtVerifications = advancedData.txtVerifications || [];

    // Detección ponderada multi-señal de capas de seguridad (SEG / ICES).
    const { segList, icesList } = detectSecurityLayers({
        domain,
        mxRecords,
        spfEntries,
        spfNestedDomains: collectSpfDomains(advancedData.spfTree),
        txtVerifications,
        mtaStsMx: advancedData.mtaSts?.policy?.parsed?.mx || [],
        dkimSelectors: advancedData.dkimSelectors || []
    });

    // NEW: Process NS provider hints
    const nsProvider = advancedData.nsProvider || null;

    // NEW: Process TLS-RPT reporters
    const tlsrptReporters = advancedData.tlsrptReporters || [];

    const providerIdentified = !!provider;
    if (!provider) {
        provider = null;
        providerSource = { key: 'provider_none' };
    }

    let dmarcPolicy = 'No configurado';
    let dmarcPolicyClass = '';
    let dmarcRua = [];
    let dmarcRuf = [];
    let dmarcDetails = {};
    
    if (dmarcParsed) {
        const p = dmarcParsed.p || 'none';
        dmarcPolicy = p;
        dmarcPolicyClass = p;
        dmarcDetails = dmarcParsed;
        
        if (dmarcParsed.rua) {
            dmarcRua = dmarcParsed.rua.split(',').map(s => s.trim());
        }
        if (dmarcParsed.ruf) {
            dmarcRuf = dmarcParsed.ruf.split(',').map(s => s.trim());
        }
    }

    return {
        provider, providerIdentified, providerSource, segList, icesList,
        spfRaw, spfEntries, spfServices,
        spfData: advancedData.spfData || { record: spfRaw, records: spfRaw ? [spfRaw] : [], multiple: false },
        dmarcRaw, dmarcParsed, dmarcPolicy, dmarcPolicyClass,
        dmarcRua, dmarcRuf, dmarcDetails,
        dmarcData: advancedData.dmarcData || { record: dmarcRaw, records: dmarcRaw ? [dmarcRaw] : [], multiple: false },
        // DMARC heredado del dominio organizativo (RFC 7489 §6.6.3) al analizar un subdominio.
        dmarcInherited: !!advancedData.dmarcInherited,
        dmarcInheritedFrom: advancedData.dmarcInheritedFrom || null,
        // Consultas que no se pudieron resolver (fallo transitorio): no se penalizan.
        spfUnavailable: !!advancedData.spfUnavailable,
        dmarcUnavailable: !!advancedData.dmarcUnavailable,
        mxRecords,
        // Null MX (RFC 7505): el dominio declara que no recibe correo.
        nullMx: !!(advancedData.nullMx || mxRecords.nullMx),
        // New advanced data
        txtVerifications,
        nsProvider,
        nsRecords: advancedData.nsRecords || [],
        mtaSts: advancedData.mtaSts || null,
        tlsRpt: advancedData.tlsRpt || null,
        tlsrptReporters,
        srvRecords: advancedData.srvRecords || null,
        daneRecords: advancedData.daneRecords || null,
        dnssec: advancedData.dnssec || null
    };
}

// ===== Scoring por categorías ponderadas =====
// El modelo aditivo anterior saturaba: SPF + DMARC reject + DKIM ya sumaban 95/100,
// así que MTA-STS, DNSSEC, DANE y BIMI no movían la nota. Ahora cada control tiene un
// presupuesto dentro de una categoría y la nota final se normaliza sobre lo que se ha
// podido EVALUAR (ver `unevaluable`), no sobre un máximo teórico.
export const SCORE_CATEGORIES = {
    auth: { max: 60, labelKey: 'score_cat_auth' },
    transport: { max: 25, labelKey: 'score_cat_transport' },
    hygiene: { max: 15, labelKey: 'score_cat_hygiene' }
};

// Presupuesto de cada check. La suma por categoría cuadra con SCORE_CATEGORIES.
// Un check sin entrada aquí (p. ej. `srv`) es puramente informativo: aporta findings
// pero no puntúa.
export const CHECK_BUDGETS = {
    spf:            { category: 'auth', max: 22, labelKey: 'score_check_spf' },
    dmarc:          { category: 'auth', max: 23, labelKey: 'score_check_dmarc' },
    dkim:           { category: 'auth', max: 15, labelKey: 'score_check_dkim' },
    mtaSts:         { category: 'transport', max: 10, labelKey: 'score_check_mta_sts' },
    dnssec:         { category: 'transport', max: 8, labelKey: 'score_check_dnssec' },
    dane:           { category: 'transport', max: 7, labelKey: 'score_check_dane' },
    dmarcReporting: { category: 'hygiene', max: 8, labelKey: 'score_check_reporting' },
    tlsRpt:         { category: 'hygiene', max: 4, labelKey: 'score_check_tls_rpt' },
    bimi:           { category: 'hygiene', max: 3, labelKey: 'score_check_bimi' }
};

// Aportes de cada señal dentro del presupuesto de su check (positivos = suman,
// negativos = restan). Un check nunca supera su `max`; la categoría no baja de 0.
export const SCORE_WEIGHTS = {
    // --- SPF (22) ---
    spfPresent: 10,
    spfAllHardfail: 8,
    spfAllSoftfail: 6,
    spfAllNeutral: -3,
    spfAllPass: -12,
    spfNoAll: -3,
    spfMultiple: -6,
    spfPtr: -2,
    spfLookupsOk: 4,
    spfIncludePermError: -22,
    spfVoidLookups: -4,
    spfMultipleAll: -3,
    spfTermsAfterAll: -2,
    // --- DMARC (23) ---
    dmarcPresent: 8,
    dmarcReject: 15,
    dmarcQuarantine: 9,
    dmarcNone: 0,
    dmarcMultiple: -6,
    dmarcVersionInvalid: -4,
    dmarcPolicyInvalid: -8,
    dmarcSpWeak: -3,
    dmarcNpWeak: -3,
    dmarcPctPartial: -2,
    // --- DKIM (15) ---
    dkim: 10,
    dkimStrongKey: 5,
    dkimKey1024: 2,
    dkimWeakKey: -5,
    dkimRevoked: -3,
    dkimMalformed: -2,
    // --- MTA-STS (10) ---
    mtaStsValid: 8,
    mtaStsMaxAgeOk: 2,
    mtaStsInvalid: -5,
    mtaStsMxMismatch: -8,
    // --- Transporte ---
    dane: 7,
    dnssec: 8,
    // --- Higiene: reporting (8) ---
    dmarcReporting: 5,
    dmarcExternalAuthorized: 3,
    dmarcExternalUnauthorized: -3,
    dmarcRuaTooMany: -1,
    // --- Higiene: TLS-RPT (4) y BIMI (3) ---
    tlsRptPresent: 4,
    tlsRptRuaInvalid: -2,
    bimi: 2,
    bimiVmc: 1,
    bimiInsecureUrl: -1
};

function dkimCountOf(result) {
    return result.dkimRecords && result.dkimRecords.records ? result.dkimRecords.records.length : 0;
}

function hasDaneOf(result) {
    if (!result.daneRecords) return false;
    return Object.values(result.daneRecords).some(arr => arr && arr.length > 0);
}

// Cada evaluador devuelve { points, findings[] }. El orden del array define el
// orden de presentación de los findings.
const SCORE_CHECKS = [
    function spf(result) {
        const findings = [];
        let points = 0;
        // La consulta falló (SERVFAIL/red): no penalizar como "sin SPF", solo informar.
        // El control queda SIN EVALUAR y sale del denominador de la nota.
        if (result.spfUnavailable) {
            findings.push({ status: 'info', key: 'finding_spf_unavailable' });
            return { points, findings, unevaluable: true };
        }
        if (!result.spfRaw) {
            findings.push({ status: 'error', key: 'finding_spf_err' });
            return { points, findings };
        }
        if (result.spfData && result.spfData.multiple) {
            points += SCORE_WEIGHTS.spfMultiple;
            findings.push({ status: 'error', key: 'finding_spf_multiple' });
        } else {
            points += SCORE_WEIGHTS.spfPresent;
            findings.push({ status: 'success', key: 'finding_spf_ok' });
        }
        const allEntry = result.spfEntries && result.spfEntries.find(e => e.type === 'all');
        if (allEntry) {
            const q = allEntry.qualifier;
            if (q === '+') {
                points += SCORE_WEIGHTS.spfAllPass;
                findings.push({ status: 'error', key: 'finding_spf_all_pass' });
            } else if (q === '?' || q === '') {
                points += SCORE_WEIGHTS.spfAllNeutral;
                findings.push({ status: 'warning', key: 'finding_spf_all_neutral' });
            } else if (q === '~') {
                points += SCORE_WEIGHTS.spfAllSoftfail;
                findings.push({ status: 'success', key: 'finding_spf_all_softfail' });
            } else if (q === '-') {
                points += SCORE_WEIGHTS.spfAllHardfail;
                findings.push({ status: 'success', key: 'finding_spf_all_hardfail' });
            }
        } else {
            // Sin mecanismo 'all' ⇒ política por defecto neutral (?all): no protege.
            points += SCORE_WEIGHTS.spfNoAll;
            findings.push({ status: 'warning', key: 'finding_spf_no_all' });
        }
        // El mecanismo 'ptr' está desaconsejado (RFC 7208 §5.5): lento y poco fiable.
        if (result.spfEntries && result.spfEntries.some(e => e.type === 'ptr')) {
            points += SCORE_WEIGHTS.spfPtr;
            findings.push({ status: 'warning', key: 'finding_spf_ptr' });
        }

        // Varios 'all' (solo cuenta el primero) y mecanismos DESPUÉS del 'all'
        // (inalcanzables: la evaluación para en el primer match, RFC 7208 §5.1).
        const entries = result.spfEntries || [];
        const allEntries = entries.filter(e => e.type === 'all');
        if (allEntries.length > 1) {
            points += SCORE_WEIGHTS.spfMultipleAll;
            findings.push({ status: 'error', key: 'finding_spf_multiple_all', replacements: { '{count}': String(allEntries.length) } });
        }
        if (allEntries.length > 0) {
            const firstAllIndex = allEntries[0].index;
            // 'redirect'/'exp' son modificadores: su posición es irrelevante.
            const unreachable = entries.filter(e => e.index > firstAllIndex && e.type !== 'all' && e.type !== 'redirect');
            if (unreachable.length > 0) {
                points += SCORE_WEIGHTS.spfTermsAfterAll;
                findings.push({
                    status: 'warning',
                    key: 'finding_spf_terms_after_all',
                    replacements: { '{terms}': unreachable.map(e => e.value ? `${e.type}:${e.value}` : e.type).join(', ') }
                });
            }
        }

        // Un registro de más de 255 caracteres no cabe en una sola cadena TXT: debe
        // publicarse partido en varias (el DNS las concatena) o algunos resolvers lo truncan.
        if (result.spfRaw.length > 255) {
            findings.push({ status: 'info', key: 'finding_spf_too_long', replacements: { '{len}': String(result.spfRaw.length) } });
        }

        // Problemas que solo se ven resolviendo el árbol: PermError por include sin
        // registro y exceso de void lookups.
        const issues = collectSpfTreeIssues(result.spfTree);
        if (issues.noRecord.length > 0) {
            points += SCORE_WEIGHTS.spfIncludePermError;
            findings.push({
                status: 'error',
                key: 'finding_spf_include_permerror',
                replacements: { '{targets}': [...new Set(issues.noRecord)].join(', ') }
            });
        }
        if (issues.voids.length > 2) {
            points += SCORE_WEIGHTS.spfVoidLookups;
            findings.push({
                status: 'error',
                key: 'finding_spf_void_lookups',
                replacements: { '{count}': String(issues.voids.length), '{mechs}': [...new Set(issues.voids)].join(', ') }
            });
        }

        const spfLookups = result.spfLookups || 0;
        if (spfLookups <= 10) {
            points += SCORE_WEIGHTS.spfLookupsOk;
            findings.push({ status: 'success', key: 'finding_spf_lookups_ok', replacements: { '{lookups}': spfLookups } });
        } else {
            findings.push({ status: 'error', key: 'finding_spf_lookups_err', replacements: { '{lookups}': spfLookups } });
        }
        return { points, findings };
    },

    function dmarc(result) {
        const findings = [];
        let points = 0;
        // La consulta falló (SERVFAIL/red): no penalizar como "sin DMARC", solo informar.
        // El control queda SIN EVALUAR y sale del denominador de la nota.
        if (result.dmarcUnavailable) {
            findings.push({ status: 'info', key: 'finding_dmarc_unavailable' });
            return { points, findings, unevaluable: true };
        }
        if (!result.dmarcRaw) {
            findings.push({ status: 'error', key: 'finding_dmarc_err' });
            return { points, findings };
        }
        if (result.dmarcData && result.dmarcData.multiple) {
            points += SCORE_WEIGHTS.dmarcMultiple;
            findings.push({ status: 'error', key: 'finding_dmarc_multiple' });
        } else {
            points += SCORE_WEIGHTS.dmarcPresent;
            const policy = result.dmarcPolicy || 'none';
            findings.push({ status: 'success', key: 'finding_dmarc_ok', replacements: { '{policy}': policy.toUpperCase() } });
            if (policy === 'reject') {
                points += SCORE_WEIGHTS.dmarcReject;
                findings.push({ status: 'success', key: 'finding_dmarc_policy_reject' });
            } else if (policy === 'quarantine') {
                points += SCORE_WEIGHTS.dmarcQuarantine;
                findings.push({ status: 'warning', key: 'finding_dmarc_policy_quarantine' });
            } else if (policy === 'none') {
                points += SCORE_WEIGHTS.dmarcNone;
                findings.push({ status: 'warning', key: 'finding_dmarc_policy_none' });
            }
        }
        // Validación de sintaxis (se evalúa aunque haya múltiples registros)
        if (result.dmarcParsed) {
            const v = result.dmarcParsed.v;
            const p = result.dmarcParsed.p;
            if (v !== 'DMARC1') {
                points += SCORE_WEIGHTS.dmarcVersionInvalid;
                findings.push({ status: 'error', key: 'finding_dmarc_version_invalid' });
            }
            if (!p || !['none', 'quarantine', 'reject'].includes(p.toLowerCase())) {
                points += SCORE_WEIGHTS.dmarcPolicyInvalid;
                findings.push({ status: 'error', key: 'finding_dmarc_policy_invalid' });
            }
        }
        // Política de subdominios (sp): un sp más débil que p abre un hueco en *.dominio
        if (result.dmarcParsed) {
            const p = (result.dmarcParsed.p || 'none').toLowerCase();
            const sp = result.dmarcParsed.sp ? result.dmarcParsed.sp.toLowerCase() : null;
            const rank = { none: 0, quarantine: 1, reject: 2 };
            if (sp && rank[sp] != null && rank[p] != null && rank[sp] < rank[p]) {
                points += SCORE_WEIGHTS.dmarcSpWeak;
                findings.push({ status: 'warning', key: 'finding_dmarc_sp_weak', replacements: { '{sp}': sp.toUpperCase(), '{p}': p.toUpperCase() } });
            }
            // np (DMARCbis): política para SUBDOMINIOS INEXISTENTES, el vector habitual
            // de suplantación (nadie vigila lo que no existe). Un np más débil que p
            // deja ese hueco abierto; si falta, se hereda sp/p y no se penaliza.
            const np = result.dmarcParsed.np ? result.dmarcParsed.np.toLowerCase() : null;
            if (np && rank[np] != null) {
                const effective = sp && rank[sp] != null ? sp : p;
                if (rank[np] < rank[effective]) {
                    points += SCORE_WEIGHTS.dmarcNpWeak;
                    findings.push({ status: 'warning', key: 'finding_dmarc_np_weak', replacements: { '{np}': np.toUpperCase(), '{p}': effective.toUpperCase() } });
                } else {
                    findings.push({ status: 'success', key: 'finding_dmarc_np_ok', replacements: { '{np}': np.toUpperCase() } });
                }
            }
            // pct < 100: la política solo se aplica a una fracción del correo
            const pct = result.dmarcParsed.pct != null ? parseInt(result.dmarcParsed.pct, 10) : 100;
            if (Number.isFinite(pct) && pct < 100) {
                points += SCORE_WEIGHTS.dmarcPctPartial;
                findings.push({ status: 'warning', key: 'finding_dmarc_pct_partial', replacements: { '{pct}': String(pct) } });
            } else if (result.dmarcParsed.pct != null) {
                // pct= está marcado como obsoleto en DMARCbis: sigue siendo válido pero
                // conviene retirarlo del registro una vez completado el despliegue.
                findings.push({ status: 'info', key: 'finding_dmarc_pct_deprecated' });
            }
            // Opciones de informe forense (fo) e intervalo de agregados (ri): informativo.
            if (result.dmarcParsed.fo) {
                findings.push({ status: 'info', key: 'finding_dmarc_fo', replacements: { '{fo}': String(result.dmarcParsed.fo) } });
            }
            if (result.dmarcParsed.ri) {
                findings.push({ status: 'info', key: 'finding_dmarc_ri', replacements: { '{ri}': String(result.dmarcParsed.ri) } });
            }
            // Alineación estricta (adkim/aspf = s) — informativo
            const adkim = (result.dmarcParsed.adkim || 'r').toLowerCase();
            const aspf = (result.dmarcParsed.aspf || 'r').toLowerCase();
            if (adkim === 's' && aspf === 's') {
                findings.push({ status: 'info', key: 'finding_dmarc_alignment_strict' });
            }
        }

        return { points, findings };
    },

    // Observabilidad: sin informes agregados no hay forma de saber quién envía en tu
    // nombre, así que endurecer la política se vuelve un salto a ciegas. Va en su
    // propia categoría (higiene) porque no protege por sí mismo: informa.
    function dmarcReporting(result) {
        const findings = [];
        let points = 0;
        if (result.dmarcUnavailable) {
            return { points, findings, unevaluable: true };
        }
        const hasRua = result.dmarcRua && result.dmarcRua.length > 0;
        const hasRuf = result.dmarcRuf && result.dmarcRuf.length > 0;
        if (hasRua || hasRuf) {
            points += SCORE_WEIGHTS.dmarcReporting;
            findings.push({ status: 'success', key: 'finding_dmarc_reporting_ok' });
        } else {
            findings.push({ status: 'warning', key: 'finding_dmarc_reporting_err' });
        }
        // RFC 7489 §6.3: un receptor puede limitar el número de destinos a los que
        // envía informes. Más de dos rua es habitual que acabe en informes perdidos.
        if (result.dmarcRua && result.dmarcRua.length > 2) {
            points += SCORE_WEIGHTS.dmarcRuaTooMany;
            findings.push({ status: 'warning', key: 'finding_dmarc_rua_too_many', replacements: { '{count}': String(result.dmarcRua.length) } });
        }

        // Autorización de destinos de informe EXTERNOS (RFC 7489 §7.1)
        if (Array.isArray(result.dmarcExternalAuth) && result.dmarcExternalAuth.length > 0) {
            const unauthorized = result.dmarcExternalAuth.filter(d => d.authorized === false);
            const unverifiable = result.dmarcExternalAuth.filter(d => d.authorized === null);
            if (unauthorized.length > 0) {
                points += SCORE_WEIGHTS.dmarcExternalUnauthorized;
                findings.push({ status: 'error', key: 'finding_dmarc_rua_unauthorized', replacements: { '{dest}': unauthorized.map(d => d.destDomain).join(', ') } });
            } else if (unverifiable.length === 0) {
                points += SCORE_WEIGHTS.dmarcExternalAuthorized;
                findings.push({ status: 'success', key: 'finding_dmarc_rua_authorized' });
            }
        } else if (hasRua || hasRuf) {
            // Todos los destinos son del propio dominio: no requieren autorización.
            points += SCORE_WEIGHTS.dmarcExternalAuthorized;
        }
        return { points, findings };
    },

    function dkim(result) {
        const records = (result.dkimRecords && result.dkimRecords.records) || [];
        const count = records.length;

        // Una zona que devuelve SERVFAIL bajo la ráfaga de sondeo es un hallazgo sobre el
        // DOMINIO, no sobre su DKIM: los resolvers de destino se topan con lo mismo, así
        // que afecta a la entregabilidad y a cualquier comprobación automática de un
        // tercero. Se observa aquí porque el sondeo de selectores es el abanico más ancho
        // del análisis, pero se redacta sobre la zona. NO toca puntos: la muestra depende
        // de nuestra propia carga, y penalizar por ella no sería defendible.
        const dnsErrors = (result.dkimRecords && result.dkimRecords.errors) || [];
        const servfails = dnsErrors.filter(e => e.code === 'servfail');
        const zoneFindings = servfails.length > 0
            ? [{ status: 'warning', key: 'finding_dns_zone_servfail', replacements: { '{n}': String(servfails.length) } }]
            : [];

        // Ausencia: NO penaliza. La detección prueba selectores comunes (best-effort);
        // un selector personalizado válido no se detecta y no debe bajar la nota, así
        // que el control sale del denominador en vez de puntuar 0.
        if (count === 0) {
            return {
                points: 0,
                findings: [{ status: 'info', key: 'finding_dkim_besteffort' }, ...zoneFindings],
                unevaluable: true
            };
        }

        let points = SCORE_WEIGHTS.dkim;
        const findings = [{ status: 'success', key: 'finding_dkim_ok', replacements: { '{count}': count } }];

        const analyses = records.map(r => ({ selector: r.selector, ...analyzeDKIMRecord(r.record) }));
        const revoked = analyses.filter(a => a.revoked);
        // El umbral de bits SOLO aplica a RSA: una clave Ed25519 son 256 bits y
        // equivale a ~3000 de RSA, así que compararla con 1024 la marcaría como débil
        // siendo la opción más fuerte de las dos (RFC 8463).
        const rsaKeys = analyses.filter(a => !a.revoked && a.algorithm === 'rsa');
        const weak = rsaKeys.filter(a => a.keyBits != null && a.keyBits < 1024);
        const deprecated = rsaKeys.filter(a => a.keyBits === 1024);
        const ed25519 = analyses.filter(a => !a.revoked && a.algorithm === 'ed25519' && !a.malformed);
        const malformed = analyses.filter(a => !a.revoked && a.malformed);
        const testing = analyses.filter(a => a.testing);

        if (revoked.length > 0) {
            points += SCORE_WEIGHTS.dkimRevoked;
            findings.push({ status: 'warning', key: 'finding_dkim_revoked', replacements: { '{selectors}': revoked.map(a => a.selector).join(', ') } });
        }
        if (weak.length > 0) {
            points += SCORE_WEIGHTS.dkimWeakKey;
            const w = weak[0];
            findings.push({ status: 'error', key: 'finding_dkim_weak_key', replacements: { '{selector}': w.selector, '{bits}': String(w.keyBits) } });
        }
        if (deprecated.length > 0) {
            points += SCORE_WEIGHTS.dkimKey1024;
            findings.push({ status: 'warning', key: 'finding_dkim_key_1024', replacements: { '{selectors}': deprecated.map(a => a.selector).join(', ') } });
        } else if (weak.length === 0 && revoked.length === 0) {
            // Todas las claves detectadas son fuertes: RSA ≥2048 o Ed25519.
            points += SCORE_WEIGHTS.dkimStrongKey;
        }
        if (malformed.length > 0) {
            points += SCORE_WEIGHTS.dkimMalformed;
        }
        if (ed25519.length > 0) {
            findings.push({ status: 'success', key: 'finding_dkim_ed25519', replacements: { '{selectors}': ed25519.map(a => a.selector).join(', ') } });
        }
        if (malformed.length > 0) {
            findings.push({ status: 'warning', key: 'finding_dkim_malformed_key', replacements: { '{selectors}': malformed.map(a => a.selector).join(', ') } });
        }
        if (testing.length > 0) {
            findings.push({ status: 'info', key: 'finding_dkim_testing', replacements: { '{selectors}': testing.map(a => a.selector).join(', ') } });
        }
        return { points, findings: [...findings, ...zoneFindings] };
    },

    function bimi(result) {
        const bimiRecord = result.bimiRecord;
        const hasBimi = bimiRecord && !bimiRecord.error && bimiRecord.record;
        if (!hasBimi) {
            return { points: 0, findings: [{ status: 'info', key: 'finding_bimi_err' }] };
        }
        // l= vacío es una declaración explícita de NO participar en BIMI (no un error):
        // publica el registro para bloquear el logo, así que no puntúa ni penaliza.
        if (bimiRecord.declined) {
            return { points: 0, findings: [{ status: 'info', key: 'finding_bimi_declined' }], unevaluable: true };
        }

        let points = SCORE_WEIGHTS.bimi;
        const findings = [{ status: 'success', key: 'finding_bimi_ok' }];
        if (bimiRecord.logoInsecure || bimiRecord.vmcInsecure) {
            points += SCORE_WEIGHTS.bimiInsecureUrl;
            findings.push({ status: 'error', key: 'finding_bimi_insecure_url' });
        }
        // Sin a= (VMC/CMC) los principales buzones —Gmail, Apple Mail— no pintan el
        // logo aunque el SVG sea correcto: el registro queda a medias.
        if (!bimiRecord.vmc) {
            findings.push({ status: 'warning', key: 'finding_bimi_no_vmc' });
        } else {
            points += SCORE_WEIGHTS.bimiVmc;
            findings.push({ status: 'success', key: 'finding_bimi_vmc_ok' });
        }
        return { points, findings };
    },

    function mtaSts(result) {
        if (!result.mtaSts) {
            return { points: 0, findings: [{ status: 'info', key: 'finding_mta_sts_err' }] };
        }
        const policyFetch = result.mtaSts.policy || {};

        // Cobertura de los MX reales por la lista `mx:` de la política (RFC 8461 §4.1).
        // Si un MX no está listado, los MTA que aplican la política RECHAZAN la entrega
        // a ese host: es el fallo más común y el más caro (correo entrante perdido).
        const mxCoverageFindings = [];
        let mxCoveragePoints = 0;
        const policyMx = policyFetch.parsed?.mx || [];
        const mxHosts = (result.mxRecords || []).map(r => r.host);
        if (policyMx.length > 0 && mxHosts.length > 0) {
            const { uncovered, unused } = checkMtaStsMxCoverage(policyMx, mxHosts);
            if (uncovered.length > 0) {
                mxCoveragePoints += SCORE_WEIGHTS.mtaStsMxMismatch;
                mxCoverageFindings.push({
                    status: 'error',
                    key: 'finding_mta_sts_mx_mismatch',
                    replacements: { '{hosts}': uncovered.join(', ') }
                });
            } else {
                mxCoverageFindings.push({ status: 'success', key: 'finding_mta_sts_mx_ok' });
            }
            if (unused.length > 0) {
                mxCoverageFindings.push({
                    status: 'info',
                    key: 'finding_mta_sts_mx_unused',
                    replacements: { '{patterns}': unused.join(', ') }
                });
            }
        }

        // La política no se pudo DESCARGAR (CORS sin proxy, red, timeout): no sabemos
        // si es válida. Informar, nunca penalizar — lo contrario castigaría a dominios
        // correctamente configurados por una limitación del navegador.
        if (policyFetch.validationReason === 'fetch_failed') {
            return {
                points: 0,
                unevaluable: true,
                findings: [{ status: 'info', key: 'finding_mta_sts_unreachable' }, ...mxCoverageFindings]
            };
        }

        if (result.mtaSts.policy?.valid) {
            const findings = [{ status: 'success', key: 'finding_mta_sts_ok' }];
            let points = SCORE_WEIGHTS.mtaStsValid + mxCoveragePoints;
            const maxAge = result.mtaSts.policy.maxAge;
            // RFC 8461: max_age es obligatorio; se recomienda ≥ 604800 s (1 semana).
            if (maxAge == null || Number.isNaN(maxAge)) {
                findings.push({ status: 'warning', key: 'finding_mta_sts_no_maxage' });
            } else if (maxAge < 604800) {
                findings.push({ status: 'warning', key: 'finding_mta_sts_low_maxage', replacements: { '{maxage}': String(maxAge) } });
            } else {
                points += SCORE_WEIGHTS.mtaStsMaxAgeOk;
            }
            return { points, findings: [...findings, ...mxCoverageFindings] };
        }
        const policy = result.mtaSts.policy || {};
        const replacements = {};
        if (policy.httpStatus != null && policy.httpStatus !== 200) {
            replacements['{status}'] = String(policy.httpStatus);
        } else if (policy.mode) {
            replacements['{mode}'] = policy.mode;
        }
        return {
            points: SCORE_WEIGHTS.mtaStsInvalid + mxCoveragePoints,
            findings: [{
                status: 'error',
                id: 'MTA_STS_POLICY_INVALID',
                type: 'error',
                key: 'finding_mta_sts_policy_invalid',
                message: 'MTA-STS TXT record exists but the HTTPS policy file is missing, invalid, or not set to enforce.',
                replacements: Object.keys(replacements).length ? replacements : undefined
            }, ...mxCoverageFindings]
        };
    },

    function tlsRpt(result) {
        if (!result.tlsRpt) {
            return { points: 0, findings: [{ status: 'info', key: 'finding_tls_rpt_err' }] };
        }
        const findings = [{ status: 'success', key: 'finding_tls_rpt_ok' }];
        let points = SCORE_WEIGHTS.tlsRptPresent;
        // RFC 8460 §3: rua debe ser mailto: o https:. Con otro esquema los informes
        // de fallo TLS no llegan a ninguna parte y el registro solo aparenta cobertura.
        const { invalid } = validateTlsRptRua(result.tlsRpt.rua);
        if (invalid.length > 0) {
            points += SCORE_WEIGHTS.tlsRptRuaInvalid;
            findings.push({
                status: 'error',
                key: 'finding_tls_rpt_rua_invalid',
                replacements: { '{uris}': invalid.join(', ') }
            });
        }
        return { points, findings };
    },

    function dane(result) {
        if (hasDaneOf(result)) {
            return { points: SCORE_WEIGHTS.dane, findings: [{ status: 'success', key: 'finding_dane_ok' }] };
        }
        // DANE (RFC 7672) se APOYA en DNSSEC: sin la zona firmada los registros TLSA no
        // son fiables y ningún MTA los usa, así que no es desplegable. Restarle puntos a
        // un dominio sin DNSSEC sería cobrarle dos veces la misma carencia (8 por DNSSEC
        // + 7 por DANE = 15 de los 25 de Transporte por una sola causa). Queda sin
        // evaluar y sale del denominador; con DNSSEC activo sí se exige.
        if (!result.dnssec || !result.dnssec.signed) {
            return {
                points: 0,
                unevaluable: true,
                findings: [{ status: 'info', key: 'finding_dane_needs_dnssec' }]
            };
        }
        return { points: 0, findings: [{ status: 'info', key: 'finding_dane_err' }] };
    },

    function dnssec(result) {
        if (result.dnssec && result.dnssec.signed) {
            return { points: SCORE_WEIGHTS.dnssec, findings: [{ status: 'success', key: 'finding_dnssec_ok' }] };
        }
        return { points: 0, findings: [{ status: 'info', key: 'finding_dnssec_err' }] };
    },

    function srv(result) {
        const findings = [];
        if (result.srvRecords && result.srvRecords.autodiscover && result.srvRecords.autodiscover.length > 0) {
            findings.push({ status: 'info', key: 'finding_srv_autodiscover_ok', replacements: { '{target}': result.srvRecords.autodiscover[0].target } });
        }
        return { points: 0, findings };
    }
];

function determinePosture(result) {
    const hasSpf = !!result.spfRaw;
    const hasDmarc = !!result.dmarcRaw;
    const dmarcPolicy = result.dmarcPolicy || 'none';
    const hasSegOrIces = (result.segList && result.segList.length > 0) || (result.icesList && result.icesList.length > 0);
    const allEntry = result.spfEntries && result.spfEntries.find(e => e.type === 'all');
    const allQualifier = allEntry ? (allEntry.qualifier || '') : '';
    const hasDkim = dkimCountOf(result) > 0;
    const hasMtaSts = result.mtaSts && result.mtaSts.policy?.valid;

    // posture.key es un identificador neutral de idioma; la UI lo traduce.
    if (hasSpf && allQualifier === '-' && hasDmarc && dmarcPolicy === 'reject' && hasSegOrIces && hasDkim && hasMtaSts) {
        return { key: 'strong', grade: 'Fuerte', color: 'green', class: 'safe', label: 'Fuerte' };
    }
    // La AUSENCIA de SEG/ICES no baja la postura a "débil": los ICES modernos son
    // API-based y no dejan ni un rastro en DNS (punto ciego documentado del análisis),
    // y muchas organizaciones filtran con el propio proveedor de correo. Su presencia
    // suma para llegar a "fuerte", pero no detectarla solo significa que no se ve.
    if (!hasSpf || allQualifier === '+' || allQualifier === '?' || !hasDmarc || dmarcPolicy === 'none') {
        return { key: 'weak', grade: 'Débil', color: 'red', class: 'danger', label: 'Débil' };
    }
    return { key: 'moderate', grade: 'Moderada', color: 'yellow', class: 'warning', label: 'Moderada' };
}

// Umbrales sobre la escala normalizada, ACOTADOS por la categoría de Autenticación.
// Sin ese tope, un dominio suplantable (DMARC en p=none, SPF con PermError) alcanzaba
// A+ a base de DNSSEC, DANE y BIMI: controles que no impiden que alguien envíe en su
// nombre. Un A+ exige autenticación íntegra + transporte endurecido + observabilidad:
// auth 60 + MTA-STS 10 + DNSSEC 8 + reporting 8 + TLS-RPT 4 = 90.
function determineGrade(score, authRatio) {
    if (score >= 90 && authRatio >= 0.95) return { grade: 'A+', cardClass: 'safe' };
    if (score >= 80 && authRatio >= 0.85) return { grade: 'A', cardClass: 'safe' };
    if (score >= 70 && authRatio >= 0.70) return { grade: 'B', cardClass: 'safe' };
    if (score >= 60 && authRatio >= 0.50) return { grade: 'C', cardClass: 'warning' };
    if (score >= 45) return { grade: 'D', cardClass: 'warning' };
    return { grade: 'F', cardClass: 'danger' };
}

export function calculateScoreAndFindings(result) {
    const findings = [];
    // Null MX (RFC 7505): declarar que no se recibe correo es una buena práctica
    // para dominios sin uso de email; se informa como positivo, sin penalizar.
    if (result.nullMx) {
        findings.push({ status: 'info', key: 'finding_null_mx' });
    }
    // DMARC heredado del dominio organizativo: aclara que la protección proviene
    // del dominio raíz, no del subdominio analizado.
    if (result.dmarcInherited && result.dmarcInheritedFrom) {
        findings.push({ status: 'info', key: 'finding_dmarc_inherited', replacements: { '{org}': result.dmarcInheritedFrom } });
    }

    // Un check nunca supera su presupuesto, pero SÍ puede quedar en negativo: una
    // política rota debe puntuar peor que su ausencia. El suelo se aplica al total de
    // la categoría, no a cada check.
    const checkResults = [];
    for (const check of SCORE_CHECKS) {
        const { points = 0, findings: sectionFindings = [], unevaluable = false } = check(result);
        findings.push(...sectionFindings);
        const budget = CHECK_BUDGETS[check.name];
        if (!budget) continue; // check informativo (p. ej. srv): no puntúa
        checkResults.push({
            id: check.name,
            labelKey: budget.labelKey,
            category: budget.category,
            max: budget.max,
            earned: unevaluable ? 0 : Math.min(points, budget.max),
            unevaluable
        });
    }

    // Desglose por categoría: es lo que permite explicar la nota en vez de afirmarla.
    const breakdown = Object.entries(SCORE_CATEGORIES).map(([id, cat]) => {
        const checks = checkResults.filter(c => c.category === id);
        const evaluable = checks.filter(c => !c.unevaluable);
        const max = evaluable.reduce((sum, c) => sum + c.max, 0);
        const raw = evaluable.reduce((sum, c) => sum + c.earned, 0);
        return {
            id,
            labelKey: cat.labelKey,
            max,
            earned: Math.max(0, Math.min(max, raw)),
            checks
        };
    });

    // Normalización sobre lo EVALUABLE: si un control no se ha podido medir (DKIM no
    // detectado, SPF/DMARC sin resolver, política MTA-STS inalcanzable), su presupuesto
    // sale del denominador en vez de contar como cero.
    const totalMax = breakdown.reduce((sum, c) => sum + c.max, 0);
    const totalEarned = breakdown.reduce((sum, c) => sum + c.earned, 0);
    const score = totalMax > 0 ? Math.round((totalEarned / totalMax) * 100) : 0;

    // Ratio de autenticación (SPF+DMARC+DKIM): es el tope de la nota. Si no hay nada
    // evaluable en esa categoría no se puede afirmar que esté mal, así que no acota.
    const auth = breakdown.find(c => c.id === 'auth');
    const authRatio = auth && auth.max > 0 ? auth.earned / auth.max : 1;

    const posture = determinePosture(result);
    const { grade, cardClass } = determineGrade(score, authRatio);

    return { score, grade, cardClass, findings, posture, breakdown, totalEarned, totalMax, authRatio };
}
