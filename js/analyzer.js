import { KB } from './knowledge.js';
import { extractRootDomain, isSameOrSubdomain } from './utils.js';
import { parseSPF, parseDMARC, analyzeDKIMRecord, validateTlsRptRua, checkMtaStsMxCoverage, isDnssecValidated } from './parsers.js';
import { classifyMailHosting } from './mailHosting.js';
import { evaluateDmarc, lowerPolicy } from './dmarc.js';

/**
 * Dominio organizativo del Tree Walk, solo si es seguro usarlo para decidir qué es
 * "propio". Un TLD que publicara DMARC sin psd=y convertiría en organizativo al propio TLD
 * (RFC 9989 §4.10.2, regla 3), y con él cualquier MX bajo .com pasaría por propio. Se
 * exige que sea el dominio auditado o un antepasado suyo, y que no sea más corto que su
 * dominio registrable estimado.
 */
function trustedOrgDomain(domain, orgDomain) {
    if (!domain || !orgDomain) return null;
    const d = domain.toLowerCase();
    const org = orgDomain.toLowerCase();
    if (!isSameOrSubdomain(d, org)) return null;
    if (org.split('.').length < extractRootDomain(d).split('.').length) return null;
    return org;
}

export function identifyMX(host, domain, orgDomain = null) {
    const h = host.toLowerCase();
    // First label of the MX hostname (e.g. "esa01" from "esa01.arquia.es")
    const firstLabel = h.split('.')[0];
    for (const entry of KB.mx) {
        if (entry.matchType === 'hostname_prefix') {
            // Match if the first hostname label starts with the pattern (e.g. "esa" matches "esa01", "esa1", "esa-gw")
            if (firstLabel.startsWith(entry.pattern)) return entry;
        } else if (entry.matchType === 'suffix') {
            // Sufijo exacto: '.mx.microsoft' casa con 'acme-com.l-v1.mx.microsoft' pero no
            // con 'mx.microsoft.com'.
            if (h.endsWith(entry.pattern)) return entry;
        } else {
            if (h.includes(entry.pattern)) return entry;
        }
    }
    if (domain) {
        // Un MX que cuelga del propio dominio (o de su dominio organizativo) es propio, sin
        // pasar por la heurística de dominio raíz: mx.ine.es es de ine.es aunque "ine" sea
        // corto.
        const org = trustedOrgDomain(domain, orgDomain);
        if (isSameOrSubdomain(h, domain) || (org && isSameOrSubdomain(h, org))) {
            return { name: host, type: 'self' };
        }
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
    if (!value || value.startsWith('(self)')) return null;
    // La máscara CIDR (`a:mail.acme.com/24`) no forma parte del nombre del servicio.
    const v = value.toLowerCase().replace(/(\/\d{1,3})?(\/\/\d{1,3})?$/, '');
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

// Identidad canónica del vendor: ignora paréntesis y sufijos genéricos para que un mismo
// vendor con distinto nombre en cada diccionario ("Sophos" en el token TXT vs "Sophos
// Email" en el MX; "Proofpoint Essentials" en el SPF vs "Proofpoint" en el MX) se
// reconozca como el mismo y no se le niegue lo que su MX SÍ confirma.
const canonVendor = (name) => String(name).toLowerCase()
    .replace(/\([^)]*\)/g, ' ')
    .replace(/\b(email|security|messaging|gateway|essentials|ironport)\b/g, ' ')
    .replace(/[^a-z0-9]+/g, '');

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
        orgDomain = null,
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
        const id = identifyMX(mx.host, domain, orgDomain);
        if (id.type === 'seg' || id.type === 'ices') add(id.name, id.type, 'mx', mx.host, W.mx);
    }

    // 2. MTA-STS: hostnames MX autorizados en la política
    for (const pattern of mtaStsMx) {
        const id = identifyMX(String(pattern).toLowerCase(), domain, orgDomain);
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
    // Vendors cuyo MX real confirma presencia en el flujo de correo (por identidad canónica).
    const mxVendorCanon = new Set(
        mxRecords
            .map(mx => identifyMX(mx.host, domain, orgDomain))
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

/**
 * ¿Hay una capa de filtrado por encima de la nativa del proveedor de buzones?
 *
 * Es el tercer eje de la nota (v5). Solo afirma lo que el DNS deja ver:
 *   reinforced     — el MX entrega a un SEG (Proofpoint, Mimecast…) o hay un ICES
 *                    detectado con confianza media o alta
 *   native         — todos los MX van directos a un proveedor (Microsoft 365, Google…)
 *   unidentified   — MX propio o desconocido: puede haber un gateway on-premise o uno que
 *                    el diccionario no conoce, así que no se evalúa (y no resta)
 *   not_applicable — el dominio no recibe correo
 *
 * "native" no significa "sin protección extra": Defender for Office 365 o los ICES que
 * solo trabajan por API no dejan rastro en el DNS. Por eso pesa la mitad y no cero.
 *
 * De un SEG que aparece en el SPF, en un token TXT o en un selector DKIM pero no en el MX
 * no consta que filtre el correo entrante (suele usarse solo para el envío): se devuelve
 * aparte en `outOfPathVendors` para poder decirlo, sin sumar.
 *
 * ES PURA, como detectSecurityLayers.
 * @returns {{ state, vendors: string[], segVendors: string[], icesVendors: string[],
 *             provider: string|null, bypassMx: string[], outOfPathVendors: string[],
 *             unknownMx: string[] }}
 */
export function classifyInboundFilter({ mxRecords = [], segList = [], icesList = [], nullMx = false, domain = '', orgDomain = null } = {}) {
    const empty = { vendors: [], segVendors: [], icesVendors: [], provider: null, bypassMx: [], outOfPathVendors: [], unknownMx: [] };
    if (!mxRecords.length || nullMx) return { state: 'not_applicable', ...empty };

    const ids = mxRecords.map(mx => ({ host: mx.host, ...identifyMX(mx.host, domain, orgDomain) }));
    const uniq = (arr) => [...new Set(arr)];

    // Lo que está EN el flujo: un MX que entrega a un SEG (o a un ICES con MX propio,
    // como Avanan en modo inline).
    const segVendors = uniq(ids.filter(id => id.type === 'seg').map(id => id.name));
    const icesInMx = ids.filter(id => id.type === 'ices').map(id => id.name);
    // Los ICES trabajan por API sobre el buzón: no necesitan el MX. Cuentan si la
    // detección llega a confianza media.
    const icesVendors = uniq([
        ...icesInMx,
        ...icesList.filter(s => !s.unconfirmed && s.level !== 'baja').map(s => s.name)
    ]);
    const inPathCanon = new Set([...segVendors, ...icesVendors].map(canonVendor));
    const outOfPathVendors = uniq(segList
        .filter(s => !(s.evidence || []).some(e => e.signal === 'mx') && !inPathCanon.has(canonVendor(s.name)))
        .map(s => s.name));

    const providerIds = ids.filter(id => id.type === 'provider');
    const provider = providerIds.length ? providerIds[0].name : null;
    const unknownMx = ids.filter(id => id.type === 'self' || id.type === 'unknown').map(id => id.host);
    const base = { ...empty, segVendors, icesVendors, provider, outOfPathVendors, unknownMx };

    if (segVendors.length || icesVendors.length) {
        // Un MX que entrega directo al proveedor, al lado del gateway, es una puerta
        // trasera: basta con mandar el correo a ese MX para saltarse el filtro.
        const bypassMx = segVendors.length ? providerIds.map(id => id.host) : [];
        return { ...base, state: 'reinforced', vendors: uniq([...segVendors, ...icesVendors]), bypassMx };
    }
    if (providerIds.length === ids.length) return { ...base, state: 'native' };
    return { ...base, state: 'unidentified' };
}

export function analyze(mxRecords, spfRaw, dmarcRaw, advancedData = {}) {
    const domain = advancedData.domain || '';
    // Dominio organizativo que ha dado el DNS Tree Walk (RFC 9989 §4.10). Sirve también
    // para reconocer como propios los MX que cuelgan de él.
    const orgDomain = advancedData.dmarcOrgDomain || null;
    const spfEntries = parseSPF(spfRaw);
    const dmarcParsed = parseDMARC(dmarcRaw);

    let provider = null;
    // providerSource es una estructura neutral de idioma: { key, arg }. La capa de
    // presentación (viewmodel) la traduce. Evita el patrón frágil de "sentinel" en español.
    let providerSource = null;
    // Detección de proveedor de correo (MX primero, luego SPF)
    for (const mx of mxRecords) {
        const id = identifyMX(mx.host, domain, orgDomain);
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
        orgDomain,
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

    let dmarcRua = [];
    let dmarcRuf = [];
    let dmarcDetails = {};
    if (dmarcParsed) {
        dmarcDetails = dmarcParsed;
        if (dmarcParsed.rua) {
            dmarcRua = dmarcParsed.rua.split(',').map(s => s.trim()).filter(Boolean);
        }
        if (dmarcParsed.ruf) {
            dmarcRuf = dmarcParsed.ruf.split(',').map(s => s.trim()).filter(Boolean);
        }
    }

    const dmarcData = advancedData.dmarcData || { record: dmarcRaw, records: dmarcRaw ? [dmarcRaw] : [], multiple: false };
    const dmarcSource = advancedData.dmarcSource || (advancedData.dmarcInherited ? 'org' : 'author');
    // Semántica RFC 9989 del registro que APLICA al dominio auditado (null si no aplica
    // ninguno: no hay, o los que hay en su nombre se descartan por ser varios).
    const dmarcEval = computeDmarcEval({
        dmarcRaw, dmarcParsed, dmarcData, dmarcSource, dmarcRua, dmarcRuf,
        dmarcIsOrgDomain: orgDomain ? orgDomain === domain.toLowerCase() : undefined
    });
    // dmarcPolicy es la política EFECTIVA y conservadora: la más débil que aplicaría
    // alguna de las dos generaciones de receptores (RFC 7489 y RFC 9989). La solicitada
    // queda en dmarcPolicyRequested para poder decir "reject en modo prueba".
    const dmarcPolicy = dmarcEval ? dmarcEval.effective.floor : 'No configurado';
    const dmarcPolicyClass = dmarcEval ? dmarcEval.effective.floor : '';
    const dmarcPolicyRequested = dmarcEval ? dmarcEval.applicable : null;

    // Eje de la PLATAFORMA DE BUZÓN, independiente del filtro de entrada que se acaba de
    // calcular. Las señales las resuelve app.js (esto es síncrono y puro); aquí solo se
    // aporta la identificación de los MX, que ya vive en este módulo.
    const mailHosting = classifyMailHosting({
        domain,
        mxIds: mxRecords.map(mx => ({ ...identifyMX(mx.host, domain, orgDomain), host: mx.host })),
        segFronting: segList.some(s => (s.evidence || []).some(e => e.signal === 'mx')),
        ...(advancedData.mailHostingSignals || {})
    });

    // Tercer eje de la nota: ¿hay una capa de filtrado por encima de la nativa?
    const inboundFilter = classifyInboundFilter({
        mxRecords, segList, icesList, domain, orgDomain,
        nullMx: !!(advancedData.nullMx || mxRecords.nullMx)
    });

    return {
        provider, providerIdentified, providerSource, segList, icesList,
        inboundFilter,
        mailHosting,
        spfRaw, spfEntries, spfServices,
        spfData: advancedData.spfData || { record: spfRaw, records: spfRaw ? [spfRaw] : [], multiple: false },
        dmarcRaw, dmarcParsed, dmarcPolicy, dmarcPolicyClass, dmarcPolicyRequested,
        dmarcRua, dmarcRuf, dmarcDetails,
        dmarcData,
        dmarcEval,
        // Dónde se encontró la política y cuál es el dominio organizativo (Tree Walk,
        // RFC 9989 §4.10). Al analizar un subdominio sin registro propio, la política se
        // hereda y le corresponde su sp (§4.10.1).
        dmarcSource,
        dmarcPolicyDomain: advancedData.dmarcPolicyDomain || (dmarcRaw ? domain : null),
        dmarcOrgDomain: orgDomain,
        dmarcWalkIncomplete: !!advancedData.dmarcWalkIncomplete,
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

// ===== Puntuación del ecosistema de correo (v5) =====
// El anillo mide la protección de TODO el ecosistema de correo del dominio, repartida en
// tres ejes que se evalúan por separado y se combinan con peso:
//   suplantación (60) — ¿puede alguien poner el dominio en el From y que llegue?
//   filtrado (25)     — ¿hay una capa de filtrado por encima de la nativa del proveedor?
//   transporte (15)   — ¿está protegido el correo entrante en tránsito?
//
// Los pesos recogen la lección de la v4: una suma plana de todo lo visible hundía a
// dominios con la autenticación perfecta por no tener DNSSEC ni MTA-STS, controles que casi
// ninguna gran empresa despliega. Por eso la suplantación manda y el transporte pesa poco.
//
// Cada eje se normaliza sobre lo que se ha podido EVALUAR (ver `unevaluable`), y un eje
// que no se puede evaluar o no aplica (un dominio sin MX no tiene ni filtrado ni
// transporte) sale de la media: los demás se reparten su peso. BIMI no puntúa: es marca,
// no seguridad.
export const SCORE_CATEGORIES = {
    antispoof: { max: 100, weight: 60, labelKey: 'score_cat_antispoof' },
    filtering: { max: 100, weight: 25, labelKey: 'score_cat_filtering' },
    transport: { max: 100, weight: 15, labelKey: 'score_cat_transport' }
};

// Presupuesto de cada check. La suma por categoría cuadra con SCORE_CATEGORIES.
// Un check sin entrada aquí (bimi, srv) es puramente informativo: aporta findings pero
// no puntúa.
export const CHECK_BUDGETS = {
    dmarc:          { category: 'antispoof', max: 50, labelKey: 'score_check_dmarc' },
    spf:            { category: 'antispoof', max: 20, labelKey: 'score_check_spf' },
    dkim:           { category: 'antispoof', max: 20, labelKey: 'score_check_dkim' },
    dmarcReporting: { category: 'antispoof', max: 10, labelKey: 'score_check_reporting' },
    inboundFilter:  { category: 'filtering', max: 100, labelKey: 'score_check_inbound_filter' },
    mtaSts:         { category: 'transport', max: 40, labelKey: 'score_check_mta_sts' },
    tlsRpt:         { category: 'transport', max: 15, labelKey: 'score_check_tls_rpt' },
    dnssec:         { category: 'transport', max: 25, labelKey: 'score_check_dnssec' },
    dane:           { category: 'transport', max: 20, labelKey: 'score_check_dane' }
};

// Puntos de cada señal. Un check queda siempre entre 0 y su `max`.
export const SCORE_WEIGHTS = {
    // --- DMARC (50): la política que un receptor aplica de verdad al From visible ---
    // quarantine y reject son los dos "enforcement" (RFC 9989 §3.2.9). reject conserva
    // una prima pequeña, pero §7.4 lo desaconseja si los usuarios escriben a listas.
    dmarcReject: 50,
    dmarcQuarantine: 46,
    dmarcNoneWithReports: 10,   // modo monitorización: no protege, pero prepara el paso
    dmarcNone: 5,
    dmarcAsNone: 5,             // valor no válido con rua: se trata como p=none
    dmarcSpNone: -12,           // subdominios existentes sin protección
    dmarcNpNone: -6,            // subdominios inexistentes sin protección
    dmarcPctPartial: -5,
    dmarcMultiple: -10,
    dmarcVersionInvalid: -10,
    // --- SPF (20) ---
    // Con DMARC en enforcement, ~all y -all protegen lo mismo, y RFC 9989 §7.1 advierte
    // de que -all puede rechazar correo legítimo reenviado antes de evaluar DMARC.
    spfPass: 20,
    spfSoftfailNoDmarc: 16,     // sin enforcement, el receptor solo tiene el SPF
    spfNeutral: 8,              // ?all o sin all
    spfPtr: -2,
    spfMultipleAll: -2,
    spfTermsAfterAll: -1,
    // --- DKIM (20): solo las claves ACTIVAS ---
    dkimStrong: 20,
    dkim1024: 17,
    dkimMalformed: 10,
    dkimWeak: 5,
    // --- Informes (10) ---
    dmarcReporting: 10,
    dmarcExternalUnauthorized: -4,
    dmarcRuaTooMany: -1,
    // --- Filtrado entrante (100) ---
    filterReinforced: 100,      // SEG en el MX, o ICES detectado
    filterBypass: 75,           // gateway, pero con un MX que entrega directo al proveedor
    filterNative: 50,           // solo el filtrado del proveedor: no es cero, pero es la base
    // --- Transporte (100) ---
    mtaStsEnforce: 36,
    mtaStsMaxAgeOk: 4,
    mtaStsMxMismatchCap: 10,    // enforce, pero con MX sin cubrir: rompe la entrega
    mtaStsUnverified: 25,       // TXT publicado y host existente; política sin descargar
    mtaStsTesting: 15,
    tlsRpt: 15,
    tlsRptRuaInvalid: 5,
    dnssec: 25,
    dane: 20
};

// Techo de la nota sin DMARC en enforcement: sin él, cualquiera puede poner el dominio en
// el From visible y los receptores no lo bloquean por DMARC. Un gateway o un transporte
// ejemplares no lo compensan.
const NO_ENFORCEMENT_CAP = 45;
// Techo cuando la suplantación no se ha podido VERIFICAR del todo: A+ exige evidencia
// completa.
const UNVERIFIED_CAP = 94;

export function letterGrade(score) {
    if (score >= 95) return 'A+';
    if (score >= 85) return 'A';
    if (score >= 70) return 'B';
    if (score >= 55) return 'C';
    if (score >= 40) return 'D';
    return 'F';
}

/** ¿El dominio recibe correo? Sin MX (o con Null MX), nada de transporte le aplica. */
function receivesMailOf(result) {
    return (result.mxRecords || []).length > 0 && !result.nullMx;
}

/** DMARC en enforcement para el dominio auditado (quarantine o reject efectivos). */
function isEnforcedOf(ev) {
    return !!ev && ev.processing === 'full' && ev.effective.floor !== 'none';
}

/**
 * Evaluación RFC 9989 del registro DMARC que aplica al dominio auditado, o null si no
 * aplica ninguno. Varios registros en el MISMO nombre se descartan todos (§4.10, paso 2):
 * si lo que queda es un registro del propio dominio, es como no tener DMARC.
 */
function computeDmarcEval(result) {
    if (!result.dmarcRaw || !result.dmarcParsed) return null;
    const source = result.dmarcSource || (result.dmarcInherited ? 'org' : 'author');
    if (result.dmarcData && result.dmarcData.multiple && source === 'author') return null;
    return evaluateDmarc(result.dmarcParsed, {
        source,
        isOrgDomain: result.dmarcIsOrgDomain,
        rua: result.dmarcRua,
        ruf: result.dmarcRuf
    });
}

// analyze() deja la evaluación en el result; los results montados a mano (tests, informes
// de versiones anteriores) no la traen y se calcula al vuelo.
function dmarcEvalOf(result) {
    return 'dmarcEval' in result ? result.dmarcEval : computeDmarcEval(result);
}

// Igual que dmarcEvalOf: los results sin `inboundFilter` (tests, informes de la v4) lo
// calculan al vuelo con lo que traen.
function inboundFilterOf(result) {
    if (result.inboundFilter) return result.inboundFilter;
    return classifyInboundFilter({
        mxRecords: result.mxRecords || [],
        segList: result.segList || [],
        icesList: result.icesList || [],
        nullMx: !!result.nullMx,
        domain: result.domain || '',
        orgDomain: result.dmarcOrgDomain || null
    });
}

/**
 * Mecanismo `all` que rige de verdad. Sin `all` propio manda el `redirect=` (RFC 7208
 * §6.1): la política por defecto es la del registro de destino, así que se busca en el
 * subárbol del redirect. Antes, `v=spf1 redirect=_spf.x.com` daba un falso "sin all" y
 * perdía los puntos del calificador aunque el destino terminara en -all.
 * @returns {{ entry: object|null, via: string|null }}
 */
function effectiveSpfAll(result) {
    const own = (result.spfEntries || []).find(e => e.type === 'all');
    if (own) return { entry: own, via: null };
    let tree = result.spfTree;
    let via = null;
    for (let depth = 0; tree && depth < 10; depth++) {
        const child = (tree.children || []).find(c => c.type === 'redirect' && c.tree);
        if (!child) break;
        via = child.target;
        if (!child.tree.record) break;
        const all = parseSPF(child.tree.record).find(e => e.type === 'all');
        if (all) return { entry: all, via };
        tree = child.tree;
    }
    return { entry: null, via };
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
        const enforced = isEnforcedOf(dmarcEvalOf(result));
        if (!result.spfRaw) {
            // Un nombre que no recibe correo y al que DMARC ya protege en enforcement (el
            // típico subdominio web, como support.apple.com) no necesita SPF para no ser
            // suplantable: se recomienda, pero no se puntúa como un fallo.
            if (!receivesMailOf(result) && enforced) {
                findings.push({ status: 'info', key: 'finding_spf_not_needed' });
                return { points, findings, unevaluable: true };
            }
            findings.push({ status: 'error', key: 'finding_spf_err' });
            return { points, findings };
        }
        // Varios registros SPF son un PermError (RFC 7208 §4.5): ningún receptor evalúa
        // ninguno, así que nada de lo que digan cuenta.
        if (result.spfData && result.spfData.multiple) {
            findings.push({ status: 'error', key: 'finding_spf_multiple' });
            return { points: 0, findings };
        }
        findings.push({ status: 'success', key: 'finding_spf_ok' });

        const { entry: allEntry, via: allVia } = effectiveSpfAll(result);
        if (allEntry && allVia) {
            findings.push({
                status: 'info',
                key: 'finding_spf_all_via_redirect',
                replacements: { '{target}': allVia, '{all}': `${allEntry.qualifier || '+'}all` }
            });
        }
        const q = allEntry ? allEntry.qualifier : null;
        if (allEntry) {
            if (q === '+') {
                findings.push({ status: 'error', key: 'finding_spf_all_pass' });
            } else if (q === '?' || q === '') {
                findings.push({ status: 'warning', key: 'finding_spf_all_neutral' });
            } else if (q === '~') {
                findings.push({ status: 'success', key: 'finding_spf_all_softfail' });
            } else if (q === '-') {
                findings.push({ status: 'success', key: 'finding_spf_all_hardfail' });
            }
        } else if (!allVia) {
            // Sin mecanismo 'all' ⇒ política por defecto neutral (?all): no protege.
            // (Con un redirect cuyo destino no resuelve, el PermError ya lo cuenta abajo.)
            findings.push({ status: 'warning', key: 'finding_spf_no_all' });
        }
        // Puntos del calificador. Con DMARC en enforcement, ~all vale lo mismo que -all.
        if (q === '-' || q === '~') {
            points = (q === '-' || enforced) ? SCORE_WEIGHTS.spfPass : SCORE_WEIGHTS.spfSoftfailNoDmarc;
        } else if (q === '+') {
            points = 0;
        } else {
            points = SCORE_WEIGHTS.spfNeutral;
        }
        // El mecanismo 'ptr' está desaconsejado (RFC 7208 §5.5): lento y poco fiable.
        if (result.spfEntries && result.spfEntries.some(e => e.type === 'ptr')) {
            points += SCORE_WEIGHTS.spfPtr;
            findings.push({ status: 'warning', key: 'finding_spf_ptr' });
        }
        // Un mecanismo desconocido —una errata— hace fallar TODA la evaluación (RFC 7208 §5).
        const unknownTerms = (result.spfEntries || []).filter(e => e.type === 'unknown');
        let permError = false;
        if (unknownTerms.length > 0) {
            permError = true;
            findings.push({
                status: 'error',
                key: 'finding_spf_unknown_mechanism',
                replacements: { '{terms}': unknownTerms.map(e => e.value).join(', ') }
            });
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
            const unreachable = entries.filter(e => e.index > firstAllIndex && !['all', 'redirect', 'exp', 'unknown'].includes(e.type));
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
            permError = true;
            findings.push({
                status: 'error',
                key: 'finding_spf_include_permerror',
                replacements: { '{targets}': [...new Set(issues.noRecord)].join(', ') }
            });
        }
        if (issues.voids.length > 2) {
            permError = true;
            findings.push({
                status: 'error',
                key: 'finding_spf_void_lookups',
                replacements: { '{count}': String(issues.voids.length), '{mechs}': [...new Set(issues.voids)].join(', ') }
            });
        }

        const spfLookups = result.spfLookups || 0;
        if (spfLookups <= 10) {
            findings.push({ status: 'success', key: 'finding_spf_lookups_ok', replacements: { '{lookups}': spfLookups } });
        } else {
            permError = true;
            findings.push({ status: 'error', key: 'finding_spf_lookups_err', replacements: { '{lookups}': spfLookups } });
        }
        // Un PermError (include roto, errata, >2 void lookups, >10 lookups) hace que
        // ningún receptor pueda evaluar el SPF: vale lo mismo que no tenerlo.
        if (permError) points = 0;
        return { points: Math.max(0, points), findings };
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
        const multiple = !!(result.dmarcData && result.dmarcData.multiple);
        const ev = dmarcEvalOf(result);
        // Varios registros en un mismo nombre se descartan TODOS (RFC 9989 §4.10, paso 2).
        // En el propio dominio eso equivale a no tener DMARC; en un subdominio la búsqueda
        // sigue hacia arriba y puede aplicar la política de su dominio organizativo.
        if (multiple) {
            points += SCORE_WEIGHTS.dmarcMultiple;
            findings.push({ status: 'error', key: 'finding_dmarc_multiple' });
        }
        if (!ev) {
            if (!multiple) findings.push({ status: 'error', key: 'finding_dmarc_err' });
            return { points: 0, findings };
        }
        const P = (v) => String(v || 'none').toUpperCase();

        // Versión: api.js ya exige v=DMARC1, así que esto solo salta con results montados a mano.
        if (result.dmarcParsed && result.dmarcParsed.v !== 'DMARC1') {
            points += SCORE_WEIGHTS.dmarcVersionInvalid;
            findings.push({ status: 'error', key: 'finding_dmarc_version_invalid' });
        }

        // Un p no válido (o un sp/np no válidos) cambia la política de TODO el registro
        // (RFC 9989 §4.10.1): p=none si hay un rua válido; ningún DMARC si no lo hay. Es
        // fácil de pasar por alto porque el registro "parece" publicado: `sp=rejct` basta
        // para que un p=reject deje de proteger nada.
        if (ev.processing !== 'full') {
            points = ev.processing === 'as_none' ? SCORE_WEIGHTS.dmarcAsNone : 0;
            const bad = ev.invalidTags.filter(k => ['p', 'sp', 'np'].includes(k));
            findings.push({
                status: 'error',
                key: ev.processing === 'as_none' ? 'finding_dmarc_invalid_as_none' : 'finding_dmarc_no_effect',
                replacements: { '{tags}': bad.map(k => `${k}=${ev.requested[k]}`).join(', ') }
            });
            return { points: Math.max(0, points), findings };
        }

        const applicable = ev.applicable;
        const floor = ev.effective.floor;
        findings.push({ status: 'success', key: 'finding_dmarc_ok', replacements: { '{policy}': P(applicable) } });
        if (ev.requested.p == null) findings.push({ status: 'info', key: 'finding_dmarc_p_missing' });

        // Se puntúa la política EFECTIVA y conservadora: la más débil que aplicaría alguna de
        // las dos generaciones de receptores. quarantine y reject son ambas enforcement.
        points += floor === 'reject'
            ? SCORE_WEIGHTS.dmarcReject
            : floor === 'quarantine'
                ? SCORE_WEIGHTS.dmarcQuarantine
                : (ev.rua.valid.length > 0 ? SCORE_WEIGHTS.dmarcNoneWithReports : SCORE_WEIGHTS.dmarcNone);
        const lowered = { '{p}': P(applicable), '{lower}': P(floor) };
        if (floor !== applicable) {
            // t=y (RFC 9989) y pct=0 (RFC 7489) rebajan un nivel la política solicitada.
            if (ev.testing && ev.pct === 0) {
                findings.push({ status: 'warning', key: 'finding_dmarc_pct_zero_with_t', replacements: lowered });
            } else if (ev.testing) {
                findings.push({ status: 'warning', key: 'finding_dmarc_testing_t', replacements: lowered });
            } else {
                findings.push({ status: 'warning', key: 'finding_dmarc_pct_zero', replacements: lowered });
            }
        } else if (floor === 'reject') {
            findings.push({ status: 'success', key: 'finding_dmarc_policy_reject' });
            // RFC 9989 §7.4: reject exige DKIM y choca con las listas de correo.
            findings.push({ status: 'info', key: 'finding_dmarc_reject_notes' });
        } else if (floor === 'quarantine') {
            findings.push({ status: 'success', key: 'finding_dmarc_policy_quarantine' });
        } else {
            // p=none sin rua ni siquiera es "modo monitorización" (RFC 9989 §3.2.12).
            findings.push({ status: 'warning', key: ev.rua.valid.length > 0 ? 'finding_dmarc_policy_none' : 'finding_dmarc_none_no_rua' });
        }

        // pct: RFC 9989 lo elimina (los receptores actualizados lo ignoran). Con RFC 7489, el
        // correo que queda fuera del porcentaje recibe la política INMEDIATAMENTE INFERIOR,
        // no "se entrega sin política".
        if (ev.effective.partialPct != null && applicable !== 'none') {
            points += SCORE_WEIGHTS.dmarcPctPartial;
            findings.push({
                status: 'warning',
                key: 'finding_dmarc_pct_partial',
                replacements: { '{pct}': String(ev.effective.partialPct), '{p}': P(applicable), '{lower}': P(lowerPolicy(applicable)) }
            });
        } else if (ev.pct != null && (ev.pct === 100 || applicable === 'none')) {
            findings.push({ status: 'info', key: 'finding_dmarc_pct_removed' });
        }
        const removed = ev.obsoleteTags.filter(k => k !== 'pct');
        if (removed.length > 0) {
            findings.push({ status: 'info', key: 'finding_dmarc_tag_removed', replacements: { '{tags}': removed.join(', ') } });
        }

        // sp/np solo rigen en el registro del dominio organizativo (RFC 9989 §4.7). Al
        // auditar el propio dominio organizativo restan, porque dejan un hueco en sus
        // subdominios; al auditar un subdominio que hereda, sp YA es la política que se ha
        // puntuado, así que solo se explica.
        if (ev.orgLevel) {
            const rank = { none: 0, quarantine: 1, reject: 2 };
            const p = ev.policies.p.requested;
            const sp = ev.requested.sp != null ? ev.policies.sp.requested : null;
            const np = ev.requested.np != null ? ev.policies.np.requested : null;
            // Resta cuando el hueco es real (el subdominio queda en none tras la transición)
            // y solo al auditar el propio dominio organizativo: al heredar, sp YA se puntúa.
            const penalize = ev.source === 'author' && floor !== 'none';
            if (penalize && ev.policies.sp.floor === 'none') points += SCORE_WEIGHTS.dmarcSpNone;
            else if (penalize && ev.policies.np.floor === 'none') points += SCORE_WEIGHTS.dmarcNpNone;
            if (sp && rank[sp] < rank[p]) {
                findings.push({ status: 'warning', key: 'finding_dmarc_sp_weak', replacements: { '{sp}': P(sp), '{p}': P(p) } });
            }
            // np: SUBDOMINIOS INEXISTENTES, el vector habitual de suplantación (nadie vigila lo
            // que no existe). Si falta, se hereda sp/p y no se penaliza.
            if (np) {
                const reference = sp || p;
                if (rank[np] < rank[reference]) {
                    findings.push({ status: 'warning', key: 'finding_dmarc_np_weak', replacements: { '{np}': P(np), '{p}': P(reference) } });
                } else {
                    findings.push({ status: 'success', key: 'finding_dmarc_np_ok', replacements: { '{np}': P(np) } });
                }
            }
        }

        if (ev.psd === 'n') findings.push({ status: 'info', key: 'finding_dmarc_psd_n' });
        if (ev.psd === 'y') findings.push({ status: 'warning', key: 'finding_dmarc_psd_y' });

        // Opciones de informe de fallo: sin ruf no tienen efecto (RFC 9989 §4.7).
        if (ev.foIgnored) {
            findings.push({ status: 'info', key: 'finding_dmarc_fo_ignored', replacements: { '{fo}': String(result.dmarcParsed.fo) } });
        } else if (result.dmarcParsed && result.dmarcParsed.fo) {
            findings.push({ status: 'info', key: 'finding_dmarc_fo', replacements: { '{fo}': String(result.dmarcParsed.fo) } });
        }
        if (ev.unknownTags.length > 0) {
            findings.push({ status: 'info', key: 'finding_dmarc_unknown_tags', replacements: { '{tags}': ev.unknownTags.join(', ') } });
        }
        const otherInvalid = ev.invalidTags.filter(k => !['p', 'sp', 'np'].includes(k));
        if (otherInvalid.length > 0) {
            findings.push({
                status: 'info',
                key: 'finding_dmarc_tag_invalid',
                replacements: { '{tags}': otherInvalid.map(k => `${k}=${result.dmarcParsed[k]}`).join(', ') }
            });
        }
        // Alineación estricta (adkim/aspf = s) — informativo
        if (ev.adkim === 's' && ev.aspf === 's') {
            findings.push({ status: 'info', key: 'finding_dmarc_alignment_strict' });
        }

        return { points: Math.max(0, points), findings };
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
        // Solo cuentan los destinos del registro que APLICA: los de unos registros
        // descartados (varios en el mismo nombre) no reciben nada.
        const ev = dmarcEvalOf(result);
        const rua = ev ? ev.rua : { valid: [], invalid: [] };
        const ruf = ev ? ev.ruf : { valid: [], invalid: [] };
        if (rua.valid.length > 0) {
            points += SCORE_WEIGHTS.dmarcReporting;
            findings.push({ status: 'success', key: 'finding_dmarc_reporting_ok' });
        } else if (ruf.valid.length > 0) {
            // Los informes de fallo casi no se envían (privacidad): sin rua no hay visibilidad.
            findings.push({ status: 'warning', key: 'finding_dmarc_ruf_only' });
        } else {
            findings.push({ status: 'warning', key: 'finding_dmarc_reporting_err' });
        }
        // `rua=dmarc@dominio` sin `mailto:` no es un URI: los receptores lo descartan en
        // silencio y el dominio cree que recibe informes.
        const invalid = [...rua.invalid, ...ruf.invalid];
        if (invalid.length > 0) {
            findings.push({ status: 'warning', key: 'finding_dmarc_rua_invalid_uri', replacements: { '{uris}': invalid.join(', ') } });
        }
        // RFC 7489 §6.2 permitía a los receptores limitarse a DOS destinos; RFC 9989 §4.6
        // pide enviar a todos, pero mientras dure la transición se puede perder alguno.
        if (rua.valid.length > 2) {
            points += SCORE_WEIGHTS.dmarcRuaTooMany;
            findings.push({ status: 'warning', key: 'finding_dmarc_rua_too_many', replacements: { '{count}': String(rua.valid.length) } });
        }

        // Autorización de destinos de informe EXTERNOS (RFC 9990 §4)
        if (Array.isArray(result.dmarcExternalAuth) && result.dmarcExternalAuth.length > 0) {
            const unauthorized = result.dmarcExternalAuth.filter(d => d.authorized === false);
            const unverifiable = result.dmarcExternalAuth.filter(d => d.authorized === null);
            if (unauthorized.length > 0) {
                points += SCORE_WEIGHTS.dmarcExternalUnauthorized;
                findings.push({ status: 'error', key: 'finding_dmarc_rua_unauthorized', replacements: { '{dest}': unauthorized.map(d => d.destDomain).join(', ') } });
            } else if (unverifiable.length === 0) {
                findings.push({ status: 'success', key: 'finding_dmarc_rua_authorized' });
            }
        }
        return { points: Math.max(0, points), findings };
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

        const findings = [{ status: 'success', key: 'finding_dkim_ok', replacements: { '{count}': count } }];

        const analyses = records.map(r => ({ selector: r.selector, ...analyzeDKIMRecord(r.record) }));
        const revoked = analyses.filter(a => a.revoked);
        const active = analyses.filter(a => !a.revoked);
        // El umbral de bits SOLO aplica a RSA: una clave Ed25519 son 256 bits y
        // equivale a ~3000 de RSA, así que compararla con 1024 la marcaría como débil
        // siendo la opción más fuerte de las dos (RFC 8463).
        const rsaKeys = active.filter(a => a.algorithm === 'rsa');
        const weak = rsaKeys.filter(a => a.keyBits != null && a.keyBits < 1024);
        const deprecated = rsaKeys.filter(a => a.keyBits === 1024);
        const ed25519 = active.filter(a => a.algorithm === 'ed25519' && !a.malformed);
        const malformed = active.filter(a => a.malformed);
        const testing = analyses.filter(a => a.testing);

        // Una clave revocada (p= vacío) es la forma CORRECTA de retirarla (RFC 6376
        // §3.6.1): se informa, no resta. Si solo aparecen claves revocadas, el selector
        // activo es otro que no se ha encontrado, y el control queda sin evaluar.
        if (revoked.length > 0) {
            findings.push({ status: 'info', key: 'finding_dkim_revoked', replacements: { '{selectors}': revoked.map(a => a.selector).join(', ') } });
        }
        if (active.length === 0) {
            return {
                points: 0,
                unevaluable: true,
                findings: [...findings.slice(1), { status: 'info', key: 'finding_dkim_besteffort' }, ...zoneFindings]
            };
        }
        let points = SCORE_WEIGHTS.dkimStrong;
        if (weak.length > 0) {
            points = SCORE_WEIGHTS.dkimWeak;
            const w = weak[0];
            findings.push({ status: 'error', key: 'finding_dkim_weak_key', replacements: { '{selector}': w.selector, '{bits}': String(w.keyBits) } });
        } else if (malformed.length > 0) {
            points = SCORE_WEIGHTS.dkimMalformed;
        } else if (deprecated.length > 0) {
            points = SCORE_WEIGHTS.dkim1024;
        }
        if (deprecated.length > 0) {
            findings.push({ status: 'warning', key: 'finding_dkim_key_1024', replacements: { '{selectors}': deprecated.map(a => a.selector).join(', ') } });
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

    // BIMI es MARCA, no seguridad: no puntúa (requiere un certificado VMC de pago y no
    // impide suplantar nada). Se queda como hallazgos informativos.
    function inboundFilter(result) {
        const f = inboundFilterOf(result);
        const findings = [];
        const list = (arr) => arr.join(', ');
        if (f.segVendors.length) {
            findings.push({ status: 'success', key: 'finding_filter_seg', replacements: { '{vendors}': list(f.segVendors) } });
        }
        // Un ICES que ya sale como SEG en el MX (Avanan inline) no se repite.
        const icesOnly = f.icesVendors.filter(v => !f.segVendors.includes(v));
        if (icesOnly.length) {
            findings.push({ status: 'success', key: 'finding_filter_ices', replacements: { '{vendors}': list(icesOnly) } });
        }
        if (f.outOfPathVendors.length) {
            findings.push({ status: 'info', key: 'finding_filter_out_of_path', replacements: { '{vendors}': list(f.outOfPathVendors) } });
        }

        if (f.state === 'reinforced') {
            if (f.bypassMx.length) {
                findings.push({
                    status: 'warning',
                    key: 'finding_filter_bypass',
                    replacements: { '{hosts}': list(f.bypassMx), '{provider}': f.provider || '', '{vendors}': list(f.segVendors) }
                });
                return { points: SCORE_WEIGHTS.filterBypass, findings };
            }
            return { points: SCORE_WEIGHTS.filterReinforced, findings };
        }
        if (f.state === 'native') {
            findings.push({ status: 'info', key: 'finding_filter_native', replacements: { '{provider}': f.provider || '' } });
            return { points: SCORE_WEIGHTS.filterNative, findings };
        }
        // MX propio o desconocido: puede haber un gateway que el DNS no delata. Ni suma ni
        // resta: queda fuera de la media.
        findings.push({ status: 'info', key: 'finding_filter_unidentified', replacements: { '{hosts}': list(f.unknownMx) } });
        return { points: 0, unevaluable: true, findings };
    },

    function bimi(result) {
        const bimiRecord = result.bimiRecord;
        const hasBimi = bimiRecord && !bimiRecord.error && bimiRecord.record;
        if (!hasBimi) {
            return { points: 0, findings: [{ status: 'info', key: 'finding_bimi_err' }] };
        }
        const findings = [];
        // El receptor busca BIMI en el dominio del remitente y, si no hay, en su dominio
        // organizativo: un subdominio sin registro propio hereda el logo.
        if (bimiRecord.inheritedFrom) {
            findings.push({ status: 'info', key: 'finding_bimi_inherited', replacements: { '{org}': bimiRecord.inheritedFrom } });
        }
        // l= vacío es una declaración explícita de NO participar en BIMI (no un error).
        if (bimiRecord.declined) {
            return { points: 0, findings: [...findings, { status: 'info', key: 'finding_bimi_declined' }] };
        }
        findings.push({ status: 'success', key: 'finding_bimi_ok' });
        if (bimiRecord.logoInsecure || bimiRecord.vmcInsecure) {
            findings.push({ status: 'warning', key: 'finding_bimi_insecure_url' });
        }
        // Sin a= (VMC/CMC) los principales buzones —Gmail, Apple Mail— no pintan el
        // logo aunque el SVG sea correcto: el registro queda a medias.
        if (!bimiRecord.vmc) {
            findings.push({ status: 'warning', key: 'finding_bimi_no_vmc' });
        } else {
            findings.push({ status: 'success', key: 'finding_bimi_vmc_ok' });
        }
        return { points: 0, findings };
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
        let mxUncovered = false;
        const policyMx = policyFetch.parsed?.mx || [];
        const mxHosts = (result.mxRecords || []).map(r => r.host);
        if (policyMx.length > 0 && mxHosts.length > 0) {
            const { uncovered, unused } = checkMtaStsMxCoverage(policyMx, mxHosts);
            if (uncovered.length > 0) {
                mxUncovered = true;
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

        // La política no se ha podido (CORS, red) o no se ha querido (privacidad) descargar,
        // pero el TXT está publicado y el host de la política existe en DNS: se acredita
        // como "publicada, sin verificar". Dejarla fuera del cálculo convertía el transporte
        // en "solo DNSSEC" justo en los dominios que sí despliegan MTA-STS.
        if (policyFetch.validationReason === 'fetch_failed') {
            return {
                points: SCORE_WEIGHTS.mtaStsUnverified,
                findings: [{ status: 'info', key: 'finding_mta_sts_unreachable' }, ...mxCoverageFindings]
            };
        }
        if (policyFetch.validationReason === 'not_fetched') {
            return { points: SCORE_WEIGHTS.mtaStsUnverified, findings: [{ status: 'info', key: 'finding_mta_sts_not_fetched' }] };
        }
        // El host de la política no existe en DNS: ningún MTA puede obtenerla. Es un fallo
        // del dominio comprobado sin haberle mandado una sola petición.
        if (policyFetch.validationReason === 'host_missing') {
            return {
                points: 0,
                findings: [{ status: 'error', key: 'finding_mta_sts_host_missing', replacements: { '{host}': policyFetch.host || '' } }]
            };
        }

        if (result.mtaSts.policy?.valid) {
            const findings = [{ status: 'success', key: 'finding_mta_sts_ok' }];
            let points = SCORE_WEIGHTS.mtaStsEnforce;
            const maxAge = result.mtaSts.policy.maxAge;
            // RFC 8461: max_age es obligatorio; se recomienda ≥ 604800 s (1 semana).
            if (maxAge == null || Number.isNaN(maxAge)) {
                findings.push({ status: 'warning', key: 'finding_mta_sts_no_maxage' });
            } else if (maxAge < 604800) {
                findings.push({ status: 'warning', key: 'finding_mta_sts_low_maxage', replacements: { '{maxage}': String(maxAge) } });
            } else {
                points += SCORE_WEIGHTS.mtaStsMaxAgeOk;
            }
            // Un MX fuera de la lista hace que los MTA que aplican la política RECHACEN la
            // entrega a ese host: la política existe, pero rompe el correo entrante.
            if (mxUncovered) points = Math.min(points, SCORE_WEIGHTS.mtaStsMxMismatchCap);
            return { points, findings: [...findings, ...mxCoverageFindings] };
        }
        const policy = result.mtaSts.policy || {};
        // mode: testing es una política VÁLIDA (RFC 8461 §5) que aún no se aplica: solo
        // genera informes TLS-RPT. Presentarla como "inválida" era una afirmación falsa ante
        // el prospecto. No suma, pero tampoco resta; y un MX sin cubrir aún no rompe nada,
        // así que se avisa sin penalizar.
        const wellFormedNotEnforced = policy.validationReason === 'mode_not_enforce' && policy.httpStatus === 200;
        if (wellFormedNotEnforced && policy.mode === 'testing') {
            const coverage = mxCoverageFindings.map(f => (f.status === 'error' ? { ...f, status: 'warning' } : f));
            return { points: SCORE_WEIGHTS.mtaStsTesting, findings: [{ status: 'warning', key: 'finding_mta_sts_testing' }, ...coverage] };
        }
        // mode: none es la forma correcta de RETIRAR una política (RFC 8461 §5).
        if (wellFormedNotEnforced && policy.mode === 'none') {
            return { points: 0, findings: [{ status: 'info', key: 'finding_mta_sts_mode_none' }] };
        }
        const replacements = {};
        if (policy.httpStatus != null && policy.httpStatus !== 200) {
            replacements['{status}'] = String(policy.httpStatus);
        } else if (policy.mode) {
            replacements['{mode}'] = policy.mode;
        }
        return {
            points: 0,
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
        let points = SCORE_WEIGHTS.tlsRpt;
        // RFC 8460 §3: rua debe ser mailto: o https:. Con otro esquema los informes
        // de fallo TLS no llegan a ninguna parte y el registro solo aparenta cobertura.
        const { invalid } = validateTlsRptRua(result.tlsRpt.rua);
        if (invalid.length > 0) {
            points = SCORE_WEIGHTS.tlsRptRuaInvalid;
            findings.push({
                status: 'error',
                key: 'finding_tls_rpt_rua_invalid',
                replacements: { '{uris}': invalid.join(', ') }
            });
        }
        return { points, findings };
    },

    function dane(result) {
        const zoneValidated = isDnssecValidated(result.dnssec);
        if (hasDaneOf(result)) {
            // RFC 7672 §2.2: un MTA solo usa DANE si el MX del dominio se resuelve de forma
            // SEGURA (zona firmada y validada) y el TLSA también llega validado. Con TLSA pero
            // sin DNSSEC en la zona del dominio —el caso típico de un MX en *.mx.microsoft
            // con la zona del cliente sin firmar— los TLSA existen, pero nadie los usa.
            const tlsaAd = (result.daneRecords && result.daneRecords.validated) || {};
            const tlsaUnvalidated = Object.keys(tlsaAd).some(h => tlsaAd[h] === false);
            if (!zoneValidated) {
                return { points: 0, unevaluable: true, findings: [{ status: 'info', key: 'finding_dane_unusable' }] };
            }
            if (tlsaUnvalidated) {
                return { points: 0, findings: [{ status: 'warning', key: 'finding_dane_unusable' }] };
            }
            return { points: SCORE_WEIGHTS.dane, findings: [{ status: 'success', key: 'finding_dane_ok' }] };
        }
        // DANE (RFC 7672) se APOYA en DNSSEC: sin la zona firmada los registros TLSA no
        // son fiables y ningún MTA los usa, así que no es desplegable. Restarle puntos a
        // un dominio sin DNSSEC sería cobrarle dos veces la misma carencia. Queda sin
        // evaluar y sale del denominador; con DNSSEC activo sí se exige.
        if (!zoneValidated) {
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
            // Claves publicadas pero respuesta sin validar: falta el DS en la zona padre o la
            // cadena está rota. Una zona así no protege nada, y darle los puntos premiaba la
            // mitad del trabajo.
            if (!isDnssecValidated(result.dnssec)) {
                return { points: 0, findings: [{ status: 'warning', key: 'finding_dnssec_unvalidated' }] };
            }
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

// Nivel de protección contra suplantación, en términos de RFC 9989 §3.2.9:
//   protected — enforcement (quarantine/reject) en el dominio y en sus subdominios
//   partial   — el dominio está en enforcement, pero sus subdominios (sp/np) o una parte
//               del correo (pct parcial) no
//   spoofable — sin DMARC aplicable en enforcement: nada bloquea un From suplantado
//   unknown   — la consulta DMARC falló: no se puede afirmar nada
// Sustituye a la antigua "postura", que exigía además un gateway detectado, MTA-STS
// verificado y -all, y que por eso no alcanzaba ningún dominio real.
function protectionLevelOf(result, ev) {
    if (result.dmarcUnavailable) return 'unknown';
    if (!isEnforcedOf(ev)) return 'spoofable';
    return ev.enforcement ? 'protected' : 'partial';
}

const LEVEL_CLASS = { protected: 'safe', partial: 'warning', spoofable: 'danger', unknown: 'warning' };

function cardClassOf(grade) {
    if (grade === 'A+' || grade === 'A' || grade === 'B') return 'safe';
    if (grade === 'F') return 'danger';
    return 'warning';
}

export function calculateScoreAndFindings(result) {
    const findings = [];
    // Null MX (RFC 7505): declarar que no se recibe correo es una buena práctica
    // para dominios sin uso de email; se informa como positivo, sin penalizar.
    if (result.nullMx) {
        findings.push({ status: 'info', key: 'finding_null_mx' });
    }
    // DMARC heredado del dominio organizativo: al subdominio le corresponde la etiqueta sp
    // del registro (RFC 9989 §4.10.1), y así se dice.
    const ev = dmarcEvalOf(result);
    if (result.dmarcInherited && result.dmarcInheritedFrom) {
        findings.push({
            status: 'info',
            key: 'finding_dmarc_inherited',
            replacements: {
                '{org}': result.dmarcInheritedFrom,
                '{tag}': ev ? ev.applicableTag : 'p',
                '{policy}': String(ev ? ev.applicable : 'none').toUpperCase()
            }
        });
    }
    // El Tree Walk no se completó (un ancestro no respondió): el dominio organizativo
    // puede no ser el real. Se dice, en vez de dar por buena una búsqueda a medias.
    if (result.dmarcWalkIncomplete) {
        findings.push({ status: 'info', key: 'finding_dmarc_walk_incomplete' });
    }

    // Un dominio que no recibe correo no tiene nada que filtrar ni que proteger en
    // tránsito: el filtrado entrante, MTA-STS, TLS-RPT, DANE y DNSSEC-para-el-MX no le
    // aplican. Se dice una vez, en vez de listar cinco "no configurado" que no son carencias.
    const receivesMail = receivesMailOf(result);
    if (!receivesMail) {
        findings.push({ status: 'info', key: 'finding_transport_not_applicable' });
    }
    const MAIL_AXES = new Set(['filtering', 'transport']);

    const checkResults = [];
    for (const check of SCORE_CHECKS) {
        const budget = CHECK_BUDGETS[check.name];
        if (budget && MAIL_AXES.has(budget.category) && !receivesMail) {
            checkResults.push({
                id: check.name, labelKey: budget.labelKey, category: budget.category,
                max: budget.max, earned: 0, unevaluable: true, notApplicable: true
            });
            continue;
        }
        const { points = 0, findings: sectionFindings = [], unevaluable = false } = check(result);
        findings.push(...sectionFindings);
        if (!budget) continue; // check informativo (bimi, srv): no puntúa
        checkResults.push({
            id: check.name,
            labelKey: budget.labelKey,
            category: budget.category,
            max: budget.max,
            earned: unevaluable ? 0 : Math.max(0, Math.min(points, budget.max)),
            unevaluable
        });
    }

    // Desglose por eje: es lo que permite explicar la nota en vez de afirmarla. Cada eje
    // se normaliza sobre lo EVALUABLE: lo que no se ha podido medir sale del denominador.
    const breakdown = Object.entries(SCORE_CATEGORIES).map(([id, cat]) => {
        const checks = checkResults.filter(c => c.category === id);
        const evaluable = checks.filter(c => !c.unevaluable);
        const max = evaluable.reduce((sum, c) => sum + c.max, 0);
        const earned = evaluable.reduce((sum, c) => sum + c.earned, 0);
        const applicable = !MAIL_AXES.has(id) || receivesMail;
        return {
            id,
            labelKey: cat.labelKey,
            weight: cat.weight,
            max,
            earned,
            score: max > 0 ? Math.round((earned / max) * 100) : 0,
            applicable,
            // ¿Entra en la media? Un eje que no aplica o que no se ha podido evaluar no.
            counted: applicable && max > 0,
            checks
        };
    });
    const anti = breakdown.find(c => c.id === 'antispoof');
    const filteringCat = breakdown.find(c => c.id === 'filtering');
    const transportCat = breakdown.find(c => c.id === 'transport');

    // --- Nota del ECOSISTEMA: media ponderada de los ejes que cuentan ---
    // Los pesos de los ejes que no cuentan se reparten entre los demás; `share` es el peso
    // efectivo, el que el desglose enseña. Sin nada evaluable, la nota es 0.
    const counted = breakdown.filter(c => c.counted);
    const totalWeight = counted.reduce((sum, c) => sum + c.weight, 0);
    for (const cat of breakdown) {
        cat.share = cat.counted && totalWeight > 0 ? Math.round((cat.weight / totalWeight) * 100) : 0;
    }
    const weighted = totalWeight > 0
        ? counted.reduce((sum, c) => sum + (c.earned / c.max) * 100 * c.weight, 0) / totalWeight
        : 0;
    let score = Math.round(weighted);

    const enforced = isEnforcedOf(ev);
    // Sin enforcement, cualquiera suplanta el From visible, y ni un gateway ni un
    // transporte ejemplares lo compensan: techo D. (Si la consulta DMARC falló no se
    // puede concluir, y no se aplica.)
    let cap = null;
    if (!enforced && !result.dmarcUnavailable && score > NO_ENFORCEMENT_CAP) {
        score = NO_ENFORCEMENT_CAP;
        cap = { key: 'no_enforcement', value: NO_ENFORCEMENT_CAP };
    }
    // A+ exige evidencia completa: reject en todos los niveles, SPF y DKIM EVALUADOS y
    // al máximo, e informes. Lo que no se ha podido verificar (p. ej. DKIM con selector
    // desconocido) limita a A: no es un fallo, pero tampoco una prueba.
    const byId = (id) => checkResults.find(c => c.id === id);
    const full = (id) => { const c = byId(id); return !!c && !c.unevaluable && c.earned === c.max; };
    const verified = enforced && ev.effective.floor === 'reject' && ev.enforcement
        && full('spf') && full('dkim') && full('dmarcReporting') && full('dmarc');
    if (!verified && score > UNVERIFIED_CAP) {
        score = UNVERIFIED_CAP;
        cap = { key: 'unverified', value: UNVERIFIED_CAP };
    }
    const grade = letterGrade(score);

    const level = protectionLevelOf(result, ev);
    // `posture` se mantiene por compatibilidad con quien lo lee (postureText, informe):
    // es el nivel de protección contra suplantación.
    const posture = { key: level, class: LEVEL_CLASS[level] };

    // --- Ejes de filtrado y transporte, para sus pastillas ---
    const inbound = inboundFilterOf(result);
    const filtering = receivesMail
        ? {
            applicable: true,
            state: inbound.state,
            evaluable: filteringCat.max > 0,
            score: filteringCat.max > 0 ? filteringCat.score : null,
            vendors: inbound.vendors,
            provider: inbound.provider,
            bypass: inbound.bypassMx.length > 0
        }
        : { applicable: false, state: 'not_applicable', evaluable: false, score: null, vendors: [], provider: null, bypass: false };
    const transport = receivesMail
        ? { applicable: true, score: transportCat.score, grade: letterGrade(transportCat.score), evaluable: transportCat.max > 0 }
        : { applicable: false, score: null, grade: null, evaluable: false };

    return {
        score,
        grade,
        cap,
        cardClass: cardClassOf(grade),
        findings,
        posture,
        level,
        filtering,
        transport,
        breakdown,
        // Suplantación, por separado: la usan quienes necesitan solo ese eje.
        antispoof: { score: anti.score, earned: anti.earned, max: anti.max },
        totalEarned: anti.earned,
        totalMax: anti.max,
        authRatio: anti.max > 0 ? anti.earned / anti.max : 1
    };
}
