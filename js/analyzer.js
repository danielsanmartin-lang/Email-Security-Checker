import { KB } from './knowledge.js';
import { parseSPF, parseDMARC, analyzeDKIMRecord } from './parsers.js';

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
        // Only flag as SEG if the MX clearly belongs to a different, external domain
        if (domainRoot && mxRoot && mxRoot !== domainRoot) {
            return { name: mxRoot, type: 'seg' };
        }
    }
    return { name: host, type: 'unknown' };
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
        mxRecords,
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

// ===== Scoring declarativo =====
// Pesos centralizados (positivos = bonus, negativos = penalización).
export const SCORE_WEIGHTS = {
    spfPresent: 20,
    spfMultiple: -10,
    spfAllPass: -25,
    spfAllNeutral: -15,
    spfNoAll: -10,
    spfPtr: -5,
    spfLookupsOk: 10,
    dmarcPresent: 20,
    dmarcMultiple: -10,
    dmarcReject: 30,
    dmarcQuarantine: 20,
    dmarcNone: 5,
    dmarcVersionInvalid: -10,
    dmarcPolicyInvalid: -25,
    dmarcReporting: 5,
    dmarcSpWeak: -10,
    dmarcPctPartial: -5,
    dmarcExternalUnauthorized: -10,
    dkim: 10,
    dkimWeakKey: -10,
    dkimRevoked: -5,
    bimi: 5,
    mtaStsValid: 5,
    mtaStsInvalid: -15,
    dane: 5,
    dnssec: 5
};

// Suma teórica de los aportes positivos (máximo alcanzable antes de acotar).
export const MAX_POSITIVE_SCORE = Object.values(SCORE_WEIGHTS)
    .filter(w => w > 0)
    .reduce((a, b) => a + b, 0);

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
                findings.push({ status: 'success', key: 'finding_spf_all_softfail' });
            } else if (q === '-') {
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
        // Reporting (rua/ruf)
        const hasRua = result.dmarcRua && result.dmarcRua.length > 0;
        const hasRuf = result.dmarcRuf && result.dmarcRuf.length > 0;
        if (hasRua || hasRuf) {
            points += SCORE_WEIGHTS.dmarcReporting;
            findings.push({ status: 'success', key: 'finding_dmarc_reporting_ok' });
        } else {
            findings.push({ status: 'warning', key: 'finding_dmarc_reporting_err' });
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
            // pct < 100: la política solo se aplica a una fracción del correo
            const pct = result.dmarcParsed.pct != null ? parseInt(result.dmarcParsed.pct, 10) : 100;
            if (Number.isFinite(pct) && pct < 100) {
                points += SCORE_WEIGHTS.dmarcPctPartial;
                findings.push({ status: 'warning', key: 'finding_dmarc_pct_partial', replacements: { '{pct}': String(pct) } });
            }
            // Alineación estricta (adkim/aspf = s) — informativo
            const adkim = (result.dmarcParsed.adkim || 'r').toLowerCase();
            const aspf = (result.dmarcParsed.aspf || 'r').toLowerCase();
            if (adkim === 's' && aspf === 's') {
                findings.push({ status: 'info', key: 'finding_dmarc_alignment_strict' });
            }
        }

        // Autorización de destinos de informe EXTERNOS (RFC 7489 §7.1)
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
        return { points, findings };
    },

    function dkim(result) {
        const records = (result.dkimRecords && result.dkimRecords.records) || [];
        const count = records.length;
        // Ausencia: NO penaliza. La detección prueba selectores comunes (best-effort);
        // un selector personalizado válido no se detecta y no debe bajar la nota.
        if (count === 0) {
            return { points: 0, findings: [{ status: 'info', key: 'finding_dkim_besteffort' }] };
        }

        let points = SCORE_WEIGHTS.dkim;
        const findings = [{ status: 'success', key: 'finding_dkim_ok', replacements: { '{count}': count } }];

        const analyses = records.map(r => ({ selector: r.selector, ...analyzeDKIMRecord(r.record) }));
        const revoked = analyses.filter(a => a.revoked);
        const weak = analyses.filter(a => !a.revoked && a.keyBits != null && a.keyBits < 1024);
        const deprecated = analyses.filter(a => !a.revoked && a.keyBits === 1024);
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
            findings.push({ status: 'warning', key: 'finding_dkim_key_1024', replacements: { '{selectors}': deprecated.map(a => a.selector).join(', ') } });
        }
        if (testing.length > 0) {
            findings.push({ status: 'info', key: 'finding_dkim_testing', replacements: { '{selectors}': testing.map(a => a.selector).join(', ') } });
        }
        return { points, findings };
    },

    function bimi(result) {
        const hasBimi = result.bimiRecord && !result.bimiRecord.error && result.bimiRecord.record;
        if (hasBimi) {
            return { points: SCORE_WEIGHTS.bimi, findings: [{ status: 'success', key: 'finding_bimi_ok' }] };
        }
        return { points: 0, findings: [{ status: 'info', key: 'finding_bimi_err' }] };
    },

    function mtaSts(result) {
        if (!result.mtaSts) {
            return { points: 0, findings: [{ status: 'info', key: 'finding_mta_sts_err' }] };
        }
        if (result.mtaSts.policy?.valid) {
            const findings = [{ status: 'success', key: 'finding_mta_sts_ok' }];
            const maxAge = result.mtaSts.policy.maxAge;
            // RFC 8461: max_age es obligatorio; se recomienda ≥ 604800 s (1 semana).
            if (maxAge == null || Number.isNaN(maxAge)) {
                findings.push({ status: 'warning', key: 'finding_mta_sts_no_maxage' });
            } else if (maxAge < 604800) {
                findings.push({ status: 'warning', key: 'finding_mta_sts_low_maxage', replacements: { '{maxage}': String(maxAge) } });
            }
            return { points: SCORE_WEIGHTS.mtaStsValid, findings };
        }
        const policy = result.mtaSts.policy || {};
        const replacements = {};
        if (policy.httpStatus != null && policy.httpStatus !== 200) {
            replacements['{status}'] = String(policy.httpStatus);
        } else if (policy.mode) {
            replacements['{mode}'] = policy.mode;
        }
        return {
            points: SCORE_WEIGHTS.mtaStsInvalid,
            findings: [{
                status: 'error',
                id: 'MTA_STS_POLICY_INVALID',
                type: 'error',
                key: 'finding_mta_sts_policy_invalid',
                message: 'MTA-STS TXT record exists but the HTTPS policy file is missing, invalid, or not set to enforce.',
                replacements: Object.keys(replacements).length ? replacements : undefined
            }]
        };
    },

    function tlsRpt(result) {
        if (result.tlsRpt) {
            return { points: 0, findings: [{ status: 'success', key: 'finding_tls_rpt_ok' }] };
        }
        return { points: 0, findings: [{ status: 'info', key: 'finding_tls_rpt_err' }] };
    },

    function dane(result) {
        if (hasDaneOf(result)) {
            return { points: SCORE_WEIGHTS.dane, findings: [{ status: 'success', key: 'finding_dane_ok' }] };
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
    if (!hasSpf || allQualifier === '+' || allQualifier === '?' || !hasDmarc || dmarcPolicy === 'none' || !hasSegOrIces) {
        return { key: 'weak', grade: 'Débil', color: 'red', class: 'danger', label: 'Débil' };
    }
    return { key: 'moderate', grade: 'Moderada', color: 'yellow', class: 'warning', label: 'Moderada' };
}

function determineGrade(score) {
    if (score >= 95) return { grade: 'A+', cardClass: 'safe' };
    if (score >= 90) return { grade: 'A', cardClass: 'safe' };
    if (score >= 80) return { grade: 'B', cardClass: 'safe' };
    if (score >= 70) return { grade: 'C', cardClass: 'warning' };
    if (score >= 50) return { grade: 'D', cardClass: 'warning' };
    return { grade: 'F', cardClass: 'danger' };
}

export function calculateScoreAndFindings(result) {
    let score = 0;
    const findings = [];
    for (const check of SCORE_CHECKS) {
        const { points, findings: sectionFindings } = check(result);
        score += points;
        findings.push(...sectionFindings);
    }

    const posture = determinePosture(result);

    // Acotar la puntuación al rango 0–100 antes de derivar el grado.
    score = Math.max(0, Math.min(100, score));
    const { grade, cardClass } = determineGrade(score);

    return { score, grade, cardClass, findings, posture };
}


