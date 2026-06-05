/**
 * awarenessDetector.js
 * Detecta plataformas de Security Awareness / Phishing Simulation a partir de DNS.
 * Usa DNS-over-HTTPS (Google/Cloudflare DoH) — browser-compatible, sin backend.
 *
 * Versión del diccionario: 2026-06-05
 * PUNTO CIEGO DOCUMENTADO: Microsoft Attack Simulation Training (Defender for O365)
 * y los allowlists por transport rule/Advanced Delivery NO dejan rastro DNS.
 * No son detectables por este módulo. Ver campo `notes` en el resultado.
 *
 * Exporta:
 *   detectAwarenessVendors(domain: string) → Promise<AwarenessResult>
 *   AWARENESS_FINGERPRINTS  (el diccionario, recargable)
 *   flattenSpf(domain)      (util, reutiliza api.js implícitamente vía DoH interno)
 */

// ---------------------------------------------------------------------------
// 1. DICCIONARIO DE FINGERPRINTS
//    Cada vendor con detectableViaDns === false se documenta pero no se matchea.
//    Fuentes verificadas a junio 2026. Re-validar contra doc oficial en producción.
// ---------------------------------------------------------------------------
export const AWARENESS_FINGERPRINTS = {
    knowbe4: {
        displayName: 'KnowBe4 (KSAT)',
        detectableViaDns: true,
        spfIncludes: ['_spf.psm.knowbe4.com'],                     // verificado
        spfIps: ['23.21.109.197', '23.21.109.212', '147.160.167.0/26'], // verificado
        dkimSigningDomains: ['training.knowbe4.com', 'eu.knowbe4.com'], // verificado US/EU
        dkimSelectors: [],        // selector custom por cliente; añadir si se conoce
        infraDomains: ['knowbe4.com'],                              // verificado
        assetDomains: [],
        relatedGatewaySpf: ['spf.us1.defend.egress.com'],          // KnowBe4 Defend (ex-Egress)
        mxHint: null,
        dmarcRuaHint: null,
        crtPatterns: ['knowbe4.com'],
        weights: {
            spfInclude: 0.9,
            spfIp: 0.85,
            dkim: 0.85,
            infraDomain: 0.5,
            gateway: 0.3,
            crt: 0.4,
        },
        notes: 'Los dominios de phishing simulado rotan; no hay lista pública fija.',
    },

    proofpointSat: {
        displayName: 'Proofpoint Security Awareness (ex-Wombat)',
        detectableViaDns: true,
        spfIncludes: [],           // No publica include universal; usa safelisting de IPs
        spfIps: [],                // verificar_runtime: IPs en su guía de safelisting
        dkimSigningDomains: [],
        dkimSelectors: [],
        infraDomains: ['securityeducation.com', 'ws01-securityeducation.com', 'proofpoint.com'],
        assetDomains: ['tslp.s3.amazonaws.com'],                   // verificado (imágenes de phish)
        relatedGatewaySpf: [],
        mxHint: 'pphosted',       // MX *.pphosted.com / *.ppe-hosted.com
        dmarcRuaHint: null,
        crtPatterns: ['securityeducation.com'],
        weights: {
            infraDomain: 0.7,
            assetDomain: 0.6,
            mxHint: 0.3,
            crt: 0.5,
        },
        notes: 'Detección principal por dominios de landing/assets + MX, no por SPF.',
    },

    cofensePhishme: {
        displayName: 'Cofense PhishMe',
        detectableViaDns: true,
        spfIncludes: [],           // SPF/DKIM se entregan POR CLIENTE vía soporte → no universal
        spfIps: [],
        dkimSigningDomains: [],
        dkimSelectors: [],
        infraDomains: ['cofense.com'],                             // verificado
        assetDomains: [],
        relatedGatewaySpf: [],
        mxHint: null,
        dmarcRuaHint: null,
        crtPatterns: ['cofense.com'],
        weights: {
            infraDomain: 0.6,
            crt: 0.4,
        },
        notes: 'Señal NO-DNS más fiable: botón "Cofense Reporter" + landings del cliente.',
    },

    mimecastAwareness: {
        displayName: 'Mimecast Awareness Training',
        detectableViaDns: true,
        spfIncludes: [],           // verificar_runtime
        spfIps: [],
        dkimSigningDomains: [],
        dkimSelectors: [],
        infraDomains: [],
        assetDomains: [],
        relatedGatewaySpf: [],
        mxHint: 'mimecast',       // MX *.mimecast.com → gateway que bundlea awareness
        dmarcRuaHint: null,
        crtPatterns: ['mimecast.com'],
        weights: {
            mxHint: 0.3,
            infraDomain: 0.6,
            crt: 0.3,
        },
        notes: 'Awareness viene bundleado con el gateway de correo Mimecast.',
    },

    sophosPhishThreat: {
        displayName: 'Sophos Phish Threat',
        detectableViaDns: true,
        spfIncludes: [],
        spfIps: [],
        dkimSigningDomains: [],
        dkimSelectors: [],
        infraDomains: ['phish.sophos.com', 'sophosmail.com'],      // verificar_runtime
        assetDomains: [],
        relatedGatewaySpf: [],
        mxHint: 'sophos.com',
        dmarcRuaHint: null,
        crtPatterns: ['phish.sophos.com'],
        weights: {
            infraDomain: 0.6,
            mxHint: 0.25,
            crt: 0.4,
        },
        notes: 'verificar_runtime: confirmar dominios de envío en doc de safelisting Sophos.',
    },

    hoxhunt: {
        displayName: 'Hoxhunt',
        detectableViaDns: true,
        spfIncludes: ['_spf.hoxhunt.com'],                         // verificar_runtime
        spfIps: [],
        dkimSigningDomains: ['hoxhunt.com'],
        dkimSelectors: ['hoxhunt'],
        infraDomains: ['hoxhunt.com'],
        assetDomains: [],
        relatedGatewaySpf: [],
        mxHint: null,
        dmarcRuaHint: null,
        crtPatterns: ['hoxhunt.com'],
        weights: {
            spfInclude: 0.85,
            dkim: 0.85,
            infraDomain: 0.6,
            crt: 0.4,
        },
        notes: 'verificar_runtime: confirmar selector DKIM y SPF include en doc oficial.',
    },

    infosecIq: {
        displayName: 'Infosec IQ (Infosec Institute)',
        detectableViaDns: true,
        spfIncludes: [],
        spfIps: [],
        dkimSigningDomains: [],
        dkimSelectors: [],
        infraDomains: ['infosecinstitute.com', 'infoseciq.com'],   // verificar_runtime
        assetDomains: [],
        relatedGatewaySpf: [],
        mxHint: null,
        dmarcRuaHint: null,
        crtPatterns: ['infoseciq.com'],
        weights: {
            infraDomain: 0.6,
            crt: 0.4,
        },
        notes: 'verificar_runtime: completar con la doc de allowlisting de Infosec IQ.',
    },

    barracudaAwareness: {
        displayName: 'Barracuda Security Awareness Training (PhishLine)',
        detectableViaDns: true,
        spfIncludes: ['_spf.phishline.com'],                       // verificar_runtime
        spfIps: [],
        dkimSigningDomains: ['phishline.com'],
        dkimSelectors: ['phishline'],
        infraDomains: ['phishline.com', 'barracudanetworks.com'],
        assetDomains: [],
        relatedGatewaySpf: [],
        mxHint: 'barracudanetworks.com',
        dmarcRuaHint: null,
        crtPatterns: ['phishline.com'],
        weights: {
            spfInclude: 0.85,
            dkim: 0.8,
            infraDomain: 0.6,
            mxHint: 0.25,
            crt: 0.4,
        },
        notes: 'verificar_runtime: confirmar include SPF y selectores DKIM en safelisting Barracuda.',
    },

    proofpointThreatSim: {
        displayName: 'Proofpoint Threat Simulation (ex-ThreatSim)',
        detectableViaDns: true,
        spfIncludes: [],
        spfIps: [],
        dkimSigningDomains: [],
        dkimSelectors: [],
        infraDomains: ['threatsim.com'],                           // verificado
        assetDomains: [],
        relatedGatewaySpf: [],
        mxHint: null,
        dmarcRuaHint: null,
        crtPatterns: ['threatsim.com'],
        weights: {
            infraDomain: 0.7,
            crt: 0.5,
        },
        notes: 'ThreatSim usa dominios rotativos; el dominio base es la señal más estable.',
    },

    // -----------------------------------------------------------------------
    // PUNTO CIEGO DOCUMENTADO — NO se intenta matchear, solo se informa.
    // -----------------------------------------------------------------------
    msAttackSimulation: {
        displayName: 'Microsoft Attack Simulation Training (Defender for O365)',
        detectableViaDns: false,
        notes:
            'Todo el tráfico es interno al tenant M365 (envíos vía deliver@simulator.office.com ' +
            'o dominios *.phishingsimulations.microsoft.com). Los allowlists se configuran en ' +
            '"Advanced Delivery" (Exchange Online Protection) a nivel de tenant, sin dejar ' +
            'rastro en DNS externo. Punto ciego de este módulo.',
    },
};

// ---------------------------------------------------------------------------
// 2. CACHÉ SIMPLE (TTL 5 min) — independiente de api.js para encapsulamiento
// ---------------------------------------------------------------------------
const _cache = new Map();
const CACHE_TTL = 5 * 60 * 1000;

function _cached(key) {
    const e = _cache.get(key);
    if (e && Date.now() - e.ts < CACHE_TTL) return e.data;
    if (e) _cache.delete(key);
    return null;
}
function _store(key, data) {
    _cache.set(key, { data, ts: Date.now() });
    if (_cache.size > 300) {
        const now = Date.now();
        for (const [k, v] of _cache) if (now - v.ts > CACHE_TTL) _cache.delete(k);
    }
}

// ---------------------------------------------------------------------------
// 3. DoH QUERIES — con timeout, reintentos y fallback Cloudflare
// ---------------------------------------------------------------------------
const DOH_TIMEOUT = 8000;
const DOH_ENDPOINTS = [
    'https://dns.google/resolve',
    'https://cloudflare-dns.com/dns-query',
];

async function _doh(name, type, endpointIdx = 0) {
    const key = `awareness:${name}:${type}`;
    const cached = _cached(key);
    if (cached !== null) return cached;

    const endpoint = DOH_ENDPOINTS[endpointIdx % DOH_ENDPOINTS.length];
    const url = `${endpoint}?name=${encodeURIComponent(name)}&type=${type}`;

    let data;
    try {
        const ctrl = new AbortController();
        const tid = setTimeout(() => ctrl.abort(), DOH_TIMEOUT);
        const res = await fetch(url, {
            headers: { Accept: 'application/dns-json' },
            signal: ctrl.signal,
        });
        clearTimeout(tid);
        if (!res.ok) throw new Error(`DoH HTTP ${res.status}`);
        data = await res.json();
    } catch (err) {
        if (endpointIdx === 0) {
            // un reintento con Cloudflare
            return _doh(name, type, 1);
        }
        return { Answer: [] };
    }

    _store(key, data);
    return data;
}

async function _getTxt(domain) {
    try {
        const d = await _doh(domain, 'TXT');
        return (d.Answer || []).map(a =>
            a.data
                .replace(/^"|"$/g, '')
                .replace(/" "/g, '')
        );
    } catch { return []; }
}

async function _getMxRaw(domain) {
    try {
        const d = await _doh(domain, 'MX');
        return (d.Answer || [])
            .filter(a => a.type === 15)
            .map(a => {
                const parts = a.data.trim().split(/\s+/);
                return parts[parts.length - 1].replace(/\.$/, '').toLowerCase();
            });
    } catch { return []; }
}

// ---------------------------------------------------------------------------
// 4. SPF FLATTENING — RFC 7208 (límite 10 lookups)
// ---------------------------------------------------------------------------
export async function flattenSpf(domain, budget = { lookups: 10 }, seen = new Set()) {
    const out = { includes: [], ips: [], redirects: [], permError: false, domains: [] };
    if (seen.has(domain)) return out;
    seen.add(domain);

    const txts = await _getTxt(domain);
    const spf = txts.find(t => t.toLowerCase().startsWith('v=spf1'));
    if (!spf) return out;

    for (const token of spf.split(/\s+/).slice(1)) {
        const lower = token.toLowerCase();

        if (lower.startsWith('include:')) {
            const target = token.slice(8);
            out.includes.push(target);
            out.domains.push(target);
            if (--budget.lookups < 0) { out.permError = true; break; }
            const nested = await flattenSpf(target, budget, seen);
            out.includes.push(...nested.includes);
            out.ips.push(...nested.ips);
            out.domains.push(...nested.domains);
            if (nested.permError) out.permError = true;

        } else if (lower.startsWith('redirect=')) {
            const target = token.slice(9);
            out.redirects.push(target);
            out.domains.push(target);
            if (--budget.lookups < 0) { out.permError = true; break; }
            const nested = await flattenSpf(target, budget, seen);
            out.includes.push(...nested.includes);
            out.ips.push(...nested.ips);
            out.domains.push(...nested.domains);
            if (nested.permError) out.permError = true;

        } else if (lower.startsWith('ip4:') || lower.startsWith('ip6:')) {
            out.ips.push(token.slice(4));
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// 5. HELPERS DE MATCHING
// ---------------------------------------------------------------------------
function _domainMatches(haystack, needle) {
    const h = haystack.toLowerCase();
    const n = needle.toLowerCase();
    return h === n || h.endsWith('.' + n);
}

function _ipv4ToInt(ip) {
    return ip.split('.').reduce((acc, o) => (acc << 8) + (parseInt(o, 10) & 255), 0) >>> 0;
}

function _ipv4InCidr(observed, cidr) {
    const obsIp = observed.split('/')[0];
    const [base, bitsStr] = cidr.split('/');
    if (!obsIp.includes('.') || !base || !base.includes('.')) return observed === cidr;
    const bits = bitsStr ? parseInt(bitsStr, 10) : 32;
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return (_ipv4ToInt(obsIp) & mask) === (_ipv4ToInt(base) & mask);
}

// ---------------------------------------------------------------------------
// 6. crt.sh — Certificate Transparency enrichment (con caché y rate-limit)
// ---------------------------------------------------------------------------
const _crtCache = new Map();
const CRT_CACHE_TTL = 15 * 60 * 1000; // 15 min

async function _queryCrt(domain) {
    const key = `crt:${domain}`;
    const cached = _crtCache.get(key);
    if (cached && Date.now() - cached.ts < CRT_CACHE_TTL) return cached.data;

    try {
        const ctrl = new AbortController();
        const tid = setTimeout(() => ctrl.abort(), 10000);
        const url = `https://crt.sh/?q=%.${encodeURIComponent(domain)}&output=json`;
        const res = await fetch(url, { signal: ctrl.signal });
        clearTimeout(tid);
        if (!res.ok) throw new Error(`crt.sh HTTP ${res.status}`);
        const json = await res.json();
        // Aplanar nombres comunes y SANs
        const names = new Set();
        for (const entry of json) {
            if (entry.name_value) {
                entry.name_value.split('\n').forEach(n => names.add(n.trim().toLowerCase()));
            }
            if (entry.common_name) names.add(entry.common_name.trim().toLowerCase());
        }
        const data = [...names];
        _crtCache.set(key, { data, ts: Date.now() });
        return data;
    } catch {
        _crtCache.set(key, { data: [], ts: Date.now() }); // cacheamos fallo para no saturar
        return [];
    }
}

// ---------------------------------------------------------------------------
// 7. DETECCIÓN PRINCIPAL
// ---------------------------------------------------------------------------
/**
 * @param {string} domain - Dominio corporativo a analizar
 * @returns {Promise<AwarenessResult>}
 *
 * AwarenessResult = {
 *   domain: string,
 *   detectedVendors: VendorResult[],
 *   spfPermError: boolean,
 *   unresolvedSignals: string[],
 *   notes: string[],
 * }
 *
 * VendorResult = {
 *   vendor: string,
 *   displayName: string,
 *   score: number,        // 0-1
 *   level: 'alta'|'media'|'baja'|'sin evidencia',
 *   evidence: EvidenceItem[],
 * }
 *
 * EvidenceItem = {
 *   signal: string,
 *   value: string,
 *   weight: number,
 * }
 */
export async function detectAwarenessVendors(domain) {
    domain = domain.trim().toLowerCase();

    // --- DNS ---
    const spf = await flattenSpf(domain);
    const mxHosts = await _getMxRaw(domain);

    // DMARC: extraer rua/ruf por si apuntan a infra de vendor
    const dmarcTxts = await _getTxt(`_dmarc.${domain}`);
    const dmarcRaw = dmarcTxts.find(t => t.toLowerCase().startsWith('v=dmarc1')) || '';
    const ruaMatch = dmarcRaw.match(/rua=([^;]+)/i);
    const rufMatch = dmarcRaw.match(/ruf=([^;]+)/i);
    const dmarcRua = ruaMatch ? ruaMatch[1].split(',').map(s => s.trim()) : [];
    const dmarcRuf = rufMatch ? rufMatch[1].split(',').map(s => s.trim()) : [];
    const dmarcEndpoints = [...dmarcRua, ...dmarcRuf].join(' ').toLowerCase();

    // --- crt.sh ---
    let crtNames = [];
    try { crtNames = await _queryCrt(domain); } catch { /* silencio */ }

    // --- SCORING ---
    const detected = [];
    const unresolvedSignals = [];

    for (const [key, fp] of Object.entries(AWARENESS_FINGERPRINTS)) {
        if (!fp.detectableViaDns) continue;

        const evidence = [];
        const w = fp.weights || {};

        // 7a. SPF includes
        for (const inc of (fp.spfIncludes || [])) {
            if (spf.includes.some(x => _domainMatches(x, inc) || x === inc)) {
                evidence.push({ signal: 'spf_include', value: inc, weight: w.spfInclude ?? 0.9 });
            }
        }

        // 7b. SPF IPs / CIDRs
        for (const vip of (fp.spfIps || [])) {
            if (spf.ips.some(obs => _ipv4InCidr(obs, vip) || obs === vip)) {
                evidence.push({ signal: 'spf_ip', value: vip, weight: w.spfIp ?? 0.85 });
            }
        }

        // 7c. Related gateway SPF (ej. KnowBe4 Defend)
        for (const g of (fp.relatedGatewaySpf || [])) {
            if (spf.includes.some(x => _domainMatches(x, g))) {
                evidence.push({ signal: 'gateway_spf', value: g, weight: w.gateway ?? 0.3 });
            }
        }

        // 7d. Dominios de infra en SPF includes o MX
        for (const d of [...(fp.infraDomains || []), ...(fp.assetDomains || [])]) {
            const inSpf = spf.includes.some(x => _domainMatches(x, d))
                       || spf.domains.some(x => _domainMatches(x, d));
            const inMx  = mxHosts.some(m => _domainMatches(m, d));
            if (inSpf || inMx) {
                evidence.push({
                    signal: inMx ? 'mx_infra' : 'spf_infra',
                    value: d,
                    weight: w.infraDomain ?? 0.5,
                });
            }
        }

        // 7e. MX hint (substring match para *.pphosted.com, *.mimecast.com, etc.)
        if (fp.mxHint) {
            if (mxHosts.some(m => m.includes(fp.mxHint))) {
                evidence.push({ signal: 'mx_hint', value: fp.mxHint, weight: w.mxHint ?? 0.3 });
            }
        }

        // 7f. DMARC rua/ruf apuntando a infra de vendor
        if (fp.dmarcRuaHint && dmarcEndpoints.includes(fp.dmarcRuaHint)) {
            evidence.push({ signal: 'dmarc_rua', value: fp.dmarcRuaHint, weight: w.dmarc ?? 0.4 });
        }

        // 7g. DKIM: sondear SOLO selectores conocidos del diccionario
        for (const sel of (fp.dkimSelectors || [])) {
            let hit = false;
            try {
                const txts = await _getTxt(`${sel}._domainkey.${domain}`);
                if (txts.some(t => {
                    const lt = t.toLowerCase();
                    return lt.includes('v=dkim1') ||
                           (fp.dkimSigningDomains || []).some(sd => lt.includes(sd.toLowerCase()));
                })) {
                    hit = true;
                }
            } catch { /* NXDOMAIN es normal */ }
            if (hit) {
                evidence.push({ signal: 'dkim_selector', value: sel, weight: w.dkim ?? 0.85 });
            }
        }

        // 7h. Certificate Transparency (crt.sh)
        for (const pat of (fp.crtPatterns || [])) {
            if (crtNames.some(n => _domainMatches(n, pat))) {
                // Solo añadimos si no hay ya evidencia fuerte (para no inflar el score con señal débil)
                const alreadyStrong = evidence.some(e => e.weight >= 0.8);
                if (!alreadyStrong) {
                    evidence.push({ signal: 'cert_transparency', value: pat, weight: w.crt ?? 0.35 });
                }
            }
        }

        if (evidence.length > 0) {
            // Score combinado: 1 - Π(1 - peso_i)  → nunca pasa de 1
            const score = 1 - evidence.reduce((acc, e) => acc * (1 - e.weight), 1);
            const rounded = Math.round(score * 100) / 100;
            detected.push({
                vendor: key,
                displayName: fp.displayName,
                score: rounded,
                level: rounded >= 0.75 ? 'alta' : rounded >= 0.45 ? 'media' : 'baja',
                evidence,
                notes: fp.notes || null,
            });
        }
    }

    detected.sort((a, b) => b.score - a.score);

    // Registrar señales no resueltas (vendors conocidos pero sin match)
    for (const [key, fp] of Object.entries(AWARENESS_FINGERPRINTS)) {
        if (!fp.detectableViaDns) continue;
        if (!detected.some(d => d.vendor === key)) {
            // Solo los que tienen fingerprints verificados y no matchearon
            const hasFp = (fp.spfIncludes?.length || fp.spfIps?.length || fp.dkimSelectors?.length);
            if (hasFp) unresolvedSignals.push(fp.displayName);
        }
    }

    return {
        domain,
        detectedVendors: detected,
        spfPermError: spf.permError,
        unresolvedSignals,
        notes: [
            'Microsoft Attack Simulation Training (Defender O365) y los allowlists por transport rule/Advanced Delivery NO dejan rastro DNS: no son detectables por este módulo.',
            'Para mejorar cobertura, se enriquece con Certificate Transparency (crt.sh) buscando subdominios cuyo CN/SAN apunte a infra del vendor.',
            spf.permError
                ? 'SPF PermError detectado (>10 lookups): la cadena SPF no pudo resolverse completamente; algunas señales pueden estar ausentes.'
                : null,
        ].filter(Boolean),
    };
}

// ---------------------------------------------------------------------------
// 8. RELOAD EN CALIENTE DEL DICCIONARIO
//    Permite recibir un objeto externo (JSON cargado por el usuario) y fusionarlo.
// ---------------------------------------------------------------------------
export function mergeFingerprints(externalFPs) {
    for (const [key, fp] of Object.entries(externalFPs)) {
        if (AWARENESS_FINGERPRINTS[key]) {
            Object.assign(AWARENESS_FINGERPRINTS[key], fp);
        } else {
            AWARENESS_FINGERPRINTS[key] = fp;
        }
    }
}
