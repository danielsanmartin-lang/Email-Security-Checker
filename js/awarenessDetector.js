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
 *   flattenSpf(domain)      (util; usa la capa DNS unificada de api.js)
 */

import { queryDNS } from './api.js';

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
        dkimSelectors: ['psm', 'psm2', 'kb4', 'ksat'],             // selectores comunes de safelisting KnowBe4
        infraDomains: ['knowbe4.com'],                              // verificado
        assetDomains: [],
        relatedGatewaySpf: ['spf.us1.defend.egress.com'],          // KnowBe4 Defend (ex-Egress)
        mxHint: null,
        dmarcRuaHint: null,
        crtPatterns: ['knowbe4.com'],
        txtPatterns: ['knowbe4-site-verification', 'knowbe4-domain-verification'],
        cnameSubdomains: ['click', 'track', 'training', 'phishtest'],
        weights: {
            spfInclude: 0.9,
            spfIp: 0.85,
            dkim: 0.85,
            infraDomain: 0.5,
            gateway: 0.3,
            crt: 0.4,
            txtVerify: 0.85,
            cname: 0.95,
        },
        notes: 'Los dominios de phishing simulado rotan; no hay lista pública fija.',
    },

    proofpointSat: {
        displayName: 'Proofpoint Security Awareness (ex-Wombat)',
        detectableViaDns: true,
        spfIncludes: [],           // No publica include universal; usa safelisting de IPs
        spfIps: [],                // verificar_runtime: IPs en su guía de safelisting
        dkimSigningDomains: ['securityeducation.com'],
        dkimSelectors: ['pp1', 'pphosted', 'proofpoint'],          // selectores Proofpoint comunes
        infraDomains: ['securityeducation.com', 'ws01-securityeducation.com', 'proofpoint.com'],
        assetDomains: ['tslp.s3.amazonaws.com'],                   // verificado (imágenes de phish)
        relatedGatewaySpf: [],
        mxHint: 'pphosted',       // MX *.pphosted.com / *.ppe-hosted.com
        dmarcRuaHint: null,
        crtPatterns: ['securityeducation.com'],
        txtPatterns: ['proofpoint-verification', 'wombat-verification'],
        cnameSubdomains: ['click', 'track', 'simulate'],
        weights: {
            infraDomain: 0.7,
            assetDomain: 0.6,
            mxHint: 0.3,
            dkim: 0.8,
            crt: 0.5,
            txtVerify: 0.85,
            cname: 0.95,
        },
        notes: 'Detección principal por dominios de landing/assets + MX, no por SPF.',
    },

    cofensePhishme: {
        displayName: 'Cofense PhishMe',
        detectableViaDns: true,
        spfIncludes: [],           // SPF/DKIM se entregan POR CLIENTE vía soporte → no universal
        spfIps: [],
        dkimSigningDomains: ['cofense.com'],
        dkimSelectors: ['cofense'],                                // selector Cofense estándar
        infraDomains: ['cofense.com'],                             // verificado
        assetDomains: [],
        relatedGatewaySpf: [],
        mxHint: null,
        dmarcRuaHint: null,
        crtPatterns: ['cofense.com'],
        txtPatterns: ['cofense-domain-verification'],
        cnameSubdomains: ['phish', 'phishtest', 'report'],
        weights: {
            infraDomain: 0.6,
            dkim: 0.8,
            crt: 0.4,
            txtVerify: 0.85,
            cname: 0.95,
        },
        notes: 'Señal NO-DNS más fiable: botón "Cofense Reporter" + landings del cliente.',
    },

    mimecastAwareness: {
        displayName: 'Mimecast Awareness Training',
        detectableViaDns: true,
        spfIncludes: [],           // verificar_runtime
        spfIps: [],
        dkimSigningDomains: ['mimecast.com'],
        dkimSelectors: ['mimecast20190707', 'mimecast20210101', 'mimecast20230101', 'mimecast-key1'],
        infraDomains: [],
        assetDomains: [],
        relatedGatewaySpf: [],
        mxHint: 'mimecast',       // MX *.mimecast.com → gateway que bundlea awareness
        dmarcRuaHint: null,
        crtPatterns: ['mimecast.com'],
        txtPatterns: ['mimecast'],
        cnameSubdomains: ['training', 'awareness'],
        weights: {
            mxHint: 0.3,
            infraDomain: 0.6,
            dkim: 0.75,
            crt: 0.3,
            txtVerify: 0.8,
            cname: 0.9,
        },
        notes: 'Awareness viene bundleado con el gateway de correo Mimecast.',
    },

    sophosPhishThreat: {
        displayName: 'Sophos Phish Threat',
        detectableViaDns: true,
        spfIncludes: [],
        spfIps: [],
        dkimSigningDomains: ['sophosmail.com'],
        dkimSelectors: ['sophos', 'sophosmail'],                   // selectores Sophos comunes
        infraDomains: ['phish.sophos.com', 'sophosmail.com'],      // verificar_runtime
        assetDomains: [],
        relatedGatewaySpf: [],
        mxHint: 'sophos.com',
        dmarcRuaHint: null,
        crtPatterns: ['phish.sophos.com'],
        txtPatterns: ['sophos-domain-verification'],
        cnameSubdomains: ['phish', 'training'],
        weights: {
            infraDomain: 0.6,
            mxHint: 0.25,
            dkim: 0.8,
            crt: 0.4,
            txtVerify: 0.85,
            cname: 0.95,
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
        txtPatterns: ['hoxhunt-domain-verification'],
        cnameSubdomains: ['click', 'track'],
        weights: {
            spfInclude: 0.85,
            dkim: 0.85,
            infraDomain: 0.6,
            crt: 0.4,
            txtVerify: 0.85,
            cname: 0.95,
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
        txtPatterns: [],
        cnameSubdomains: ['training'],
        weights: {
            infraDomain: 0.6,
            crt: 0.4,
            cname: 0.9,
        },
        notes: 'verificar_runtime: completar con la doc de allowlisting de Infosec IQ.',
    },

    barracudaAwareness: {
        displayName: 'Barracuda Security Awareness Training (PhishLine)',
        detectableViaDns: true,
        spfIncludes: ['_spf.phishline.com'],                       // verificar_runtime
        spfIps: [],
        dkimSigningDomains: ['phishline.com'],
        dkimSelectors: ['phishline', 'barracuda'],
        infraDomains: ['phishline.com', 'barracudanetworks.com'],
        assetDomains: [],
        relatedGatewaySpf: [],
        mxHint: 'barracudanetworks.com',
        dmarcRuaHint: null,
        crtPatterns: ['phishline.com'],
        txtPatterns: ['barracuda-phishline', 'phishline-verification'],
        cnameSubdomains: ['phish', 'training'],
        weights: {
            spfInclude: 0.85,
            dkim: 0.8,
            infraDomain: 0.6,
            mxHint: 0.25,
            crt: 0.4,
            txtVerify: 0.85,
            cname: 0.95,
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
        txtPatterns: [],
        cnameSubdomains: ['simulate', 'phish'],
        weights: {
            infraDomain: 0.7,
            crt: 0.5,
            cname: 0.95,
        },
        notes: 'ThreatSim usa dominios rotativos; el dominio base es la señal más estable.',
    },

    // -----------------------------------------------------------------------
    // NUEVOS VENDORS DE AWARENESS
    // -----------------------------------------------------------------------

    terranovaFortra: {
        displayName: 'Terranova Security (Fortra)',
        detectableViaDns: true,
        spfIncludes: [],
        spfIps: [],
        dkimSigningDomains: ['terranovasecurity.com'],
        dkimSelectors: [],
        infraDomains: ['terranovasecurity.com'],
        assetDomains: [],
        relatedGatewaySpf: [],
        mxHint: null,
        dmarcRuaHint: null,
        crtPatterns: ['terranovasecurity.com'],
        txtPatterns: [],
        cnameSubdomains: ['training', 'phish'],
        weights: {
            infraDomain: 0.6,
            dkim: 0.8,
            crt: 0.4,
            cname: 0.9,
        },
        notes: 'Adquirida por Fortra; dominios de phish sim rotan.',
    },

    ninjio: {
        displayName: 'NINJIO',
        detectableViaDns: true,
        spfIncludes: [],
        spfIps: [],
        dkimSigningDomains: ['ninjio.com'],
        dkimSelectors: [],
        infraDomains: ['ninjio.com'],
        assetDomains: [],
        relatedGatewaySpf: [],
        mxHint: null,
        dmarcRuaHint: null,
        crtPatterns: ['ninjio.com'],
        txtPatterns: [],
        cnameSubdomains: ['training'],
        weights: {
            infraDomain: 0.6,
            dkim: 0.8,
            crt: 0.4,
            cname: 0.9,
        },
        notes: 'Awareness basado en vídeos; señal DNS limitada.',
    },

    curricula: {
        displayName: 'Curricula',
        detectableViaDns: true,
        spfIncludes: [],
        spfIps: [],
        dkimSigningDomains: ['curricula.com'],
        dkimSelectors: [],
        infraDomains: ['curricula.com'],
        assetDomains: [],
        relatedGatewaySpf: [],
        mxHint: null,
        dmarcRuaHint: null,
        crtPatterns: ['curricula.com'],
        txtPatterns: [],
        cnameSubdomains: ['phish', 'training'],
        weights: {
            infraDomain: 0.6,
            dkim: 0.8,
            crt: 0.4,
            cname: 0.9,
        },
        notes: 'Plataforma de awareness gamificada.',
    },

    keepnetLabs: {
        displayName: 'Keepnet Labs',
        detectableViaDns: true,
        spfIncludes: [],
        spfIps: [],
        dkimSigningDomains: ['keepnetlabs.com'],
        dkimSelectors: [],
        infraDomains: ['keepnetlabs.com'],
        assetDomains: [],
        relatedGatewaySpf: [],
        mxHint: null,
        dmarcRuaHint: null,
        crtPatterns: ['keepnetlabs.com'],
        txtPatterns: [],
        cnameSubdomains: ['phish', 'simulate'],
        weights: {
            infraDomain: 0.6,
            dkim: 0.8,
            crt: 0.4,
            cname: 0.9,
        },
        notes: 'Plataforma de phishing simulation multi-vector.',
    },

    cybeready: {
        displayName: 'CybeReady',
        detectableViaDns: true,
        spfIncludes: [],
        spfIps: [],
        dkimSigningDomains: ['cybeready.com'],
        dkimSelectors: [],
        infraDomains: ['cybeready.com'],
        assetDomains: [],
        relatedGatewaySpf: [],
        mxHint: null,
        dmarcRuaHint: null,
        crtPatterns: ['cybeready.com'],
        txtPatterns: [],
        cnameSubdomains: ['click', 'training'],
        weights: {
            infraDomain: 0.6,
            dkim: 0.8,
            crt: 0.4,
            cname: 0.9,
        },
        notes: 'Awareness autónomo basado en ML.',
    },

    lucyThrivedx: {
        displayName: 'Lucy Security (ThriveDX)',
        detectableViaDns: true,
        spfIncludes: [],
        spfIps: [],
        dkimSigningDomains: [],
        dkimSelectors: [],
        infraDomains: ['lucysecurity.com', 'thrivedx.com'],
        assetDomains: [],
        relatedGatewaySpf: [],
        mxHint: null,
        dmarcRuaHint: null,
        crtPatterns: ['lucysecurity.com'],
        txtPatterns: [],
        cnameSubdomains: ['phish', 'training'],
        weights: {
            infraDomain: 0.6,
            crt: 0.4,
            cname: 0.9,
        },
        notes: 'Self-hosted o cloud; señal DNS variable.',
    },

    phishedIo: {
        displayName: 'Phished.io',
        detectableViaDns: true,
        spfIncludes: [],
        spfIps: [],
        dkimSigningDomains: ['phished.io'],
        dkimSelectors: [],
        infraDomains: ['phished.io'],
        assetDomains: [],
        relatedGatewaySpf: [],
        mxHint: null,
        dmarcRuaHint: null,
        crtPatterns: ['phished.io'],
        txtPatterns: [],
        cnameSubdomains: ['click', 'track'],
        weights: {
            infraDomain: 0.6,
            dkim: 0.8,
            crt: 0.4,
            cname: 0.9,
        },
        notes: 'Plataforma europea de phish sim con AI.',
    },

    sosafe: {
        displayName: 'SoSafe',
        detectableViaDns: true,
        spfIncludes: [],
        spfIps: [],
        dkimSigningDomains: ['sosafe-awareness.com'],
        dkimSelectors: [],
        infraDomains: ['sosafe-awareness.com', 'sosafe.de'],
        assetDomains: [],
        relatedGatewaySpf: [],
        mxHint: null,
        dmarcRuaHint: null,
        crtPatterns: ['sosafe-awareness.com'],
        txtPatterns: [],
        cnameSubdomains: ['click', 'track', 'training'],
        weights: {
            infraDomain: 0.6,
            dkim: 0.8,
            crt: 0.4,
            cname: 0.9,
        },
        notes: 'Líder europeo en awareness con fuerte presencia DACH.',
    },

    metacompliance: {
        displayName: 'MetaCompliance',
        detectableViaDns: true,
        spfIncludes: [],
        spfIps: [],
        dkimSigningDomains: ['metacompliance.com'],
        dkimSelectors: [],
        infraDomains: ['metacompliance.com'],
        assetDomains: [],
        relatedGatewaySpf: [],
        mxHint: null,
        dmarcRuaHint: null,
        crtPatterns: ['metacompliance.com'],
        txtPatterns: [],
        cnameSubdomains: ['phish', 'training'],
        weights: {
            infraDomain: 0.6,
            dkim: 0.8,
            crt: 0.4,
            cname: 0.9,
        },
        notes: 'Plataforma de awareness y compliance; presencia UK/EU.',
    },

    usecure: {
        displayName: 'usecure',
        detectableViaDns: true,
        spfIncludes: [],
        spfIps: [],
        dkimSigningDomains: ['usecure.io'],
        dkimSelectors: [],
        infraDomains: ['usecure.io'],
        assetDomains: [],
        relatedGatewaySpf: [],
        mxHint: null,
        dmarcRuaHint: null,
        crtPatterns: ['usecure.io'],
        txtPatterns: [],
        cnameSubdomains: ['phish', 'training'],
        weights: {
            infraDomain: 0.6,
            dkim: 0.8,
            crt: 0.4,
            cname: 0.9,
        },
        notes: 'MSP-focused awareness platform.',
    },

    riotMantra: {
        displayName: 'Riot / Mantra',
        detectableViaDns: true,
        spfIncludes: [],
        spfIps: [],
        dkimSigningDomains: [],
        dkimSelectors: [],
        infraDomains: ['tryriot.com', 'yourmantra.com'],
        assetDomains: [],
        relatedGatewaySpf: [],
        mxHint: null,
        dmarcRuaHint: null,
        crtPatterns: ['tryriot.com', 'yourmantra.com'],
        txtPatterns: [],
        cnameSubdomains: ['click', 'phish'],
        weights: {
            infraDomain: 0.6,
            crt: 0.4,
            cname: 0.9,
        },
        notes: 'Awareness basado en Slack/Teams + phishing sim.',
    },

    arcticWolfAwareness: {
        displayName: 'Arctic Wolf Managed Security Awareness',
        detectableViaDns: true,
        spfIncludes: [],
        spfIps: [],
        dkimSigningDomains: [],
        dkimSelectors: [],
        infraDomains: ['arcticwolf.com'],
        assetDomains: [],
        relatedGatewaySpf: [],
        mxHint: null,
        dmarcRuaHint: null,
        crtPatterns: ['arcticwolf.com'],
        txtPatterns: [],
        cnameSubdomains: ['training', 'phish'],
        weights: {
            infraDomain: 0.6,
            crt: 0.4,
            cname: 0.9,
        },
        notes: 'Parte de la plataforma MDR de Arctic Wolf.',
    },

    webrootAwareness: {
        displayName: 'Webroot Security Awareness Training',
        detectableViaDns: true,
        spfIncludes: [],
        spfIps: [],
        dkimSigningDomains: [],
        dkimSelectors: [],
        infraDomains: ['webroot.com'],
        assetDomains: [],
        relatedGatewaySpf: [],
        mxHint: null,
        dmarcRuaHint: null,
        crtPatterns: ['webroot.com'],
        txtPatterns: [],
        cnameSubdomains: ['training', 'phish'],
        weights: {
            infraDomain: 0.6,
            crt: 0.4,
            cname: 0.9,
        },
        notes: 'Ahora parte de OpenText; detección DNS limitada.',
    },

    proofpointZenguide: {
        displayName: 'Proofpoint ZenGuide (ex-Living Security)',
        detectableViaDns: true,
        spfIncludes: [],
        spfIps: [],
        dkimSigningDomains: [],
        dkimSelectors: [],
        infraDomains: ['livingsecurity.com'],
        assetDomains: [],
        relatedGatewaySpf: [],
        mxHint: null,
        dmarcRuaHint: null,
        crtPatterns: ['livingsecurity.com'],
        txtPatterns: [],
        cnameSubdomains: ['training', 'click'],
        weights: {
            infraDomain: 0.6,
            crt: 0.4,
            cname: 0.9,
        },
        notes: 'Adquirida por Proofpoint; renombrada a ZenGuide.',
    },

    // -----------------------------------------------------------------------
    // MICROSOFT AST — detección heurística de baja confianza.
    // El tráfico es interno al tenant M365 pero hay señales indirectas.
    // -----------------------------------------------------------------------
    msAttackSimulation: {
        displayName: 'Microsoft Attack Simulation Training (Defender for O365)',
        detectableViaDns: true,                                    // heurístico de baja confianza
        spfIncludes: [],
        spfIps: [],
        dkimSigningDomains: [],
        dkimSelectors: [],
        infraDomains: [],
        assetDomains: [],
        relatedGatewaySpf: [],
        mxHint: 'protection.outlook.com',                          // señal indirecta: usa M365
        dmarcRuaHint: 'dmarc.microsoft.com',                       // señal indirecta: reporting nativo
        crtPatterns: [],
        txtPatterns: [],
        cnameSubdomains: [],
        weights: {
            mxHint: 0.15,          // solo indica que PODRÍAN usar AST
            dmarc: 0.1,            // reporting nativo → más engagement con M365 security
        },
        notes:
            'Detección ESPECULATIVA. El tráfico AST es interno al tenant M365 (envíos vía ' +
            'deliver@simulator.office.com o *.phishingsimulations.microsoft.com). ' +
            'Las señales indirectas solo indican que el dominio usa M365 y podría ' +
            'estar usando AST. Confianza baja por diseño.',
    },
};

// ---------------------------------------------------------------------------
// 2-3. DoH QUERIES — reutiliza la capa DNS unificada de api.js
//      (caché TTL compartida + fallback Google→Cloudflare). Evita duplicar el
//      cliente DoH y aprovecha consultas ya cacheadas por el análisis principal.
// ---------------------------------------------------------------------------
async function _doh(name, type) {
    try {
        return await queryDNS(name, type);
    } catch {
        return { Answer: [] };
    }
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

async function _getCname(domain) {
    try {
        const d = await _doh(domain, 'CNAME');
        return (d.Answer || [])
            .filter(a => a.type === 5)
            .map(a => a.data.trim().replace(/\.$/, '').toLowerCase());
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

// Expande una IPv6 (con "::") a un BigInt de 128 bits.
function _ipv6ToBigInt(ip) {
    const [head, tail] = ip.split('::');
    const h = head ? head.split(':').filter(Boolean) : [];
    const t = tail !== undefined ? (tail ? tail.split(':').filter(Boolean) : []) : [];
    if (tail === undefined && h.length !== 8) return null; // sin "::" debe tener 8 grupos
    const missing = 8 - (h.length + t.length);
    if (missing < 0) return null;
    const groups = [...h, ...Array(ip.includes('::') ? missing : 0).fill('0'), ...t];
    if (groups.length !== 8) return null;
    let acc = 0n;
    for (const g of groups) {
        const n = parseInt(g, 16);
        if (Number.isNaN(n)) return null;
        acc = (acc << 16n) + BigInt(n);
    }
    return acc;
}

function _ipv6InCidr(observed, cidr) {
    const obsIp = observed.split('/')[0];
    if (!obsIp.includes(':')) return false;
    const [base, bitsStr] = cidr.split('/');
    if (!base || !base.includes(':')) return observed === cidr;
    const bits = bitsStr ? parseInt(bitsStr, 10) : 128;
    const obs = _ipv6ToBigInt(obsIp);
    const baseInt = _ipv6ToBigInt(base);
    if (obs === null || baseInt === null) return false;
    if (bits <= 0) return true;
    const mask = (~0n << BigInt(128 - bits)) & ((1n << 128n) - 1n);
    return (obs & mask) === (baseInt & mask);
}

export function _ipInCidr(observed, cidr) {
    if (observed === cidr) return true;
    return observed.includes(':') ? _ipv6InCidr(observed, cidr) : _ipv4InCidr(observed, cidr);
}

// ---------------------------------------------------------------------------
// 6. crt.sh — Certificate Transparency enrichment (con caché y rate-limit)
// ---------------------------------------------------------------------------
const _crtCache = new Map();
const CRT_CACHE_TTL = 60 * 60 * 1000; // 60 min (crt.sh es frágil/rate-limited)

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
    const rootTxts = await _getTxt(domain);

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

    // --- CNAME Probing ---
    const AWARENESS_SUBDOMAINS = [
        'click', 'track', 'phish', 'phishtest', 'training', 'awareness',
        'security-training', 'learn', 'simulate', 'campaign',
        'mail-test', 'phishing-test', 'sat', 'cb', 'knowbe4'
    ];
    const cnameResults = {};
    await Promise.all(AWARENESS_SUBDOMAINS.map(async sub => {
        const targets = await _getCname(`${sub}.${domain}`);
        if (targets.length > 0) {
            cnameResults[sub] = targets;
        }
    }));

    // --- Generic DKIM selectors probing ---
    const GENERIC_AWARENESS_SELECTORS = ['s1', 's2', 'k1', 'k2', 'mail', 'default', 'phish', 'sim', 'training'];
    const genericDkimResults = {};
    await Promise.all(GENERIC_AWARENESS_SELECTORS.map(async sel => {
        const txts = await _getTxt(`${sel}._domainkey.${domain}`);
        if (txts.length > 0) {
            genericDkimResults[sel] = txts;
        }
    }));

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

        // 7b. SPF IPs / CIDRs (IPv4 e IPv6)
        for (const vip of (fp.spfIps || [])) {
            if (spf.ips.some(obs => _ipInCidr(obs, vip))) {
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

        // 7e. MX hint — el peso lo define CADA fingerprint en w.mxHint, que codifica
        // cuánto significa su gateway/MX para ESE vendor: p. ej. el MX de Proofpoint
        // (pphosted, 0.3) o Mimecast (0.3) — gateways de seguridad reales que suelen
        // venderse o complementarse con concienciación — pesan más que el simple
        // "usa M365" de Microsoft AST (0.15). El peso es el mismo tanto si el hint
        // coincide como sufijo exacto (p. ej. "protection.outlook.com") como por
        // substring (p. ej. el token "pphosted"); ambos son igual de fiables, solo
        // difiere cómo se escribió el hint. w.mxExact / w.mxSubstring permiten override.
        if (fp.mxHint) {
            const mxBase = w.mxHint ?? 0.3;
            let mxMatched = false;
            for (const m of mxHosts) {
                if (m === fp.mxHint || m.endsWith('.' + fp.mxHint)) {
                    evidence.push({ signal: 'mx_hint_exact', value: m, weight: w.mxExact ?? mxBase });
                    mxMatched = true;
                    break;
                }
            }
            if (!mxMatched) {
                for (const m of mxHosts) {
                    if (m.includes(fp.mxHint)) {
                        evidence.push({ signal: 'mx_hint_substring', value: m, weight: w.mxSubstring ?? mxBase });
                        break;
                    }
                }
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

        // 7i. CNAME Probe
        for (const sub of (fp.cnameSubdomains || [])) {
            const targets = cnameResults[sub];
            if (targets) {
                for (const target of targets) {
                    const matchesInfra = (fp.infraDomains || []).some(id => target.includes(id));
                    const matchesDkimSig = (fp.dkimSigningDomains || []).some(dsd => target.includes(dsd));
                    if (matchesInfra || matchesDkimSig) {
                        evidence.push({
                            signal: 'cname_probe',
                            value: `${sub} -> ${target}`,
                            weight: w.cname ?? 0.95
                        });
                        break;
                    }
                }
            }
        }

        // 7j. Generic DKIM Selectors Probe
        const GENERIC_AWARENESS_SELECTORS = ['s1', 's2', 'k1', 'k2', 'mail', 'default', 'phish', 'sim', 'training'];
        for (const sel of GENERIC_AWARENESS_SELECTORS) {
            const txts = genericDkimResults[sel];
            if (txts) {
                for (const txt of txts) {
                    const matchesDkimSig = (fp.dkimSigningDomains || []).some(dsd => txt.toLowerCase().includes(dsd.toLowerCase()));
                    const matchesInfra = (fp.infraDomains || []).some(id => txt.toLowerCase().includes(id.toLowerCase()));
                    if (matchesDkimSig || matchesInfra) {
                        evidence.push({
                            signal: 'generic_dkim_probe',
                            value: `${sel}._domainkey -> ${txt}`,
                            weight: w.dkimGeneric ?? 0.8
                        });
                        break;
                    }
                }
            }
        }

        // 7k. Cross-correlation with SEG/ICES
        let correlatedSeg = false;
        if (key === 'proofpointSat') {
            correlatedSeg = mxHosts.some(m => m.includes('pphosted.com')) || spf.includes.some(s => s.includes('proofpoint.com'));
        } else if (key === 'barracudaAwareness') {
            correlatedSeg = mxHosts.some(m => m.includes('barracuda')) || spf.includes.some(s => s.includes('barracuda'));
        } else if (key === 'mimecastAwareness') {
            correlatedSeg = mxHosts.some(m => m.includes('mimecast')) || spf.includes.some(s => s.includes('mimecast'));
        } else if (key === 'sophosPhishThreat') {
            correlatedSeg = mxHosts.some(m => m.includes('sophos')) || spf.includes.some(s => s.includes('sophos'));
        }

        if (correlatedSeg) {
            evidence.push({
                signal: 'correlated_seg',
                value: `Co-located with ${fp.displayName} SEG/ICES infrastructure`,
                weight: w.correlatedSeg ?? 0.3
            });
        }

        // 7l. TXT Verification Tokens
        for (const pat of (fp.txtPatterns || [])) {
            if (rootTxts.some(t => t.toLowerCase().includes(pat.toLowerCase()))) {
                evidence.push({ signal: 'txt_verify', value: pat, weight: w.txtVerify ?? 0.85 });
            }
        }

        // crt.sh nunca debe ser señal ÚNICA (alto riesgo de falso positivo):
        // requiere al menos una evidencia que no provenga de Certificate Transparency.
        const nonCrtEvidence = evidence.filter(e => e.signal !== 'cert_transparency');
        if (evidence.length > 0 && nonCrtEvidence.length > 0) {
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
