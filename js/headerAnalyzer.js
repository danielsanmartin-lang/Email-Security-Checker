/**
 * headerAnalyzer.js
 * Detección de plataformas de Awareness / Phishing Simulation a partir de las
 * CABECERAS de un correo (pegadas por el usuario). Complementa al detector DNS:
 * muchas plataformas —incluido Microsoft Attack Simulation Training, que es el punto
 * ciego del análisis DNS— dejan rastro inequívoco en Return-Path, From, Received y en
 * X-headers propietarias. Es la señal de mayor confianza porque procede del envío real.
 *
 * 100% local: trabaja sobre el texto pegado, sin consultas de red.
 *
 * Exporta:
 *   parseHeaders(raw)         → Map<string, string[]>  (nombre en minúsculas → valores, des-plegados)
 *   detectFromHeaders(raw)    → { detectedVendors, headerCount, error? }
 *   HEADER_FINGERPRINTS       (diccionario, recargable vía mergeHeaderFingerprints)
 *   mergeHeaderFingerprints(obj)
 */

// ---------------------------------------------------------------------------
// Diccionario de firmas por cabecera.
//   headerPatterns: [{ header, contains, weight? }]
//       - el VALOR de esa cabecera contiene `contains` (case-insensitive)
//       - `contains` vacío/ausente ⇒ basta con que la cabecera EXISTA (X-headers propietarias)
//   textPatterns: [string]  → el patrón aparece en cualquier parte del bloque de cabeceras
//   weight: confianza por defecto (las cabeceras son señal directa → alta)
// ---------------------------------------------------------------------------
export const HEADER_FINGERPRINTS = {
    msAttackSimulation: {
        displayName: 'Microsoft Attack Simulation Training (Defender for O365)',
        weight: 0.95,
        headerPatterns: [
            { header: 'return-path', contains: 'simulator.office.com' },
            { header: 'from', contains: 'simulator.office.com' },
        ],
        textPatterns: ['simulator.office.com', 'phishingsimulations.microsoft.com'],
        note: 'Rastro del envío de simulación AST (interno al tenant M365). No detectable por DNS.',
    },
    knowbe4: {
        displayName: 'KnowBe4 (KSAT)',
        weight: 0.9,
        headerPatterns: [
            { header: 'x-phishtest', contains: '' },     // X-header propietaria de KnowBe4
            { header: 'x-mailer', contains: 'knowbe4' },
        ],
        textPatterns: ['knowbe4.com', 'psm.knowbe4.com', 'kb4.io'],
    },
    cofensePhishme: {
        displayName: 'Cofense PhishMe',
        weight: 0.9,
        headerPatterns: [
            { header: 'x-phishme', contains: '' },
            { header: 'x-cofense', contains: '' },
        ],
        textPatterns: ['cofense.com', 'phishme.com'],
    },
    gophish: {
        displayName: 'Gophish (open-source / red team)',
        weight: 0.92,
        headerPatterns: [
            { header: 'x-gophish-contact', contains: '' },   // únicas de Gophish
            { header: 'x-gophish-signature', contains: '' },
        ],
        textPatterns: [],
        note: 'Framework open-source habitual en ejercicios de red team / pentest.',
    },
    proofpointSat: {
        displayName: 'Proofpoint Security Awareness (ex-Wombat)',
        weight: 0.85,
        headerPatterns: [
            { header: 'x-mailer', contains: 'wombat' },
        ],
        textPatterns: ['securityeducation.com', 'ws01-securityeducation.com'],
    },
    hoxhunt: {
        displayName: 'Hoxhunt',
        weight: 0.9,
        headerPatterns: [],
        textPatterns: ['hoxhunt.com'],
    },
    barracudaAwareness: {
        displayName: 'Barracuda / PhishLine',
        weight: 0.85,
        headerPatterns: [],
        textPatterns: ['phishline.com'],
    },
    sophosPhishThreat: {
        displayName: 'Sophos Phish Threat',
        weight: 0.75,
        headerPatterns: [],
        textPatterns: ['phishthreat', 'sophosmail.com'],
    },
};

/**
 * Parsea un bloque de cabeceras de correo (RFC 5322), des-plegando líneas
 * continuadas (folding: líneas que empiezan por espacio/tab pertenecen a la anterior).
 * Se detiene en la primera línea en blanco (separador cabeceras/cuerpo), si la hay.
 * @param {string} raw
 * @returns {Map<string, string[]>} nombre en minúsculas → array de valores
 */
export function parseHeaders(raw) {
    const map = new Map();
    if (!raw) return map;
    const lines = String(raw).replace(/\r\n/g, '\n').split('\n');
    const unfolded = [];
    for (const line of lines) {
        if (/^[ \t]/.test(line) && unfolded.length) {
            // continuación de la cabecera anterior
            unfolded[unfolded.length - 1] += ' ' + line.trim();
        } else if (line.trim() === '') {
            if (unfolded.length) break; // fin de cabeceras
            // líneas en blanco iniciales: ignorar
        } else {
            unfolded.push(line);
        }
    }
    for (const h of unfolded) {
        const idx = h.indexOf(':');
        if (idx <= 0) continue;
        const name = h.slice(0, idx).trim().toLowerCase();
        const value = h.slice(idx + 1).trim();
        if (!map.has(name)) map.set(name, []);
        map.get(name).push(value);
    }
    return map;
}

/**
 * Detecta vendors de awareness a partir de cabeceras pegadas.
 * @param {string} raw
 * @returns {{ detectedVendors: Array, headerCount: number, error?: string }}
 */
export function detectFromHeaders(raw) {
    if (!raw || !String(raw).trim()) {
        return { detectedVendors: [], headerCount: 0, error: 'empty' };
    }
    const headers = parseHeaders(raw);
    if (headers.size === 0) {
        return { detectedVendors: [], headerCount: 0, error: 'no_headers' };
    }
    const lowerRaw = String(raw).toLowerCase();
    const detected = [];

    for (const [key, fp] of Object.entries(HEADER_FINGERPRINTS)) {
        const evidence = [];

        for (const hp of (fp.headerPatterns || [])) {
            const vals = headers.get(hp.header.toLowerCase()) || [];
            for (const v of vals) {
                if (!hp.contains || v.toLowerCase().includes(hp.contains.toLowerCase())) {
                    evidence.push({
                        signal: hp.contains ? 'header_value' : 'header_present',
                        value: hp.contains ? `${hp.header}: …${hp.contains}…` : hp.header,
                        weight: hp.weight ?? fp.weight ?? 0.9,
                    });
                    break;
                }
            }
        }

        for (const tp of (fp.textPatterns || [])) {
            if (lowerRaw.includes(tp.toLowerCase())) {
                evidence.push({ signal: 'sender_domain', value: tp, weight: fp.weight ?? 0.9 });
            }
        }

        if (evidence.length) {
            const score = 1 - evidence.reduce((acc, e) => acc * (1 - e.weight), 1);
            const rounded = Math.round(score * 100) / 100;
            detected.push({
                vendor: key,
                displayName: fp.displayName,
                score: rounded,
                level: rounded >= 0.75 ? 'alta' : rounded >= 0.45 ? 'media' : 'baja',
                evidence,
                source: 'headers',
                productConfirmed: true, // el correo de simulación procede realmente del vendor
                notes: fp.note || null,
            });
        }
    }

    detected.sort((a, b) => b.score - a.score);
    return { detectedVendors: detected, headerCount: headers.size };
}

/** Reload en caliente del diccionario de cabeceras (fusiona/añade vendors). */
export function mergeHeaderFingerprints(externalFPs) {
    if (!externalFPs || typeof externalFPs !== 'object') return;
    for (const [key, fp] of Object.entries(externalFPs)) {
        if (HEADER_FINGERPRINTS[key]) {
            Object.assign(HEADER_FINGERPRINTS[key], fp);
        } else {
            HEADER_FINGERPRINTS[key] = fp;
        }
    }
}
