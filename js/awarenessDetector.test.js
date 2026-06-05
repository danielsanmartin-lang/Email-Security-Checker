/**
 * awarenessDetector.test.js
 * Tests unitarios para el motor de detección de Security Awareness vendors.
 *
 * Framework: Vitest (ESM-compatible)
 * Para ejecutar: npx vitest run js/awarenessDetector.test.js
 *
 * NOTA: Las pruebas mockean la resolución DNS para no necesitar red.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
    flattenSpf,
    detectAwarenessVendors,
    AWARENESS_FINGERPRINTS,
    mergeFingerprints,
} from './awarenessDetector.js';

// ---------------------------------------------------------------------------
// FIXTURES — registros DNS de ejemplo por vendor
// Formato: { domain → { TXT: [...], MX: [...] } }
// ---------------------------------------------------------------------------
const DNS_FIXTURES = {
    // KnowBe4: include SPF, IP CIDR, puerta de enlace Defend
    'spf.knowbe4.com': {
        TXT: ['v=spf1 ip4:23.21.109.197 ip4:23.21.109.212 ip4:147.160.167.0/26 ~all'],
    },
    'knowbe4domain.com': {
        TXT: ['v=spf1 include:_spf.psm.knowbe4.com ~all'],
        MX: ['10 mx1.knowbe4domain.com'],
    },
    '_spf.psm.knowbe4.com': {
        TXT: ['v=spf1 ip4:23.21.109.197 ip4:23.21.109.212 ip4:147.160.167.0/26 ~all'],
    },
    '_dmarc.knowbe4domain.com': { TXT: ['v=DMARC1; p=none;'] },

    // Proofpoint SAT: MX hint, infra domain en SPF
    'proofpointdomain.com': {
        TXT: ['v=spf1 include:securityeducation.com ~all'],
        MX: ['10 mail.pphosted.com', '20 mx2.pphosted.com'],
    },
    'securityeducation.com': {
        TXT: ['v=spf1 ip4:198.0.0.0/8 ~all'],
    },
    '_dmarc.proofpointdomain.com': { TXT: ['v=DMARC1; p=quarantine; rua=mailto:dmarc@agari.com'] },

    // Cofense: infra domain en SPF
    'cofensedomain.com': {
        TXT: ['v=spf1 include:cofense.com ~all'],
        MX: ['10 mx.cofensedomain.com'],
    },
    'cofense.com': {
        TXT: ['v=spf1 ip4:10.0.0.0/8 ~all'],
    },
    '_dmarc.cofensedomain.com': { TXT: ['v=DMARC1; p=none;'] },

    // Mimecast Awareness: MX hint
    'mimecastdomain.com': {
        TXT: ['v=spf1 include:_spf.mimecast.com ~all'],
        MX: ['10 eu-smtp-inbound-1.mimecast.com', '20 eu-smtp-inbound-2.mimecast.com'],
    },
    '_spf.mimecast.com': {
        TXT: ['v=spf1 ip4:207.211.30.0/24 ~all'],
    },
    '_dmarc.mimecastdomain.com': { TXT: ['v=DMARC1; p=reject;'] },

    // Hoxhunt: SPF include + DKIM selector
    'hoxhuntdomain.com': {
        TXT: ['v=spf1 include:_spf.hoxhunt.com ~all'],
        MX: ['10 mx.hoxhuntdomain.com'],
    },
    '_spf.hoxhunt.com': {
        TXT: ['v=spf1 ip4:35.220.0.0/14 ~all'],
    },
    'hoxhunt._domainkey.hoxhuntdomain.com': {
        TXT: ['v=DKIM1; k=rsa; p=MIIBIjAN...hoxhunt.com'],
    },
    '_dmarc.hoxhuntdomain.com': { TXT: ['v=DMARC1; p=none;'] },

    // Barracuda/PhishLine
    'barracudadomain.com': {
        TXT: ['v=spf1 include:_spf.phishline.com ~all'],
        MX: ['10 mx.barracudanetworks.com'],
    },
    '_spf.phishline.com': {
        TXT: ['v=spf1 ip4:64.235.144.0/20 ~all'],
    },
    '_dmarc.barracudadomain.com': { TXT: ['v=DMARC1; p=none;'] },

    // Clean domain — sin evidencia
    'cleandomain.com': {
        TXT: ['v=spf1 include:spf.protection.outlook.com -all'],
        MX: ['10 cleandomain-com.mail.protection.outlook.com'],
    },
    'spf.protection.outlook.com': {
        TXT: ['v=spf1 ip4:40.92.0.0/15 ip4:40.107.0.0/16 ~all'],
    },
    '_dmarc.cleandomain.com': { TXT: ['v=DMARC1; p=reject; rua=mailto:rua@dmarc.microsoft.com'] },

    // SPF PermError — >10 lookups
    'permerrordomain.com': {
        TXT: ['v=spf1 include:a.com include:b.com include:c.com include:d.com include:e.com include:f.com include:g.com include:h.com include:i.com include:j.com include:k.com ~all'],
        MX: [],
    },
    ...Object.fromEntries(
        ['a','b','c','d','e','f','g','h','i','j','k'].map(l => [
            `${l}.com`, { TXT: [`v=spf1 ip4:1.2.3.${l.charCodeAt(0)} ~all`] }
        ])
    ),
};

// ---------------------------------------------------------------------------
// MOCK global fetch para interceptar DoH y crt.sh
// ---------------------------------------------------------------------------
function makeDohResponse(records) {
    if (!records || records.length === 0) return { Status: 3, Answer: [] }; // NXDOMAIN
    return {
        Status: 0,
        Answer: records.map(r => {
            const isMx = r.includes(' ') && /^\d+\s/.test(r);
            return {
                type: isMx ? 15 : 16,
                data: isMx ? r : `"${r}"`,
            };
        }),
    };
}

function buildFetchMock(fixtures) {
    return vi.fn(async (url) => {
        const urlStr = String(url);

        // crt.sh → siempre vacío en tests unitarios
        if (urlStr.includes('crt.sh')) {
            return { ok: true, json: async () => [] };
        }

        // DoH query
        const nameMatch = urlStr.match(/[?&]name=([^&]+)/);
        const typeMatch = urlStr.match(/[?&]type=([^&]+)/);
        if (!nameMatch || !typeMatch) return { ok: false, status: 400 };

        const name = decodeURIComponent(nameMatch[1]).toLowerCase();
        const type = decodeURIComponent(typeMatch[1]).toUpperCase();

        const fixture = fixtures[name];
        let records = [];
        if (fixture) {
            if (type === 'TXT') records = fixture.TXT || [];
            if (type === 'MX')  records = fixture.MX  || [];
        }

        const body = makeDohResponse(records);
        return {
            ok: true,
            status: 200,
            json: async () => body,
        };
    });
}

// ---------------------------------------------------------------------------
// TESTS
// ---------------------------------------------------------------------------
describe('AWARENESS_FINGERPRINTS dictionary', () => {
    it('debe tener entradas con detectableViaDns', () => {
        const detectable = Object.values(AWARENESS_FINGERPRINTS).filter(f => f.detectableViaDns);
        expect(detectable.length).toBeGreaterThan(0);
    });

    it('Microsoft Attack Simulation debe estar marcado como no detectable', () => {
        expect(AWARENESS_FINGERPRINTS.msAttackSimulation.detectableViaDns).toBe(false);
        expect(AWARENESS_FINGERPRINTS.msAttackSimulation.notes).toBeTruthy();
    });

    it('KnowBe4 debe tener spfIncludes y spfIps definidos', () => {
        const kb4 = AWARENESS_FINGERPRINTS.knowbe4;
        expect(kb4.spfIncludes.length).toBeGreaterThan(0);
        expect(kb4.spfIps.length).toBeGreaterThan(0);
    });

    it('todos los vendors detectables deben tener weights', () => {
        for (const [key, fp] of Object.entries(AWARENESS_FINGERPRINTS)) {
            if (!fp.detectableViaDns) continue;
            expect(fp.weights, `${key} should have weights`).toBeTruthy();
        }
    });
});

describe('flattenSpf', () => {
    beforeEach(() => {
        global.fetch = buildFetchMock(DNS_FIXTURES);
    });
    afterEach(() => { vi.restoreAllMocks(); });

    it('debe aplanar un SPF con un include simple', async () => {
        const result = await flattenSpf('knowbe4domain.com');
        expect(result.includes).toContain('_spf.psm.knowbe4.com');
        expect(result.permError).toBe(false);
    });

    it('debe extraer IPs del include resuelto', async () => {
        const result = await flattenSpf('knowbe4domain.com');
        expect(result.ips.some(ip => ip.startsWith('23.21.109'))).toBe(true);
    });

    it('debe detectar PermError cuando hay >10 lookups', async () => {
        const result = await flattenSpf('permerrordomain.com');
        expect(result.permError).toBe(true);
    });

    it('debe manejar dominio sin SPF (devuelve vacío sin error)', async () => {
        global.fetch = buildFetchMock({ 'nodomain.com': { TXT: [], MX: [] } });
        const result = await flattenSpf('nodomain.com');
        expect(result.includes).toHaveLength(0);
        expect(result.permError).toBe(false);
    });

    it('no debe entrar en loop con referencias circulares', async () => {
        global.fetch = buildFetchMock({
            'loop-a.com': { TXT: ['v=spf1 include:loop-b.com ~all'] },
            'loop-b.com': { TXT: ['v=spf1 include:loop-a.com ~all'] },
        });
        // No debe lanzar excepción ni colgarse
        const result = await flattenSpf('loop-a.com');
        expect(result).toBeDefined();
    });
});

describe('detectAwarenessVendors — KnowBe4', () => {
    beforeEach(() => { global.fetch = buildFetchMock(DNS_FIXTURES); });
    afterEach(() => { vi.restoreAllMocks(); });

    it('debe detectar KnowBe4 por SPF include', async () => {
        const result = await detectAwarenessVendors('knowbe4domain.com');
        expect(result.domain).toBe('knowbe4domain.com');
        const kb4 = result.detectedVendors.find(v => v.vendor === 'knowbe4');
        expect(kb4).toBeDefined();
        expect(kb4.score).toBeGreaterThan(0.5);
        expect(['alta', 'media', 'baja']).toContain(kb4.level);
        expect(kb4.evidence.some(e => e.signal === 'spf_include')).toBe(true);
    });

    it('debe tener score >= 0.85 con include SPF fuerte', async () => {
        const result = await detectAwarenessVendors('knowbe4domain.com');
        const kb4 = result.detectedVendors.find(v => v.vendor === 'knowbe4');
        expect(kb4.score).toBeGreaterThanOrEqual(0.85);
    });
});

describe('detectAwarenessVendors — Proofpoint SAT', () => {
    beforeEach(() => { global.fetch = buildFetchMock(DNS_FIXTURES); });
    afterEach(() => { vi.restoreAllMocks(); });

    it('debe detectar Proofpoint SAT por infra domain + MX', async () => {
        const result = await detectAwarenessVendors('proofpointdomain.com');
        const pp = result.detectedVendors.find(v => v.vendor === 'proofpointSat');
        expect(pp).toBeDefined();
        expect(pp.evidence.some(e => e.signal.includes('infra') || e.signal.includes('mx'))).toBe(true);
    });
});

describe('detectAwarenessVendors — Cofense', () => {
    beforeEach(() => { global.fetch = buildFetchMock(DNS_FIXTURES); });
    afterEach(() => { vi.restoreAllMocks(); });

    it('debe detectar Cofense por infra domain en SPF', async () => {
        const result = await detectAwarenessVendors('cofensedomain.com');
        const cf = result.detectedVendors.find(v => v.vendor === 'cofensePhishme');
        expect(cf).toBeDefined();
    });
});

describe('detectAwarenessVendors — Mimecast Awareness', () => {
    beforeEach(() => { global.fetch = buildFetchMock(DNS_FIXTURES); });
    afterEach(() => { vi.restoreAllMocks(); });

    it('debe detectar Mimecast por MX hint', async () => {
        const result = await detectAwarenessVendors('mimecastdomain.com');
        const mm = result.detectedVendors.find(v => v.vendor === 'mimecastAwareness');
        expect(mm).toBeDefined();
        expect(mm.evidence.some(e => e.signal === 'mx_hint')).toBe(true);
    });
});

describe('detectAwarenessVendors — Hoxhunt', () => {
    beforeEach(() => { global.fetch = buildFetchMock(DNS_FIXTURES); });
    afterEach(() => { vi.restoreAllMocks(); });

    it('debe detectar Hoxhunt por SPF include y DKIM', async () => {
        const result = await detectAwarenessVendors('hoxhuntdomain.com');
        const hh = result.detectedVendors.find(v => v.vendor === 'hoxhunt');
        expect(hh).toBeDefined();
        expect(hh.score).toBeGreaterThan(0.7);
    });
});

describe('detectAwarenessVendors — dominio limpio', () => {
    beforeEach(() => { global.fetch = buildFetchMock(DNS_FIXTURES); });
    afterEach(() => { vi.restoreAllMocks(); });

    it('no debe detectar vendors en un dominio sin evidencia', async () => {
        const result = await detectAwarenessVendors('cleandomain.com');
        expect(result.detectedVendors).toHaveLength(0);
    });

    it('debe incluir la nota del punto ciego de Microsoft en notes', async () => {
        const result = await detectAwarenessVendors('cleandomain.com');
        expect(result.notes.some(n => n.includes('Microsoft'))).toBe(true);
    });
});

describe('detectAwarenessVendors — SPF PermError', () => {
    beforeEach(() => { global.fetch = buildFetchMock(DNS_FIXTURES); });
    afterEach(() => { vi.restoreAllMocks(); });

    it('debe reportar spfPermError true cuando SPF supera los 10 lookups', async () => {
        const result = await detectAwarenessVendors('permerrordomain.com');
        expect(result.spfPermError).toBe(true);
    });
});

describe('scoring — producto de probabilidades independientes', () => {
    it('combinación de señales no debe superar 1', () => {
        const evidence = [
            { signal: 'spf_include', weight: 0.9 },
            { signal: 'spf_ip',      weight: 0.85 },
            { signal: 'dkim',        weight: 0.85 },
        ];
        const score = 1 - evidence.reduce((acc, e) => acc * (1 - e.weight), 1);
        expect(score).toBeLessThanOrEqual(1);
        expect(score).toBeGreaterThan(0.9); // tres señales fuertes → score muy alto
    });

    it('una señal sola de 0.6 produce score de 0.6 exactamente', () => {
        const evidence = [{ weight: 0.6 }];
        const score = 1 - evidence.reduce((acc, e) => acc * (1 - e.weight), 1);
        expect(score).toBeCloseTo(0.6);
    });
});

describe('mergeFingerprints — recarga en caliente', () => {
    it('debe poder añadir un vendor nuevo al diccionario', () => {
        mergeFingerprints({
            testVendorNew: {
                displayName: 'Vendor de Test',
                detectableViaDns: true,
                spfIncludes: ['_spf.testvendor.example'],
                spfIps: [],
                dkimSelectors: [],
                infraDomains: ['testvendor.example'],
                relatedGatewaySpf: [],
                mxHint: null,
                crtPatterns: [],
                weights: { spfInclude: 0.9, infraDomain: 0.5 },
            },
        });
        expect(AWARENESS_FINGERPRINTS.testVendorNew).toBeDefined();
        expect(AWARENESS_FINGERPRINTS.testVendorNew.displayName).toBe('Vendor de Test');
    });

    it('debe poder actualizar campos de un vendor existente', () => {
        const originalNotes = AWARENESS_FINGERPRINTS.knowbe4.notes;
        mergeFingerprints({
            knowbe4: { notes: 'Nota actualizada en caliente.' },
        });
        expect(AWARENESS_FINGERPRINTS.knowbe4.notes).toBe('Nota actualizada en caliente.');
        // Restaurar
        mergeFingerprints({ knowbe4: { notes: originalNotes } });
    });
});

describe('CIDR matching — helper ipv4InCidr', () => {
    // Probar indirectamente mediante detección con IP dentro del CIDR de KnowBe4
    beforeEach(() => {
        // Dominio con SPF que contiene una IP dentro del rango 147.160.167.0/26
        global.fetch = buildFetchMock({
            'cidrtest.com': {
                TXT: ['v=spf1 ip4:147.160.167.32 ~all'], // dentro de /26 de KnowBe4
                MX: [],
            },
            '_dmarc.cidrtest.com': { TXT: [] },
        });
    });
    afterEach(() => { vi.restoreAllMocks(); });

    it('debe detectar KnowBe4 cuando la IP está dentro de su CIDR', async () => {
        const result = await detectAwarenessVendors('cidrtest.com');
        const kb4 = result.detectedVendors.find(v => v.vendor === 'knowbe4');
        expect(kb4).toBeDefined();
        expect(kb4.evidence.some(e => e.signal === 'spf_ip')).toBe(true);
    });
});
