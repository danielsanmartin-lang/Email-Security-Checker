import { describe, it, expect } from 'vitest';
import { extractRootDomain, calculateScoreAndFindings, collectSpfDomains, detectSecurityLayers } from './analyzer.js';

describe('collectSpfDomains', () => {
    it('aplana includes/redirects de todo el árbol SPF', () => {
        const tree = {
            domain: 'x.com', lookups: 2, children: [
                { type: 'include', target: 'a.com', tree: { domain: 'a.com', children: [
                    { type: 'include', target: 'nested.mimecast.com', tree: { domain: 'nested.mimecast.com', children: [] } }
                ] } },
                { type: 'a', target: '(self)' }
            ]
        };
        const domains = collectSpfDomains(tree);
        expect(domains).toContain('a.com');
        expect(domains).toContain('nested.mimecast.com');
        expect(domains).not.toContain('(self)');
    });
    it('devuelve [] para árbol nulo', () => {
        expect(collectSpfDomains(null)).toEqual([]);
    });
});

describe('detectSecurityLayers (multi-señal ponderado)', () => {
    it('detecta SEG por MX con confianza alta', () => {
        const { segList } = detectSecurityLayers({
            domain: 'acme.com',
            mxRecords: [{ priority: 10, host: 'acme-com.mail.protection.outlook.com' }, { priority: 5, host: 'mx.mimecast.com' }]
        });
        const mimecast = segList.find(s => s.name === 'Mimecast');
        expect(mimecast).toBeTruthy();
        expect(mimecast.level).toBe('alta');
        expect(mimecast.evidence.some(e => e.signal === 'mx')).toBe(true);
    });

    it('combina señales (MX+TXT) elevando la confianza vía noisy-OR', () => {
        const { segList } = detectSecurityLayers({
            domain: 'acme.com',
            mxRecords: [{ priority: 5, host: 'mx.mimecast.com' }],
            txtVerifications: [{ name: 'Mimecast', category: 'seg', record: 'mimecast-verification=abc' }]
        });
        const mimecast = segList.find(s => s.name === 'Mimecast');
        expect(mimecast.evidence.length).toBe(2);
        expect(mimecast.score).toBeGreaterThan(0.9);
    });

    it('detecta SEG en include SPF anidado', () => {
        const tree = { domain: 'acme.com', children: [
            { type: 'include', target: 'relay.example.com', tree: { domain: 'relay.example.com', children: [
                { type: 'include', target: '_spf.mimecast.com', tree: { domain: '_spf.mimecast.com', children: [] } }
            ] } }
        ] };
        const { segList } = detectSecurityLayers({
            domain: 'acme.com',
            spfEntries: [{ type: 'include', value: 'relay.example.com' }],
            spfNestedDomains: collectSpfDomains(tree)
        });
        expect(segList.some(s => s.name === 'Mimecast' && s.evidence.some(e => e.signal === 'spf_nested'))).toBe(true);
    });

    it('detecta ICES por selector DKIM aunque el MX sea del proveedor', () => {
        const { icesList } = detectSecurityLayers({
            domain: 'acme.com',
            mxRecords: [{ priority: 10, host: 'acme-com.mail.protection.outlook.com' }],
            dkimSelectors: ['selector1', 'abnormal']
        });
        expect(icesList.some(i => i.name === 'Abnormal Security')).toBe(true);
    });

    it('usa la lista mx de MTA-STS como señal', () => {
        const { segList } = detectSecurityLayers({
            domain: 'acme.com',
            mtaStsMx: ['mx.mimecast.com', '*.protection.outlook.com']
        });
        expect(segList.some(s => s.name === 'Mimecast' && s.evidence.some(e => e.signal === 'mta_sts'))).toBe(true);
    });
});

describe('extractRootDomain', () => {
    it('extrae el dominio raíz de un host simple', () => {
        expect(extractRootDomain('mail.example.com')).toBe('example.com');
        expect(extractRootDomain('example.com')).toBe('example.com');
    });

    it('maneja TLDs compuestos conocidos', () => {
        expect(extractRootDomain('mx1.company.co.uk')).toBe('company.co.uk');
        expect(extractRootDomain('foo.bar.com.au')).toBe('bar.com.au');
        expect(extractRootDomain('a.b.info.tr')).toBe('b.info.tr');
    });

    it('extrae 2 labels cuando el SLD es largo (TLD de 2 chars)', () => {
        expect(extractRootDomain('mail.example.io')).toBe('example.io');
    });

    it('aplica la heurística (3 labels) para TLD 2-char + SLD corto', () => {
        // tld 'io' (2 chars) + sld 'abc' (<=3 chars) → se trata como compuesto
        expect(extractRootDomain('host.abc.io')).toBe('host.abc.io');
    });

    it('devuelve cadena vacía para entrada vacía', () => {
        expect(extractRootDomain('')).toBe('');
    });
});

describe('calculateScoreAndFindings', () => {
    const baseResult = (overrides = {}) => ({
        spfRaw: 'v=spf1 -all',
        spfData: { multiple: false },
        spfEntries: [{ type: 'all', qualifier: '-' }],
        spfLookups: 3,
        dmarcRaw: 'v=DMARC1; p=reject; rua=mailto:a@b.com',
        dmarcData: { multiple: false },
        dmarcParsed: { v: 'DMARC1', p: 'reject', rua: 'mailto:a@b.com' },
        dmarcPolicy: 'reject',
        dmarcRua: ['mailto:a@b.com'],
        dmarcRuf: [],
        dkimRecords: { records: [{ selector: 'google' }] },
        bimiRecord: { record: 'v=BIMI1; l=https://x/logo.svg' },
        mtaSts: { policy: { valid: true } },
        tlsRpt: { record: 'v=TLSRPTv1' },
        daneRecords: { 'mx.example.com': ['data'] },
        srvRecords: {},
        segList: [{ name: 'Proofpoint' }],
        icesList: [],
        ...overrides
    });

    it('acota la puntuación a un máximo de 100', () => {
        const { score } = calculateScoreAndFindings(baseResult());
        expect(score).toBeLessThanOrEqual(100);
        expect(score).toBeGreaterThanOrEqual(0);
    });

    it('nunca devuelve un score negativo aunque haya muchos fallos', () => {
        const { score } = calculateScoreAndFindings({
            spfRaw: 'v=spf1 +all',
            spfData: { multiple: true },
            spfEntries: [{ type: 'all', qualifier: '+' }],
            spfLookups: 25,
            dmarcRaw: 'v=DMARC1; p=invalid',
            dmarcData: { multiple: true },
            dmarcParsed: { v: 'BAD', p: 'invalid' },
            dmarcPolicy: 'none',
            dmarcRua: [],
            dmarcRuf: [],
            dkimRecords: { records: [] },
            bimiRecord: null,
            mtaSts: { policy: { valid: false } },
            tlsRpt: null,
            daneRecords: {},
            srvRecords: {},
            segList: [],
            icesList: []
        });
        expect(score).toBeGreaterThanOrEqual(0);
    });

    it('asigna grado alto y postura fuerte a una config completa', () => {
        const card = calculateScoreAndFindings(baseResult());
        expect(['A+', 'A', 'B']).toContain(card.grade);
        expect(card.posture.key).toBe('strong');
    });

    it('marca postura débil sin SPF ni DMARC', () => {
        const card = calculateScoreAndFindings(baseResult({
            spfRaw: null,
            spfEntries: [],
            dmarcRaw: null,
            dmarcParsed: null,
            dmarcPolicy: 'none',
            segList: [],
            icesList: []
        }));
        expect(card.posture.key).toBe('weak');
    });

    it('detecta múltiples SPF como error', () => {
        const card = calculateScoreAndFindings(baseResult({ spfData: { multiple: true } }));
        expect(card.findings.some(f => f.key === 'finding_spf_multiple')).toBe(true);
    });
});
