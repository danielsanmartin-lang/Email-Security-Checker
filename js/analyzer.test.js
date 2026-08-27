import { describe, it, expect } from 'vitest';
import { extractRootDomain, calculateScoreAndFindings, collectSpfDomains, collectSpfTreeIssues, detectSecurityLayers, identifyTXTVerifications, identifyMX, isSameBrand } from './analyzer.js';

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

    it('degrada a "baja" un SEG cuya ÚNICA evidencia es un token TXT si el MX no lo confirma', () => {
        // Caso Amazon: MX propio (amazon-smtp.amazon.com) + token de verificación de un
        // vendor SEG. Sin presencia en el MX, un SEG no puede estar filtrando el correo.
        const { segList } = detectSecurityLayers({
            domain: 'acme.com',
            mxRecords: [{ priority: 5, host: 'acme-smtp.acme.com' }],
            txtVerifications: [{ name: 'Barracuda', category: 'seg', record: 'barracuda-domain-verification=abc' }]
        });
        const barracuda = segList.find(s => s.name === 'Barracuda');
        expect(barracuda).toBeTruthy();
        expect(barracuda.score).toBeLessThanOrEqual(0.4);
        expect(barracuda.level).toBe('baja');
        expect(barracuda.unconfirmed).toBe(true);
    });

    it('NO degrada el SEG si el MX confirma al mismo vendor', () => {
        const { segList } = detectSecurityLayers({
            domain: 'acme.com',
            mxRecords: [{ priority: 5, host: 'mx.mimecast.com' }],
            txtVerifications: [{ name: 'Mimecast', category: 'seg', record: 'mimecast-verification=abc' }]
        });
        const mimecast = segList.find(s => s.name === 'Mimecast');
        expect(mimecast.score).toBeGreaterThan(0.9);
        expect(mimecast.unconfirmed).toBeUndefined();
    });

    it('fusiona en UNA sola entrada el mismo vendor detectado por MX y por token TXT', () => {
        // Antes: "Sophos Email" (MX) + "Sophos" (TXT) salían como dos entradas por el
        // nombre inconsistente en el KB. Tras normalizar nombres, deben fusionarse.
        const txt = identifyTXTVerifications(['sophos-domain-verification=abc']);
        expect(txt[0].name).toBe('Sophos Email');
        const { segList } = detectSecurityLayers({
            domain: 'acme.com',
            mxRecords: [{ priority: 10, host: 'mx.sophos.com' }],
            txtVerifications: txt
        });
        const sophos = segList.filter(s => s.name === 'Sophos Email');
        expect(sophos).toHaveLength(1);
        expect(sophos[0].evidence.map(e => e.signal).sort()).toEqual(['mx', 'txt']);
        expect(sophos[0].level).toBe('alta');
    });

    it('NO marca "unconfirmed" cuando el MX confirma al vendor bajo OTRO nombre (identidad canónica)', () => {
        // El token TXT de Sophos mapea a "Sophos", pero el MX de Sophos identifica como
        // "Sophos Email". Son el mismo vendor: el token no debe salir "sin confirmar".
        const { segList } = detectSecurityLayers({
            domain: 'acme.com',
            mxRecords: [{ priority: 10, host: 'mx.sophos.com' }],
            txtVerifications: [{ name: 'Sophos', category: 'seg', record: 'sophos-domain-verification=abc' }]
        });
        expect(segList.every(s => !s.unconfirmed)).toBe(true);
        // El MX de Sophos sigue dando confianza alta.
        expect(segList.some(s => s.level === 'alta' && s.evidence.some(e => e.signal === 'mx'))).toBe(true);
    });

    it('el token cisco-ci-domain-verification no produce NINGUNA capa de seguridad', () => {
        // Es la verificación de dominio de Webex Control Hub (CI = Common Identity):
        // prueba que el dominio se dio de alta en una organización de Webex, no por
        // dónde pasa el correo. Un SEG de Cisco lo probaría el MX (*.iphmx.com).
        const txt = identifyTXTVerifications(['cisco-ci-domain-verification=1b256bd11daa486ba2fa405d2d5de70f75feb6757dd8993c']);
        const cisco = txt.find(t => t.name.includes('Webex'));
        expect(cisco).toBeTruthy();
        expect(cisco.category).toBe('other');

        const { segList, icesList } = detectSecurityLayers({
            domain: 'amazon.com',
            mxRecords: [{ priority: 5, host: 'amazon-smtp.amazon.com' }],
            txtVerifications: txt
        });
        expect(segList.some(s => s.name.toLowerCase().includes('cisco'))).toBe(false);
        expect(icesList.some(i => i.name.toLowerCase().includes('cisco'))).toBe(false);
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

    it('avisa cuando SPF no tiene mecanismo all', () => {
        const card = calculateScoreAndFindings(baseResult({ spfEntries: [{ type: 'include', value: 'x' }] }));
        expect(card.findings.some(f => f.key === 'finding_spf_no_all')).toBe(true);
    });

    it('avisa del mecanismo ptr (desaconsejado)', () => {
        const card = calculateScoreAndFindings(baseResult({
            spfEntries: [{ type: 'all', qualifier: '-' }, { type: 'ptr', value: '' }]
        }));
        expect(card.findings.some(f => f.key === 'finding_spf_ptr')).toBe(true);
    });

    it('detecta política de subdominio más débil (sp)', () => {
        const card = calculateScoreAndFindings(baseResult({
            dmarcParsed: { v: 'DMARC1', p: 'reject', sp: 'none' }
        }));
        expect(card.findings.some(f => f.key === 'finding_dmarc_sp_weak')).toBe(true);
    });

    it('detecta pct parcial en DMARC', () => {
        const card = calculateScoreAndFindings(baseResult({
            dmarcParsed: { v: 'DMARC1', p: 'reject', pct: '50' }
        }));
        expect(card.findings.some(f => f.key === 'finding_dmarc_pct_partial')).toBe(true);
    });

    it('marca destino DMARC externo no autorizado', () => {
        const card = calculateScoreAndFindings(baseResult({
            dmarcExternalAuth: [{ uri: 'mailto:r@ext.com', destDomain: 'ext.com', authorized: false }]
        }));
        expect(card.findings.some(f => f.key === 'finding_dmarc_rua_unauthorized')).toBe(true);
    });

    it('confirma autorización externa DMARC correcta', () => {
        const card = calculateScoreAndFindings(baseResult({
            dmarcExternalAuth: [{ uri: 'mailto:r@ext.com', destDomain: 'ext.com', authorized: true }]
        }));
        expect(card.findings.some(f => f.key === 'finding_dmarc_rua_authorized')).toBe(true);
    });

    it('no penaliza la ausencia de DKIM (info best-effort)', () => {
        const card = calculateScoreAndFindings(baseResult({ dkimRecords: { records: [] } }));
        const f = card.findings.find(x => x.key === 'finding_dkim_besteffort');
        expect(f).toBeTruthy();
        expect(f.status).toBe('info');
    });

    it('detecta clave DKIM débil (<1024 bits)', () => {
        const RSA_512 = 'MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKyJEaa3SfJ/U3LSG8oJ6tikdzKzRrAinSnmqCrJVlbz75GKqVc1Ck6Qq2sOS6bf93KA8BQSz/nKOegAPr2BTAsCAwEAAQ==';
        const card = calculateScoreAndFindings(baseResult({
            dkimRecords: { records: [{ selector: 's1', record: `v=DKIM1; p=${RSA_512}` }] }
        }));
        expect(card.findings.some(f => f.key === 'finding_dkim_weak_key')).toBe(true);
    });

    it('detecta clave DKIM revocada (p= vacío)', () => {
        const card = calculateScoreAndFindings(baseResult({
            dkimRecords: { records: [{ selector: 's1', record: 'v=DKIM1; p=' }] }
        }));
        expect(card.findings.some(f => f.key === 'finding_dkim_revoked')).toBe(true);
    });

    it('informa Null MX (RFC 7505) sin penalizar', () => {
        const card = calculateScoreAndFindings(baseResult({ nullMx: true }));
        const f = card.findings.find(x => x.key === 'finding_null_mx');
        expect(f).toBeTruthy();
        expect(f.status).toBe('info');
    });

    it('informa DMARC heredado del dominio organizativo', () => {
        const card = calculateScoreAndFindings(baseResult({
            dmarcInherited: true,
            dmarcInheritedFrom: 'example.com'
        }));
        const f = card.findings.find(x => x.key === 'finding_dmarc_inherited');
        expect(f).toBeTruthy();
        expect(f.replacements['{org}']).toBe('example.com');
    });

    it('bonifica DNSSEC firmado', () => {
        const card = calculateScoreAndFindings(baseResult({ dnssec: { signed: true } }));
        expect(card.findings.some(f => f.key === 'finding_dnssec_ok')).toBe(true);
    });

    it('avisa de max_age bajo en MTA-STS', () => {
        const card = calculateScoreAndFindings(baseResult({
            mtaSts: { policy: { valid: true, maxAge: 3600 } }
        }));
        expect(card.findings.some(f => f.key === 'finding_mta_sts_low_maxage')).toBe(true);
    });
});

describe('collectSpfTreeIssues', () => {
    const tree = {
        domain: 'x.com', lookups: 3, children: [
            { type: 'a', target: 'muerto.x.com', void: true },
            { type: 'mx', target: 'vivo.x.com', void: false },
            { type: 'include', target: 'roto.com', tree: { domain: 'roto.com', error: 'no_spf_record', children: [] } },
            { type: 'include', target: 'ok.com', tree: { domain: 'ok.com', error: null, children: [
                { type: 'exists', target: 'otro-muerto.com', void: true },
                { type: 'include', target: 'x.com', tree: { domain: 'x.com', error: 'loop', children: [] } }
            ] } }
        ]
    };

    it('recoge includes sin registro SPF (PermError) en cualquier profundidad', () => {
        expect(collectSpfTreeIssues(tree).noRecord).toEqual(['roto.com']);
    });

    it('recoge los mecanismos con consulta vacía (void lookups)', () => {
        const { voids } = collectSpfTreeIssues(tree);
        expect(voids).toContain('a:muerto.x.com');
        expect(voids).toContain('exists:otro-muerto.com');
        expect(voids).not.toContain('mx:vivo.x.com');
    });

    it('recoge los bucles', () => {
        expect(collectSpfTreeIssues(tree).loops).toEqual(['x.com']);
    });

    it('tolera un árbol nulo', () => {
        expect(collectSpfTreeIssues(null)).toEqual({ noRecord: [], voids: [], loops: [] });
    });
});

describe('comprobaciones nuevas del motor (v3)', () => {
    const base = (overrides = {}) => ({
        spfRaw: 'v=spf1 -all',
        spfData: { multiple: false },
        spfEntries: [{ type: 'all', qualifier: '-', index: 1 }],
        spfLookups: 3,
        dmarcRaw: 'v=DMARC1; p=reject; rua=mailto:a@b.com',
        dmarcData: { multiple: false },
        dmarcParsed: { v: 'DMARC1', p: 'reject', rua: 'mailto:a@b.com' },
        dmarcPolicy: 'reject',
        dmarcRua: ['mailto:a@b.com'],
        dmarcRuf: [],
        dkimRecords: { records: [] },
        bimiRecord: null,
        mtaSts: null,
        tlsRpt: null,
        daneRecords: {},
        srvRecords: {},
        mxRecords: [],
        segList: [],
        icesList: [],
        ...overrides
    });
    const keys = (card) => card.findings.map(f => f.key);

    it('marca PermError cuando un include no publica SPF', () => {
        const card = calculateScoreAndFindings(base({
            spfTree: { domain: 'x.com', children: [
                { type: 'include', target: 'roto.com', tree: { domain: 'roto.com', error: 'no_spf_record', children: [] } }
            ] }
        }));
        expect(keys(card)).toContain('finding_spf_include_permerror');
    });

    it('avisa de más de 2 void lookups, pero no de 2', () => {
        const voidChild = (n) => ({ type: 'a', target: `m${n}.com`, void: true });
        const withVoids = (n) => calculateScoreAndFindings(base({
            spfTree: { domain: 'x.com', children: Array.from({ length: n }, (_, i) => voidChild(i)) }
        }));
        expect(keys(withVoids(2))).not.toContain('finding_spf_void_lookups');
        expect(keys(withVoids(3))).toContain('finding_spf_void_lookups');
    });

    it('detecta varios "all" y mecanismos inalcanzables tras el primero', () => {
        const card = calculateScoreAndFindings(base({
            spfRaw: 'v=spf1 -all include:tarde.com ~all',
            spfEntries: [
                { type: 'v', value: 'spf1', index: 0 },
                { type: 'all', qualifier: '-', index: 1 },
                { type: 'include', value: 'tarde.com', qualifier: '+', index: 2 },
                { type: 'all', qualifier: '~', index: 3 }
            ]
        }));
        expect(keys(card)).toContain('finding_spf_multiple_all');
        expect(keys(card)).toContain('finding_spf_terms_after_all');
    });

    it('no marca términos inalcanzables cuando el "all" va el último', () => {
        const card = calculateScoreAndFindings(base({
            spfEntries: [
                { type: 'v', value: 'spf1', index: 0 },
                { type: 'include', value: 'ok.com', qualifier: '+', index: 1 },
                { type: 'all', qualifier: '-', index: 2 }
            ]
        }));
        expect(keys(card)).not.toContain('finding_spf_terms_after_all');
        expect(keys(card)).not.toContain('finding_spf_multiple_all');
    });

    it('avisa si la política MTA-STS no cubre algún MX real', () => {
        const card = calculateScoreAndFindings(base({
            mxRecords: [{ host: 'mx1.nuevo.com' }],
            mtaSts: { policy: { valid: true, parsed: { mx: ['*.viejo.net'] }, maxAge: 604800 } }
        }));
        expect(keys(card)).toContain('finding_mta_sts_mx_mismatch');
    });

    it('confirma la cobertura cuando la política sí lista los MX', () => {
        const card = calculateScoreAndFindings(base({
            mxRecords: [{ host: 'mx1.acme.com' }],
            mtaSts: { policy: { valid: true, parsed: { mx: ['*.acme.com'] }, maxAge: 604800 } }
        }));
        expect(keys(card)).toContain('finding_mta_sts_mx_ok');
        expect(keys(card)).not.toContain('finding_mta_sts_mx_mismatch');
    });

    it('no penaliza una política MTA-STS que no se pudo descargar', () => {
        const unreachable = calculateScoreAndFindings(base({
            mtaSts: { policy: { valid: false, validationReason: 'fetch_failed' } }
        }));
        const sinMtaSts = calculateScoreAndFindings(base());
        expect(keys(unreachable)).toContain('finding_mta_sts_unreachable');
        expect(keys(unreachable)).not.toContain('finding_mta_sts_policy_invalid');
        // Sale del denominador: nunca puntúa peor que no tener MTA-STS.
        expect(unreachable.score).toBeGreaterThanOrEqual(sinMtaSts.score);
        const mtaStsCheck = unreachable.breakdown
            .find(c => c.id === 'transport').checks.find(c => c.id === 'mtaSts');
        expect(mtaStsCheck.unevaluable).toBe(true);
    });

    it('sigue penalizando una política descargada pero inválida', () => {
        const card = calculateScoreAndFindings(base({
            mtaSts: { policy: { valid: false, validationReason: 'mode_not_enforce', httpStatus: 200, mode: 'testing' } }
        }));
        expect(keys(card)).toContain('finding_mta_sts_policy_invalid');
    });

    it('valida los destinos TLS-RPT', () => {
        const malo = calculateScoreAndFindings(base({ tlsRpt: { record: 'v=TLSRPTv1', rua: ['http://x.com'] } }));
        const bueno = calculateScoreAndFindings(base({ tlsRpt: { record: 'v=TLSRPTv1', rua: ['mailto:t@x.com'] } }));
        expect(keys(malo)).toContain('finding_tls_rpt_rua_invalid');
        expect(keys(bueno)).not.toContain('finding_tls_rpt_rua_invalid');
    });

    it('distingue BIMI sin VMC, con VMC y declinado', () => {
        const sinVmc = calculateScoreAndFindings(base({ bimiRecord: { record: 'v=BIMI1; l=https://x/l.svg', logo: 'https://x/l.svg', vmc: null } }));
        const conVmc = calculateScoreAndFindings(base({ bimiRecord: { record: 'v=BIMI1; l=https://x/l.svg; a=https://x/v.pem', logo: 'https://x/l.svg', vmc: 'https://x/v.pem' } }));
        const declinado = calculateScoreAndFindings(base({ bimiRecord: { record: 'v=BIMI1; l=', declined: true } }));
        expect(keys(sinVmc)).toContain('finding_bimi_no_vmc');
        expect(keys(conVmc)).toContain('finding_bimi_vmc_ok');
        expect(keys(declinado)).toContain('finding_bimi_declined');
        expect(declinado.score).toBeLessThan(conVmc.score);
    });

    it('penaliza una URL BIMI sin HTTPS', () => {
        const card = calculateScoreAndFindings(base({
            bimiRecord: { record: 'v=BIMI1; l=http://x/l.svg', logo: 'http://x/l.svg', logoInsecure: true }
        }));
        expect(keys(card)).toContain('finding_bimi_insecure_url');
    });

    it('no trata una clave Ed25519 de 256 bits como clave débil', () => {
        const card = calculateScoreAndFindings(base({
            dkimRecords: { records: [{ selector: 'ed', record: 'v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=' }] }
        }));
        expect(keys(card)).toContain('finding_dkim_ed25519');
        expect(keys(card)).not.toContain('finding_dkim_weak_key');
    });

    it('avisa de np más débil que la política efectiva', () => {
        const debil = calculateScoreAndFindings(base({
            dmarcParsed: { v: 'DMARC1', p: 'reject', np: 'none', rua: 'mailto:a@b.com' }
        }));
        const fuerte = calculateScoreAndFindings(base({
            dmarcParsed: { v: 'DMARC1', p: 'reject', np: 'reject', rua: 'mailto:a@b.com' }
        }));
        expect(keys(debil)).toContain('finding_dmarc_np_weak');
        expect(keys(fuerte)).toContain('finding_dmarc_np_ok');
    });

    it('avisa de demasiados destinos rua', () => {
        const card = calculateScoreAndFindings(base({
            dmarcRua: ['mailto:a@b.com', 'mailto:c@d.com', 'mailto:e@f.com']
        }));
        expect(keys(card)).toContain('finding_dmarc_rua_too_many');
    });

    it('avisa de un registro SPF de más de 255 caracteres', () => {
        const card = calculateScoreAndFindings(base({
            spfRaw: 'v=spf1 ' + 'ip4:1.2.3.4 '.repeat(30) + '-all'
        }));
        expect(keys(card)).toContain('finding_spf_too_long');
    });
});

describe('scoring por categorías ponderadas', () => {
    const strong = () => ({
        spfRaw: 'v=spf1 include:x.com -all',
        spfData: { multiple: false },
        spfEntries: [{ type: 'v', index: 0 }, { type: 'include', value: 'x.com', index: 1 }, { type: 'all', qualifier: '-', index: 2 }],
        spfLookups: 3,
        spfTree: { domain: 'd.com', children: [] },
        dmarcRaw: 'v=DMARC1; p=reject',
        dmarcData: { multiple: false },
        dmarcParsed: { v: 'DMARC1', p: 'reject', sp: 'reject' },
        dmarcPolicy: 'reject',
        dmarcRua: ['mailto:r@d.com'],
        dmarcRuf: [],
        dmarcExternalAuth: [],
        dkimRecords: { records: [{ selector: 's1', record: 'v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=' }] },
        bimiRecord: { record: 'v=BIMI1', logo: 'https://x/l.svg', vmc: 'https://x/v.pem' },
        mtaSts: { policy: { valid: true, maxAge: 604800, parsed: { mx: ['*.d.com'] } } },
        mxRecords: [{ host: 'mx.d.com' }],
        tlsRpt: { record: 'v=TLSRPTv1', rua: ['mailto:t@d.com'] },
        daneRecords: { 'mx.d.com': ['x'] },
        dnssec: { signed: true },
        srvRecords: {},
        segList: [], icesList: []
    });

    it('un dominio completo llega a 100 / A+', () => {
        const card = calculateScoreAndFindings(strong());
        expect(card.score).toBe(100);
        expect(card.grade).toBe('A+');
    });

    it('el desglose cuadra con los presupuestos de cada categoría', () => {
        const card = calculateScoreAndFindings(strong());
        expect(card.breakdown.map(c => c.id)).toEqual(['auth', 'transport', 'hygiene']);
        expect(card.breakdown.find(c => c.id === 'auth').max).toBe(60);
        expect(card.breakdown.find(c => c.id === 'transport').max).toBe(25);
        expect(card.breakdown.find(c => c.id === 'hygiene').max).toBe(15);
        expect(card.totalMax).toBe(100);
    });

    it('la autenticación acota la nota: sin transporte no hay A+', () => {
        const card = calculateScoreAndFindings({
            ...strong(), mtaSts: null, dnssec: { signed: false }, daneRecords: {}, bimiRecord: null, tlsRpt: null
        });
        expect(card.breakdown.find(c => c.id === 'auth').earned).toBe(60);
        expect(card.grade).not.toBe('A+');
    });

    it('DMARC p=none no puede alcanzar A/A+ por muchos extras que tenga', () => {
        const card = calculateScoreAndFindings({
            ...strong(), dmarcParsed: { v: 'DMARC1', p: 'none' }, dmarcPolicy: 'none'
        });
        expect(card.authRatio).toBeLessThan(0.85);
        expect(['B', 'C', 'D', 'F']).toContain(card.grade);
    });

    it('un PermError de SPF agota el presupuesto del control', () => {
        const card = calculateScoreAndFindings({
            ...strong(),
            spfTree: { domain: 'd.com', children: [
                { type: 'include', target: 'roto.com', tree: { domain: 'roto.com', error: 'no_spf_record', children: [] } }
            ] }
        });
        const spfCheck = card.breakdown.find(c => c.id === 'auth').checks.find(c => c.id === 'spf');
        expect(spfCheck.earned).toBeLessThanOrEqual(0);
        expect(card.grade).not.toBe('A+');
    });

    it('un control no evaluable sale del denominador en vez de contar 0', () => {
        const sinDkim = calculateScoreAndFindings({ ...strong(), dkimRecords: { records: [] } });
        const dkimCheck = sinDkim.breakdown.find(c => c.id === 'auth').checks.find(c => c.id === 'dkim');
        expect(dkimCheck.unevaluable).toBe(true);
        expect(sinDkim.totalMax).toBe(85);
        expect(sinDkim.score).toBe(100);
    });

    it('ningún check supera su presupuesto y ninguna categoría baja de 0', () => {
        const card = calculateScoreAndFindings(strong());
        for (const cat of card.breakdown) {
            expect(cat.earned).toBeGreaterThanOrEqual(0);
            expect(cat.earned).toBeLessThanOrEqual(cat.max);
            for (const check of cat.checks) {
                expect(check.earned).toBeLessThanOrEqual(check.max);
            }
        }
    });

    it('la nota se mantiene entre 0 y 100 en el peor caso', () => {
        const card = calculateScoreAndFindings({
            spfRaw: 'v=spf1 +all',
            spfData: { multiple: true },
            spfEntries: [{ type: 'all', qualifier: '+', index: 1 }],
            spfLookups: 25,
            dmarcRaw: 'v=DMARC2; p=nada',
            dmarcData: { multiple: true },
            dmarcParsed: { v: 'DMARC2', p: 'nada' },
            dmarcPolicy: 'nada',
            dmarcRua: [], dmarcRuf: [],
            dkimRecords: { records: [{ selector: 'x', record: 'v=DKIM1; p=' }] },
            mtaSts: { policy: { valid: false, validationReason: 'mode_not_enforce', httpStatus: 200 } },
            mxRecords: [], daneRecords: {}, srvRecords: {}, segList: [], icesList: []
        });
        expect(card.score).toBeGreaterThanOrEqual(0);
        expect(card.score).toBeLessThanOrEqual(100);
        expect(card.grade).toBe('F');
    });
});

describe('identifyMX: un MX externo desconocido NO es una capa de seguridad', () => {
    it('no inventa un SEG con el nombre del dominio hermano (paypal.com → paypalcorp.com)', () => {
        const id = identifyMX('mx1.paypalcorp.com', 'paypal.com');
        expect(id.type).toBe('unknown');
        expect(id.type).not.toBe('seg');
        expect(id.external).toBe(true);
        expect(id.sameBrand).toBe(true);
    });

    it('tampoco con un hosting no catalogado', () => {
        const id = identifyMX('mx.hosting-desconocido.net', 'acme.com');
        expect(id.type).toBe('unknown');
        expect(id.external).toBe(true);
        expect(id.sameBrand).toBe(false);
    });

    it('sigue reconociendo los SEG reales del diccionario', () => {
        expect(identifyMX('mx.mimecast.com', 'acme.com').type).toBe('seg');
        expect(identifyMX('esa01.arquia.es', 'arquia.es').name).toContain('Cisco');
        expect(identifyMX('acme-com.mail.protection.outlook.com', 'acme.com').type).toBe('provider');
    });

    it('un MX del propio dominio sigue siendo propio', () => {
        expect(identifyMX('mx1.acme.com', 'acme.com').type).toBe('self');
    });

    it('un MX externo desconocido no llega a segList', () => {
        const { segList, icesList } = detectSecurityLayers({
            domain: 'paypal.com',
            mxRecords: [{ priority: 10, host: 'mx1.paypalcorp.com' }]
        });
        expect(segList).toEqual([]);
        expect(icesList).toEqual([]);
    });
});

describe('isSameBrand', () => {
    it('empareja marca compartida y variantes de TLD', () => {
        expect(isSameBrand('paypalcorp.com', 'paypal.com')).toBe(true);
        expect(isSameBrand('acmegroup.net', 'acme.com')).toBe(true);
        expect(isSameBrand('empresa.com', 'empresa.es')).toBe(true);
    });

    it('no empareja por etiquetas cortas ni por dominios ajenos', () => {
        expect(isSameBrand('mx.com', 'acme.com')).toBe(false);
        expect(isSameBrand('srv.net', 'acme.com')).toBe(false);
        expect(isSameBrand('proofpoint.com', 'acme.com')).toBe(false);
        expect(isSameBrand('', 'acme.com')).toBe(false);
    });
});

describe('postura: la ausencia de SEG/ICES no la hunde', () => {
    const authOk = (overrides = {}) => ({
        spfRaw: 'v=spf1 -all',
        spfEntries: [{ type: 'all', qualifier: '-', index: 1 }],
        spfData: { multiple: false },
        spfLookups: 2,
        dmarcRaw: 'v=DMARC1; p=reject',
        dmarcData: { multiple: false },
        dmarcParsed: { v: 'DMARC1', p: 'reject' },
        dmarcPolicy: 'reject',
        dmarcRua: ['mailto:a@b.com'],
        dmarcRuf: [],
        dkimRecords: { records: [] },
        mxRecords: [], daneRecords: {}, srvRecords: {},
        segList: [], icesList: [],
        ...overrides
    });

    it('un dominio bien autenticado sin SEG detectable no es "débil"', () => {
        const { posture } = calculateScoreAndFindings(authOk());
        expect(posture.key).not.toBe('weak');
    });

    it('pero sin DMARC aplicado sigue siendo "débil"', () => {
        const { posture } = calculateScoreAndFindings(authOk({
            dmarcParsed: { v: 'DMARC1', p: 'none' }, dmarcPolicy: 'none'
        }));
        expect(posture.key).toBe('weak');
    });
});

describe('tokens TXT: solo son capa de seguridad si el producto es de CORREO', () => {
    // Los tokens reales que publica google.com en su TXT del ápex. Ninguno debe
    // producir una capa de seguridad: el cisco-ci-domain-verification es la
    // verificación de dominio de Webex Control Hub, no un gateway de correo.
    const GOOGLE_TXT = [
        'onetrust-domain-verification=6d685f1d41a94696ad7ef771f68993e0',
        'google-site-verification=wD8N7i1JTNTkezJ49swvWW48f8_9xveREV4oB-0Hf5o',
        'work-accounts-domain-verification=Tcj6JjIMZOw2KsSEw2Nt2rLae89tN6',
        'facebook-domain-verification=22rm551cu4k0ab0bxsw536tlds4h95',
        'apple-domain-verification=30afIBcvSuDV2PLX',
        'cisco-ci-domain-verification=47c38bc8c4b74b7233e9053220c1bbe76bcc1cd33c7acf7acd36cd6a5332004b',
        'v=spf1 include:_spf.google.com ~all'
    ];

    it('google.com no genera ninguna capa de seguridad a partir de sus tokens', () => {
        const txtVerifications = identifyTXTVerifications(GOOGLE_TXT);
        const { segList, icesList } = detectSecurityLayers({
            domain: 'google.com',
            mxRecords: [{ priority: 10, host: 'smtp.google.com' }],
            txtVerifications
        });
        expect(segList).toEqual([]);
        expect(icesList).toEqual([]);
    });

    it('el token de Cisco se sigue reconociendo, pero como Webex y sin categoría de seguridad', () => {
        const found = identifyTXTVerifications(GOOGLE_TXT).find(v => v.name.includes('Webex'));
        expect(found).toBeTruthy();
        expect(found.category).toBe('other');
        expect(found.name).not.toContain('Secure Email');
    });

    it('un token que SÍ es de seguridad de correo sigue contando como capa', () => {
        const txtVerifications = identifyTXTVerifications(['abnormalsecurity-domain-verification=abc123']);
        const { icesList } = detectSecurityLayers({ domain: 'acme.com', txtVerifications });
        expect(icesList.map(i => i.name)).toContain('Abnormal Security');
    });
});

describe('DANE no se penaliza dos veces cuando falta DNSSEC', () => {
    const base = (over = {}) => ({
        spfRaw: 'v=spf1 -all',
        spfEntries: [{ type: 'all', qualifier: '-', index: 1 }],
        spfData: { multiple: false },
        spfLookups: 2,
        dmarcRaw: 'v=DMARC1; p=reject',
        dmarcData: { multiple: false },
        dmarcParsed: { v: 'DMARC1', p: 'reject' },
        dmarcPolicy: 'reject',
        dmarcRua: ['mailto:a@b.com'], dmarcRuf: [],
        dkimRecords: { records: [] },
        mxRecords: [], daneRecords: {}, srvRecords: {},
        segList: [], icesList: [],
        ...over
    });
    const daneCheck = (card) => card.breakdown.find(c => c.id === 'transport').checks.find(c => c.id === 'dane');

    it('sin DNSSEC, DANE queda sin evaluar y sale del denominador', () => {
        const card = calculateScoreAndFindings(base({ dnssec: { signed: false } }));
        expect(daneCheck(card).unevaluable).toBe(true);
        expect(card.breakdown.find(c => c.id === 'transport').max).toBe(18);
        expect(card.findings.map(f => f.key)).toContain('finding_dane_needs_dnssec');
    });

    it('con DNSSEC pero sin DANE, sí se exige y resta', () => {
        const card = calculateScoreAndFindings(base({ dnssec: { signed: true } }));
        expect(daneCheck(card).unevaluable).toBe(false);
        expect(card.breakdown.find(c => c.id === 'transport').max).toBe(25);
        expect(card.findings.map(f => f.key)).toContain('finding_dane_err');
    });

    it('con DNSSEC y DANE se puntúa entero', () => {
        const card = calculateScoreAndFindings(base({
            dnssec: { signed: true }, daneRecords: { 'mx.acme.com': ['3 1 1 abc'] }
        }));
        expect(daneCheck(card).earned).toBe(7);
    });

    it('un dominio sin DNSSEC no sale peor que antes por esta vía', () => {
        const sinDnssec = calculateScoreAndFindings(base({ dnssec: { signed: false } }));
        const conDnssecSinDane = calculateScoreAndFindings(base({ dnssec: { signed: true } }));
        expect(sinDnssec.score).toBeGreaterThan(conDnssecSinDane.score - 100);
        expect(sinDnssec.breakdown.find(c => c.id === 'transport').max).toBeLessThan(
            conDnssecSinDane.breakdown.find(c => c.id === 'transport').max);
    });
});
