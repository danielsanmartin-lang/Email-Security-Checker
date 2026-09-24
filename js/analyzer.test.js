import { describe, it, expect } from 'vitest';
import { analyze, extractRootDomain, calculateScoreAndFindings, collectSpfDomains, collectSpfTreeIssues, detectSecurityLayers, classifyInboundFilter, identifyTXTVerifications, identifyMX, isSameBrand } from './analyzer.js';

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

    it('el respaldo para sufijos no listados solo usa etiquetas genéricas (com., gov., ac.…)', () => {
        expect(extractRootDomain('a.b.com.xx')).toBe('b.com.xx');
        expect(extractRootDomain('host.gov.zz')).toBe('host.gov.zz');
    });

    it('una marca corta bajo un ccTLD NO se toma por sufijo público', () => {
        // Antes bastaba "SLD de ≤3 letras + TLD de 2" para tratarlo como compuesto: mx.ine.es
        // salía como dominio registrable propio (falso "MX externo", DMARC sin heredar…).
        expect(extractRootDomain('host.abc.io')).toBe('abc.io');
        expect(extractRootDomain('mx.ine.es')).toBe('ine.es');
        expect(extractRootDomain('mail.dhl.de')).toBe('dhl.de');
        expect(extractRootDomain('reports.zdf.de')).toBe('zdf.de');
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
        mxRecords: [{ priority: 10, host: 'mx.example.com' }],
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

    it('asigna grado alto y nivel "protegido" a una config completa', () => {
        const card = calculateScoreAndFindings(baseResult());
        expect(['A+', 'A']).toContain(card.grade);
        expect(card.posture.key).toBe('protected');
        expect(card.level).toBe('protected');
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
        expect(card.posture.key).toBe('spoofable');
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

    it('una zona que devuelve SERVFAIL se reporta como hallazgo, sin tocar la nota', () => {
        // Que los NS autoritativos de un dominio fallen bajo carga es un dato sobre ESE
        // dominio (afecta a su entregabilidad), no un fallo de la herramienta. Pero no se
        // puntúa: la muestra depende de nuestra propia ráfaga de consultas.
        const limpio = calculateScoreAndFindings(baseResult({ dkimRecords: { records: [], errors: [] } }));
        const roto = calculateScoreAndFindings(baseResult({
            dkimRecords: { records: [], errors: [{ selector: 's1', code: 'servfail' }, { selector: 's2', code: 'servfail' }], attempted: 9 }
        }));
        expect(roto.findings.some(f => f.key === 'finding_dns_zone_servfail')).toBe(true);
        expect(limpio.findings.some(f => f.key === 'finding_dns_zone_servfail')).toBe(false);
        expect(roto.score).toBe(limpio.score);
    });

    it('un fallo de red nuestro NO se atribuye a la zona del dominio', () => {
        const card = calculateScoreAndFindings(baseResult({
            dkimRecords: { records: [], errors: [{ selector: 's1', code: 'network' }], attempted: 9 }
        }));
        expect(card.findings.some(f => f.key === 'finding_dns_zone_servfail')).toBe(false);
    });

    it('tolera un dkimRecords sin la clave errors (resultados anteriores)', () => {
        expect(() => calculateScoreAndFindings(baseResult({ dkimRecords: { records: [] } }))).not.toThrow();
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
        mxRecords: [{ priority: 10, host: 'mx.example.com' }],
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

    it('una política publicada que no se pudo descargar cuenta como "publicada, sin verificar"', () => {
        const unreachable = calculateScoreAndFindings(base({
            mtaSts: { policy: { valid: false, validationReason: 'fetch_failed' } }
        }));
        const sinMtaSts = calculateScoreAndFindings(base());
        expect(keys(unreachable)).toContain('finding_mta_sts_unreachable');
        expect(keys(unreachable)).not.toContain('finding_mta_sts_policy_invalid');
        const mtaStsCheck = unreachable.breakdown
            .find(c => c.id === 'transport').checks.find(c => c.id === 'mtaSts');
        expect(mtaStsCheck.unevaluable).toBe(false);
        expect(mtaStsCheck.earned).toBe(25);
        expect(unreachable.transport.score).toBeGreaterThan(sinMtaSts.transport.score);
    });

    it('una política en testing es VÁLIDA: se avisa sin penalizar y no se llama "inválida"', () => {
        const card = calculateScoreAndFindings(base({
            mtaSts: { policy: { valid: false, validationReason: 'mode_not_enforce', httpStatus: 200, mode: 'testing' } }
        }));
        expect(keys(card)).toContain('finding_mta_sts_testing');
        expect(keys(card)).not.toContain('finding_mta_sts_policy_invalid');
        const check = card.breakdown.find(c => c.id === 'transport').checks.find(c => c.id === 'mtaSts');
        expect(check.earned).toBe(15);
        expect(check.unevaluable).toBe(false);
    });

    it('mode: none es una política retirada: informativo, sin penalizar', () => {
        const card = calculateScoreAndFindings(base({
            mtaSts: { policy: { valid: false, validationReason: 'mode_not_enforce', httpStatus: 200, mode: 'none' } }
        }));
        expect(keys(card)).toContain('finding_mta_sts_mode_none');
        expect(keys(card)).not.toContain('finding_mta_sts_policy_invalid');
    });

    it('sigue penalizando una política descargada pero inválida', () => {
        const card = calculateScoreAndFindings(base({
            mtaSts: { policy: { valid: false, validationReason: 'invalid_version', httpStatus: 200, mode: 'enforce' } }
        }));
        expect(keys(card)).toContain('finding_mta_sts_policy_invalid');
    });

    it('un host de política que no resuelve es un fallo comprobado sin contactar al dominio', () => {
        const card = calculateScoreAndFindings(base({
            mtaSts: { policy: { valid: false, validationReason: 'host_missing', host: 'mta-sts.acme.com' } }
        }));
        const f = card.findings.find(x => x.key === 'finding_mta_sts_host_missing');
        expect(f.status).toBe('error');
        expect(f.replacements['{host}']).toBe('mta-sts.acme.com');
        const check = card.breakdown.find(c => c.id === 'transport').checks.find(c => c.id === 'mtaSts');
        expect(check.unevaluable).toBe(false);
        expect(check.earned).toBe(0);
    });

    it('una política no descargada por privacidad cuenta como publicada, sin verificar', () => {
        const card = calculateScoreAndFindings(base({
            mtaSts: { policy: { valid: false, validationReason: 'not_fetched' } }
        }));
        expect(keys(card)).toContain('finding_mta_sts_not_fetched');
        const check = card.breakdown.find(c => c.id === 'transport').checks.find(c => c.id === 'mtaSts');
        expect(check.unevaluable).toBe(false);
        expect(check.earned).toBe(25);
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
        // BIMI es marca, no seguridad: no mueve ninguna de las dos notas.
        expect(declinado.score).toBe(conVmc.score);
        expect(sinVmc.score).toBe(conVmc.score);
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

    it('hay tres ejes con peso 60/25/15', () => {
        const card = calculateScoreAndFindings(strong());
        expect(card.breakdown.map(c => c.id)).toEqual(['antispoof', 'filtering', 'transport']);
        expect(card.breakdown.map(c => c.weight)).toEqual([60, 25, 15]);
        expect(card.breakdown.find(c => c.id === 'antispoof').max).toBe(100);
        expect(card.breakdown.find(c => c.id === 'transport').max).toBe(100);
        expect(card.transport).toMatchObject({ applicable: true, score: 100, grade: 'A+' });
        expect(card.totalMax).toBe(100);
    });

    it('un MX sin identificar deja el filtrado fuera de la media y reparte su peso', () => {
        const card = calculateScoreAndFindings(strong());
        const filtering = card.breakdown.find(c => c.id === 'filtering');
        expect(card.filtering).toMatchObject({ applicable: true, state: 'unidentified', evaluable: false, score: null });
        expect(filtering.counted).toBe(false);
        expect(card.breakdown.map(c => c.share)).toEqual([80, 0, 20]);
    });

    it('el transporte cuenta en la nota, pero pesa poco', () => {
        const card = calculateScoreAndFindings({
            ...strong(), mtaSts: null, dnssec: { signed: false }, daneRecords: {}, bimiRecord: null, tlsRpt: null
        });
        expect(card.antispoof.score).toBe(100);
        expect(card.transport.grade).toBe('F');
        // 60·100 / (60 + 15): el filtrado no cuenta (MX sin identificar).
        expect(card.score).toBe(80);
        expect(card.grade).toBe('B');
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
        const spfCheck = card.breakdown.find(c => c.id === 'antispoof').checks.find(c => c.id === 'spf');
        expect(spfCheck.earned).toBeLessThanOrEqual(0);
        expect(card.grade).not.toBe('A+');
    });

    it('un control no evaluable sale del denominador en vez de contar 0', () => {
        const sinDkim = calculateScoreAndFindings({ ...strong(), dkimRecords: { records: [] } });
        const dkimCheck = sinDkim.breakdown.find(c => c.id === 'antispoof').checks.find(c => c.id === 'dkim');
        expect(dkimCheck.unevaluable).toBe(true);
        expect(sinDkim.totalMax).toBe(80);
        // Lo no verificado no resta, pero tampoco prueba nada: sin DKIM no hay A+.
        expect(sinDkim.score).toBe(94);
        expect(sinDkim.grade).toBe('A');
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

    it('un dominio bien autenticado sin SEG detectable no es "suplantable"', () => {
        const { posture } = calculateScoreAndFindings(authOk());
        expect(posture.key).toBe('protected');
    });

    it('pero sin DMARC aplicado sigue siendo "suplantable"', () => {
        const { posture } = calculateScoreAndFindings(authOk({
            dmarcParsed: { v: 'DMARC1', p: 'none' }, dmarcPolicy: 'none'
        }));
        expect(posture.key).toBe('spoofable');
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
        mxRecords: [{ priority: 10, host: 'mx.acme.com' }], daneRecords: {}, srvRecords: {},
        segList: [], icesList: [],
        ...over
    });
    const daneCheck = (card) => card.breakdown.find(c => c.id === 'transport').checks.find(c => c.id === 'dane');

    it('sin DNSSEC, DANE queda sin evaluar y sale del denominador', () => {
        const card = calculateScoreAndFindings(base({ dnssec: { signed: false } }));
        expect(daneCheck(card).unevaluable).toBe(true);
        expect(card.breakdown.find(c => c.id === 'transport').max).toBe(80);
        expect(card.findings.map(f => f.key)).toContain('finding_dane_needs_dnssec');
    });

    it('con DNSSEC pero sin DANE, sí se exige y resta', () => {
        const card = calculateScoreAndFindings(base({ dnssec: { signed: true } }));
        expect(daneCheck(card).unevaluable).toBe(false);
        expect(card.breakdown.find(c => c.id === 'transport').max).toBe(100);
        expect(card.findings.map(f => f.key)).toContain('finding_dane_err');
    });

    it('con DNSSEC y DANE se puntúa entero', () => {
        const card = calculateScoreAndFindings(base({
            dnssec: { signed: true }, daneRecords: { 'mx.acme.com': ['3 1 1 abc'] }
        }));
        expect(daneCheck(card).earned).toBe(20);
    });

    it('un dominio sin DNSSEC no sale peor que antes por esta vía', () => {
        const sinDnssec = calculateScoreAndFindings(base({ dnssec: { signed: false } }));
        const conDnssecSinDane = calculateScoreAndFindings(base({ dnssec: { signed: true } }));
        // Firmar la zona suma; no firmarla no resta además por DANE.
        expect(sinDnssec.score).toBeLessThan(conDnssecSinDane.score);
        expect(daneCheck(sinDnssec).earned).toBe(0);
        expect(sinDnssec.breakdown.find(c => c.id === 'transport').max).toBeLessThan(
            conDnssecSinDane.breakdown.find(c => c.id === 'transport').max);
    });
});

// ===========================================================================
// RFC 9989 (DMARCbis, mayo de 2026) y su convivencia con RFC 7489.
// Cada caso reproduce un fallo real del veredicto anterior: el registro "parecía"
// protegido y la nota lo daba por bueno.
// ===========================================================================
describe('DMARC según RFC 9989: la política que de verdad se aplica', () => {
    const MX = [{ priority: 10, host: 'mx.example.com' }];
    const scored = (dmarcRaw, extra = {}) => {
        const r = analyze(MX, 'v=spf1 -all', dmarcRaw, { domain: 'example.com', ...extra });
        Object.assign(r, { spfLookups: 2, dkimRecords: { records: [] } });
        const card = calculateScoreAndFindings(r);
        const dmarcCheck = card.breakdown.find(b => b.id === 'antispoof').checks.find(c => c.id === 'dmarc');
        return { r, card, dmarcCheck, keys: card.findings.map(f => f.key) };
    };

    it('t=y rebaja un nivel: p=reject en prueba puntúa como quarantine', () => {
        const { r, dmarcCheck, keys } = scored('v=DMARC1; p=reject; t=y; rua=mailto:d@example.com');
        expect(r.dmarcPolicy).toBe('quarantine');
        expect(r.dmarcPolicyRequested).toBe('reject');
        expect(dmarcCheck.earned).toBe(46);
        expect(keys).toContain('finding_dmarc_testing_t');
        expect(keys).not.toContain('finding_dmarc_policy_reject');
    });

    it('pct=0 con quarantine equivale a none en los receptores RFC 7489', () => {
        const { r, dmarcCheck, keys } = scored('v=DMARC1; p=quarantine; pct=0; rua=mailto:d@example.com');
        expect(r.dmarcPolicy).toBe('none');
        expect(dmarcCheck.earned).toBe(10);
        expect(keys).toContain('finding_dmarc_pct_zero');
    });

    it('pct=0 y t=y juntos se reconocen como la forma correcta de probar', () => {
        const { keys } = scored('v=DMARC1; p=reject; pct=0; t=y; rua=mailto:d@example.com');
        expect(keys).toContain('finding_dmarc_pct_zero_with_t');
    });

    it('un pct parcial describe el reparto real: el resto recibe la política inferior', () => {
        const { card } = scored('v=DMARC1; p=reject; pct=50; rua=mailto:d@example.com');
        const f = card.findings.find(x => x.key === 'finding_dmarc_pct_partial');
        expect(f.replacements).toMatchObject({ '{pct}': '50', '{p}': 'REJECT', '{lower}': 'QUARANTINE' });
        expect(card.grade).not.toBe('A+');
    });

    it('pct=100 y ri/rf se marcan como etiquetas eliminadas', () => {
        const { keys } = scored('v=DMARC1; p=reject; pct=100; ri=86400; rf=afrf; rua=mailto:d@example.com');
        expect(keys).toContain('finding_dmarc_pct_removed');
        expect(keys).toContain('finding_dmarc_tag_removed');
    });

    it('quarantine es enforcement: puntúa casi como reject y da "protegido"', () => {
        const { dmarcCheck, card } = scored('v=DMARC1; p=quarantine; rua=mailto:d@example.com');
        expect(dmarcCheck.earned).toBe(46);
        expect(card.level).toBe('protected');
    });

    it('reject añade la nota de RFC 9989 §7.4 (DKIM obligatorio, listas de correo)', () => {
        const { keys } = scored('v=DMARC1; p=reject; rua=mailto:d@example.com');
        expect(keys).toContain('finding_dmarc_policy_reject');
        expect(keys).toContain('finding_dmarc_reject_notes');
    });

    it('un subdominio que hereda p=reject; sp=none se puntúa con sp, no con p', () => {
        const { r, dmarcCheck, card } = scored('v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com', {
            domain: 'shop.example.com', dmarcInherited: true, dmarcInheritedFrom: 'example.com',
            dmarcSource: 'org', dmarcPolicyDomain: 'example.com', dmarcOrgDomain: 'example.com'
        });
        expect(r.dmarcPolicy).toBe('none');
        expect(dmarcCheck.earned).toBe(10);
        const inherited = card.findings.find(f => f.key === 'finding_dmarc_inherited');
        expect(inherited.replacements).toMatchObject({ '{org}': 'example.com', '{tag}': 'sp', '{policy}': 'NONE' });
        expect(card.posture.key).toBe('spoofable');
        expect(card.score).toBeLessThanOrEqual(45);
    });

    it('p en mayúsculas es válido (ABNF) y puntúa como su minúscula', () => {
        const { dmarcCheck, keys } = scored('v=DMARC1; p=Reject; rua=mailto:d@example.com');
        expect(dmarcCheck.earned).toBe(50);
        expect(keys).toContain('finding_dmarc_policy_reject');
    });

    it('un sp no válido convierte TODO el registro en p=none (RFC 9989 §4.10.1)', () => {
        const { r, keys, card } = scored('v=DMARC1; p=reject; sp=rejct; rua=mailto:d@example.com');
        expect(r.dmarcEval.processing).toBe('as_none');
        expect(r.dmarcPolicy).toBe('none');
        expect(keys).toContain('finding_dmarc_invalid_as_none');
        expect(card.posture.key).toBe('spoofable');
    });

    it('sin rua válido, una política no válida deja el registro sin efecto', () => {
        const { r, keys } = scored('v=DMARC1; p=rechazar');
        expect(r.dmarcEval.processing).toBe('none');
        expect(keys).toContain('finding_dmarc_no_effect');
    });

    it('varios registros en el propio dominio se descartan: sin política ni informes', () => {
        const { r, card, dmarcCheck } = scored('v=DMARC1; p=reject; rua=mailto:d@example.com', {
            dmarcData: { record: 'v=DMARC1; p=reject; rua=mailto:d@example.com', records: ['v=DMARC1; p=reject; rua=mailto:d@example.com', 'v=DMARC1; p=none'], multiple: true }
        });
        expect(r.dmarcEval).toBeNull();
        expect(r.dmarcPolicy).toBe('No configurado');
        expect(dmarcCheck.earned).toBe(0);
        const reporting = card.breakdown.find(b => b.id === 'antispoof').checks.find(c => c.id === 'dmarcReporting');
        expect(reporting.earned).toBe(0);
        expect(card.posture.key).toBe('spoofable');
    });

    it('un rua sin mailto: no cuenta como informes y se avisa', () => {
        const { card, keys } = scored('v=DMARC1; p=reject; rua=dmarc@example.com');
        const reporting = card.breakdown.find(b => b.id === 'antispoof').checks.find(c => c.id === 'dmarcReporting');
        expect(reporting.earned).toBe(0);
        expect(keys).toContain('finding_dmarc_rua_invalid_uri');
        expect(keys).toContain('finding_dmarc_reporting_err');
    });

    it('solo ruf no es visibilidad: aviso y sin puntos de informes', () => {
        const { keys } = scored('v=DMARC1; p=reject; ruf=mailto:f@example.com');
        expect(keys).toContain('finding_dmarc_ruf_only');
    });

    it('p=none sin rua no es ni monitorización', () => {
        const { keys } = scored('v=DMARC1; p=none');
        expect(keys).toContain('finding_dmarc_none_no_rua');
    });

    it('psd=y en un dominio corporativo se avisa; psd=n se explica', () => {
        expect(scored('v=DMARC1; p=reject; psd=y; rua=mailto:d@example.com').keys).toContain('finding_dmarc_psd_y');
        expect(scored('v=DMARC1; p=reject; psd=n; rua=mailto:d@example.com').keys).toContain('finding_dmarc_psd_n');
    });

    it('fo sin ruf no tiene efecto; etiquetas desconocidas se señalan', () => {
        const { keys } = scored('v=DMARC1; p=reject; fo=1; rua=mailto:d@example.com; rau=mailto:x@example.com');
        expect(keys).toContain('finding_dmarc_fo_ignored');
        expect(keys).toContain('finding_dmarc_unknown_tags');
    });

    it('"protegido" exige enforcement también en los subdominios (sp)', () => {
        const strongish = (dmarcRaw) => {
            const r = analyze(MX, 'v=spf1 -all', dmarcRaw, { domain: 'example.com' });
            Object.assign(r, {
                spfLookups: 2,
                dkimRecords: { records: [{ selector: 's1', record: 'v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=' }] },
                mtaSts: { policy: { valid: true } }
            });
            return calculateScoreAndFindings(r).posture.key;
        };
        expect(strongish('v=DMARC1; p=quarantine; rua=mailto:d@example.com')).toBe('protected');
        expect(strongish('v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com')).toBe('partial');
    });
});

describe('SPF: redirect, varios registros y erratas', () => {
    const spfScore = (overrides) => {
        const card = calculateScoreAndFindings({
            spfData: { multiple: false }, spfLookups: 2,
            dmarcRaw: 'v=DMARC1; p=reject', dmarcData: { multiple: false }, dmarcParsed: { v: 'DMARC1', p: 'reject' },
            dmarcRua: ['mailto:a@b.com'], dmarcRuf: [], dkimRecords: { records: [] },
            mxRecords: [], daneRecords: {}, srvRecords: {}, segList: [], icesList: [],
            ...overrides
        });
        const spf = card.breakdown.find(b => b.id === 'antispoof').checks.find(c => c.id === 'spf');
        return { card, spf, keys: card.findings.map(f => f.key) };
    };

    it('con redirect= el all efectivo sale del registro de destino', () => {
        const { spf, keys } = spfScore({
            spfRaw: 'v=spf1 redirect=_spf.example.net',
            spfEntries: [{ type: 'v', index: 0 }, { type: 'redirect', value: '_spf.example.net', qualifier: '+', index: 1 }],
            spfTree: { domain: 'example.com', lookups: 1, children: [
                { type: 'redirect', target: '_spf.example.net', tree: { domain: '_spf.example.net', lookups: 0, record: 'v=spf1 ip4:192.0.2.0/24 -all', children: [] } }
            ] }
        });
        expect(keys).toContain('finding_spf_all_via_redirect');
        expect(keys).toContain('finding_spf_all_hardfail');
        expect(keys).not.toContain('finding_spf_no_all');
        expect(spf.earned).toBe(20);
    });

    it('varios registros SPF son PermError: no suman ni el all ni los lookups', () => {
        const { spf, keys, card } = spfScore({
            spfRaw: 'v=spf1 -all',
            spfData: { multiple: true },
            spfEntries: [{ type: 'all', qualifier: '-', index: 1 }]
        });
        expect(keys).toContain('finding_spf_multiple');
        expect(keys).not.toContain('finding_spf_all_hardfail');
        expect(spf.earned).toBe(0);
        // Con DMARC en reject el dominio sigue protegido (DKIM puede alinear), pero sin A+.
        expect(card.grade).not.toBe('A+');
    });

    it('un mecanismo desconocido (errata) es PermError', () => {
        const { spf, keys } = spfScore({
            spfRaw: 'v=spf1 inlcude:_spf.google.com -all',
            spfEntries: [{ type: 'v', index: 0 }, { type: 'unknown', value: 'inlcude:_spf.google.com', qualifier: '+', index: 1 }, { type: 'all', qualifier: '-', index: 2 }]
        });
        expect(keys).toContain('finding_spf_unknown_mechanism');
        expect(spf.earned).toBeLessThanOrEqual(0);
    });
});

describe('identifyMX: sufijos y MX propios sin heurística', () => {
    it('reconoce el MX de Exchange Online con DNSSEC (*.mx.microsoft) como Microsoft 365', () => {
        const id = identifyMX('contoso-com.l-v1.mx.microsoft', 'contoso.com');
        expect(id.type).toBe('provider');
        expect(id.name).toBe('Microsoft 365');
    });

    it('el sufijo es exacto: mx.microsoft.com no es el MX de M365', () => {
        expect(identifyMX('mx.microsoft.com', 'acme.com').name).not.toBe('Microsoft 365');
    });

    it('un MX bajo una marca corta de ccTLD es propio (mx.ine.es → ine.es)', () => {
        expect(identifyMX('mx.ine.es', 'ine.es').type).toBe('self');
        expect(identifyMX('mail.dhl.de', 'dhl.de').type).toBe('self');
    });

    it('al auditar un subdominio, el MX del dominio organizativo también es propio', () => {
        expect(identifyMX('mx.example.com', 'shop.example.com', 'example.com').type).toBe('self');
    });

    it('un dominio organizativo más corto que el registrable no se da por bueno', () => {
        // Si un TLD publicara DMARC sin psd=y, el Tree Walk lo daría como organizativo.
        expect(identifyMX('mx.otra.com', 'acme.com', 'com').type).not.toBe('self');
    });
});

describe('DNSSEC y DANE: firmar no basta, tiene que validar', () => {
    const transport = (over) => {
        const card = calculateScoreAndFindings({
            spfRaw: 'v=spf1 -all', spfEntries: [{ type: 'all', qualifier: '-', index: 1 }], spfData: { multiple: false }, spfLookups: 2,
            dmarcRaw: 'v=DMARC1; p=reject', dmarcData: { multiple: false }, dmarcParsed: { v: 'DMARC1', p: 'reject' },
            dmarcRua: ['mailto:a@b.com'], dmarcRuf: [], dkimRecords: { records: [] },
            mxRecords: [{ priority: 10, host: 'mx.acme.com' }], daneRecords: {}, srvRecords: {}, segList: [], icesList: [],
            ...over
        });
        const t = card.breakdown.find(b => b.id === 'transport');
        return { card, dnssec: t.checks.find(c => c.id === 'dnssec'), dane: t.checks.find(c => c.id === 'dane'), keys: card.findings.map(f => f.key) };
    };

    it('DNSKEY sin AD (cadena sin validar) no puntúa y se avisa', () => {
        const { dnssec, keys } = transport({ dnssec: { signed: true, hasDnskey: true, ad: false, validationKnown: true } });
        expect(dnssec.earned).toBe(0);
        expect(keys).toContain('finding_dnssec_unvalidated');
    });

    it('con un resolver propio (validación desconocida) se da por buena la firma', () => {
        const { dnssec } = transport({ dnssec: { signed: true, hasDnskey: true, ad: false, validationKnown: false } });
        expect(dnssec.earned).toBe(25);
    });

    it('TLSA en los MX sin DNSSEC en la zona del dominio: DANE no se usa ni puntúa', () => {
        const { dane, keys } = transport({
            dnssec: { signed: false, hasDnskey: false, ad: false, validationKnown: true },
            daneRecords: { 'acme-com.l-v1.mx.microsoft': ['3 1 1 abc'] }
        });
        expect(dane.unevaluable).toBe(true);
        expect(keys).toContain('finding_dane_unusable');
    });

    it('con la zona validada pero el TLSA sin validar, DANE tampoco puntúa', () => {
        const daneRecords = { 'mx.acme.com': ['3 1 1 abc'] };
        Object.defineProperty(daneRecords, 'validated', { value: { 'mx.acme.com': false }, enumerable: false });
        const { dane } = transport({ dnssec: { signed: true, hasDnskey: true, ad: true, validationKnown: true }, daneRecords });
        expect(dane.earned).toBe(0);
        expect(dane.unevaluable).toBe(false);
    });
});

// ===========================================================================
// Calibración contra dominios reales (v4, recalibrada en v5 con el filtrado entrante).
// Los registros son los publicados el 2026-09-23 y, salesforce.com, el 2026-09-24
// (consulta solo DNS); si alguno de estos casos cambia de letra, el modelo ha dejado de
// decir lo que un receptor haría de verdad con el correo de ese dominio.
// ===========================================================================
describe('v5: calibración con dominios medidos', () => {
    const RSA_1024 = 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHKI9Hv9UXFuaCMiUm4ByPZYWK4CySUGGnMLiUksN5v0eN7MlEbY1C3O8tU4yvGMGGrtJ279KC1EJi8twRn1bqVt5TsffmluZ6r5wZUndUHOLUmNubZdcaG8jW0uXy9w2pOJhr8sz+UAvXvthBnok0Ld8NL37wHC7lNePzrMYwGQIDAQAB';
    const RSA_2048 = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmBBYI7zVX1AV5i/TYH8ujMlXkMfD7YzBoRnf1b34d5hhBa0RG3k7GT5Z8irrBPeP/ZIxKEIn4okhyhpd2NY0OP1RQsEEzDSnVQL5MmtINeyxY0bBALRL/maj6EtXrKrpAQvkfPOlEo9U4mRDJaLb0D0G6nxmqbztSlHToGlgp6B9EvDV/NNgYYhBVCaqfzVoJqgRzes5elhnODddSCw4burNfq+375sHa5vSlf6nZ38hz6witOE1NZEhI1MYIwiQhsfVy3tav9mdbL/YcW0gBmXMjq/03QlAQS8pUL4ZwGPhPjnt/0Q3X6jYforhfLIraQIrVRPhp5a6ilstNaZ8TQIDAQAB';
    const NO_DNSSEC = { signed: false, hasDnskey: false, ad: false, validationKnown: true };
    const card = (mx, spf, dmarc, opts = {}, extra = {}) => {
        const r = analyze(mx, spf, dmarc, { dnssec: NO_DNSSEC, daneRecords: {}, srvRecords: {}, ...opts });
        Object.assign(r, { spfLookups: 2, dkimRecords: { records: [] }, ...extra });
        return calculateScoreAndFindings(r);
    };
    const mx = (...hosts) => hosts.map((host, i) => ({ priority: 10 + i, host }));

    it('telefonica.com: p=none, aunque el resto esté bien, es suplantable (D)', () => {
        const c = card(mx('telefonicacorp.mail.protection.outlook.com'),
            'v=spf1 include:spf.protection.outlook.com include:_spf.telefonica.com include:_spf.salesforce.com -all',
            'v=DMARC1;p=none;pct=100;fo=1;ri=3600;rua=mailto:x@dmarc-reports.cloudflare.net;',
            { domain: 'telefonica.com' },
            { spfLookups: 5, dkimRecords: { records: [
                { selector: 'selector1', record: `v=DKIM1; k=rsa; p=${RSA_1024}` },
                { selector: 'k1', record: `k=rsa; p=${RSA_1024}` }
            ] } });
        expect(c).toMatchObject({ score: 45, grade: 'D', level: 'spoofable', cap: { key: 'no_enforcement', value: 45 } });
        expect(c.transport).toMatchObject({ applicable: true, grade: 'F' });
        expect(c.filtering).toMatchObject({ state: 'native', provider: 'Microsoft 365', score: 50 });
    });

    it('support.apple.com: sin MX ni SPF, cubierto por sp=reject de apple.com (A, transporte no aplica)', () => {
        const c = card([], null, 'v=DMARC1; p=quarantine; sp=reject; rua=mailto:d@rua.agari.com; ruf=mailto:d@ruf.agari.com;', {
            domain: 'support.apple.com', dmarcInherited: true, dmarcInheritedFrom: 'apple.com',
            dmarcSource: 'org', dmarcPolicyDomain: 'apple.com', dmarcOrgDomain: 'apple.com'
        });
        expect(c).toMatchObject({ score: 94, grade: 'A', level: 'protected' });
        expect(c.transport).toMatchObject({ applicable: false, score: null });
        expect(c.filtering).toMatchObject({ applicable: false, state: 'not_applicable' });
        const keys = c.findings.map(f => f.key);
        expect(keys).toContain('finding_spf_not_needed');
        expect(keys).toContain('finding_transport_not_applicable');
        expect(keys).not.toContain('finding_spf_err');
    });

    it('iberdrola.es: reject, SPF por redirect y Trend Micro en el MX; transporte F (A)', () => {
        const c = card(mx('iberdrola.in.tmes.trendmicro.eu'), 'v=spf1 redirect=spf.iberdrola.com',
            'v=DMARC1; p=reject; rua=mailto:dmarc_rua@iberdrola.com; ruf=mailto:dmarc_ruf@iberdrola.com; fo=1; aspf=s; adkim=s;',
            { domain: 'iberdrola.es' },
            { spfLookups: 6, spfTree: { domain: 'iberdrola.es', lookups: 6, children: [
                { type: 'redirect', target: 'spf.iberdrola.com', tree: { domain: 'spf.iberdrola.com', lookups: 5, record: 'v=spf1 ip4:192.0.2.0/24 -all', children: [] } }
            ] } });
        // 0,60·100 + 0,25·100 + 0,15·0 = 85. Sin DKIM detectable no habría A+ de todos modos.
        expect(c).toMatchObject({ score: 85, grade: 'A', level: 'protected', cap: null });
        expect(c.filtering).toMatchObject({ state: 'reinforced', vendors: ['Trend Micro Email Security'], score: 100 });
        expect(c.transport.grade).toBe('F');
    });

    it('posteo.de: transporte ejemplar no compensa un DMARC en none (F / transporte A)', () => {
        const daneRecords = { 'mx01.posteo.de': ['3 1 1 abc'] };
        const c = card(mx('mx03.posteo.de', 'mx01.posteo.de'), 'v=spf1 ip4:185.67.36.0/23 ip6:2a05:bc0:1000::/47 ~all',
            'v=DMARC1; p=none; sp=quarantine; adkim=s; aspf=s', {
                domain: 'posteo.de', daneRecords,
                dnssec: { signed: true, hasDnskey: true, ad: true, validationKnown: true },
                mtaSts: { record: 'v=STSv1; id=1', policy: { valid: false, validationReason: 'not_fetched' } },
                tlsRpt: { record: 'v=TLSRPTv1; rua=mailto:tlsrpt@posteo.de', rua: ['mailto:tlsrpt@posteo.de'] }
            }, { spfLookups: 0 });
        // MX propio: el filtrado no cuenta. (0,60·26 + 0,15·85) / 0,75 = 38.
        expect(c).toMatchObject({ score: 38, grade: 'F', level: 'spoofable' });
        expect(c.filtering.state).toBe('unidentified');
        expect(c.transport).toMatchObject({ applicable: true, score: 85, grade: 'A' });
    });

    it('ncsc.gov.uk: suplantación perfecta, pero filtrado solo nativo y transporte D (B)', () => {
        const c = card(mx('ncsc-gov-uk.mail.protection.outlook.com'), 'v=spf1 include:spf.protection.outlook.com -all',
            'v=DMARC1;p=reject;adkim=s;aspf=s;rua=mailto:dmarc-rua@dmarc.service.gov.uk;', {
                domain: 'ncsc.gov.uk',
                mtaSts: { record: 'v=STSv1; id=1', policy: { valid: false, validationReason: 'not_fetched' } },
                tlsRpt: { record: 'v=TLSRPTv1;rua=mailto:tls-rua@mailcheck.service.ncsc.gov.uk', rua: ['mailto:tls-rua@mailcheck.service.ncsc.gov.uk'] }
            }, { spfLookups: 1, dkimRecords: { records: [
                { selector: 'selector1', record: `v=DKIM1; k=rsa; p=${RSA_2048}` },
                { selector: 'selector2', record: `v=DKIM1; k=rsa; p=${RSA_2048}` }
            ] } });
        // 0,60·100 + 0,25·50 + 0,15·50 = 80.
        expect(c.antispoof.score).toBe(100);
        expect(c).toMatchObject({ score: 80, grade: 'B', level: 'protected', cap: null });
        expect(c.filtering).toMatchObject({ state: 'native', provider: 'Microsoft 365' });
        expect(c.transport.grade).toBe('D');
    });

    it('salesforce.com: reject, Proofpoint en el MX y solo DNSSEC en transporte (A)', () => {
        const c = card(mx('mxa-00177002.gslb.pphosted.com', 'mxb-00177002.gslb.pphosted.com'),
            'v=spf1 include:_spf.google.com include:_spf.salesforce.com exists:%{i}._spf.corp.salesforce.com ~all',
            'v=DMARC1;p=reject;fo=1:d:s;pct=100;rua=mailto:dmarc_agg@vali.email,mailto:0e5a5c34@inbox.ondmarc.com;ruf=mailto:0e5a5c34@inbox.ondmarc.com', {
                domain: 'salesforce.com',
                dnssec: { signed: true, hasDnskey: true, ad: true, validationKnown: true }
            }, { spfLookups: 4, dkimRecords: { records: [
                { selector: 's1', record: `v=DKIM1; k=rsa; p=${RSA_1024}` },
                { selector: 's2', record: `v=DKIM1; k=rsa; p=${RSA_2048}` }
            ] } });
        // Suplantación 97 (DKIM de 1024), filtrado 100 y transporte 25 (solo DNSSEC):
        // 0,60·97 + 0,25·100 + 0,15·25 = 86,95.
        expect(c.antispoof.score).toBe(97);
        expect(c.filtering).toMatchObject({ state: 'reinforced', vendors: ['Proofpoint'], score: 100, bypass: false });
        expect(c).toMatchObject({ score: 87, grade: 'A', level: 'protected' });
        const seg = c.findings.find(f => f.key === 'finding_filter_seg');
        expect(seg).toMatchObject({ status: 'success', replacements: { '{vendors}': 'Proofpoint' } });
    });

    it('el mismo dominio con MX directo a Microsoft 365 baja por el filtrado nativo', () => {
        const auth = ['v=spf1 include:spf.protection.outlook.com -all', 'v=DMARC1; p=reject; rua=mailto:d@example.com'];
        const dkim = { dkimRecords: { records: [{ selector: 'selector1', record: `v=DKIM1; k=rsa; p=${RSA_2048}` }] } };
        const pp = card(mx('mxa-001.gslb.pphosted.com'), ...auth, { domain: 'example.com' }, dkim);
        const m365 = card(mx('example-com.mail.protection.outlook.com'), ...auth, { domain: 'example.com' }, dkim);
        expect(pp.antispoof.score).toBe(m365.antispoof.score);
        expect(pp.score).toBe(85);
        expect(m365.score).toBe(73);
        expect(m365.grade).toBe('B');
        const native = m365.findings.find(f => f.key === 'finding_filter_native');
        expect(native).toMatchObject({ status: 'info', replacements: { '{provider}': 'Microsoft 365' } });
    });

    describe('reglas del modelo', () => {
        const MX = mx('mx.example.com');
        const dkimOf = (c) => c.breakdown.find(b => b.id === 'antispoof').checks.find(k => k.id === 'dkim');
        const spfOf = (c) => c.breakdown.find(b => b.id === 'antispoof').checks.find(k => k.id === 'spf');

        it('una clave DKIM revocada junto a una activa no resta', () => {
            const activa = { selector: 's1', record: `v=DKIM1; k=rsa; p=${RSA_2048}` };
            const revocada = { selector: 'old', record: 'v=DKIM1; k=rsa; p=' };
            const solo = card(MX, 'v=spf1 -all', 'v=DMARC1; p=reject; rua=mailto:d@example.com', { domain: 'example.com' },
                { dkimRecords: { records: [activa] } });
            const ambas = card(MX, 'v=spf1 -all', 'v=DMARC1; p=reject; rua=mailto:d@example.com', { domain: 'example.com' },
                { dkimRecords: { records: [activa, revocada] } });
            expect(ambas.score).toBe(solo.score);
            expect(dkimOf(ambas).earned).toBe(20);
            const f = ambas.findings.find(x => x.key === 'finding_dkim_revoked');
            expect(f.status).toBe('info');
        });

        it('si solo aparecen claves revocadas, DKIM queda sin evaluar', () => {
            const c = card(MX, 'v=spf1 -all', 'v=DMARC1; p=reject; rua=mailto:d@example.com', { domain: 'example.com' },
                { dkimRecords: { records: [{ selector: 'old', record: 'v=DKIM1; k=rsa; p=' }] } });
            expect(dkimOf(c).unevaluable).toBe(true);
        });

        it('~all vale lo mismo que -all cuando DMARC aplica política (RFC 9989 §7.1)', () => {
            const soft = card(MX, 'v=spf1 ~all', 'v=DMARC1; p=reject; rua=mailto:d@example.com', { domain: 'example.com' });
            const hard = card(MX, 'v=spf1 -all', 'v=DMARC1; p=reject; rua=mailto:d@example.com', { domain: 'example.com' });
            expect(spfOf(soft).earned).toBe(20);
            expect(soft.score).toBe(hard.score);
        });

        it('sin enforcement, ~all sí vale menos que -all', () => {
            const soft = card(MX, 'v=spf1 ~all', 'v=DMARC1; p=none; rua=mailto:d@example.com', { domain: 'example.com' });
            expect(spfOf(soft).earned).toBe(16);
        });

        it('sin enforcement la nota no pasa de 45, por perfecto que sea el resto', () => {
            const c = card(MX, 'v=spf1 -all', 'v=DMARC1; p=none; rua=mailto:d@example.com', { domain: 'example.com' },
                { dkimRecords: { records: [{ selector: 's1', record: `v=DKIM1; k=rsa; p=${RSA_2048}` }] } });
            expect(c.score).toBe(45);
            expect(c.grade).toBe('D');
        });

        it('un dominio con Null MX no se evalúa en transporte', () => {
            const nullMx = Object.assign([], { nullMx: true });
            const c = card(nullMx, 'v=spf1 -all', 'v=DMARC1; p=reject; rua=mailto:d@example.com', { domain: 'example.com', nullMx: true });
            expect(c.transport.applicable).toBe(false);
        });

        it('BIMI heredado del dominio organizativo se explica, y no puntúa', () => {
            const base = card(MX, 'v=spf1 -all', 'v=DMARC1; p=reject; rua=mailto:d@example.com', { domain: 'shop.example.com' });
            const conBimi = card(MX, 'v=spf1 -all', 'v=DMARC1; p=reject; rua=mailto:d@example.com', { domain: 'shop.example.com' }, {
                bimiRecord: { record: 'v=BIMI1; l=https://example.com/logo.svg', parsed: { l: 'https://example.com/logo.svg' }, inheritedFrom: 'example.com' }
            });
            const f = conBimi.findings.find(x => x.key === 'finding_bimi_inherited');
            expect(f.replacements).toEqual({ '{org}': 'example.com' });
            expect(conBimi.score).toBe(base.score);
        });
    });
});

// ===========================================================================
// v5: filtrado entrante, el tercer eje de la nota. Solo se afirma lo que el DNS deja
// ver: un MX propio o desconocido no se evalúa, y "solo nativo" no es cero.
// ===========================================================================
describe('classifyInboundFilter', () => {
    const mx = (...hosts) => hosts.map((host, i) => ({ priority: 10 + i, host }));
    const classify = (mxRecords, extra = {}) => {
        const signals = { domain: 'acme.com', mxRecords, ...extra };
        const { segList, icesList } = detectSecurityLayers(signals);
        return classifyInboundFilter({ mxRecords, segList, icesList, domain: 'acme.com', ...extra });
    };

    it('SEG en el MX: reforzado, con el vendor', () => {
        const f = classify(mx('mxa-001.gslb.pphosted.com', 'mxb-001.gslb.pphosted.com'));
        expect(f).toMatchObject({ state: 'reinforced', vendors: ['Proofpoint'], segVendors: ['Proofpoint'], bypassMx: [] });
    });

    it('SEG en el MX y un MX de respaldo directo a Microsoft 365: bypass', () => {
        const f = classify(mx('mx.mimecast.com', 'acme-com.mail.protection.outlook.com'));
        expect(f.state).toBe('reinforced');
        expect(f.bypassMx).toEqual(['acme-com.mail.protection.outlook.com']);
        expect(f.provider).toBe('Microsoft 365');
    });

    it('SEG solo en el SPF: no filtra la entrada, se dice aparte', () => {
        const f = classify(mx('acme-com.mail.protection.outlook.com'), {
            spfEntries: [{ type: 'include', value: 'spf.pphosted.com' }]
        });
        expect(f.state).toBe('native');
        expect(f.outOfPathVendors).toEqual(['Proofpoint']);
    });

    it('el mismo vendor con otro nombre en el SPF no se da por ausente del MX', () => {
        // MX ppe-hosted.com → "Proofpoint"; SPF ppe-hosted.com → "Proofpoint Essentials".
        const f = classify(mx('mx1-eu1.ppe-hosted.com'), {
            spfEntries: [{ type: 'include', value: 'spf.ppe-hosted.com' }]
        });
        expect(f.state).toBe('reinforced');
        expect(f.outOfPathVendors).toEqual([]);
    });

    it('ICES con confianza media sobre Microsoft 365: reforzado sin tocar el MX', () => {
        const f = classify(mx('acme-com.mail.protection.outlook.com'), {
            txtVerifications: [{ name: 'Abnormal Security', category: 'ices', record: 'abnormal-verification=x' }]
        });
        expect(f).toMatchObject({ state: 'reinforced', vendors: ['Abnormal Security'], icesVendors: ['Abnormal Security'], bypassMx: [] });
    });

    it('un ICES de confianza baja no basta', () => {
        const f = classifyInboundFilter({
            mxRecords: mx('acme-com.mail.protection.outlook.com'),
            icesList: [{ name: 'X', category: 'ices', level: 'baja', score: 0.5 }]
        });
        expect(f.state).toBe('native');
    });

    it('MX directo a Google Workspace: solo nativo', () => {
        const f = classify(mx('aspmx.l.google.com', 'alt1.aspmx.l.google.com'));
        expect(f).toMatchObject({ state: 'native', provider: 'Google Workspace' });
    });

    it('MX propio o desconocido: sin identificar, no se afirma nada', () => {
        expect(classify(mx('mx1.acme.com')).state).toBe('unidentified');
        expect(classify(mx('mx.hosting-desconocido.net')).state).toBe('unidentified');
        // Mezcla de proveedor y MX propio: el propio puede ser un gateway on-premise.
        const mixto = classify(mx('acme-com.mail.protection.outlook.com', 'mx2.acme.com'));
        expect(mixto.state).toBe('unidentified');
        expect(mixto.unknownMx).toEqual(['mx2.acme.com']);
    });

    it('sin MX o con Null MX: no aplica', () => {
        expect(classifyInboundFilter({ mxRecords: [] }).state).toBe('not_applicable');
        expect(classifyInboundFilter({ mxRecords: mx('.'), nullMx: true }).state).toBe('not_applicable');
    });

    it('analyze() deja el veredicto en el result', () => {
        const r = analyze(mx('mx.mimecast.com'), 'v=spf1 -all', 'v=DMARC1; p=reject', { domain: 'acme.com' });
        expect(r.inboundFilter).toMatchObject({ state: 'reinforced', vendors: ['Mimecast'] });
    });
});

describe('v5: la nota del ecosistema', () => {
    const RSA_2048 = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmBBYI7zVX1AV5i/TYH8ujMlXkMfD7YzBoRnf1b34d5hhBa0RG3k7GT5Z8irrBPeP/ZIxKEIn4okhyhpd2NY0OP1RQsEEzDSnVQL5MmtINeyxY0bBALRL/maj6EtXrKrpAQvkfPOlEo9U4mRDJaLb0D0G6nxmqbztSlHToGlgp6B9EvDV/NNgYYhBVCaqfzVoJqgRzes5elhnODddSCw4burNfq+375sHa5vSlf6nZ38hz6witOE1NZEhI1MYIwiQhsfVy3tav9mdbL/YcW0gBmXMjq/03QlAQS8pUL4ZwGPhPjnt/0Q3X6jYforhfLIraQIrVRPhp5a6ilstNaZ8TQIDAQAB';
    // Transporte completo para un MX dado: MTA-STS que lo cubre, TLS-RPT, DNSSEC y DANE.
    const fullTransport = (host) => ({
        dnssec: { signed: true, hasDnskey: true, ad: true, validationKnown: true },
        mtaSts: { record: 'v=STSv1; id=1', policy: { valid: true, maxAge: 604800, parsed: { mx: [host] } } },
        tlsRpt: { record: 'v=TLSRPTv1', rua: ['mailto:t@acme.com'] },
        daneRecords: { [host]: ['3 1 1 abc'] }
    });
    const PP = 'mxa-1.gslb.pphosted.com';
    const M365 = 'acme-com.mail.protection.outlook.com';
    const card = (mxHosts, dmarc, opts = {}, extra = {}) => {
        const mxRecords = mxHosts.map((host, i) => ({ priority: 10 + i, host }));
        const r = analyze(mxRecords, 'v=spf1 -all', dmarc, { domain: 'acme.com', srvRecords: {}, ...opts });
        Object.assign(r, {
            spfLookups: 1,
            dkimRecords: { records: [{ selector: 's1', record: `v=DKIM1; k=rsa; p=${RSA_2048}` }] },
            ...extra
        });
        return calculateScoreAndFindings(r);
    };
    const REJECT = 'v=DMARC1; p=reject; rua=mailto:d@acme.com';

    it('con todo verificado, gateway y transporte completo se llega a A+', () => {
        const c = card([PP], REJECT, fullTransport(PP));
        expect(c.transport.score).toBe(100);
        expect(c).toMatchObject({ score: 100, grade: 'A+', cap: null });
    });

    it('con filtrado solo nativo no se llega a A+ aunque todo lo demás sea perfecto', () => {
        const c = card([M365], REJECT, fullTransport(M365));
        // 0,60·100 + 0,25·50 + 0,15·100 = 87,5
        expect(c.score).toBe(88);
        expect(c.grade).toBe('A');
    });

    it('sin enforcement, ni un gateway ni un transporte ejemplar pasan del 45', () => {
        const c = card([PP], 'v=DMARC1; p=none; rua=mailto:d@acme.com', fullTransport(PP));
        expect(c.filtering.state).toBe('reinforced');
        expect(c).toMatchObject({ score: 45, grade: 'D', cap: { key: 'no_enforcement', value: 45 } });
    });

    it('la suplantación sin verificar del todo limita la nota global a 94', () => {
        const c = card([PP], REJECT, fullTransport(PP), { dkimRecords: { records: [] } });
        expect(c).toMatchObject({ score: 94, grade: 'A', cap: { key: 'unverified', value: 94 } });
    });

    it('un MX de respaldo que salta el gateway cuesta puntos y se avisa', () => {
        const limpio = card([PP], REJECT);
        const bypass = card([PP, M365], REJECT);
        expect(bypass.filtering).toMatchObject({ state: 'reinforced', bypass: true, score: 75 });
        expect(bypass.score).toBeLessThan(limpio.score);
        const f = bypass.findings.find(x => x.key === 'finding_filter_bypass');
        expect(f).toMatchObject({
            status: 'warning',
            replacements: { '{hosts}': 'acme-com.mail.protection.outlook.com', '{provider}': 'Microsoft 365', '{vendors}': 'Proofpoint' }
        });
    });

    it('un dominio sin MX solo se puntúa por la suplantación', () => {
        const c = card([], REJECT);
        expect(c.filtering.applicable).toBe(false);
        expect(c.transport.applicable).toBe(false);
        expect(c.breakdown.map(b => b.share)).toEqual([100, 0, 0]);
        expect(c.score).toBe(c.antispoof.score);
        expect(c.breakdown.find(b => b.id === 'filtering').checks[0]).toMatchObject({ notApplicable: true });
    });

    it('un MX sin identificar no resta: la nota es la misma que sin el eje', () => {
        const c = card(['mx1.acme.com'], REJECT);
        expect(c.filtering.state).toBe('unidentified');
        expect(c.findings.some(f => f.key === 'finding_filter_unidentified' && f.status === 'info')).toBe(true);
        expect(c.breakdown.find(b => b.id === 'filtering').counted).toBe(false);
    });
});
