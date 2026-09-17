import { describe, it, expect } from 'vitest';
import { classifyMailHosting, asnMatchesBrand, hostingLevel } from './mailHosting.js';

// Los fixtures son TRANSCRIPCIONES de medidas reales contra DNS en vivo (2026-09-17),
// no invenciones: si el clasificador deja de reproducirlos, la regresión es real.
// Ver el script de verificación en vivo para volver a levantarlos.

const telefonica = {
    domain: 'telefonica.es',
    mxIds: [{ host: 'mx01.hornetsecurity.com', type: 'seg', name: 'Hornetsecurity' }],
    autodiscover: { cname: 'autodiscover.outlook.com', ips: ['52.98.250.184'], status: 'ok' },
    ipIntel: { '52.98.250.184': { ip: '52.98.250.184', asn: '8075', asName: 'MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US', ptr: null } },
    dkimChains: [{ selector: 'selector1', cname: null, hasKey: false }],
    segFronting: true
};

const inditex = {
    domain: 'inditex.com',
    mxIds: [{ host: 'mxb-005d4502.gslb.pphosted.com', type: 'seg', name: 'Proofpoint' }],
    autodiscover: { cname: null, ips: ['195.77.161.26'], status: 'ok' },
    ipIntel: {
        '195.77.161.26': {
            ip: '195.77.161.26', asn: '204748',
            asName: 'AS_INDITEX - INDUSTRIA DE DISENO TEXTIL SOCIEDAD ANONIMA, ES',
            ptr: '26.red-195-77-161.customer.static.ccgg.telefonica.net'
        }
    },
    dkimChains: [
        { selector: 'selector1', cname: 'selector1-inditex-com._domainkey.grupoinditex.onmicrosoft.com', hasKey: true },
        { selector: 'selector2', cname: 'selector2-inditex-com._domainkey.grupoinditex.onmicrosoft.com', hasKey: true }
    ],
    segFronting: true
};

const congreso = {
    domain: 'congreso.es',
    mxIds: [{ host: 'mxb-006a4e02.gslb.pphosted.com', type: 'seg', name: 'Proofpoint' }],
    autodiscover: { cname: 'correo.congreso.es', ips: ['213.27.204.104'], status: 'ok' },
    ipIntel: { '213.27.204.104': { ip: '213.27.204.104', asn: '8220', asName: 'COLT - COLT Technology Services Group Limited, GB', ptr: 'correo.congreso.es' } },
    dkimChains: [{ selector: 'selector1', cname: 'selector1-congreso-es._domainkey.congresoes.onmicrosoft.com', hasKey: true }],
    segFronting: true
};

const mercadona = {
    domain: 'mercadona.es',
    mxIds: [{ host: 'mx2.hc1196-26.c3s2.iphmx.com', type: 'seg', name: 'Cisco Email Security (IronPort)' }],
    autodiscover: { cname: null, ips: ['195.57.200.148'], status: 'ok' },
    ipIntel: { '195.57.200.148': { ip: '195.57.200.148', asn: '201976', asName: 'ASMERCADONA - Mercadona S.A, ES', ptr: null } },
    dkimChains: [],
    segFronting: true
};

const csic = {
    domain: 'csic.es',
    mxIds: [{ host: 'mx.csic.es', type: 'self', name: 'mx.csic.es' }],
    mxIps: { 'mx.csic.es': ['161.111.10.17'] },
    autodiscover: { cname: 'phpnodes.hosting.sgai.csic.es', ips: ['161.111.70.134'], status: 'ok' },
    ipIntel: {
        '161.111.70.134': { ip: '161.111.70.134', asn: '766', asName: 'RedIRIS - Entidad Publica Empresarial Red.es, ES', ptr: 'phpnodes.hosting.sgai.csic.es' },
        '161.111.10.17': { ip: '161.111.10.17', asn: '766', asName: 'RedIRIS - Entidad Publica Empresarial Red.es, ES', ptr: 'smtpin.csic.es' }
    },
    dkimChains: []
};

const ugr = {
    domain: 'ugr.es',
    mxIds: [{ host: 'mxb-006a4e02.gslb.pphosted.com', type: 'seg', name: 'Proofpoint' }],
    autodiscover: { cname: null, ips: [], status: 'nxdomain' },
    dkimChains: [],
    segFronting: true
};

const cabify = {
    domain: 'cabify.com',
    mxIds: [{ host: 'aspmx.l.google.com', type: 'provider', name: 'Google Workspace' }],
    autodiscover: { cname: null, ips: [], status: 'nxdomain' },
    dkimChains: []
};

describe('classifyMailHosting — verdad-terreno medida en vivo', () => {
    it.each([
        ['telefonica.es (SEG delante, buzones en M365)', telefonica, 'cloud', 'm365'],
        ['inditex.com (tenant M365 + ASN propio)', inditex, 'hybrid', 'm365'],
        ['congreso.es (tenant M365 + autodiscover propio)', congreso, 'hybrid', 'm365'],
        ['mercadona.es (ASN propio, sin tenant)', mercadona, 'on_premise', 'own'],
        ['csic.es (MX propio + autodiscover propio)', csic, 'on_premise', 'own'],
        ['ugr.es (sin señales)', ugr, 'undetermined', 'unknown'],
        ['cabify.com (Google Workspace)', cabify, 'cloud', 'google']
    ])('%s', (_label, signals, kind, platform) => {
        const r = classifyMailHosting(signals);
        expect(r.kind).toBe(kind);
        expect(r.platform).toBe(platform);
    });

    it('extrae el tenant de M365 del CNAME de DKIM', () => {
        expect(classifyMailHosting(inditex).tenant).toBe('grupoinditex.onmicrosoft.com');
        expect(classifyMailHosting(congreso).tenant).toBe('congresoes.onmicrosoft.com');
    });

    it('un tenant visto en dos selectores cuenta UNA vez (es el mismo hecho)', () => {
        // inditex publica selector1 y selector2 hacia el mismo tenant. Contarlos como
        // evidencia independiente inflaría la confianza sin aportar información nueva.
        const r = classifyMailHosting(inditex);
        const tenantSignals = r.evidence.filter(e => e.signal === 'dkim_tenant_m365');
        expect(tenantSignals).toHaveLength(1);
    });

    it('la confianza de un híbrido no supera la de su mitad más débil', () => {
        const r = classifyMailHosting(congreso);
        expect(r.kind).toBe('hybrid');
        expect(r.confidence).toBeLessThanOrEqual(0.9);
    });
});

describe('classifyMailHosting — reglas negativas (falsos positivos que NO debe cometer)', () => {
    it('la ausencia de autodiscover NO es indicio de servidor propio', () => {
        // autodiscover es un protocolo de Microsoft: Google Workspace no lo publica nunca.
        const r = classifyMailHosting(cabify);
        expect(r.kind).toBe('cloud');
        expect(r.evidence.some(e => e.signal.startsWith('autodiscover_own'))).toBe(false);
        expect(r.notes.map(n => n.key)).toContain('no_autodiscover');
    });

    it('un SEG en el MX no decide dónde están los buzones, y se avisa de ello', () => {
        // Mismo gateway delante, veredictos opuestos: esa es justo la razón del módulo.
        expect(classifyMailHosting(telefonica).kind).toBe('cloud');
        expect(classifyMailHosting(mercadona).kind).toBe('on_premise');
        expect(classifyMailHosting(telefonica).notes.map(n => n.key)).toContain('seg_fronting');
    });

    it('una IP detrás de un CDN NO se lee como infraestructura propia', () => {
        const r = classifyMailHosting({
            domain: 'ejemplo.com',
            mxIds: [{ host: 'mx.proveedor.net', type: 'seg', name: 'X' }],
            autodiscover: { cname: null, ips: ['104.16.1.1'], status: 'ok' },
            ipIntel: { '104.16.1.1': { ip: '104.16.1.1', asn: '13335', asName: 'CLOUDFLARENET', ptr: null } }
        });
        expect(r.kind).toBe('undetermined');
        expect(r.notes.map(n => n.key)).toContain('cdn_asn');
    });

    it('un ASN de hiperescalar por sí solo no basta para afirmar nube', () => {
        // AS8075 cubre Exchange Online y también las VM de Azure donde alguien corre
        // su propio Exchange: el peso está por debajo del umbral a propósito.
        const r = classifyMailHosting({
            domain: 'ejemplo.com',
            mxIds: [],
            autodiscover: { cname: null, ips: ['52.98.1.1'], status: 'ok' },
            ipIntel: { '52.98.1.1': { ip: '52.98.1.1', asn: '8075', asName: 'MICROSOFT', ptr: null } }
        });
        expect(r.kind).toBe('undetermined');
    });

    it('un MX propio por sí solo no basta: puede ser un CNAME a un hosting', () => {
        const solo = classifyMailHosting({
            domain: 'ejemplo.com',
            mxIds: [{ host: 'mail.ejemplo.com', type: 'self', name: 'mail.ejemplo.com' }],
            autodiscover: { cname: null, ips: [], status: 'nxdomain' }
        });
        expect(solo.kind).toBe('undetermined');

        // Con la IP en un ASN que no es de nadie conocido, ya sí.
        const conAsn = classifyMailHosting({
            domain: 'ejemplo.com',
            mxIds: [{ host: 'mail.ejemplo.com', type: 'self', name: 'mail.ejemplo.com' }],
            mxIps: { 'mail.ejemplo.com': ['198.51.100.7'] },
            ipIntel: { '198.51.100.7': { ip: '198.51.100.7', asn: '64500', asName: 'ALGO LOCAL', ptr: null } },
            autodiscover: { cname: null, ips: [], status: 'nxdomain' }
        });
        expect(conAsn.kind).toBe('on_premise');
    });

    it('un fallo de DNS no se presenta como ausencia de registros', () => {
        const r = classifyMailHosting({
            domain: 'ejemplo.com',
            mxIds: [],
            autodiscover: { cname: null, ips: [], status: 'unavailable' }
        });
        expect(r.kind).toBe('undetermined');
        expect(r.incomplete).toBe(true);
        expect(r.notes.map(n => n.key)).toContain('dns_incomplete');
        expect(r.notes.map(n => n.key)).not.toContain('no_autodiscover');
    });

    it('un certificado en CT nunca sostiene solo un veredicto', () => {
        const r = classifyMailHosting({
            domain: 'ugr.es',
            mxIds: [{ host: 'mxb.pphosted.com', type: 'seg', name: 'Proofpoint' }],
            autodiscover: { cname: null, ips: [], status: 'nxdomain' },
            ctHostnames: ['owa.ugr.es', 'webmail.ugr.es']
        });
        expect(r.kind).toBe('undetermined');
    });
});

describe('classifyMailHosting — otros casos', () => {
    it('detecta alojamiento en un tercero', () => {
        const r = classifyMailHosting({
            domain: 'pyme.es',
            mxIds: [],
            autodiscover: { cname: null, ips: ['51.83.1.1'], status: 'ok' },
            ipIntel: { '51.83.1.1': { ip: '51.83.1.1', asn: '16276', asName: 'OVH SAS', ptr: null } }
        });
        expect(r.kind).toBe('hosted_third_party');
        expect(r.platform).toBe('hosted');
        expect(r.hoster).toBe('OVH SAS');
    });

    it('DANE delata un MTA autogestionado', () => {
        const r = classifyMailHosting({
            domain: 'ejemplo.com',
            mxIds: [{ host: 'mail.ejemplo.com', type: 'self', name: 'mail.ejemplo.com' }],
            autodiscover: { cname: null, ips: [], status: 'nxdomain' },
            daneRecords: { 'mail.ejemplo.com': ['3 1 1 abc'] }
        });
        expect(r.kind).toBe('on_premise');
        expect(r.evidence.some(e => e.signal === 'dane')).toBe(true);
    });

    it('un PTR de línea fija de cliente cuenta como señal débil', () => {
        const r = classifyMailHosting(inditex);
        expect(r.evidence.some(e => e.signal === 'ptr_isp_static')).toBe(true);
    });

    it('sin señal alguna devuelve undetermined y evidencia vacía', () => {
        const r = classifyMailHosting({ domain: 'vacio.com' });
        expect(r.kind).toBe('undetermined');
        expect(r.confidence).toBe(0);
        expect(r.evidence).toEqual([]);
    });

    it('tolera una entrada vacía sin reventar', () => {
        expect(() => classifyMailHosting()).not.toThrow();
        expect(classifyMailHosting().kind).toBe('undetermined');
    });

    it('google._domainkey fija la plataforma cuando no hay nada más', () => {
        const r = classifyMailHosting({ domain: 'ejemplo.com', googleDkim: true });
        expect(r.platform).toBe('google');
    });
});

describe('asnMatchesBrand', () => {
    it('reconoce el ASN de la propia empresa', () => {
        expect(asnMatchesBrand('AS_INDITEX - INDUSTRIA DE DISENO TEXTIL, ES', 'inditex.com')).toBe(true);
        expect(asnMatchesBrand('ASMERCADONA - Mercadona S.A, ES', 'mercadona.es')).toBe(true);
    });

    it('no empareja el ASN de un operador ajeno', () => {
        // Contraejemplo real: csic.es anuncia desde RedIRIS, no desde un ASN propio.
        expect(asnMatchesBrand('RedIRIS - Entidad Publica Empresarial Red.es, ES', 'csic.es')).toBe(false);
        expect(asnMatchesBrand('COLT - COLT Technology Services Group Limited, GB', 'congreso.es')).toBe(false);
    });

    it('rechaza etiquetas cortas o genéricas, que emparejarían por casualidad', () => {
        expect(asnMatchesBrand('MAILGUN', 'mail.com')).toBe(false);
        expect(asnMatchesBrand('CLOUDFLARENET', 'cloud.es')).toBe(false);
        expect(asnMatchesBrand('ABC NETWORKS', 'abc.es')).toBe(false);
    });

    it('tolera entradas vacías', () => {
        expect(asnMatchesBrand(null, 'inditex.com')).toBe(false);
        expect(asnMatchesBrand('AS_INDITEX', '')).toBe(false);
    });
});

describe('hostingLevel', () => {
    it('usa los mismos cortes que el resto de la interfaz', () => {
        expect(hostingLevel(0.9)).toBe('alta');
        expect(hostingLevel(0.85)).toBe('alta');
        expect(hostingLevel(0.6)).toBe('media');
        expect(hostingLevel(0.55)).toBe('media');
        expect(hostingLevel(0.3)).toBe('baja');
        expect(hostingLevel(0)).toBe('baja');
    });
});

describe('classifyMailHosting — ramas de desempate', () => {
    it('si autodiscover ya resolvió a la nube, sus IPs no fabrican una pata on-premise', () => {
        // Riesgo real: telefonica.es apunta autodiscover a Microsoft, pero si alguna de
        // esas IPs cayera en un ASN llamado "TELEFONICA", el emparejamiento por marca
        // inventaría un híbrido que no existe. El extremo está en la nube: punto.
        const r = classifyMailHosting({
            domain: 'telefonica.es',
            mxIds: [],
            autodiscover: { cname: 'autodiscover.outlook.com', ips: ['1.2.3.4'], status: 'ok' },
            ipIntel: { '1.2.3.4': { ip: '1.2.3.4', asn: '3352', asName: 'TELEFONICA DE ESPANA', ptr: 'algo.telefonica.es' } }
        });
        expect(r.kind).toBe('cloud');
        expect(r.evidence.some(e => e.signal.startsWith('autodiscover_own'))).toBe(false);
    });

    it('un proveedor cloud que no es Microsoft ni Google queda como plataforma genérica', () => {
        const r = classifyMailHosting({
            domain: 'ejemplo.com',
            mxIds: [{ host: 'mx.zoho.com', type: 'provider', name: 'Zoho Mail' }],
            autodiscover: { cname: null, ips: [], status: 'nxdomain' }
        });
        expect(r.kind).toBe('cloud');
        expect(r.platform).toBe('cloud');
    });

    it('si Cymru no da nombre de organización, se usa el del diccionario', () => {
        const r = classifyMailHosting({
            domain: 'pyme.es',
            mxIds: [],
            autodiscover: { cname: null, ips: ['51.83.1.1'], status: 'ok' },
            ipIntel: { '51.83.1.1': { ip: '51.83.1.1', asn: '16276', asName: null, ptr: null } }
        });
        expect(r.hoster).toBe('OVH');
    });

    it('un CNAME de DKIM sin nombre de tenant sigue contando como señal', () => {
        const r = classifyMailHosting({
            domain: 'ejemplo.com',
            mxIds: [],
            autodiscover: { cname: null, ips: [], status: 'nxdomain' },
            dkimChains: [{ selector: 'selector1', cname: 'sel1._domainkey.x.dkim.mail.microsoft', hasKey: true }]
        });
        expect(r.tenant).toBeNull();
        expect(r.evidence.some(e => e.signal === 'dkim_tenant_m365')).toBe(true);
        expect(r.platform).toBe('m365');
    });

    it('Certificate Transparency sí refuerza cuando hay otra señal que la sostenga', () => {
        const r = classifyMailHosting({
            domain: 'ejemplo.com',
            mxIds: [{ host: 'mail.ejemplo.com', type: 'self', name: 'mail.ejemplo.com' }],
            mxIps: { 'mail.ejemplo.com': ['198.51.100.7'] },
            ipIntel: { '198.51.100.7': { ip: '198.51.100.7', asn: '64500', asName: 'LOCAL', ptr: null } },
            autodiscover: { cname: null, ips: [], status: 'nxdomain' },
            ctHostnames: ['owa.ejemplo.com', 'www.otrodominio.com']
        });
        expect(r.kind).toBe('on_premise');
        expect(r.evidence.some(e => e.signal === 'ct_onprem_host')).toBe(true);
    });

    it('un híbrido sin plataforma cloud identificada se etiqueta como infraestructura propia', () => {
        const r = classifyMailHosting({
            domain: 'ejemplo.com',
            mxIds: [{ host: 'mx.zoho.com', type: 'provider', name: 'Zoho Mail' }],
            autodiscover: { cname: 'correo.ejemplo.com', ips: [], status: 'ok' }
        });
        expect(r.kind).toBe('hybrid');
        expect(r.platform).toBe('own');
    });

    it('un MX propio identificado solo por nombre también cuenta', () => {
        const r = classifyMailHosting({
            domain: 'ejemplo.com',
            mxIds: [{ type: 'self', name: 'mail.ejemplo.com' }],
            autodiscover: { cname: null, ips: [], status: 'nxdomain' },
            daneRecords: { 'mail.ejemplo.com': ['3 1 1 abc'] }
        });
        expect(r.evidence.some(e => e.signal === 'mx_self')).toBe(true);
    });

    it('una IP de autodiscover sin inteligencia disponible no aporta ni resta', () => {
        const r = classifyMailHosting({
            domain: 'ejemplo.com',
            mxIds: [],
            autodiscover: { cname: null, ips: ['203.0.113.9'], status: 'ok' }
        });
        expect(r.kind).toBe('undetermined');
        expect(r.evidence).toEqual([]);
    });
});
