import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { queryDNS, getMX, getDMARC, getDKIM, getSPFLookupTree, checkRBL, getDNSSEC, checkDomainExists, checkDMARCExternalAuth, fetchMTASTSPolicyFile, clearDnsCache } from './api.js';
import { saveSettings, resetSettingsCache, DEFAULT_SETTINGS } from './settings.js';

// Mock de fetch que responde con JSON con forma DoH según (name, type) de la query.
function fetchMock(handler) {
    return vi.fn(async (url) => {
        const u = new URL(url);
        const name = u.searchParams.get('name');
        const type = u.searchParams.get('type');
        return { ok: true, status: 200, json: async () => handler(name, type) };
    });
}

describe('queryDNS (validación del Status DoH)', () => {
    beforeEach(() => clearDnsCache());
    afterEach(() => vi.restoreAllMocks());

    it('hace fallback a Cloudflare cuando Google devuelve SERVFAIL (Status 2)', async () => {
        global.fetch = vi.fn(async (url) => {
            const isGoogle = String(url).startsWith('https://dns.google/');
            return {
                ok: true,
                status: 200,
                json: async () => isGoogle
                    ? { Status: 2 }
                    : { Status: 0, Answer: [{ type: 16, data: '"v=spf1 -all"' }] }
            };
        });
        const data = await queryDNS('broken.example', 'TXT');
        expect(data.Status).toBe(0);
        expect(data.Answer).toHaveLength(1);
        expect(global.fetch).toHaveBeenCalledTimes(2);
    });

    it("lanza code 'servfail' si ambos resolvers fallan, sin cachear el fallo", async () => {
        let mode = 'fail';
        global.fetch = vi.fn(async () => ({
            ok: true,
            status: 200,
            json: async () => mode === 'fail' ? { Status: 2 } : { Status: 0, Answer: [] }
        }));
        await expect(queryDNS('servfail.example', 'TXT')).rejects.toMatchObject({ code: 'servfail' });
        // El fallo no queda cacheado: cuando el resolver se recupera, la misma consulta funciona.
        mode = 'ok';
        const data = await queryDNS('servfail.example', 'TXT');
        expect(data.Status).toBe(0);
    });

    it('NXDOMAIN (Status 3) sigue siendo una respuesta concluyente, no un error', async () => {
        global.fetch = fetchMock(() => ({ Status: 3 }));
        const data = await queryDNS('nope.example', 'TXT');
        expect(data.Status).toBe(3);
        expect(global.fetch).toHaveBeenCalledTimes(1);
    });
});

describe('queryDNS (caché TTL)', () => {
    beforeEach(() => clearDnsCache());
    afterEach(() => vi.restoreAllMocks());

    it('cachea la respuesta: dos llamadas secuenciales = 1 fetch', async () => {
        global.fetch = fetchMock(() => ({ Status: 0, Answer: [] }));
        await queryDNS('cache.example', 'TXT');
        await queryDNS('cache.example', 'TXT');
        expect(global.fetch).toHaveBeenCalledTimes(1);
    });

    it('clearDnsCache invalida la caché: vuelve a consultar', async () => {
        global.fetch = fetchMock(() => ({ Status: 0, Answer: [] }));
        await queryDNS('cache.example', 'TXT');
        clearDnsCache();
        await queryDNS('cache.example', 'TXT');
        expect(global.fetch).toHaveBeenCalledTimes(2);
    });
});

describe('fetchMTASTSPolicyFile', () => {
    beforeEach(() => clearDnsCache());
    afterEach(() => vi.restoreAllMocks());

    it('rechaza una política redirigida (RFC 8461 §3.3)', async () => {
        global.fetch = vi.fn(async () => ({ type: 'opaqueredirect', status: 0, ok: false, text: async () => '' }));
        const r = await fetchMTASTSPolicyFile('ex.com');
        expect(r.validationReason).toBe('redirect_not_allowed');
        expect(r.valid).toBe(false);
    });

    it('usa el código HTTP real del proxy allorigins (404 → fetch_failed)', async () => {
        saveSettings({ allowCorsProxy: true });
        global.fetch = vi.fn(async (url) => {
            if (String(url).includes('allorigins')) {
                return { ok: true, status: 200, json: async () => ({ contents: 'Not Found', status: { http_code: 404 } }) };
            }
            // Fetch directo falla (CORS) → cae al proxy.
            throw new TypeError('Failed to fetch');
        });
        const r = await fetchMTASTSPolicyFile('ex.com');
        expect(r.httpStatus).toBe(404);
        expect(r.validationReason).toBe('fetch_failed');
        saveSettings({ allowCorsProxy: DEFAULT_SETTINGS.allowCorsProxy });
    });

    it('sin el proxy activado no envía el dominio a un tercero', async () => {
        resetSettingsCache();
        const calls = [];
        global.fetch = vi.fn(async (url) => {
            calls.push(String(url));
            throw new TypeError('Failed to fetch');
        });
        const r = await fetchMTASTSPolicyFile('ex.com');
        expect(r.validationReason).toBe('fetch_failed');
        expect(calls.some(u => u.includes('allorigins'))).toBe(false);
    });
});

describe('resolver DoH configurable', () => {
    beforeEach(() => { clearDnsCache(); resetSettingsCache(); });
    afterEach(() => { vi.restoreAllMocks(); saveSettings({ ...DEFAULT_SETTINGS }); resetSettingsCache(); });

    it('usa Google por defecto y cae a los demás si falla', async () => {
        const hosts = [];
        global.fetch = vi.fn(async (url) => {
            hosts.push(new URL(String(url)).host);
            if (hosts.length === 1) throw new TypeError('boom');
            return { ok: true, status: 200, json: async () => ({ Status: 0, Answer: [] }) };
        });
        await queryDNS('ex.com', 'TXT');
        expect(hosts[0]).toBe('dns.google');
        expect(hosts.length).toBeGreaterThan(1);
    });

    it('respeta el resolver elegido como primario', async () => {
        saveSettings({ resolver: 'quad9' });
        const hosts = [];
        global.fetch = vi.fn(async (url) => {
            hosts.push(new URL(String(url)).host);
            return { ok: true, status: 200, json: async () => ({ Status: 0, Answer: [] }) };
        });
        await queryDNS('ex.com', 'TXT');
        expect(hosts[0]).toContain('quad9');
    });

    it('un resolver propio no cae a resolvers públicos (el dominio no sale de tu red)', async () => {
        saveSettings({ resolver: 'custom', customResolverUrl: 'https://dns.interno.local/resolve' });
        const hosts = [];
        global.fetch = vi.fn(async (url) => {
            hosts.push(new URL(String(url)).host);
            throw new TypeError('boom');
        });
        await expect(queryDNS('ex.com', 'TXT')).rejects.toMatchObject({ code: 'network' });
        expect(hosts).toEqual(['dns.interno.local']);
    });
});

describe('queryDNS (deduplicación en vuelo)', () => {
    beforeEach(() => clearDnsCache());
    afterEach(() => vi.restoreAllMocks());

    it('reutiliza la misma promesa para consultas idénticas concurrentes', async () => {
        let calls = 0;
        global.fetch = vi.fn(async () => {
            calls++;
            await Promise.resolve();
            return { ok: true, status: 200, json: async () => ({ Status: 0, Answer: [] }) };
        });
        const [a, b] = await Promise.all([queryDNS('x.example', 'TXT'), queryDNS('x.example', 'TXT')]);
        expect(a).toBe(b);
        expect(calls).toBe(1);
    });
});

describe('getSPFLookupTree', () => {
    beforeEach(() => clearDnsCache());
    afterEach(() => vi.restoreAllMocks());

    const spfMock = (map) => fetchMock((name, type) => {
        if (type !== 'TXT') return { Status: 0 };
        const rec = map[name];
        return rec ? { Status: 0, Answer: [{ type: 16, data: `"${rec}"` }] } : { Status: 0 };
    });

    // Mock que además responde a las sondas de void lookup (A/AAAA/MX).
    const spfMockWithHosts = (spfMap, hostMap = {}) => fetchMock((name, type) => {
        if (type === 'TXT') {
            const rec = spfMap[name];
            return rec ? { Status: 0, Answer: [{ type: 16, data: `"${rec}"` }] } : { Status: 0 };
        }
        const answers = (hostMap[name] || {})[type];
        if (answers === 'nxdomain') return { Status: 3 };
        return answers ? { Status: 0, Answer: answers } : { Status: 0 };
    });

    it('marca no_spf_record cuando el destino de un include no publica SPF', async () => {
        global.fetch = spfMock({ 'ex.com': 'v=spf1 include:roto.com -all' });
        const tree = await getSPFLookupTree('ex.com');
        const child = tree.children.find(c => c.target === 'roto.com');
        expect(child.tree.error).toBe('no_spf_record');
    });

    it('no marca no_spf_record en el ápex (el dominio simplemente no tiene SPF)', async () => {
        global.fetch = spfMock({});
        const tree = await getSPFLookupTree('sin-spf.com');
        expect(tree.error).toBeNull();
        expect(tree.record).toBeNull();
    });

    it('marca void los mecanismos a/mx/exists cuya consulta vuelve vacía o NXDOMAIN', async () => {
        global.fetch = spfMockWithHosts(
            { 'ex.com': 'v=spf1 a:vivo.com a:muerto.com mx:sinmx.com exists:no.com -all' },
            {
                'vivo.com': { A: [{ type: 1, data: '1.2.3.4' }] },
                'muerto.com': { A: 'nxdomain', AAAA: 'nxdomain' },
                'sinmx.com': { MX: null },
                'no.com': { A: 'nxdomain' }
            }
        );
        const tree = await getSPFLookupTree('ex.com');
        const voidOf = (target) => tree.children.find(c => c.target === target).void;
        expect(voidOf('vivo.com')).toBe(false);
        expect(voidOf('muerto.com')).toBe(true);
        expect(voidOf('sinmx.com')).toBe(true);
        expect(voidOf('no.com')).toBe(true);
    });

    it('un host con solo AAAA no cuenta como void', async () => {
        global.fetch = spfMockWithHosts(
            { 'ex.com': 'v=spf1 a:solo-v6.com -all' },
            { 'solo-v6.com': { A: null, AAAA: [{ type: 28, data: '::1' }] } }
        );
        const tree = await getSPFLookupTree('ex.com');
        expect(tree.children.find(c => c.target === 'solo-v6.com').void).toBe(false);
    });

    it('cuenta los mecanismos con máscara CIDR (a/24, mx/24)', async () => {
        global.fetch = spfMock({ 'ex.com': 'v=spf1 a/24 mx/24 -all' });
        const tree = await getSPFLookupTree('ex.com');
        expect(tree.lookups).toBe(2);
    });

    it('un include repetido entre ramas hermanas no es un bucle', async () => {
        global.fetch = spfMock({
            'root.com': 'v=spf1 include:a.com include:b.com -all',
            'a.com': 'v=spf1 include:shared.com -all',
            'b.com': 'v=spf1 include:shared.com -all',
            'shared.com': 'v=spf1 ip4:1.2.3.4 -all'
        });
        const tree = await getSPFLookupTree('root.com');
        // 2 includes directos + 1 include dentro de cada rama = 4; ninguna marca 'loop'.
        expect(tree.lookups).toBe(4);
        const flatErrors = JSON.stringify(tree).match(/"error":"loop"/g);
        expect(flatErrors).toBeNull();
    });

    it('detecta un bucle real (a→b→a)', async () => {
        global.fetch = spfMock({
            'a.com': 'v=spf1 include:b.com -all',
            'b.com': 'v=spf1 include:a.com -all'
        });
        const tree = await getSPFLookupTree('a.com');
        expect(JSON.stringify(tree)).toContain('"error":"loop"');
    });
});

describe('getDKIM (TXT multi-string)', () => {
    beforeEach(() => clearDnsCache());
    afterEach(() => vi.restoreAllMocks());

    it('concatena una clave DKIM partida en varios chunks entrecomillados', async () => {
        global.fetch = fetchMock((name) =>
            name === 'default._domainkey.ex.com'
                ? { Status: 0, Answer: [{ type: 16, data: '"v=DKIM1; k=rsa; p=AAAA" "BBBBCCCC"' }] }
                : { Status: 0 }
        );
        const r = await getDKIM('ex.com', 'default');
        expect(r.records).toHaveLength(1);
        expect(r.records[0].record).toBe('v=DKIM1; k=rsa; p=AAAABBBBCCCC');
    });
});

describe('getMX (Null MX y robustez)', () => {
    beforeEach(() => clearDnsCache());
    afterEach(() => vi.restoreAllMocks());

    it('reconoce Null MX (RFC 7505, "0 .") como array vacío marcado', async () => {
        global.fetch = fetchMock(() => ({ Status: 0, Answer: [{ type: 15, data: '0 .' }] }));
        const mx = await getMX('parked.example');
        expect(mx).toHaveLength(0);
        expect(mx.nullMx).toBe(true);
    });

    it('ordena por prioridad y quita el punto final del host', async () => {
        global.fetch = fetchMock(() => ({ Status: 0, Answer: [
            { type: 15, data: '20 mx2.example.com.' },
            { type: 15, data: '10 mx1.example.com.' }
        ] }));
        const mx = await getMX('example.com');
        expect(mx.map(r => r.host)).toEqual(['mx1.example.com', 'mx2.example.com']);
        expect(mx.nullMx).toBeUndefined();
    });

    it('descarta registros MX malformados sin lanzar', async () => {
        global.fetch = fetchMock(() => ({ Status: 0, Answer: [
            { type: 15, data: '10' },
            { type: 15, data: '5 mx.example.com.' }
        ] }));
        const mx = await getMX('example.com');
        expect(mx).toHaveLength(1);
        expect(mx[0].host).toBe('mx.example.com');
    });
});

describe('getDMARC (herencia del dominio organizativo)', () => {
    beforeEach(() => clearDnsCache());
    afterEach(() => vi.restoreAllMocks());

    it('devuelve el registro del subdominio cuando existe', async () => {
        global.fetch = fetchMock((name) =>
            name === '_dmarc.mail.example.com'
                ? { Status: 0, Answer: [{ type: 16, data: '"v=DMARC1; p=reject"' }] }
                : { Status: 0 }
        );
        const r = await getDMARC('mail.example.com');
        expect(r.record).toContain('p=reject');
    });
});

describe('checkRBL', () => {
    beforeEach(() => clearDnsCache());
    afterEach(() => vi.restoreAllMocks());

    it('listed con código 127.0.0.2', async () => {
        global.fetch = fetchMock(() => ({ Status: 0, Answer: [{ type: 1, data: '127.0.0.2' }] }));
        const r = await checkRBL('1.2.3.4', 'bl.example');
        expect(r.status).toBe('listed');
        expect(r.listed).toBe(true);
    });

    it('error/inconcluso con 127.255.255.254 (resolver público bloqueado)', async () => {
        global.fetch = fetchMock(() => ({ Status: 0, Answer: [{ type: 1, data: '127.255.255.254' }] }));
        const r = await checkRBL('1.2.3.4', 'bl.example');
        expect(r.status).toBe('error');
        expect(r.listed).toBe(false);
    });

    it('clean cuando no hay respuesta (NXDOMAIN)', async () => {
        global.fetch = fetchMock(() => ({ Status: 3 }));
        const r = await checkRBL('1.2.3.4', 'bl.example');
        expect(r.status).toBe('clean');
        expect(r.listed).toBe(false);
    });
});

describe('checkDomainExists', () => {
    beforeEach(() => clearDnsCache());
    afterEach(() => vi.restoreAllMocks());

    it('false en NXDOMAIN (Status 3)', async () => {
        global.fetch = fetchMock(() => ({ Status: 3 }));
        expect(await checkDomainExists('nope.example')).toBe(false);
    });

    it('true cuando el dominio existe (Status 0)', async () => {
        global.fetch = fetchMock(() => ({ Status: 0, Answer: [{ type: 2, data: 'ns1.example.com.' }] }));
        expect(await checkDomainExists('exists.example')).toBe(true);
    });
});

describe('getDNSSEC', () => {
    beforeEach(() => clearDnsCache());
    afterEach(() => vi.restoreAllMocks());

    it('signed cuando hay DNSKEY (type 48) y flag AD', async () => {
        global.fetch = fetchMock(() => ({ Status: 0, AD: true, Answer: [{ type: 48, data: '256 3 8 AwEAAd...' }] }));
        const r = await getDNSSEC('signed.example');
        expect(r.signed).toBe(true);
        expect(r.ad).toBe(true);
    });

    it('no firmado sin DNSKEY', async () => {
        global.fetch = fetchMock(() => ({ Status: 0, AD: false }));
        const r = await getDNSSEC('plain.example');
        expect(r.signed).toBe(false);
    });
});

describe('checkDMARCExternalAuth', () => {
    beforeEach(() => clearDnsCache());
    afterEach(() => vi.restoreAllMocks());

    it('authorized=true cuando el destino publica _report._dmarc', async () => {
        global.fetch = fetchMock((name) =>
            name === 'acme.com._report._dmarc.ext.com'
                ? { Status: 0, Answer: [{ type: 16, data: '"v=DMARC1"' }] }
                : { Status: 0 }
        );
        const r = await checkDMARCExternalAuth('acme.com', ['mailto:rua@ext.com']);
        expect(r).toHaveLength(1);
        expect(r[0].destDomain).toBe('ext.com');
        expect(r[0].authorized).toBe(true);
    });

    it('authorized=false cuando el destino externo no autoriza', async () => {
        global.fetch = fetchMock(() => ({ Status: 0 }));
        const r = await checkDMARCExternalAuth('acme.com', ['mailto:rua@ext.com']);
        expect(r[0].authorized).toBe(false);
    });

    it('ignora destinos del mismo dominio', async () => {
        global.fetch = fetchMock(() => ({ Status: 0 }));
        const r = await checkDMARCExternalAuth('acme.com', ['mailto:rua@acme.com']);
        expect(r).toHaveLength(0);
    });
});
