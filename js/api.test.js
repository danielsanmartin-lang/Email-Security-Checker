import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { queryDNS, getMX, getDMARC, getDKIM, getSPFLookupTree, checkRBL, getDNSSEC, checkDomainExists, checkDMARCExternalAuth, fetchMTASTSPolicyFile, clearDnsCache, reverseIpForDns, getAutodiscover, getIpIntel, getDkimSelectorChain, discoverDmarcPolicy, isDmarcRecord, isDkimKeyRecord, getMTASTS, getDANE, checkLookalikes } from './api.js';
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

describe('queryDNS (semáforo de concurrencia)', () => {
    beforeEach(() => { clearDnsCache(); resetSettingsCache(); saveSettings({ ...DEFAULT_SETTINGS }); });
    afterEach(() => vi.restoreAllMocks());

    // Un análisis real dispara ~120 consultas en picos de 40 simultáneas, y los
    // autoritativos frágiles responden SERVFAIL a parte de la ráfaga. El tope es la
    // razón de ser del cambio, así que se fija aquí.
    it('nunca supera 6 consultas en vuelo por muchas que se pidan a la vez', async () => {
        let active = 0, max = 0;
        global.fetch = vi.fn(async () => {
            active++;
            if (active > max) max = active;
            await new Promise(r => setTimeout(r, 5));
            active--;
            return { ok: true, status: 200, json: async () => ({ Status: 0, Answer: [] }) };
        });
        // 40 nombres DISTINTOS: con el mismo nombre la deduplicación en vuelo los
        // colapsaría en una sola consulta y el test no probaría nada.
        await Promise.all(Array.from({ length: 40 }, (_, i) => queryDNS(`h${i}.example`, 'TXT')));
        // Exactamente 6, no "como mucho 6": así el test también detecta que la piscina se
        // aproveche entera y no se serialice de más.
        expect(max).toBe(6);
        expect(global.fetch).toHaveBeenCalledTimes(40);
    });

    it('un acierto de caché no pide turno: responde con la piscina saturada', async () => {
        // Fija el ORDEN dentro de queryDNS: si la comprobación de caché se moviera detrás
        // del semáforo, esta consulta ya resuelta se quedaría esperando detrás de las 6
        // bloqueadas y el test moriría por timeout.
        let abrir;
        const puerta = new Promise(r => { abrir = r; });
        global.fetch = vi.fn(async (url) => {
            if (new URL(String(url)).searchParams.get('name') !== 'cacheada.example') await puerta;
            return { ok: true, status: 200, json: async () => ({ Status: 0, Answer: [] }) };
        });
        await queryDNS('cacheada.example', 'TXT');
        const bloqueadas = Array.from({ length: 6 }, (_, i) => queryDNS(`b${i}.example`, 'TXT'));
        await expect(queryDNS('cacheada.example', 'TXT')).resolves.toBeTruthy();
        abrir(); // imprescindible: si no, los 6 turnos se filtrarían al siguiente test
        await Promise.all(bloqueadas);
    });

    it('las sondas void encadenadas (A→AAAA) tampoco bloquean la piscina', async () => {
        // _probeVoidLookup consulta A y, si viene vacía, AAAA: DNS dependiente EN SERIE.
        // Si el turno envolviera la sonda entera en vez de cada consulta, 6 sondas
        // reteniendo turno y necesitando un séptimo se bloquearían entre ellas.
        const mecanismos = Array.from({ length: 10 }, (_, i) => `a:h${i}.com`).join(' ');
        global.fetch = fetchMock((name, type) => {
            if (type === 'TXT' && name === 'ex.com') {
                return { Status: 0, Answer: [{ type: 16, data: `"v=spf1 ${mecanismos} -all"` }] };
            }
            return { Status: 0 }; // A y AAAA vacías: todas void
        });
        const tree = await getSPFLookupTree('ex.com');
        expect(tree.children.filter(c => c.void === true)).toHaveLength(10);
    });

    it('el árbol SPF recursivo no se bloquea con la piscina llena', async () => {
        // Regresión del riesgo de deadlock: si un nodo padre retuviera su hueco mientras
        // espera a los includes hijos, una cadena más profunda que la piscina no
        // terminaría nunca. La cadena tiene 8 niveles y la piscina 6.
        global.fetch = fetchMock((name, type) => {
            if (type !== 'TXT') return { Status: 0 };
            const m = name.match(/^n(\d+)\.example$/);
            if (m) {
                const i = Number(m[1]);
                const rec = i < 8 ? `v=spf1 include:n${i + 1}.example -all` : 'v=spf1 -all';
                return { Status: 0, Answer: [{ type: 16, data: `"${rec}"` }] };
            }
            return { Status: 0 };
        });
        // Se satura la piscina con consultas lentas en paralelo al árbol.
        const ruido = Array.from({ length: 20 }, (_, i) => queryDNS(`ruido${i}.example`, 'A'));
        const tree = await getSPFLookupTree('n0.example');
        await Promise.all(ruido);
        expect(JSON.stringify(tree)).toContain('n8.example');
    });
});

describe('queryDNS (reintento ante SERVFAIL)', () => {
    beforeEach(() => { clearDnsCache(); resetSettingsCache(); saveSettings({ ...DEFAULT_SETTINGS }); });
    afterEach(() => vi.restoreAllMocks());

    it('reintenta una vez y acierta si la zona se recupera', async () => {
        // Comportamiento real medido en gruporamos.com: el SERVFAIL es transitorio y el
        // subconjunto de consultas que falla cambia en cada pasada.
        let vuelta = 0;
        global.fetch = vi.fn(async () => {
            vuelta++;
            // Las 3 primeras (la cadena entera de resolvers) fallan; a partir de ahí, bien.
            return { ok: true, status: 200, json: async () => vuelta <= 3 ? { Status: 2 } : { Status: 0, Answer: [] } };
        });
        const data = await queryDNS('flaky.example', 'TXT');
        expect(data.Status).toBe(0);
        expect(vuelta).toBe(4); // 3 de la primera cadena + 1 acierto en el reintento
    });

    it('un fallo de red NO se reintenta: el problema es local, no de la zona', async () => {
        global.fetch = vi.fn(async () => { throw new TypeError('offline'); });
        await expect(queryDNS('sinred.example', 'TXT')).rejects.toMatchObject({ code: 'network' });
        // Una sola pasada por los tres resolvers, sin segunda ronda.
        expect(global.fetch).toHaveBeenCalledTimes(3);
    });

    it('REFUSED (RCODE 5) no se reintenta: es una negativa deliberada, no un tropiezo', async () => {
        // Caso real en checkRBL: las DNSBL rechazan las consultas que les llegan vía
        // resolver público. Reintentar da exactamente la misma respuesta, así que sería
        // 300 ms de espera por comprobación a cambio de nada.
        global.fetch = fetchMock(() => ({ Status: 5 }));
        await expect(queryDNS('refused.example', 'TXT')).rejects.toMatchObject({ code: 'servfail', rcode: 5 });
        expect(global.fetch).toHaveBeenCalledTimes(3);
    });

    it('deja de reintentar una zona ya demostrada caída (no se paga 300 ms por nombre)', async () => {
        // El detector de awareness sondea 17 selectores EN SERIE. Sin este corte, un
        // dominio con el DNS roto se llevaba +5 s de reloj para no averiguar nada.
        global.fetch = fetchMock(() => ({ Status: 2 }));
        // Primer nombre: 3 resolvers + espera + 3 resolvers = 6, y la zona queda anotada.
        await expect(queryDNS('a._domainkey.rota.example', 'TXT')).rejects.toMatchObject({ code: 'servfail' });
        expect(global.fetch).toHaveBeenCalledTimes(6);
        // Los siguientes nombres de la MISMA zona se rinden a la primera pasada.
        await expect(queryDNS('b._domainkey.rota.example', 'TXT')).rejects.toMatchObject({ code: 'servfail' });
        expect(global.fetch).toHaveBeenCalledTimes(9);
        // Otra zona distinta conserva su reintento: el corte es por zona, no global.
        await expect(queryDNS('c.otra.example', 'TXT')).rejects.toMatchObject({ code: 'servfail' });
        expect(global.fetch).toHaveBeenCalledTimes(15);
    });

    it('con resolver propio no se reintenta (no se le dobla el tráfico a tu infra)', async () => {
        saveSettings({ resolver: 'custom', customResolverUrl: 'https://dns.interno.local/resolve' });
        global.fetch = fetchMock(() => ({ Status: 2 }));
        await expect(queryDNS('ex.com', 'TXT')).rejects.toMatchObject({ code: 'servfail' });
        expect(global.fetch).toHaveBeenCalledTimes(1);
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

    it('marca la CAUSA de cada selector sin comprobar y cuántos se intentaron', async () => {
        // "No se pudo comprobar" no es lo mismo que "no hay DKIM ahí", y un SERVFAIL de la
        // zona auditada no es lo mismo que quedarse sin red: la UI dice cosas distintas.
        global.fetch = fetchMock(() => ({ Status: 2 }));
        const r = await getDKIM('rota.example', ['s1', 's2']);
        expect(r.attempted).toBe(2);
        expect(r.records).toHaveLength(0);
        expect(r.errors.map(e => e.selector).sort()).toEqual(['s1', 's2']);
        expect(r.errors.every(e => e.code === 'servfail')).toBe(true);
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

describe('fetchMTASTSPolicyFile: validación del dominio en el punto del fetch', () => {
    afterEach(() => vi.restoreAllMocks());

    it('rechaza un dominio con formato inválido sin llegar a hacer la petición', async () => {
        global.fetch = vi.fn();
        const r = await fetchMTASTSPolicyFile('no es un dominio/../etc');
        expect(r.validationReason).toBe('invalid_domain');
        expect(r.valid).toBe(false);
        expect(global.fetch).not.toHaveBeenCalled();
    });
});

describe('checkDMARCExternalAuth: la comparación es por dominio ORGANIZATIVO (RFC 7489 §7.1)', () => {
    // Sin limpiar la caché, la respuesta del test anterior para el mismo nombre se
    // reutiliza y el siguiente caso mide lo que no es.
    beforeEach(() => clearDnsCache());
    afterEach(() => vi.restoreAllMocks());

    // El RFC exige verificación solo cuando difiere el dominio organizativo. Comparar
    // cadenas exactas acusaba de "destino externo no autorizado" a quien manda los
    // informes a un subdominio propio, que es la práctica habitual (amazon.com →
    // dmarc.amazon.com): un error rojo sobre una configuración correcta.
    const noDebeConsultar = async (domain, uris) => {
        const fetchSpy = vi.fn();
        global.fetch = fetchSpy;
        const r = await checkDMARCExternalAuth(domain, uris);
        expect(r).toEqual([]);
        expect(fetchSpy).not.toHaveBeenCalled();
    };

    it('un subdominio propio no requiere autorización', async () => {
        await noDebeConsultar('amazon.com', ['mailto:report@dmarc.amazon.com']);
    });

    it('tampoco al analizar un subdominio cuyo destino cuelga del dominio raíz', async () => {
        await noDebeConsultar('news.acme.com', ['mailto:r@dmarc.acme.com']);
    });

    it('funciona con TLD compuestos', async () => {
        await noDebeConsultar('acme.co.uk', ['mailto:r@dmarc.acme.co.uk']);
    });

    it('un destino realmente externo SÍ se verifica y se marca si falta el registro', async () => {
        global.fetch = vi.fn(async () => ({ ok: true, status: 200, json: async () => ({ Status: 3 }) }));
        const r = await checkDMARCExternalAuth('acme.com', ['mailto:r@rua.proveedor.com']);
        expect(r).toEqual([{ uri: 'mailto:r@rua.proveedor.com', destDomain: 'rua.proveedor.com', authorized: false }]);
        expect(global.fetch).toHaveBeenCalled();
    });

    it('y se marca autorizado si el destino publica el registro', async () => {
        global.fetch = vi.fn(async () => ({
            ok: true, status: 200,
            json: async () => ({ Status: 0, Answer: [{ type: 16, data: '"v=DMARC1"' }] })
        }));
        const r = await checkDMARCExternalAuth('acme.com', ['mailto:r@rua.proveedor.com']);
        expect(r[0].authorized).toBe(true);
    });
});

// ===========================================================================
// Sondas del hospedaje del correo
// Las respuestas de Team Cymru son TRANSCRIPCIONES literales de consultas reales:
// si el formato del TXT cambia, el parser debe romperse aquí y no en producción.
// ===========================================================================

describe('reverseIpForDns', () => {
    it('invierte IPv4 por octetos', () => {
        expect(reverseIpForDns('195.77.161.26')).toBe('26.161.77.195');
    });

    it('expande e invierte IPv6 por nibbles, incluida la abreviatura ::', () => {
        expect(reverseIpForDns('2001:db8::1')).toBe(
            '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2'
        );
    });

    it('devuelve null ante entradas que no son una IP', () => {
        expect(reverseIpForDns('no-soy-una-ip')).toBeNull();
        expect(reverseIpForDns('1.2.3')).toBeNull();
        expect(reverseIpForDns('999.1.1.1')).toBeNull();
        expect(reverseIpForDns('')).toBeNull();
        expect(reverseIpForDns(null)).toBeNull();
    });
});

describe('getAutodiscover', () => {
    beforeEach(() => clearDnsCache());
    afterEach(() => vi.restoreAllMocks());

    it('conserva el CNAME de la cadena además de la IP final', async () => {
        global.fetch = fetchMock((name) => {
            if (name === 'autodiscover.acme.com') {
                return { Status: 0, Answer: [
                    { type: 5, data: 'autodiscover.outlook.com.' },
                    { type: 1, data: '52.98.1.1' }
                ] };
            }
            return { Status: 3, Answer: [] };
        });
        const r = await getAutodiscover('acme.com');
        expect(r.cname).toBe('autodiscover.outlook.com');
        expect(r.ips).toEqual(['52.98.1.1']);
        expect(r.status).toBe('ok');
    });

    it('distingue "no existe" de "no se pudo consultar"', async () => {
        // Esta distinción es la que impide leer un fallo de red como ausencia de
        // autodiscover, y de ahí como indicio de servidor propio.
        global.fetch = fetchMock(() => ({ Status: 3, Answer: [] }));
        expect((await getAutodiscover('acme.com')).status).toBe('nxdomain');

        clearDnsCache();
        global.fetch = fetchMock(() => ({ Status: 2, Answer: [] }));
        const r = await getAutodiscover('acme.com');
        expect(r.status).toBe('unavailable');
        expect(r.cname).toBeNull();
    });
});

describe('getIpIntel', () => {
    beforeEach(() => clearDnsCache());
    afterEach(() => vi.restoreAllMocks());

    it('parsea el ASN, el prefijo, el país y el nombre de la organización', async () => {
        global.fetch = fetchMock((name) => {
            if (name === '26.161.77.195.origin.asn.cymru.com') {
                return { Status: 0, Answer: [{ type: 16, data: '"204748 | 195.77.160.0/23 | ES | ripencc | 1996-12-02"' }] };
            }
            if (name === 'AS204748.asn.cymru.com') {
                return { Status: 0, Answer: [{ type: 16, data: '"204748 | ES | ripencc | 2018-01-16 | AS_INDITEX - INDUSTRIA DE DISENO TEXTIL SOCIEDAD ANONIMA, ES"' }] };
            }
            if (name === '26.161.77.195.in-addr.arpa') {
                return { Status: 0, Answer: [{ type: 12, data: '26.red-195-77-161.customer.static.ccgg.telefonica.net.' }] };
            }
            return { Status: 3, Answer: [] };
        });
        const r = await getIpIntel('195.77.161.26');
        expect(r.asn).toBe('204748');
        expect(r.prefix).toBe('195.77.160.0/23');
        expect(r.cc).toBe('ES');
        expect(r.asName).toBe('AS_INDITEX - INDUSTRIA DE DISENO TEXTIL SOCIEDAD ANONIMA, ES');
        expect(r.ptr).toBe('26.red-195-77-161.customer.static.ccgg.telefonica.net');
    });

    it('degrada a null cuando Cymru no responde, sin inventar nada', async () => {
        global.fetch = fetchMock(() => ({ Status: 3, Answer: [] }));
        const r = await getIpIntel('198.51.100.1');
        expect(r.asn).toBeNull();
        expect(r.asName).toBeNull();
        expect(r.ptr).toBeNull();
    });

    it('no consulta nada si la IP no es válida', async () => {
        global.fetch = fetchMock(() => ({ Status: 0, Answer: [] }));
        const r = await getIpIntel('no-es-ip');
        expect(global.fetch).not.toHaveBeenCalled();
        expect(r.asn).toBeNull();
    });

    it('usa la zona IPv6 de Cymru para direcciones IPv6', async () => {
        const seen = [];
        global.fetch = fetchMock((name) => { seen.push(name); return { Status: 3, Answer: [] }; });
        await getIpIntel('2001:db8::1');
        expect(seen.some(n => n.endsWith('.origin6.asn.cymru.com'))).toBe(true);
        expect(seen.some(n => n.endsWith('.ip6.arpa'))).toBe(true);
    });
});

describe('getDkimSelectorChain', () => {
    beforeEach(() => clearDnsCache());
    afterEach(() => vi.restoreAllMocks());

    it('conserva el CNAME al tenant, que es lo que getDKIM descarta', async () => {
        global.fetch = fetchMock((name) => {
            if (name === 'selector1._domainkey.acme.com') {
                return { Status: 0, Answer: [
                    { type: 5, data: 'selector1-acme-com._domainkey.acmetenant.onmicrosoft.com.' },
                    { type: 16, data: '"v=DKIM1; k=rsa; p=MIIB"' }
                ] };
            }
            return { Status: 3, Answer: [] };
        });
        const r = await getDkimSelectorChain('acme.com', ['selector1', 'selector2']);
        expect(r).toHaveLength(2);
        expect(r[0].cname).toBe('selector1-acme-com._domainkey.acmetenant.onmicrosoft.com');
        expect(r[0].hasKey).toBe(true);
        expect(r[1].cname).toBeNull();
    });

    it('reutiliza la caché de la consulta que ya hizo getDKIM', async () => {
        global.fetch = fetchMock(() => ({ Status: 0, Answer: [{ type: 16, data: '"v=DKIM1; p=abc"' }] }));
        await queryDNS('selector1._domainkey.acme.com', 'TXT');
        const antes = global.fetch.mock.calls.length;
        await getDkimSelectorChain('acme.com', ['selector1']);
        expect(global.fetch.mock.calls.length).toBe(antes);
    });
});

// ===========================================================================
// RFC 9989 / 9990: Tree Walk, verificación de destinos externos y reconocimiento
// ===========================================================================

// Zona simulada: nombre → lista de TXT. Lo que no está responde NXDOMAIN.
function txtZone(zone) {
    return fetchMock((name, type) => {
        if (type === 'TXT' && zone[name]) {
            return { Status: 0, Answer: zone[name].map(v => ({ type: 16, data: `"${v}"` })) };
        }
        return { Status: 3 };
    });
}

describe('isDmarcRecord (RFC 9989 §4.7/§4.8)', () => {
    it('admite espacios alrededor del "=" y exige DMARC1 exacto', () => {
        expect(isDmarcRecord('v=DMARC1; p=reject')).toBe(true);
        expect(isDmarcRecord('v = DMARC1; p=reject')).toBe(true);
        expect(isDmarcRecord('v=DMARC1')).toBe(true);
        expect(isDmarcRecord('v=DMARC10; p=reject')).toBe(false);
        expect(isDmarcRecord('v=dmarc1; p=reject')).toBe(false);
        expect(isDmarcRecord('p=reject; v=DMARC1')).toBe(false);
    });
});

describe('discoverDmarcPolicy (DNS Tree Walk)', () => {
    beforeEach(() => clearDnsCache());
    afterEach(() => vi.restoreAllMocks());

    it('usa el registro propio y aun así determina el dominio organizativo', async () => {
        global.fetch = txtZone({ '_dmarc.example.com': ['v=DMARC1; p=reject'] });
        const r = await discoverDmarcPolicy('example.com');
        expect(r).toMatchObject({ source: 'author', policyDomain: 'example.com', orgDomain: 'example.com', inherited: false });
        expect(r.walked.map(w => w.name)).toEqual(['example.com', 'com']);
    });

    it('un subdominio sin registro hereda el del dominio organizativo', async () => {
        global.fetch = txtZone({ '_dmarc.example.com': ['v=DMARC1; p=reject; sp=quarantine'] });
        const r = await discoverDmarcPolicy('shop.example.com');
        expect(r).toMatchObject({ source: 'org', policyDomain: 'example.com', orgDomain: 'example.com', inherited: true, inheritedFrom: 'example.com' });
        expect(r.record).toContain('sp=quarantine');
    });

    it('funciona con marcas cortas bajo un ccTLD (la heurística no lo hacía)', async () => {
        global.fetch = txtZone({ '_dmarc.abc.es': ['v=DMARC1; p=reject'] });
        const r = await discoverDmarcPolicy('correo.abc.es');
        expect(r).toMatchObject({ source: 'org', policyDomain: 'abc.es', orgDomain: 'abc.es' });
    });

    it('psd=n en un nivel intermedio lo declara organizativo y detiene la búsqueda', async () => {
        global.fetch = txtZone({
            '_dmarc.dept.example.com': ['v=DMARC1; p=quarantine; psd=n'],
            '_dmarc.example.com': ['v=DMARC1; p=reject']
        });
        const r = await discoverDmarcPolicy('a.dept.example.com');
        expect(r).toMatchObject({ source: 'org', orgDomain: 'dept.example.com', policyDomain: 'dept.example.com' });
    });

    it('varios registros en el propio dominio se descartan y se sube a buscar', async () => {
        global.fetch = txtZone({
            '_dmarc.shop.example.com': ['v=DMARC1; p=none', 'v=DMARC1; p=reject'],
            '_dmarc.example.com': ['v=DMARC1; p=quarantine']
        });
        const r = await discoverDmarcPolicy('shop.example.com');
        expect(r.multiple).toBe(true);
        expect(r.records).toHaveLength(2);
        expect(r).toMatchObject({ source: 'org', policyDomain: 'example.com' });
    });

    it('en el dominio organizativo, varios registros significan no tener política', async () => {
        global.fetch = txtZone({ '_dmarc.example.com': ['v=DMARC1; p=none', 'v=DMARC1; p=reject'] });
        const r = await discoverDmarcPolicy('example.com');
        expect(r).toMatchObject({ multiple: true, record: null, source: null });
    });

    it('un ancestro que no responde deja la búsqueda incompleta, no "sin registro"', async () => {
        global.fetch = fetchMock((name) => {
            if (name === '_dmarc.com') return { Status: 2 };
            if (name === '_dmarc.example.com') return { Status: 3 };
            return { Status: 3 };
        });
        const r = await discoverDmarcPolicy('example.com');
        expect(r.incomplete).toBe(true);
        expect(r.walked.find(w => w.name === 'com').status).toBe('error');
    });

    it('un SERVFAIL en el propio dominio se propaga (DMARC "no disponible")', async () => {
        global.fetch = fetchMock(() => ({ Status: 2 }));
        await expect(discoverDmarcPolicy('rota.example')).rejects.toMatchObject({ code: 'servfail' });
    });
});

describe('checkDMARCExternalAuth (RFC 9990 §4)', () => {
    beforeEach(() => clearDnsCache());
    afterEach(() => vi.restoreAllMocks());

    it('antepone el dominio DONDE se encontró la política, no el subdominio auditado', async () => {
        const asked = [];
        global.fetch = fetchMock((name) => {
            asked.push(name);
            return name === 'example.com._report._dmarc.rua.vendor.net'
                ? { Status: 0, Answer: [{ type: 16, data: '"v=DMARC1"' }] }
                : { Status: 3 };
        });
        const r = await checkDMARCExternalAuth('example.com', ['mailto:x@rua.vendor.net'], { orgDomain: 'example.com' });
        expect(r[0].authorized).toBe(true);
        expect(asked).toContain('example.com._report._dmarc.rua.vendor.net');
    });

    it('un destino bajo el dominio organizativo no se verifica, aunque la marca sea corta', async () => {
        const fetchSpy = vi.fn();
        global.fetch = fetchSpy;
        const r = await checkDMARCExternalAuth('abc.es', ['mailto:d@reports.abc.es'], { orgDomain: 'abc.es' });
        expect(r).toEqual([]);
        expect(fetchSpy).not.toHaveBeenCalled();
    });

    it('con psd=n, un destino en el dominio padre SÍ es externo', async () => {
        global.fetch = fetchMock(() => ({ Status: 3 }));
        const r = await checkDMARCExternalAuth('dept.example.com', ['mailto:d@example.com'], { orgDomain: 'dept.example.com' });
        expect(r[0]).toMatchObject({ destDomain: 'example.com', authorized: false });
    });

    it('el registro de autorización exige v=DMARC1 al principio y respeta mayúsculas', async () => {
        global.fetch = fetchMock(() => ({ Status: 0, Answer: [{ type: 16, data: '"v=dmarc1"' }] }));
        const r = await checkDMARCExternalAuth('example.com', ['mailto:x@ext.net'], { orgDomain: 'example.com' });
        expect(r[0].authorized).toBe(false);
    });

    it('expone el rua con el que el receptor reescribe el destino', async () => {
        global.fetch = fetchMock(() => ({ Status: 0, Answer: [{ type: 16, data: '"v=DMARC1; rua=mailto:otro@ext.net"' }] }));
        const r = await checkDMARCExternalAuth('example.com', ['mailto:x@ext.net'], { orgDomain: 'example.com' });
        expect(r[0]).toMatchObject({ authorized: true, override: 'mailto:otro@ext.net' });
    });
});

describe('DKIM: v= es opcional (RFC 6376 §3.6.1)', () => {
    beforeEach(() => clearDnsCache());
    afterEach(() => vi.restoreAllMocks());

    it('isDkimKeyRecord', () => {
        expect(isDkimKeyRecord('v=DKIM1; k=rsa; p=AAAA')).toBe(true);
        expect(isDkimKeyRecord('k=rsa; p=AAAA')).toBe(true);
        expect(isDkimKeyRecord('p=')).toBe(true);
        expect(isDkimKeyRecord('v=DKIM2; p=AAAA')).toBe(false);
        expect(isDkimKeyRecord('google-site-verification=abc')).toBe(false);
    });

    it('getDKIM encuentra una clave publicada sin v=DKIM1', async () => {
        global.fetch = fetchMock((name) =>
            name === 's1._domainkey.ex.com'
                ? { Status: 0, Answer: [{ type: 16, data: '"k=rsa; p=AAAABBBB"' }] }
                : { Status: 3 }
        );
        const r = await getDKIM('ex.com', 's1');
        expect(r.records).toHaveLength(1);
    });
});

describe('MTA-STS sin contactar con el dominio auditado', () => {
    beforeEach(() => { clearDnsCache(); resetSettingsCache(); saveSettings({ ...DEFAULT_SETTINGS }); });
    afterEach(() => { vi.restoreAllMocks(); saveSettings({ ...DEFAULT_SETTINGS }); resetSettingsCache(); });

    const dohAndPolicy = (hostExists) => vi.fn(async (url) => {
        const href = String(url);
        if (href.includes('mta-sts.acme.com/.well-known')) {
            return { ok: true, status: 200, type: 'basic', text: async () => 'version: STSv1\nmode: enforce\nmx: mx.acme.com\nmax_age: 604800\n' };
        }
        const u = new URL(href);
        const name = u.searchParams.get('name');
        const type = u.searchParams.get('type');
        let body = { Status: 3 };
        if (name === '_mta-sts.acme.com' && type === 'TXT') body = { Status: 0, Answer: [{ type: 16, data: '"v=STSv1; id=1"' }] };
        if (hostExists && name === 'mta-sts.acme.com' && type === 'A') body = { Status: 0, Answer: [{ type: 1, data: '192.0.2.10' }] };
        return { ok: true, status: 200, json: async () => body };
    });

    it('por defecto no descarga la política: ni una petición a mta-sts.<dominio>', async () => {
        global.fetch = dohAndPolicy(true);
        const r = await getMTASTS('acme.com');
        expect(r.policy.validationReason).toBe('not_fetched');
        expect(global.fetch.mock.calls.some(([u]) => String(u).includes('mta-sts.acme.com/.well-known'))).toBe(false);
    });

    it('si mta-sts.<dominio> no resuelve, la política está rota (solo DNS)', async () => {
        global.fetch = dohAndPolicy(false);
        const r = await getMTASTS('acme.com');
        expect(r.policy).toMatchObject({ validationReason: 'host_missing', host: 'mta-sts.acme.com' });
    });

    it('con el ajuste activado, la descarga directa se hace y sin Referer', async () => {
        saveSettings({ contactAuditedHosts: true });
        global.fetch = dohAndPolicy(true);
        const r = await getMTASTS('acme.com');
        expect(r.policy.valid).toBe(true);
        const call = global.fetch.mock.calls.find(([u]) => String(u).includes('mta-sts.acme.com/.well-known'));
        expect(call[1].referrerPolicy).toBe('no-referrer');
    });
});

describe('DNSSEC y DANE: validación', () => {
    beforeEach(() => { clearDnsCache(); resetSettingsCache(); saveSettings({ ...DEFAULT_SETTINGS }); });
    afterEach(() => { vi.restoreAllMocks(); saveSettings({ ...DEFAULT_SETTINGS }); resetSettingsCache(); });

    it('getDNSSEC distingue DNSKEY sin validar y sabe si el resolver valida', async () => {
        global.fetch = fetchMock(() => ({ Status: 0, AD: false, Answer: [{ type: 48, data: '257 3 13 abc' }] }));
        const r = await getDNSSEC('island.example');
        expect(r).toMatchObject({ signed: true, hasDnskey: true, ad: false, validationKnown: true });
    });

    it('getDANE anota si cada TLSA llegó validado, sin alterar la lista de hosts', async () => {
        global.fetch = fetchMock((name) => name === '_25._tcp.mx.acme.com'
            ? { Status: 0, AD: true, Answer: [{ type: 52, data: '3 1 1 abc' }] }
            : { Status: 3 });
        const r = await getDANE(['mx.acme.com']);
        expect(Object.keys(r)).toEqual(['mx.acme.com']);
        expect(r.validated['mx.acme.com']).toBe(true);
    });
});

describe('getSPFLookupTree: redirect= se ignora si hay all (RFC 7208 §6.1)', () => {
    beforeEach(() => clearDnsCache());
    afterEach(() => vi.restoreAllMocks());

    it('no sigue ni cuenta el redirect cuando el registro ya tiene all', async () => {
        global.fetch = txtZone({
            'ex.com': ['v=spf1 ip4:192.0.2.1 redirect=_spf.otro.com -all'],
            '_spf.otro.com': ['v=spf1 include:a.com include:b.com -all']
        });
        const tree = await getSPFLookupTree('ex.com');
        expect(tree.lookups).toBe(0);
        expect(tree.children.some(c => c.type === 'redirect')).toBe(false);
    });
});

describe('checkLookalikes', () => {
    beforeEach(() => clearDnsCache());
    afterEach(() => vi.restoreAllMocks());

    const baseline = { domain: 'acme.es', mx: ['mx1.acme.es'], ns: ['ns1.acme.es', 'ns2.acme.es'] };
    const candidates = [
        { domain: 'acme.com', technique: 'tld' },
        { domain: 'acme-es.com', technique: 'combo' },
        { domain: 'acrne.es', technique: 'homoglyph' },
        { domain: 'acm.es', technique: 'omission' },
        { domain: 'amce.es', technique: 'transposition' }
    ];

    it('separa libres, ajenos con MX, registrados sin MX, propios y sin resolver', async () => {
        global.fetch = fetchMock((name, type) => {
            if (name === 'acme.com' && type === 'MX') return { Status: 0, Answer: [{ type: 15, data: '10 mx1.acme.es.' }] };
            if (name === 'acme-es.com' && type === 'MX') return { Status: 0, Answer: [{ type: 15, data: '10 mail.evil.example.' }] };
            if (name === 'acrne.es' && type === 'MX') return { Status: 0 };
            if (name === 'acm.es' && type === 'MX') return { Status: 3 };
            if (name === 'amce.es' && type === 'MX') return { Status: 2 };
            if (type === 'NS') return { Status: 0, Answer: [{ type: 2, data: 'ns1.parking.example.' }] };
            return { Status: 0 };
        });
        const r = await checkLookalikes(candidates, baseline);
        expect(r.checked).toBe(5);
        expect(r.unresolved).toBe(1);
        // Orden: primero los ajenos con MX, luego los registrados, y los propios al final.
        expect(r.found.map(f => [f.domain, f.kind])).toEqual([
            ['acme-es.com', 'mx'],
            ['acrne.es', 'registered'],
            ['acme.com', 'own']
        ]);
        expect(r.found[0]).toMatchObject({ technique: 'combo', mx: ['mail.evil.example'], ns: ['ns1.parking.example'] });
        expect(r.found[0]).not.toHaveProperty('index');
    });

    it('un Null MX cuenta como registrado sin MX', async () => {
        global.fetch = fetchMock((name, type) => {
            if (type === 'MX') return { Status: 0, Answer: [{ type: 15, data: '0 .' }] };
            return { Status: 0 };
        });
        const r = await checkLookalikes([{ domain: 'acme.net', technique: 'tld' }], baseline);
        expect(r.found).toEqual([expect.objectContaining({ domain: 'acme.net', kind: 'registered', mx: [] })]);
    });
});

