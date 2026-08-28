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
