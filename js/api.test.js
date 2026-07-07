import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { queryDNS, getMX, getDMARC, checkRBL, getDNSSEC, checkDomainExists, checkDMARCExternalAuth, clearDnsCache } from './api.js';

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
