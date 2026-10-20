// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { performAnalysis } from './app.js';
import { clearDnsCache } from './api.js';

// Mock DoH: responde por (name, type). Cubre el flujo completo de performAnalysis.
function doh(map) {
    return vi.fn(async (url) => {
        const s = String(url);
        // Peticiones no-DoH (crt.sh, allorigins, MTA-STS https) → fallan silenciosas.
        if (!s.includes('dns.google') && !s.includes('cloudflare-dns')) {
            throw new TypeError('non-DoH fetch blocked in test');
        }
        const u = new URL(s);
        const name = u.searchParams.get('name');
        const type = u.searchParams.get('type');
        const answer = map(name, type);
        return { ok: true, status: 200, json: async () => answer };
    });
}

const TXT = (v) => ({ Status: 0, Answer: [{ type: 16, data: `"${v}"` }] });
const NONE = { Status: 0 };

describe('performAnalysis (integración, DoH mockeado)', () => {
    beforeEach(() => clearDnsCache());
    afterEach(() => vi.restoreAllMocks());

    it('recorre el flujo completo y devuelve un result puntuado', async () => {
        global.fetch = doh((name, type) => {
            if (name === 'acme.com' && type === 'NS') return { Status: 0, Answer: [{ type: 2, data: 'ns1.acme.com.' }] };
            if (name === 'acme.com' && type === 'MX') return { Status: 0, Answer: [{ type: 15, data: '10 mx.acme.com.' }] };
            if (name === 'acme.com' && type === 'TXT') return TXT('v=spf1 include:_spf.google.com -all');
            if (name === '_dmarc.acme.com' && type === 'TXT') return TXT('v=DMARC1; p=reject; rua=mailto:r@acme.com');
            if (name === '_spf.google.com' && type === 'TXT') return TXT('v=spf1 ip4:1.2.3.4 -all');
            return NONE;
        });

        const steps = [];
        const { result, awarenessPromise } = await performAnalysis('acme.com', null, {
            onStep: (id, state) => steps.push(`${id}:${state}`)
        });

        expect(result).toBeTruthy();
        expect(result.mxRecords).toHaveLength(1);
        expect(result.mxRecords[0].host).toBe('mx.acme.com');
        expect(result.spfRaw).toContain('v=spf1');
        expect(result.dmarcRaw).toContain('p=reject');
        expect(result.scoreCard).toBeTruthy();
        expect(typeof result.scoreCard.score).toBe('number');
        expect(result.scannedAt).toBeTruthy();
        // La detección de awareness se devuelve como promesa (render progresivo).
        expect(awarenessPromise).toBeInstanceOf(Promise);
        await awarenessPromise;
        // Se emitieron pasos de progreso vía onStep.
        expect(steps.some(s => s.startsWith('step-mx'))).toBe(true);
        expect(steps).toContain('step-analysis:done');
    });

    it('lanza code "nxdomain" cuando el dominio no existe', async () => {
        global.fetch = doh(() => ({ Status: 3 }));
        await expect(performAnalysis('nope.example')).rejects.toMatchObject({ code: 'nxdomain' });
    });

    it('lanza code "servfail" si MX y SPF fallan a la vez (zona rota)', async () => {
        // NS existe (no NXDOMAIN) pero MX y el TXT del ápex devuelven SERVFAIL.
        global.fetch = doh((name, type) => {
            if (type === 'NS') return { Status: 0, Answer: [{ type: 2, data: 'ns1.x.' }] };
            if (type === 'MX' || type === 'TXT') return { Status: 2 };
            return NONE;
        });
        await expect(performAnalysis('broken.example')).rejects.toMatchObject({ code: 'servfail' });
    });

    // Fetch DoH que retiene todo salvo lo que `pass` deja pasar, hasta abrir la puerta.
    function gatedDoh(pass, answer) {
        let abrir;
        const puerta = new Promise(r => { abrir = r; });
        const names = [];
        global.fetch = vi.fn(async (url) => {
            const s = String(url);
            if (!s.includes('dns.google') && !s.includes('cloudflare-dns')) throw new TypeError('non-DoH fetch blocked in test');
            const u = new URL(s);
            const name = u.searchParams.get('name');
            const type = u.searchParams.get('type');
            names.push(`${name}:${type}`);
            if (!pass(name, type)) await puerta;
            return { ok: true, status: 200, json: async () => answer(name, type) };
        });
        return { names, abrir };
    }

    it('con NXDOMAIN, lo que quedaba en la cola ya no se pide', async () => {
        // La existencia del dominio ya no hace de puerta: se pregunta a la vez que todo lo
        // demás. Pero en cuanto el NS dice NXDOMAIN, lo encolado se cancela.
        const { names, abrir } = gatedDoh(
            (name, type) => type === 'NS',
            (name, type) => (type === 'NS' ? { Status: 3 } : NONE)
        );
        await expect(performAnalysis('nope.example')).rejects.toMatchObject({ code: 'nxdomain' });
        const pedidas = names.length;
        abrir();
        await new Promise(r => setTimeout(r, 50));
        // Solo lo que ya estaba en vuelo (la zona admite 6 a la vez), nunca el abanico
        // entero de ~40 consultas del análisis.
        expect(pedidas).toBeLessThan(12);
        expect(names.length).toBe(pedidas);
    });

    it('un SERVFAIL del NS sigue abortando el análisis con code "servfail"', async () => {
        // Comportamiento fijado a propósito: sin poder confirmar que el dominio existe, se
        // informa del fallo de resolución en vez de pintar un dominio vacío.
        global.fetch = doh((name, type) => (type === 'NS' ? { Status: 2 } : NONE));
        await expect(performAnalysis('ns-roto.example')).rejects.toMatchObject({ code: 'servfail' });
    });

    it('si falla el TXT del ápex (SPF), DKIM se conserva', async () => {
        // Antes los selectores DKIM esperaban al SPF y, si este fallaba, DKIM salía como
        // "no comprobado" aunque sus registros estuvieran publicados.
        global.fetch = doh((name, type) => {
            if (name === 'acme.com' && type === 'NS') return { Status: 0, Answer: [{ type: 2, data: 'ns1.acme.com.' }] };
            if (name === 'acme.com' && type === 'MX') return { Status: 0, Answer: [{ type: 15, data: '10 mx.acme.com.' }] };
            if (name === 'acme.com' && type === 'TXT') return { Status: 2 };
            if (name === 'google._domainkey.acme.com' && type === 'TXT') return TXT('v=DKIM1; k=rsa; p=MIIB');
            return NONE;
        });
        const { result } = await performAnalysis('acme.com', null, { background: false });
        expect(result.spfUnavailable).toBe(true);
        expect(result.dkimRecords.records.map(r => r.selector)).toContain('google');
        expect(result.dkimRecords.attempted).toBeGreaterThan(0);
    });

    it('cancelado desde fuera, rechaza con code "aborted" y no pide lo encolado', async () => {
        const { names, abrir } = gatedDoh(() => false, () => NONE);
        const ctrl = new AbortController();
        const run = performAnalysis('acme.com', null, { signal: ctrl.signal });
        await new Promise(r => setTimeout(r, 10));
        ctrl.abort();
        abrir();
        await expect(run).rejects.toMatchObject({ code: 'aborted' });
        const pedidas = names.length;
        await new Promise(r => setTimeout(r, 50));
        expect(names.length).toBe(pedidas);
    });

    it('con nombres CT: subdominios con correo, hospedaje recalculado y certificados de parecidos', async () => {
        const { clearCtCache } = await import('./ct.js');
        clearCtCache();
        global.fetch = vi.fn(async (url) => {
            const s = String(url);
            if (s.includes('crt.sh/?q=%.acme.com')) {
                return { ok: true, status: 200, json: async () => [{ name_value: 'news.acme.com\nowa.acme.com' }] };
            }
            if (s.includes('crt.sh') || s.includes('certspotter') || s.includes('microsoftonline')) {
                return { ok: false, status: 502, json: async () => ({}) };
            }
            if (!s.includes('dns.google') && !s.includes('cloudflare-dns')) throw new TypeError('non-DoH fetch blocked in test');
            const u = new URL(s);
            const name = u.searchParams.get('name');
            const type = u.searchParams.get('type');
            const answer = (() => {
                if (name === 'acme.com' && type === 'NS') return { Status: 0, Answer: [{ type: 2, data: 'ns1.acme.com.' }] };
                if (name === 'acme.com' && type === 'MX') return { Status: 0, Answer: [{ type: 15, data: '10 mail.acme.com.' }] };
                if (name === 'acme.com' && type === 'TXT') return TXT('v=spf1 mx -all');
                if (name === '_dmarc.acme.com' && type === 'TXT') return TXT('v=DMARC1; p=reject; sp=none');
                if (name === 'news.acme.com' && type === 'TXT') return TXT('v=spf1 include:sendgrid.net -all');
                if (name === 'acrne.com' && type === 'MX') return { Status: 0, Answer: [{ type: 15, data: '10 mx.evil.example.' }] };
                if (type === 'MX' && name !== 'acme.com') return { Status: 3 };
                return NONE;
            })();
            return { ok: true, status: 200, json: async () => answer };
        });
        const run = await performAnalysis('acme.com');
        expect(run.result.mailHosting.kind).toBe('undetermined');

        const subs = await run.mailSubdomainsPromise;
        expect(subs.ctNames).toBe(2);
        expect(subs.found.map(f => [f.name, f.spoofable])).toEqual([['news.acme.com', true]]);

        const hosting = await run.mailHostingPromise;
        expect(hosting.kind).toBe('on_premise');

        const lookalikes = await run.lookalikeCertsPromise;
        const acrne = lookalikes.found.find(f => f.domain === 'acrne.com');
        expect(acrne.kind).toBe('mx');
        // Las dos fuentes CT caídas: "no comprobado", no "sin certificados".
        expect(acrne.cert).toEqual({ status: 'unchecked' });
        await run.awarenessPromise;
    });
});
