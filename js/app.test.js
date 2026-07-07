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
});
