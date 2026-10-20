import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { getCtNames, getCertIssuances, clearCtCache } from './ct.js';

// Respuestas JSON por fuente. `crt` y `spotter` son funciones (url) → cuerpo, o lanzan.
function ctFetch({ crt, spotter }) {
    return vi.fn(async (url) => {
        const s = String(url);
        const handler = s.includes('crt.sh') ? crt : s.includes('certspotter') ? spotter : null;
        if (!handler) throw new TypeError(`fetch inesperado: ${s}`);
        const body = await handler(s);
        if (body === 502) return { ok: false, status: 502, json: async () => ({}) };
        return { ok: true, status: 200, json: async () => body };
    });
}
const calls = (host) => global.fetch.mock.calls.filter(([u]) => String(u).includes(host)).length;

describe('getCtNames', () => {
    beforeEach(() => clearCtCache());
    afterEach(() => { vi.restoreAllMocks(); vi.useRealTimers(); });

    it('usa crt.sh, solo certificados vigentes y sin duplicados', async () => {
        global.fetch = ctFetch({
            crt: () => [{ name_value: 'WWW.acme.com\nmail.acme.com', common_name: 'acme.com' }, { name_value: 'mail.acme.com' }],
            spotter: () => { throw new Error('no debería usarse'); }
        });
        const names = await getCtNames('acme.com');
        expect(names.sort()).toEqual(['acme.com', 'mail.acme.com', 'www.acme.com']);
        const url = String(global.fetch.mock.calls[0][0]);
        expect(url).toContain('exclude=expired');
        expect(url).toContain('deduplicate=Y');
        expect(calls('certspotter')).toBe(0);
    });

    it('si crt.sh falla, pregunta a Certspotter', async () => {
        global.fetch = ctFetch({
            crt: () => 502,
            spotter: () => [{ dns_names: ['owa.acme.com', '*.acme.com'] }]
        });
        expect(await getCtNames('acme.com')).toEqual(['owa.acme.com', '*.acme.com']);
    });

    it('si crt.sh no trae nombres, también pregunta a Certspotter', async () => {
        global.fetch = ctFetch({ crt: () => [], spotter: () => [{ dns_names: ['vpn.acme.com'] }] });
        expect(await getCtNames('acme.com')).toEqual(['vpn.acme.com']);
    });

    it('si crt.sh tarda más de 4 s, Certspotter entra en paralelo y gana el primero', async () => {
        vi.useFakeTimers();
        let soltarCrt;
        global.fetch = ctFetch({
            crt: () => new Promise(r => { soltarCrt = r; }),
            spotter: () => [{ dns_names: ['mail.acme.com'] }]
        });
        const p = getCtNames('acme.com');
        await vi.advanceTimersByTimeAsync(3900);
        expect(calls('certspotter')).toBe(0);
        await vi.advanceTimersByTimeAsync(200);
        expect(calls('certspotter')).toBe(1);
        expect(await p).toEqual(['mail.acme.com']);
        soltarCrt([{ name_value: 'tarde.acme.com' }]);
    });

    it('con las dos fuentes caídas devuelve [] (y lo cachea: no se insiste)', async () => {
        global.fetch = ctFetch({ crt: () => 502, spotter: () => { throw new TypeError('offline'); } });
        expect(await getCtNames('acme.com')).toEqual([]);
        expect(await getCtNames('acme.com')).toEqual([]);
        expect(global.fetch).toHaveBeenCalledTimes(2);
    });

    it('comparte la consulta en vuelo y cachea el resultado', async () => {
        global.fetch = ctFetch({ crt: () => [{ name_value: 'a.acme.com' }], spotter: () => [] });
        const [a, b] = await Promise.all([getCtNames('acme.com'), getCtNames('ACME.com')]);
        expect(a).toEqual(b);
        await getCtNames('acme.com');
        expect(global.fetch).toHaveBeenCalledTimes(1);
    });

    it('con la señal ya cancelada no pide nada', async () => {
        global.fetch = ctFetch({ crt: () => [], spotter: () => [] });
        const ctrl = new AbortController();
        ctrl.abort();
        await expect(getCtNames('acme.com', { signal: ctrl.signal })).rejects.toMatchObject({ code: 'aborted' });
        expect(global.fetch).not.toHaveBeenCalled();
    });

    it('cancelar retira a un llamante, no la consulta que comparte con otro', async () => {
        let soltar;
        global.fetch = ctFetch({ crt: () => new Promise(r => { soltar = r; }), spotter: () => [] });
        const ctrl = new AbortController();
        const cancelado = getCtNames('acme.com', { signal: ctrl.signal });
        const otro = getCtNames('acme.com');
        ctrl.abort();
        await expect(cancelado).rejects.toMatchObject({ code: 'aborted' });
        await vi.waitFor(() => expect(soltar).toBeTypeOf('function'));
        soltar([{ name_value: 'x.acme.com' }]);
        expect(await otro).toEqual(['x.acme.com']);
    });
});

describe('getCertIssuances', () => {
    beforeEach(() => clearCtCache());
    afterEach(() => vi.restoreAllMocks());

    const NOW = Date.parse('2026-10-19T00:00:00Z');

    it('lee fecha y emisor de crt.sh, solo los vigentes, del más reciente al más antiguo', async () => {
        global.fetch = ctFetch({
            crt: () => [
                { not_before: '2026-01-10T00:00:00', not_after: '2027-01-10T00:00:00', issuer_name: 'C=US, O=Let\'s Encrypt, CN=R11' },
                { not_before: '2026-10-01T00:00:00', not_after: '2026-12-30T00:00:00', issuer_name: 'C=US, O="DigiCert, Inc.", CN=X' },
                { not_before: '2019-03-01T00:00:00', not_after: '2019-05-30T00:00:00', issuer_name: 'O=Let\'s Encrypt' },
                { not_before: 'no es una fecha', issuer_name: 'CN=Solo CN' }
            ],
            spotter: () => { throw new Error('no debería usarse'); }
        });
        const { certs, firstSeen } = await getCertIssuances('acrne.com', { now: NOW });
        expect(certs).toEqual([
            { notBefore: '2026-10-01T00:00:00', issuer: 'DigiCert, Inc.' },
            { notBefore: '2026-01-10T00:00:00', issuer: 'Let\'s Encrypt' }
        ]);
        // El caducado no cuenta como vigente, pero sí dice desde cuándo hay certificados.
        expect(firstSeen).toBe('2019-03-01T00:00:00');
        const url = String(global.fetch.mock.calls[0][0]);
        expect(url).toContain('q=acrne.com');
        expect(url).not.toContain('exclude=expired');
    });

    it('si crt.sh falla, usa Certspotter', async () => {
        global.fetch = ctFetch({
            crt: () => 502,
            spotter: () => [{ not_before: '2026-10-15T00:00:00Z', issuer: { friendly_name: 'Amazon Trust Services' } }, { not_before: '2026-09-01T00:00:00Z', issuer: { name: 'C=US, O=Google Trust Services, CN=WR3' } }]
        });
        // Certspotter no guarda el historial: sin `firstSeen`.
        expect(await getCertIssuances('acrne.com')).toEqual({
            certs: [
                { notBefore: '2026-10-15T00:00:00Z', issuer: 'Amazon Trust Services' },
                { notBefore: '2026-09-01T00:00:00Z', issuer: 'Google Trust Services' }
            ],
            firstSeen: null
        });
    });

    it('tras una caída de crt.sh, las siguientes consultas van directas a Certspotter', async () => {
        global.fetch = ctFetch({ crt: () => 502, spotter: () => [{ not_before: '2026-10-01T00:00:00Z', issuer: { friendly_name: 'X' } }] });
        await getCertIssuances('uno.com');
        await getCertIssuances('dos.com');
        await getCtNames('tres.com');
        expect(calls('crt.sh')).toBe(1);
        expect(calls('certspotter')).toBe(3);
    });

    it('si fallan las dos, rechaza (es "no comprobado", no "sin certificados")', async () => {
        global.fetch = ctFetch({ crt: () => 502, spotter: () => 502 });
        await expect(getCertIssuances('acrne.com')).rejects.toThrow();
    });

    it('cancelado no consulta y, si se cancela tras el fallo de crt.sh, no pasa a Certspotter', async () => {
        const ctrl = new AbortController();
        ctrl.abort();
        global.fetch = ctFetch({ crt: () => 502, spotter: () => [] });
        await expect(getCertIssuances('acrne.com', { signal: ctrl.signal })).rejects.toMatchObject({ code: 'aborted' });
        expect(global.fetch).not.toHaveBeenCalled();

        const ctrl2 = new AbortController();
        global.fetch = ctFetch({ crt: () => { ctrl2.abort(); return 502; }, spotter: () => [] });
        await expect(getCertIssuances('acrne.com', { signal: ctrl2.signal })).rejects.toMatchObject({ code: 'aborted' });
        expect(calls('certspotter')).toBe(0);
    });
});

describe('certificados de los dominios parecidos', () => {
    beforeEach(() => clearCtCache());
    afterEach(() => vi.restoreAllMocks());
    const NOW = Date.parse('2026-10-19T00:00:00Z');

    it('lookalikeCertStatus: reciente hasta 30 días, vigente después, ninguno si no hay', async () => {
        const { lookalikeCertStatus } = await import('./ct.js');
        expect(lookalikeCertStatus({ certs: [] }, NOW)).toEqual({ status: 'none' });
        expect(lookalikeCertStatus({ certs: [{ notBefore: '2026-10-14T00:00:00Z', issuer: 'X' }] }, NOW)).toEqual({ status: 'recent', notBefore: '2026-10-14T00:00:00Z', issuer: 'X', days: 5 });
        expect(lookalikeCertStatus({ certs: [{ notBefore: '2026-08-01T00:00:00Z', issuer: null }] }, NOW)).toMatchObject({ status: 'active', days: 79 });
        // Con historial, los días desde el primer certificado.
        expect(lookalikeCertStatus({ certs: [], firstSeen: '2026-10-09T00:00:00Z' }, NOW)).toEqual({ status: 'none', firstSeen: '2026-10-09T00:00:00Z', firstSeenDays: 10 });
    });

    it('marca los 3 primeros que reciben correo y rellena su certificado en serie', async () => {
        const { markLookalikeCertChecks, checkLookalikeCerts } = await import('./ct.js');
        const lookalike = {
            found: ['a', 'b', 'c', 'd'].map(n => ({ domain: `${n}.com`, kind: 'mx' }))
                .concat([{ domain: 'reg.com', kind: 'registered' }])
        };
        expect(markLookalikeCertChecks(lookalike).map(f => f.domain)).toEqual(['a.com', 'b.com', 'c.com']);
        expect(lookalike.found[0].cert).toEqual({ status: 'checking' });
        expect(lookalike.found[3].cert).toBeUndefined();

        let enVuelo = 0, max = 0;
        global.fetch = vi.fn(async (url) => {
            enVuelo++;
            max = Math.max(max, enVuelo);
            await Promise.resolve();
            enVuelo--;
            const s = String(url);
            if (s.includes('q=a.com')) return { ok: true, status: 200, json: async () => [{ not_before: '2026-10-10T00:00:00', issuer_name: 'O=Let\'s Encrypt' }] };
            if (s.includes('q=b.com')) return { ok: true, status: 200, json: async () => [] };
            return { ok: false, status: 502, json: async () => ({}) }; // c.com: las dos fuentes caídas
        });
        const out = await checkLookalikeCerts(lookalike, { now: NOW });
        expect(out).toBe(lookalike);
        expect(lookalike.found.map(f => f.cert && f.cert.status)).toEqual(['recent', 'none', 'unchecked', undefined, undefined]);
        expect(max).toBe(1);
    });

    it('cancelado, deja de comprobar', async () => {
        const { checkLookalikeCerts } = await import('./ct.js');
        const ctrl = new AbortController();
        ctrl.abort();
        global.fetch = vi.fn();
        await expect(checkLookalikeCerts({ found: [{ domain: 'a.com', kind: 'mx', cert: { status: 'checking' } }] }, { signal: ctrl.signal }))
            .rejects.toMatchObject({ code: 'aborted' });
        expect(global.fetch).not.toHaveBeenCalled();
    });
});
