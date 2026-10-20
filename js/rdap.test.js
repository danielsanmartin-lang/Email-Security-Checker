import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
    getRegistrationDate, clearRdapCache, markLookalikeAgeChecks, checkLookalikeAges,
    lookalikeAgeStatus, NEW_DOMAIN_DAYS, LOOKALIKE_AGE_MAX
} from './rdap.js';

const BOOTSTRAP = {
    services: [
        [['com', 'net'], ['https://rdap.verisign.com/com/v1/']],
        [['app', 'dev'], ['http://insecure.example/', 'https://pubapi.registry.google/rdap']],
        [['uk'], ['https://rdap.nominet.uk/uk/']],
        [['solo-http'], ['http://rdap.solo-http.example/']]
    ]
};

const rdap = (date) => ({ objectClassName: 'domain', events: [{ eventAction: 'last changed', eventDate: '2026-04-17T00:00:00Z' }, { eventAction: 'registration', eventDate: date }] });

// `registry` es (url) → cuerpo, 404 o lanza.
function rdapFetch(registry) {
    return vi.fn(async (url) => {
        const s = String(url);
        if (s === 'https://data.iana.org/rdap/dns.json') return { ok: true, status: 200, json: async () => BOOTSTRAP };
        const body = await registry(s);
        if (body === 404) return { ok: false, status: 404, json: async () => ({}) };
        return { ok: true, status: 200, json: async () => body };
    });
}
const urls = () => global.fetch.mock.calls.map(([u]) => String(u));

describe('getRegistrationDate', () => {
    beforeEach(() => clearRdapCache());
    afterEach(() => vi.restoreAllMocks());

    it('pregunta al registro del TLD que dice el bootstrap de IANA, solo por https', async () => {
        global.fetch = rdapFetch(() => rdap('2018-05-08T00:00:00Z'));
        expect(await getRegistrationDate('Zep.App')).toBe('2018-05-08T00:00:00Z');
        expect(urls()).toEqual(['https://data.iana.org/rdap/dns.json', 'https://pubapi.registry.google/rdap/domain/zep.app']);
    });

    it('usa el sufijo con servicio (un .co.uk va al registro de .uk)', async () => {
        global.fetch = rdapFetch(() => rdap('1999-02-14T00:00:00Z'));
        expect(await getRegistrationDate('google.co.uk')).toBe('1999-02-14T00:00:00Z');
        expect(urls()[1]).toBe('https://rdap.nominet.uk/uk/domain/google.co.uk');
    });

    it('un TLD sin RDAP (o sin https) es "no se sabe", sin consultar a nadie más', async () => {
        global.fetch = rdapFetch(() => { throw new Error('no debería consultarse'); });
        expect(await getRegistrationDate('zepo.io')).toBeNull();
        expect(await getRegistrationDate('a.solo-http')).toBeNull();
        expect(urls()).toEqual(['https://data.iana.org/rdap/dns.json']);
    });

    it('sin evento de alta, con una fecha rota o con el registro caído: null', async () => {
        global.fetch = rdapFetch((u) => (u.includes('sin-evento') ? { events: [] } : u.includes('rota') ? rdap('ayer') : 404));
        expect(await getRegistrationDate('sin-evento.com')).toBeNull();
        expect(await getRegistrationDate('rota.com')).toBeNull();
        expect(await getRegistrationDate('caido.com')).toBeNull();
    });

    it('cachea la respuesta, pero no un fallo pasajero', async () => {
        let caido = true;
        global.fetch = rdapFetch(() => (caido ? 404 : rdap('2020-01-01T00:00:00Z')));
        expect(await getRegistrationDate('acme.com')).toBeNull();
        caido = false;
        expect(await getRegistrationDate('acme.com')).toBe('2020-01-01T00:00:00Z');
        expect(await getRegistrationDate('acme.com')).toBe('2020-01-01T00:00:00Z');
        // Un bootstrap y dos consultas al registro: la tercera sale de la caché.
        expect(urls().filter(u => u.includes('verisign'))).toHaveLength(2);
        expect(urls().filter(u => u.includes('iana'))).toHaveLength(1);
    });

    it('si el bootstrap falla, el siguiente intento lo vuelve a pedir', async () => {
        let n = 0;
        global.fetch = vi.fn(async (url) => {
            if (String(url).includes('iana') && n++ === 0) throw new TypeError('offline');
            return String(url).includes('iana')
                ? { ok: true, status: 200, json: async () => BOOTSTRAP }
                : { ok: true, status: 200, json: async () => rdap('2020-01-01T00:00:00Z') };
        });
        expect(await getRegistrationDate('acme.com')).toBeNull();
        expect(await getRegistrationDate('acme.com')).toBe('2020-01-01T00:00:00Z');
    });

    it('cancelado, rechaza en vez de decir "no se sabe"', async () => {
        const ctrl = new AbortController();
        ctrl.abort();
        global.fetch = rdapFetch(() => rdap('2020-01-01T00:00:00Z'));
        await expect(getRegistrationDate('acme.com', { signal: ctrl.signal })).rejects.toMatchObject({ code: 'aborted' });
        expect(global.fetch).not.toHaveBeenCalled();
    });
});

describe('antigüedad de los dominios parecidos', () => {
    beforeEach(() => clearRdapCache());
    afterEach(() => vi.restoreAllMocks());
    const NOW = Date.parse('2026-10-20T00:00:00Z');

    it('lookalikeAgeStatus: nuevo hasta NEW_DOMAIN_DAYS, antiguo después, sin fecha si no la hay', () => {
        expect(NEW_DOMAIN_DAYS).toBe(90);
        expect(lookalikeAgeStatus(null, NOW)).toEqual({ status: 'unknown' });
        expect(lookalikeAgeStatus('2026-09-16T00:00:00Z', NOW)).toEqual({ status: 'new', registered: '2026-09-16T00:00:00Z', days: 34 });
        expect(lookalikeAgeStatus('2026-07-22T00:00:00Z', NOW)).toMatchObject({ status: 'new', days: 90 });
        expect(lookalikeAgeStatus('2018-05-08T00:00:00Z', NOW)).toMatchObject({ status: 'old' });
    });

    it('marca solo los que reciben correo, hasta el máximo', () => {
        const found = Array.from({ length: LOOKALIKE_AGE_MAX + 2 }, (_, i) => ({ domain: `v${i}.com`, kind: 'mx' }))
            .concat([{ domain: 'reg.com', kind: 'registered' }, { domain: 'own.com', kind: 'own' }]);
        const picked = markLookalikeAgeChecks({ found });
        expect(picked).toHaveLength(LOOKALIKE_AGE_MAX);
        expect(found.filter(f => f.age).every(f => f.kind === 'mx')).toBe(true);
        expect(found[0].age).toEqual({ status: 'checking' });
    });

    it('rellena la fecha de todos, con pocas consultas a la vez', async () => {
        let enVuelo = 0, max = 0;
        global.fetch = vi.fn(async (url) => {
            const s = String(url);
            if (s.includes('iana')) return { ok: true, status: 200, json: async () => BOOTSTRAP };
            enVuelo++;
            max = Math.max(max, enVuelo);
            await new Promise(r => setTimeout(r, 1));
            enVuelo--;
            if (s.includes('nuevo')) return { ok: true, status: 200, json: async () => rdap('2026-09-16T00:00:00Z') };
            if (s.includes('viejo')) return { ok: true, status: 200, json: async () => rdap('2018-05-08T00:00:00Z') };
            return { ok: false, status: 404, json: async () => ({}) };
        });
        const lookalike = {
            found: ['nuevo', 'viejo', 'a', 'b', 'c', 'd'].map(n => ({ domain: `${n}.com`, kind: 'mx' }))
                .concat([{ domain: 'zepo.io', kind: 'mx' }])
        };
        markLookalikeAgeChecks(lookalike);
        expect(await checkLookalikeAges(lookalike, { now: NOW })).toBe(lookalike);
        expect(lookalike.found.map(f => f.age.status)).toEqual(['new', 'old', 'unknown', 'unknown', 'unknown', 'unknown', 'unknown']);
        expect(max).toBeLessThanOrEqual(3);
    });

    it('cancelado, deja de comprobar', async () => {
        const ctrl = new AbortController();
        ctrl.abort();
        global.fetch = vi.fn();
        await expect(checkLookalikeAges({ found: [{ domain: 'a.com', kind: 'mx', age: { status: 'checking' } }] }, { signal: ctrl.signal }))
            .rejects.toMatchObject({ code: 'aborted' });
        expect(global.fetch).not.toHaveBeenCalled();
    });
});
