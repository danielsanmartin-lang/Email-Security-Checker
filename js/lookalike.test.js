import { describe, it, expect } from 'vitest';
import { generateLookalikes, classifyLookalike, ownershipLinks, isDeliverableMx, assessLookalikeRisk, lookalikeSpfSenders, lookalikeMxProfile } from './lookalike.js';

describe('generateLookalikes', () => {
    const domains = (list) => list.map(c => c.domain);

    it('empieza por los cambios de TLD y mete el país en el nombre', () => {
        const list = generateLookalikes('acme.es');
        expect(list[0]).toEqual({ domain: 'acme.com', technique: 'tld' });
        expect(domains(list)).toContain('acme-es.com');
        expect(domains(list)).toContain('acmees.com');
        expect(domains(list)).not.toContain('acme.es');
    });

    it('cubre homoglifos, omisión, transposición, repetición y guion', () => {
        const list = generateLookalikes('acme.es');
        const byTechnique = (t) => list.filter(c => c.technique === t).map(c => c.domain);
        expect(byTechnique('homoglyph')).toContain('acrne.es');
        expect(byTechnique('omission')).toContain('acm.es');
        expect(byTechnique('transposition')).toContain('amce.es');
        expect(byTechnique('repetition')).toContain('accme.es');
        expect(byTechnique('hyphenation')).toContain('ac-me.es');
    });

    it('trabaja sobre el dominio registrable, no sobre el subdominio', () => {
        const list = generateLookalikes('mail.bbva.com');
        expect(domains(list)).toContain('bbva.es');
        expect(domains(list).some(d => d.startsWith('mail'))).toBe(false);
    });

    it('conserva los sufijos compuestos', () => {
        const list = generateLookalikes('acme.co.uk');
        expect(domains(list)).toContain('acme.com');
        expect(domains(list)).toContain('acme-couk.com');
        expect(domains(list)).toContain('acm.co.uk');
    });

    it('solo genera nombres válidos, sin repetir y como mucho `max`', () => {
        const list = generateLookalikes('a-very-long-company-name.com', { max: 30 });
        expect(list.length).toBeLessThanOrEqual(30);
        expect(new Set(domains(list)).size).toBe(list.length);
        for (const { domain } of list) {
            const label = domain.split('.')[0];
            expect(label).toMatch(/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/);
            expect(label).not.toContain('--');
        }
    });

    it('no omite letras en nombres de menos de 4', () => {
        expect(generateLookalikes('ing.com').some(c => c.technique === 'omission')).toBe(false);
    });

    it('devuelve una lista vacía con una entrada sin dominio', () => {
        expect(generateLookalikes('')).toEqual([]);
        expect(generateLookalikes('localhost')).toEqual([]);
    });
});

describe('classifyLookalike', () => {
    const baseline = { domain: 'acme.es', mx: ['mx1.acme.es', 'acme-es.mail.protection.outlook.com'], ns: ['ns1.dns.net', 'ns2.dns.net'] };

    it('ajeno con MX: puede recibir correo', () => {
        expect(classifyLookalike({ mx: ['mx.evil.example'], ns: ['ns1.evil.example'] }, baseline)).toBe('mx');
    });

    it('registrado sin MX', () => {
        expect(classifyLookalike({ mx: [], ns: ['ns1.parking.example'] }, baseline)).toBe('registered');
    });

    it('con los mismos MX que el auditado: probablemente propio', () => {
        expect(classifyLookalike({ mx: ['acme-es.mail.protection.outlook.com'], ns: [] }, baseline)).toBe('own');
    });

    it('con MX que cuelgan del dominio auditado: propio', () => {
        expect(classifyLookalike({ mx: ['mail.acme.es.'], ns: [] }, baseline)).toBe('own');
    });

    it('con el mismo juego de NS, en cualquier orden: propio', () => {
        expect(classifyLookalike({ mx: ['mx.otro.example'], ns: ['NS2.dns.net.', 'ns1.dns.net'] }, baseline)).toBe('own');
    });

    it('con el SPF delegado (redirect) o los informes DMARC al auditado: propio', () => {
        expect(classifyLookalike({ mx: ['mx.otro.example'], ns: [], links: ownershipLinks(['v=spf1 redirect=_spf.acme.es'], []) }, baseline)).toBe('own');
        expect(classifyLookalike({ mx: ['mx.otro.example'], ns: [], links: ownershipLinks([], ['v=DMARC1; p=reject; rua=mailto:dmarc@acme.es']) }, baseline)).toBe('own');
    });

    it('un include: al auditado NO prueba nada: es lo normal si el auditado es un proveedor', () => {
        const links = ownershipLinks(['v=spf1 include:_spf.acme.es -all'], []);
        expect(links).toEqual([]);
        expect(classifyLookalike({ mx: ['mx.otro.example'], ns: [], links }, baseline)).toBe('mx');
    });

    it('un MX que no es un host ("300 ~.") no entrega correo', () => {
        expect(isDeliverableMx('~')).toBe(false);
        expect(isDeliverableMx('mail.evil.example.')).toBe(true);
        expect(classifyLookalike({ mx: ['~'], ns: [] }, baseline)).toBe('registered');
    });

    it('compartir solo uno de los NS no basta', () => {
        expect(classifyLookalike({ mx: ['mx.otro.example'], ns: ['ns1.dns.net', 'ns9.other.net'] }, baseline)).toBe('mx');
    });
});

describe('assessLookalikeRisk (veredicto por reglas fijas)', () => {
    const mx = (over) => ({ domain: 'x.com', kind: 'mx', technique: 'tld', mx: ['mail.x.com'], spf: null, ...over });
    const keys = (r) => r.reasons.map(x => x.key);

    // Los cuatro que reciben correo en zepo.app, con sus datos reales.
    it('zepo.online: registrado hace un mes y reenvía el correo → alto', () => {
        const r = assessLookalikeRisk(mx({
            domain: 'zepo.online', mx: ['eforward1.registrar-servers.com', 'eforward2.registrar-servers.com'],
            spf: 'v=spf1 include:spf.efwd.registrar-servers.com ~all',
            age: { status: 'new', registered: '2026-09-16T00:00:00Z', days: 34 }, cert: { status: 'active', days: 34 }
        }));
        expect(r.level).toBe('high');
        expect(keys(r)).toEqual(['new', 'forwarding', 'no_send']);
    });

    it('ezpo.app: buzones en Google, registrado hace meses → medio', () => {
        const r = assessLookalikeRisk(mx({
            domain: 'ezpo.app', technique: 'transposition', mx: ['smtp.google.com'], spf: 'v=spf1 include:_spf.google.com ~all',
            age: { status: 'old', registered: '2026-01-27T00:00:00Z', days: 266 }
        }));
        expect(r).toEqual({ level: 'medium', reasons: [{ key: 'mailbox', provider: 'Google Workspace' }, { key: 'old', registered: '2026-01-27T00:00:00Z' }] });
    });

    it('zep.app: de 2018 y solo reenvía (su `mx` en el SPF son los reenviadores) → bajo', () => {
        const r = assessLookalikeRisk(mx({
            domain: 'zep.app', technique: 'omission', mx: ['fwd1.porkbun.com', 'fwd2.porkbun.com'], spf: 'v=spf1 mx include:_spf.porkbun.com ~all',
            age: { status: 'old', registered: '2018-05-08T00:00:00Z', days: 3087 }, cert: { status: 'recent', days: 26 }
        }));
        expect(r.level).toBe('low');
        expect(keys(r)).toEqual(['forwarding', 'no_send', 'old']);
    });

    it('zepo.io: reenvío de Cloudflare, sin fecha de registro → bajo, y lo dice', () => {
        const r = assessLookalikeRisk(mx({
            domain: 'zepo.io', mx: ['route1.mx.cloudflare.net', 'route2.mx.cloudflare.net'], spf: 'v=spf1 include:_spf.mx.cloudflare.net ~all',
            age: { status: 'unknown' }, cert: { status: 'recent', days: 30 }
        }));
        expect(r.level).toBe('low');
        expect(keys(r)).toEqual(['forwarding', 'no_send', 'age_unknown']);
    });

    it('un certificado reciente en un dominio nuevo se suma a los motivos', () => {
        const r = assessLookalikeRisk(mx({ age: { status: 'new', days: 5 }, cert: { status: 'recent', days: 2 } }));
        expect(r.level).toBe('high');
        expect(keys(r).slice(0, 2)).toEqual(['new', 'cert_new']);
    });

    it('un homoglifo que puede enviar es alto aunque sea antiguo; uno que no puede, no', () => {
        const old = { status: 'old', registered: '2015-01-01T00:00:00Z', days: 4000 };
        expect(assessLookalikeRisk(mx({ technique: 'homoglyph', spf: 'v=spf1 ip4:192.0.2.1 -all', age: old })).level).toBe('high');
        expect(assessLookalikeRisk(mx({ technique: 'homoglyph', mx: ['acrne-com.mail.protection.outlook.com'], age: old })).level).toBe('high');
        expect(assessLookalikeRisk(mx({ technique: 'homoglyph', spf: 'v=spf1 -all', age: old })).level).toBe('low');
    });

    it('aparcado: bajo, o medio si se registró hace poco', () => {
        expect(assessLookalikeRisk(mx({ mx: ['park-mx.above.com'], age: { status: 'old', registered: '2010-01-01T00:00:00Z' } })).level).toBe('low');
        expect(assessLookalikeRisk(mx({ mx: ['park-mx.above.com'], age: { status: 'new', days: 3 } })).level).toBe('medium');
    });

    it('sin fecha de registro, un primer certificado de hace días lo sube a medio', () => {
        const r = assessLookalikeRisk(mx({ mx: ['route1.mx.cloudflare.net'], age: { status: 'unknown' }, cert: { status: 'recent', days: 4, firstSeen: '2026-10-16T00:00:00Z', firstSeenDays: 4 } }));
        expect(r.level).toBe('medium');
        expect(keys(r)[0]).toBe('first_cert');
        // Con un historial largo, no.
        expect(assessLookalikeRisk(mx({ mx: ['route1.mx.cloudflare.net'], age: { status: 'unknown' }, cert: { status: 'recent', days: 4, firstSeenDays: 900 } })).level).toBe('low');
    });

    it('sin SPF no puede enviar autenticado; si la consulta falló, no se afirma que no tenga', () => {
        expect(keys(assessLookalikeRisk(mx({ spf: null })))).toEqual(['receives', 'no_spf']);
        expect(keys(assessLookalikeRisk(mx({ spf: undefined })))).toEqual(['receives', 'spf_unknown']);
    });

    it('mientras falta la fecha de registro, "evaluando", salvo que ya sea alto', () => {
        expect(assessLookalikeRisk(mx({ age: { status: 'checking' } })).level).toBe('pending');
        expect(assessLookalikeRisk(mx({ technique: 'homoglyph', spf: 'v=spf1 a -all', age: { status: 'checking' } })).level).toBe('high');
        // Más allá del máximo de consultas RDAP no hay `age`: se evalúa con lo que hay.
        expect(assessLookalikeRisk(mx({ spf: 'v=spf1 include:sendgrid.net -all' })).level).toBe('medium');
    });

    it('propio y registrado sin MX', () => {
        expect(assessLookalikeRisk({ kind: 'own', mx: ['mx1.acme.es'] })).toEqual({ level: 'own', reasons: [{ key: 'own' }] });
        expect(assessLookalikeRisk({ kind: 'registered', mx: [] })).toEqual({ level: 'low', reasons: [{ key: 'no_mx' }] });
    });
});

describe('lookalikeSpfSenders y lookalikeMxProfile', () => {
    it('solo cuentan los mecanismos que autorizan (+), sin los reenviadores', () => {
        expect(lookalikeSpfSenders('v=spf1 include:_spf.google.com include:spf.efwd.registrar-servers.com ~all', 'server')).toEqual(['Google Workspace']);
        expect(lookalikeSpfSenders('v=spf1 ip4:192.0.2.1 a mx -all', 'server')).toEqual(['servers']);
        expect(lookalikeSpfSenders('v=spf1 ~include:_spf.google.com ?a -all', 'server')).toEqual([]);
        expect(lookalikeSpfSenders('v=spf1 include:raro.example -all', 'server')).toEqual(['raro.example']);
        expect(lookalikeSpfSenders(null, 'server')).toEqual([]);
    });

    it('`mx` no autoriza un envío propio si el MX solo reenvía o aparca', () => {
        expect(lookalikeSpfSenders('v=spf1 mx -all', 'forwarding')).toEqual([]);
        expect(lookalikeSpfSenders('v=spf1 mx -all', 'parking')).toEqual([]);
    });

    it('distingue buzones, reenvío, aparcamiento y servidor', () => {
        expect(lookalikeMxProfile(['aspmx.l.google.com'], 'a.com')).toEqual({ kind: 'mailbox', provider: 'Google Workspace' });
        expect(lookalikeMxProfile(['fwd1.porkbun.com', 'fwd2.porkbun.com'], 'a.com')).toEqual({ kind: 'forwarding' });
        expect(lookalikeMxProfile(['park-mx.above.com'], 'a.com')).toEqual({ kind: 'parking' });
        // Un reenviador junto a un servidor cualquiera ya no es "solo reenvío".
        expect(lookalikeMxProfile(['fwd1.porkbun.com', 'mail.a.com'], 'a.com')).toEqual({ kind: 'server' });
    });
});
