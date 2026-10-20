import { describe, it, expect } from 'vitest';
import { selectMailSubdomains, classifyMailSubdomain, MAX_MAIL_SUBDOMAINS } from './mailSubdomains.js';

describe('selectMailSubdomains', () => {
    it('solo subdominios concretos del auditado, sin comodines ni repetidos, los de envío primero', () => {
        const names = [
            'acme.com', '*.acme.com', 'www.acme.com', 'news.acme.com', 'NEWS.acme.com.', 'a.b.acme.com',
            'vpn.acme.com', 'acme.com.evil.net', 'otra.com', 'mail.acme.com', 'notacme.com'
        ];
        expect(selectMailSubdomains(names, 'acme.com')).toEqual([
            'mail.acme.com', 'news.acme.com', 'vpn.acme.com', 'www.acme.com', 'a.b.acme.com'
        ]);
    });

    it('respeta el cupo', () => {
        const names = Array.from({ length: 40 }, (_, i) => `h${i}.acme.com`);
        expect(selectMailSubdomains(names, 'acme.com')).toHaveLength(MAX_MAIL_SUBDOMAINS);
        expect(selectMailSubdomains(null, 'acme.com')).toEqual([]);
    });
});

describe('classifyMailSubdomain', () => {
    const dmarc = (record, source = 'org', extra = {}) => ({ record, source, inherited: source !== 'author', multiple: false, ...extra });

    it('un SPF que solo dice -all no cuenta como remitente', () => {
        expect(classifyMailSubdomain('x.acme.com', { spf: 'v=spf1 -all' }).sends).toBe(false);
        expect(classifyMailSubdomain('x.acme.com', { spf: 'v=spf1 include:sendgrid.net -all' }).sends).toBe(true);
        expect(classifyMailSubdomain('x.acme.com', { mx: ['mx.acme.com'] }).receives).toBe(true);
    });

    it('hereda sp del dominio organizativo: p=reject con sp=none deja el subdominio suplantable', () => {
        const r = classifyMailSubdomain('news.acme.com', { spf: 'v=spf1 include:x -all', dmarc: dmarc('v=DMARC1; p=reject; sp=none') });
        expect(r).toMatchObject({ policy: 'none', inherited: true, spoofable: true });
    });

    it('con la política heredada en reject, protegido', () => {
        const r = classifyMailSubdomain('news.acme.com', { spf: 'v=spf1 include:x -all', dmarc: dmarc('v=DMARC1; p=reject') });
        expect(r).toMatchObject({ policy: 'reject', spoofable: false });
    });

    it('su propio registro manda', () => {
        const r = classifyMailSubdomain('news.acme.com', { spf: 'v=spf1 include:x -all', dmarc: dmarc('v=DMARC1; p=quarantine', 'author') });
        expect(r).toMatchObject({ policy: 'quarantine', inherited: false, spoofable: false });
    });

    it('sin DMARC, suplantable; si la consulta falló, sin veredicto', () => {
        expect(classifyMailSubdomain('a.acme.com', { spf: 'v=spf1 mx -all', dmarc: { record: null } }).spoofable).toBe(true);
        expect(classifyMailSubdomain('a.acme.com', { spf: 'v=spf1 mx -all', dmarcUnavailable: true })).toMatchObject({ policy: 'unknown', spoofable: null });
    });

    it('varios registros en su propio nombre se descartan: suplantable', () => {
        const r = classifyMailSubdomain('a.acme.com', { mx: ['m'], dmarc: dmarc('v=DMARC1; p=reject', 'author', { multiple: true }) });
        expect(r.spoofable).toBe(true);
    });
});
