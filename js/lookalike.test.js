import { describe, it, expect } from 'vitest';
import { generateLookalikes, classifyLookalike, ownershipLinks, isDeliverableMx } from './lookalike.js';

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
