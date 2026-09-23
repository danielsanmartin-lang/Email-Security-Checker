import { describe, it, expect } from 'vitest';
import { treeWalkTargets, selectOrgDomain, splitReportUris, evaluateDmarc, lowerPolicy, weakerPolicy } from './dmarc.js';
import { parseDMARC } from './parsers.js';

describe('treeWalkTargets (RFC 9989 §4.10)', () => {
    it('sube de etiqueta en etiqueta hasta el TLD', () => {
        expect(treeWalkTargets('a.mail.example.com')).toEqual(['mail.example.com', 'example.com', 'com']);
        expect(treeWalkTargets('example.com')).toEqual(['com']);
    });

    it('con 8 etiquetas o más salta a las 7 últimas: nunca más de 8 consultas', () => {
        // El ejemplo literal del RFC.
        const targets = treeWalkTargets('a.b.c.d.e.f.g.h.i.j.mail.example.com');
        expect(targets[0]).toBe('g.h.i.j.mail.example.com');
        expect(targets).toHaveLength(7);
        expect(targets[targets.length - 1]).toBe('com');
    });

    it('con exactamente 8 etiquetas el primer salto es el padre', () => {
        expect(treeWalkTargets('a.b.c.d.e.f.example.com')[0]).toBe('b.c.d.e.f.example.com');
    });

    it('un nombre de una sola etiqueta no tiene a dónde subir', () => {
        expect(treeWalkTargets('localhost')).toEqual([]);
    });
});

describe('selectOrgDomain (RFC 9989 §4.10.2)', () => {
    it('elige el registro con menos etiquetas cuando nadie declara psd', () => {
        // Ejemplo del RFC: registros en mail.example.com y example.com → example.com.
        const found = [{ name: 'mail.example.com' }, { name: 'example.com' }];
        expect(selectOrgDomain(found, 'a.mail.example.com')).toBe('example.com');
    });

    it('psd=n declara el dominio organizativo', () => {
        const found = [{ name: 'mail.example.com', psd: 'n' }, { name: 'example.com' }];
        expect(selectOrgDomain(found, 'a.mail.example.com')).toBe('mail.example.com');
    });

    it('psd=y marca un sufijo público: el organizativo es el nombre justo por debajo', () => {
        expect(selectOrgDomain([{ name: 'com', psd: 'y' }], 'a.mail.example.com')).toBe('example.com');
    });

    it('psd=y en el propio dominio de partida no cuenta como PSD', () => {
        expect(selectOrgDomain([{ name: 'example.com', psd: 'y' }], 'example.com')).toBe('example.com');
    });

    it('sin registros, el organizativo es el propio dominio de partida', () => {
        expect(selectOrgDomain([], 'shop.example.com')).toBe('shop.example.com');
    });
});

describe('splitReportUris', () => {
    it('acepta mailto: y https:, y tolera el sufijo de tamaño obsoleto', () => {
        const r = splitReportUris(['mailto:d@example.com', 'mailto:d@example.com!10m', 'https://r.example.net/dmarc']);
        expect(r.valid).toHaveLength(3);
        expect(r.invalid).toEqual([]);
    });

    it('rechaza la dirección sin esquema, que los receptores descartan en silencio', () => {
        expect(splitReportUris(['dmarc@example.com', 'mailto:dmarc', 'http://x.example']).invalid).toHaveLength(3);
    });
});

describe('evaluateDmarc', () => {
    const ev = (raw, ctx) => evaluateDmarc(parseDMARC(raw), ctx);

    it('lowerPolicy y weakerPolicy', () => {
        expect(lowerPolicy('reject')).toBe('quarantine');
        expect(lowerPolicy('quarantine')).toBe('none');
        expect(lowerPolicy('none')).toBe('none');
        expect(weakerPolicy('reject', 'quarantine')).toBe('quarantine');
    });

    it('t=y: RFC 9989 aplica un nivel menos; RFC 7489 lo ignora', () => {
        const r = ev('v=DMARC1; p=reject; t=y');
        expect(r.effective).toMatchObject({ rfc9989: 'quarantine', rfc7489: 'reject', floor: 'quarantine' });
    });

    it('pct=0: RFC 7489 aplica un nivel menos; RFC 9989 lo ignora', () => {
        const r = ev('v=DMARC1; p=reject; pct=0');
        expect(r.effective).toMatchObject({ rfc9989: 'reject', rfc7489: 'quarantine', floor: 'quarantine' });
        expect(r.obsoleteTags).toContain('pct');
    });

    it('t no tiene efecto sobre none', () => {
        expect(ev('v=DMARC1; p=none; t=y').effective.floor).toBe('none');
    });

    it('al heredar, aplica sp (o p si no hay sp)', () => {
        expect(ev('v=DMARC1; p=reject; sp=quarantine', { source: 'org' })).toMatchObject({ applicableTag: 'sp', applicable: 'quarantine' });
        expect(ev('v=DMARC1; p=reject', { source: 'org' })).toMatchObject({ applicableTag: 'p', applicable: 'reject' });
    });

    it('np hereda de sp y sp de p', () => {
        const r = ev('v=DMARC1; p=reject; sp=quarantine');
        expect(r.policies.np.requested).toBe('quarantine');
        expect(ev('v=DMARC1; p=reject').policies.np.requested).toBe('reject');
    });

    it('enforcement exige p, sp y np fuera de none (RFC 9989 §3.2.9)', () => {
        expect(ev('v=DMARC1; p=quarantine').enforcement).toBe(true);
        expect(ev('v=DMARC1; p=reject; sp=none').enforcement).toBe(false);
        expect(ev('v=DMARC1; p=reject; np=none').enforcement).toBe(false);
        expect(ev('v=DMARC1; p=quarantine; t=y').enforcement).toBe(false);
        expect(ev('v=DMARC1; p=reject; pct=50').enforcement).toBe(false);
    });

    it('en un registro de subdominio, su sp no rige: solo cuenta su p', () => {
        expect(ev('v=DMARC1; p=reject; sp=none', { isOrgDomain: false }).enforcement).toBe(true);
    });

    it('valores no válidos: p/sp/np cambian el procesado; el resto cae al valor por defecto', () => {
        expect(ev('v=DMARC1; p=reject; sp=rejct; rua=mailto:d@example.com').processing).toBe('as_none');
        expect(ev('v=DMARC1; p=rejct').processing).toBe('none');
        const r = ev('v=DMARC1; p=reject; t=yes; adkim=strict; pct=150');
        expect(r.processing).toBe('full');
        expect(r.testing).toBe(false);
        expect(r.adkim).toBe('r');
        expect(r.pct).toBeNull();
        expect(r.invalidTags).toEqual(expect.arrayContaining(['t', 'adkim', 'pct']));
    });

    it('sin p equivale a none', () => {
        expect(ev('v=DMARC1; rua=mailto:d@example.com')).toMatchObject({ processing: 'full', applicable: 'none' });
    });

    it('reconoce etiquetas eliminadas y desconocidas', () => {
        const r = ev('v=DMARC1; p=reject; ri=3600; rf=afrf; rau=mailto:x@y.z');
        expect(r.obsoleteTags).toEqual(['ri', 'rf']);
        expect(r.unknownTags).toEqual(['rau']);
    });

    it('fo se ignora si no hay ruf válido', () => {
        expect(ev('v=DMARC1; p=reject; fo=1').foIgnored).toBe(true);
        expect(ev('v=DMARC1; p=reject; fo=1; ruf=mailto:f@example.com').foIgnored).toBe(false);
    });

    it('null sin registro', () => {
        expect(evaluateDmarc(null)).toBeNull();
    });
});
