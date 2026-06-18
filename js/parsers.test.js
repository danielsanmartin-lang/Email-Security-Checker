import { describe, it, expect } from 'vitest';
import { parseSPF, parseDMARC, parseMTASTSPolicy, validateMTASTSPolicy, extractTxtValue } from './parsers.js';

describe('extractTxtValue', () => {
    it('concatena múltiples cadenas entrecomilladas', () => {
        expect(extractTxtValue('"v=spf1 include:a " "include:b ~all"')).toBe('v=spf1 include:a include:b ~all');
    });
    it('maneja una sola cadena entrecomillada', () => {
        expect(extractTxtValue('"v=DMARC1; p=reject"')).toBe('v=DMARC1; p=reject');
    });
    it('cae a quitar comillas si no hay formato entrecomillado', () => {
        expect(extractTxtValue('v=spf1 -all')).toBe('v=spf1 -all');
    });
    it('devuelve cadena vacía para entrada vacía', () => {
        expect(extractTxtValue('')).toBe('');
        expect(extractTxtValue(null)).toBe('');
    });
});

describe('parseSPF', () => {
    it('devuelve [] para entrada vacía', () => {
        expect(parseSPF('')).toEqual([]);
        expect(parseSPF(null)).toEqual([]);
    });

    it('parsea include, ip4 y all con qualifier', () => {
        const entries = parseSPF('v=spf1 include:_spf.google.com ip4:1.2.3.4 ~all');
        const types = entries.map(e => e.type);
        expect(types).toContain('v');
        expect(types).toContain('include');
        expect(types).toContain('ip4');
        const all = entries.find(e => e.type === 'all');
        expect(all.qualifier).toBe('~');
        const inc = entries.find(e => e.type === 'include');
        expect(inc.value).toBe('_spf.google.com');
    });

    it('asigna qualifier + por defecto a mecanismos sin prefijo', () => {
        const entries = parseSPF('v=spf1 mx -all');
        const mx = entries.find(e => e.type === 'mx');
        expect(mx.qualifier).toBe('+');
        expect(parseSPF('v=spf1 -all').find(e => e.type === 'all').qualifier).toBe('-');
    });

    it('maneja redirect y exists', () => {
        const entries = parseSPF('v=spf1 redirect=_spf.example.com');
        expect(entries.find(e => e.type === 'redirect').value).toBe('_spf.example.com');
    });
});

describe('parseDMARC', () => {
    it('devuelve null para entrada vacía', () => {
        expect(parseDMARC('')).toBeNull();
    });

    it('parsea tags en un objeto', () => {
        const d = parseDMARC('v=DMARC1; p=reject; rua=mailto:a@b.com; pct=100');
        expect(d.v).toBe('DMARC1');
        expect(d.p).toBe('reject');
        expect(d.rua).toBe('mailto:a@b.com');
        expect(d.pct).toBe('100');
    });
});

describe('parseMTASTSPolicy', () => {
    it('parsea version, mode y múltiples mx', () => {
        const p = parseMTASTSPolicy('version: STSv1\nmode: enforce\nmx: mail1.example.com\nmx: mail2.example.com\nmax_age: 86400');
        expect(p.version).toBe('STSv1');
        expect(p.mode).toBe('enforce');
        expect(p.mx).toEqual(['mail1.example.com', 'mail2.example.com']);
    });

    it('devuelve null si no hay campos reconocibles', () => {
        expect(parseMTASTSPolicy('# solo comentario')).toBeNull();
    });
});

describe('validateMTASTSPolicy', () => {
    it('valida una política enforce correcta', () => {
        const res = validateMTASTSPolicy({ httpStatus: 200, parsed: { version: 'STSv1', mode: 'enforce' } });
        expect(res.valid).toBe(true);
    });

    it('rechaza modo testing', () => {
        const res = validateMTASTSPolicy({ httpStatus: 200, parsed: { version: 'STSv1', mode: 'testing' } });
        expect(res.valid).toBe(false);
        expect(res.reason).toBe('mode_not_enforce');
    });

    it('rechaza HTTP != 200', () => {
        const res = validateMTASTSPolicy({ httpStatus: 404, parsed: null });
        expect(res.valid).toBe(false);
    });

    it('rechaza versión inválida', () => {
        const res = validateMTASTSPolicy({ httpStatus: 200, parsed: { version: 'STSv2', mode: 'enforce' } });
        expect(res.valid).toBe(false);
        expect(res.reason).toBe('invalid_version');
    });
});
