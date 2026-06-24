import { describe, it, expect } from 'vitest';
import { parseSPF, parseDMARC, parseMTASTSPolicy, validateMTASTSPolicy, extractTxtValue, analyzeDKIMRecord, parseMaxAge } from './parsers.js';

// Claves públicas RSA reales (SPKI DER en base64 = valor del tag p= de un registro DKIM)
const RSA_1024 = 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHKI9Hv9UXFuaCMiUm4ByPZYWK4CySUGGnMLiUksN5v0eN7MlEbY1C3O8tU4yvGMGGrtJ279KC1EJi8twRn1bqVt5TsffmluZ6r5wZUndUHOLUmNubZdcaG8jW0uXy9w2pOJhr8sz+UAvXvthBnok0Ld8NL37wHC7lNePzrMYwGQIDAQAB';
const RSA_2048 = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmBBYI7zVX1AV5i/TYH8ujMlXkMfD7YzBoRnf1b34d5hhBa0RG3k7GT5Z8irrBPeP/ZIxKEIn4okhyhpd2NY0OP1RQsEEzDSnVQL5MmtINeyxY0bBALRL/maj6EtXrKrpAQvkfPOlEo9U4mRDJaLb0D0G6nxmqbztSlHToGlgp6B9EvDV/NNgYYhBVCaqfzVoJqgRzes5elhnODddSCw4burNfq+375sHa5vSlf6nZ38hz6witOE1NZEhI1MYIwiQhsfVy3tav9mdbL/YcW0gBmXMjq/03QlAQS8pUL4ZwGPhPjnt/0Q3X6jYforhfLIraQIrVRPhp5a6ilstNaZ8TQIDAQAB';

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

    it('expone max_age sin afectar a la validez', () => {
        const res = validateMTASTSPolicy({ httpStatus: 200, parsed: { version: 'STSv1', mode: 'enforce', max_age: '604800' } });
        expect(res.valid).toBe(true);
        expect(res.maxAge).toBe(604800);
    });

    it('maxAge es null si falta max_age (sigue siendo válida)', () => {
        const res = validateMTASTSPolicy({ httpStatus: 200, parsed: { version: 'STSv1', mode: 'enforce' } });
        expect(res.valid).toBe(true);
        expect(res.maxAge).toBeNull();
    });
});

describe('parseMaxAge', () => {
    it('convierte a entero', () => {
        expect(parseMaxAge({ max_age: '86400' })).toBe(86400);
    });
    it('devuelve null si falta o es inválido', () => {
        expect(parseMaxAge({})).toBeNull();
        expect(parseMaxAge(null)).toBeNull();
        expect(parseMaxAge({ max_age: 'abc' })).toBeNull();
    });
});

describe('analyzeDKIMRecord', () => {
    it('calcula 2048 bits para una clave RSA real', () => {
        const a = analyzeDKIMRecord(`v=DKIM1; k=rsa; p=${RSA_2048}`);
        expect(a.revoked).toBe(false);
        expect(a.algorithm).toBe('rsa');
        expect(a.keyBits).toBe(2048);
    });

    it('calcula 1024 bits para una clave RSA real', () => {
        const a = analyzeDKIMRecord(`v=DKIM1; p=${RSA_1024}`);
        expect(a.keyBits).toBe(1024);
        expect(a.algorithm).toBe('rsa'); // rsa por defecto
    });

    it('detecta clave revocada (p= vacío)', () => {
        const a = analyzeDKIMRecord('v=DKIM1; k=rsa; p=');
        expect(a.revoked).toBe(true);
        expect(a.keyBits).toBeNull();
    });

    it('detecta modo testing (t=y)', () => {
        const a = analyzeDKIMRecord(`v=DKIM1; t=y; p=${RSA_2048}`);
        expect(a.testing).toBe(true);
    });

    it('no calcula bits RSA para claves ed25519', () => {
        const a = analyzeDKIMRecord('v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=');
        expect(a.algorithm).toBe('ed25519');
        expect(a.keyBits).toBeNull();
    });
});
