import { describe, it, expect } from 'vitest';
import { parseHeaders, detectFromHeaders } from './headerAnalyzer.js';

describe('parseHeaders', () => {
    it('parsea cabeceras y des-pliega líneas continuadas (folding)', () => {
        const raw = 'From: a@b.com\nSubject: hola\n mundo\n\nbody aquí';
        const h = parseHeaders(raw);
        expect(h.get('from')).toEqual(['a@b.com']);
        expect(h.get('subject')).toEqual(['hola mundo']);
        expect(h.has('body')).toBe(false); // se corta en la línea en blanco (cuerpo)
    });

    it('agrupa múltiples cabeceras con el mismo nombre', () => {
        const h = parseHeaders('Received: by x\nReceived: by y');
        expect(h.get('received')).toHaveLength(2);
    });

    it('devuelve un Map vacío para entrada vacía', () => {
        expect(parseHeaders('').size).toBe(0);
        expect(parseHeaders(null).size).toBe(0);
    });
});

describe('detectFromHeaders', () => {
    it('devuelve error empty para entrada vacía', () => {
        expect(detectFromHeaders('').error).toBe('empty');
        expect(detectFromHeaders('   ').error).toBe('empty');
    });

    it('detecta Microsoft AST por simulator.office.com (cubre el punto ciego DNS)', () => {
        const raw = 'Return-Path: <noreply@simulator.office.com>\nFrom: IT <noreply@simulator.office.com>\nSubject: test';
        const r = detectFromHeaders(raw);
        const ast = r.detectedVendors.find(v => v.vendor === 'msAttackSimulation');
        expect(ast).toBeTruthy();
        expect(ast.level).toBe('alta');
        expect(ast.productConfirmed).toBe(true);
        expect(ast.source).toBe('headers');
    });

    it('detecta Gophish por la cabecera propietaria X-Gophish-Contact', () => {
        const raw = 'From: x@y.com\nX-Gophish-Contact: target@corp.com\nSubject: hi';
        const r = detectFromHeaders(raw);
        expect(r.detectedVendors.some(v => v.vendor === 'gophish')).toBe(true);
    });

    it('detecta KnowBe4 por la cabecera X-PHISHTEST', () => {
        const raw = 'From: x@y.com\nX-PHISHTEST: abc123\nSubject: hi';
        const r = detectFromHeaders(raw);
        expect(r.detectedVendors.some(v => v.vendor === 'knowbe4')).toBe(true);
    });

    it('no detecta nada en un correo corporativo normal', () => {
        const raw = 'From: jefe@empresa.com\nTo: yo@empresa.com\nSubject: reunion\nReceived: by mail.empresa.com';
        const r = detectFromHeaders(raw);
        expect(r.detectedVendors).toHaveLength(0);
    });
});
