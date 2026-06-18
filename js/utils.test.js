import { describe, it, expect } from 'vitest';
import { normalizeDomain, html, raw, SafeHtml } from './utils.js';
import { escapeHtml } from './parsers.js';

describe('normalizeDomain', () => {
    it('extrae el dominio de un email', () => {
        expect(normalizeDomain('  User@Sub.Example.COM ')).toBe('sub.example.com');
    });
    it('quita esquema, www y ruta', () => {
        expect(normalizeDomain('https://www.example.com/path?x=1')).toBe('example.com');
    });
    it('devuelve cadena vacía para entrada vacía', () => {
        expect(normalizeDomain('')).toBe('');
        expect(normalizeDomain(null)).toBe('');
    });
});

describe('escapeHtml', () => {
    it('escapa caracteres peligrosos incluyendo comillas', () => {
        expect(escapeHtml(`<img src=x onerror="alert('x')">`)).toBe(
            '&lt;img src=x onerror=&quot;alert(&#39;x&#39;)&quot;&gt;'
        );
    });
    it('maneja null/undefined', () => {
        expect(escapeHtml(null)).toBe('');
        expect(escapeHtml(undefined)).toBe('');
    });
});

describe('html`` tagged template', () => {
    it('escapa interpolaciones por defecto', () => {
        const evil = '<script>alert(1)</script>';
        expect(html`<div>${evil}</div>`.toString()).toBe(
            '<div>&lt;script&gt;alert(1)&lt;/script&gt;</div>'
        );
    });

    it('no re-escapa valores raw() ni html anidado', () => {
        const inner = html`<b>${'<x>'}</b>`;
        const out = html`<p>${inner} ${raw('<hr>')}</p>`.toString();
        expect(out).toBe('<p><b>&lt;x&gt;</b> <hr></p>');
    });

    it('renderiza arrays concatenando con escapado', () => {
        const items = ['a&b', '<c>'];
        const out = html`<ul>${items.map(i => html`<li>${i}</li>`)}</ul>`.toString();
        expect(out).toBe('<ul><li>a&amp;b</li><li>&lt;c&gt;</li></ul>');
    });

    it('ignora null/false en interpolaciones', () => {
        expect(html`<x>${null}${false}${0}</x>`.toString()).toBe('<x>0</x>');
    });

    it('devuelve un SafeHtml', () => {
        expect(html`<a>`).toBeInstanceOf(SafeHtml);
    });
});
