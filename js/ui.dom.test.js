// @vitest-environment jsdom
import { describe, it, expect } from 'vitest';
import { renderSPFTree } from './ui.js';

describe('renderSPFTree (jsdom)', () => {
    it('escapa nombres de dominio maliciosos en el árbol SPF', () => {
        const tree = {
            domain: '<img src=x onerror=alert(1)>',
            lookups: 1,
            error: null,
            children: [
                { type: 'include', target: '"><script>alert(2)</script>' }
            ]
        };
        const out = renderSPFTree(tree).toString();
        expect(out).not.toContain('<img src=x');
        expect(out).not.toContain('<script>alert(2)');
        expect(out).toContain('&lt;img src=x');
        expect(out).toContain('&lt;script&gt;');
    });

    it('renderiza el código de error loop de forma localizada y segura', () => {
        const out = renderSPFTree({ domain: 'a.com', lookups: 0, error: 'loop', children: [] }).toString();
        expect(out).toContain('tooltip-trigger');
        expect(out).toContain('[Error:');
        // No debe filtrar el código crudo
        expect(out).not.toMatch(/\[Error: loop\]/);
    });
});
