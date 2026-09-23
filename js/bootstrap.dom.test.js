// @vitest-environment jsdom
//
// El camino del navegador: bootstrap.js se cablea solo en DOMContentLoaded. El test de
// integración llama a init() a mano para aislar cada caso, así que este fichero (con su
// propio registro de módulos) comprueba que el arranque real sigue funcionando.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const INDEX_HTML = readFileSync(join(HERE, '..', 'index.html'), 'utf8');

describe('bootstrap.js en el navegador', () => {
    it('se cablea en DOMContentLoaded sin que nadie llame a init()', async () => {
        localStorage.setItem('lang', 'es');
        const inner = INDEX_HTML.slice(INDEX_HTML.indexOf('<html'), INDEX_HTML.lastIndexOf('</html>'));
        document.documentElement.innerHTML = inner.slice(inner.indexOf('>') + 1);
        await import('./bootstrap.js');

        const modal = document.getElementById('settings-modal');
        document.getElementById('settings-btn').click();
        expect(modal.classList.contains('hidden')).toBe(true);

        document.dispatchEvent(new window.Event('DOMContentLoaded'));
        document.getElementById('settings-btn').click();
        expect(modal.classList.contains('hidden')).toBe(false);
    });
});
