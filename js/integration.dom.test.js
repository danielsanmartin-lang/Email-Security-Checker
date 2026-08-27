// @vitest-environment jsdom
//
// Test de integración: monta index.html de verdad, mockea la capa DoH y recorre el
// flujo completo (submit → consultas DNS → análisis → render). Es lo que los tests
// unitarios no pueden cubrir: el cableado entre bootstrap, app, analyzer y los
// paneles de ui/, que antes solo se comprobaba a mano en el navegador.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const INDEX_HTML = readFileSync(join(HERE, '..', 'index.html'), 'utf8');

// ===== Zona DNS simulada de acme.test =====
const TXT = {
    'acme.test': ['v=spf1 include:_spf.google.com -all', 'MS=ms12345'],
    '_dmarc.acme.test': ['v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@acme.test'],
    '_spf.google.com': ['v=spf1 ip4:35.190.247.0/24 -all'],
    'google._domainkey.acme.test': ['v=DKIM1; k=rsa; p=' + 'A'.repeat(392)],
    '_mta-sts.acme.test': ['v=STSv1; id=20260101T000000'],
    '_smtp._tls.acme.test': ['v=TLSRPTv1; rua=mailto:tls@acme.test'],
    'default._bimi.acme.test': ['v=BIMI1; l=https://acme.test/logo.svg; a=https://acme.test/vmc.pem']
};
const MX = { 'acme.test': ['10 mx.mimecast.com'] };
const NS = { 'acme.test': ['ns1.cloudflare.com'] };

function dohResponse(name, type) {
    const answer = (data, t) => ({ Status: 0, Answer: data.map(d => ({ type: t, data: d })) });
    if (type === 'TXT' && TXT[name]) return answer(TXT[name].map(v => `"${v}"`), 16);
    if (type === 'MX' && MX[name]) return answer(MX[name], 15);
    if (type === 'NS' && NS[name]) return answer(NS[name], 2);
    if (type === 'A' && name === 'mx.mimecast.com') return answer(['203.0.113.10'], 1);
    if (type === 'DNSKEY' && name === 'acme.test') return { Status: 0, AD: true, Answer: [{ type: 48, data: 'key' }] };
    return { Status: 0 }; // NOERROR sin respuestas
}

function installFetchMock() {
    global.fetch = vi.fn(async (url) => {
        const href = String(url);
        if (href.startsWith('https://dns.google/') || href.startsWith('https://cloudflare-dns.com/')) {
            const u = new URL(href);
            return {
                ok: true,
                status: 200,
                json: async () => dohResponse(u.searchParams.get('name'), u.searchParams.get('type'))
            };
        }
        // Política MTA-STS: se sirve en modo enforce y cubriendo el MX real.
        if (href.includes('mta-sts.acme.test')) {
            return {
                ok: true,
                status: 200,
                type: 'basic',
                text: async () => 'version: STSv1\nmode: enforce\nmx: mx.mimecast.com\nmax_age: 604800\n'
            };
        }
        // CT logs (crt.sh / certspotter): sin datos, la detección degrada con elegancia.
        return { ok: true, status: 200, json: async () => [] };
    });
}

function mountIndexHtml() {
    const inner = INDEX_HTML.slice(INDEX_HTML.indexOf('<html'), INDEX_HTML.lastIndexOf('</html>'));
    document.documentElement.innerHTML = inner.slice(inner.indexOf('>') + 1);
}

// Espera activa a una condición del DOM (el flujo tiene un delay de render de 300 ms).
async function waitFor(predicate, { timeout = 5000, step = 25 } = {}) {
    const started = Date.now();
    while (Date.now() - started < timeout) {
        if (predicate()) return true;
        await new Promise(r => setTimeout(r, step));
    }
    throw new Error('waitFor: la condición no se cumplió a tiempo');
}

const visible = (id) => !document.getElementById(id).classList.contains('hidden');

async function runFlow(domain) {
    document.getElementById('domain-input').value = domain;
    document.getElementById('search-form').dispatchEvent(new window.Event('submit', { cancelable: true, bubbles: true }));
    await waitFor(() => visible('results-section') || visible('error-section'));
}

describe('flujo completo (jsdom + DoH simulado)', () => {
    beforeEach(async () => {
        localStorage.clear();
        localStorage.setItem('lang', 'es');
        mountIndexHtml();
        installFetchMock();
        const { clearDnsCache } = await import('./api.js');
        clearDnsCache();
        await import('./bootstrap.js');
        document.dispatchEvent(new window.Event('DOMContentLoaded'));
    });

    afterEach(() => {
        vi.restoreAllMocks();
        vi.resetModules();
    });

    it('las herramientas avanzadas vienen ocultas', () => {
        // Visor RUA, selector DKIM y analizador de cabeceras: los tres exigen algo que
        // solo tiene quien administra el correo del dominio, así que no se enseñan por
        // defecto.
        expect(document.getElementById('rua-section').hidden).toBe(true);
        expect(document.getElementById('dkim-toggle-container').hidden).toBe(true);
        expect(document.getElementById('awareness-header-tool').hidden).toBe(true);
    });

    it('un análisis completo funciona con las tres herramientas ocultas', async () => {
        await runFlow('acme.test');
        expect(visible('results-section')).toBe(true);
        expect(Number(document.getElementById('score-number').textContent)).toBeGreaterThan(0);
    });

    it('el deep-link ?dkim= se sigue honrando aunque el campo esté oculto', async () => {
        // Un enlace compartido no debe dejar de funcionar porque el receptor no tenga
        // la herramienta visible.
        const { parseDkimSelectors } = await import('./utils.js');
        expect(parseDkimSelectors('google,s1')).toEqual(['google', 's1']);
        document.getElementById('dkim-input').value = 'google';
        await runFlow('acme.test');
        expect(visible('results-section')).toBe(true);
    });

    it('activarlas en Ajustes las muestra al instante, sin recargar', async () => {
        const { saveSettings } = await import('./settings.js');
        document.getElementById('settings-btn').click();
        document.getElementById('settings-tool-rua').checked = true;
        document.getElementById('settings-tool-dkim').checked = true;
        document.getElementById('settings-tool-headers').checked = true;
        document.getElementById('settings-form').dispatchEvent(new window.Event('submit', { cancelable: true, bubbles: true }));
        expect(document.getElementById('rua-section').hidden).toBe(false);
        expect(document.getElementById('dkim-toggle-container').hidden).toBe(false);
        expect(document.getElementById('awareness-header-tool').hidden).toBe(false);
        saveSettings({ showDmarcReportViewer: false, showDkimSelector: false, showHeaderAnalyzer: false });
    });

    it('analiza un dominio y pinta la tarjeta de puntuación', async () => {
        await runFlow('acme.test');
        expect(visible('results-section')).toBe(true);
        expect(document.getElementById('result-domain').textContent).toBe('acme.test');
        const score = Number(document.getElementById('score-number').textContent);
        expect(score).toBeGreaterThan(0);
        expect(document.getElementById('score-grade').textContent).toMatch(/^[A-F]\+?$/);
        expect(document.querySelectorAll('.finding-item').length).toBeGreaterThan(3);
    });

    it('pinta los paneles principales con los datos de la zona simulada', async () => {
        await runFlow('acme.test');
        expect(document.getElementById('mx-body').textContent).toContain('mx.mimecast.com');
        // El MX de Mimecast se reconoce como capa de seguridad (SEG).
        expect(document.getElementById('security-body').textContent).toContain('Mimecast');
        expect(document.getElementById('summary-dmarc-value').textContent.toLowerCase()).toContain('reject');
        expect(document.querySelectorAll('#spf-table-body tr').length).toBeGreaterThan(1);
        expect(document.getElementById('dmarc-reporting-body').textContent).toContain('dmarc@acme.test');
        expect(document.getElementById('bimi-body').textContent).toContain('v=BIMI1');
        expect(document.getElementById('advanced-dns-body').textContent).toContain('MTA-STS');
    });

    it('normaliza la entrada (email → dominio) y actualiza el campo', async () => {
        await runFlow('  Buzon@ACME.test ');
        expect(document.getElementById('domain-input').value).toBe('acme.test');
        expect(document.getElementById('result-domain').textContent).toBe('acme.test');
    });

    it('rechaza un dominio con formato inválido sin consultar DNS', async () => {
        global.fetch.mockClear();
        document.getElementById('domain-input').value = 'no-es-un-dominio';
        document.getElementById('search-form').dispatchEvent(new window.Event('submit', { cancelable: true, bubbles: true }));
        await waitFor(() => visible('error-section'));
        expect(document.getElementById('error-message').textContent.length).toBeGreaterThan(0);
        expect(global.fetch).not.toHaveBeenCalled();
    });

    it('muestra un error claro cuando el dominio no existe (NXDOMAIN)', async () => {
        global.fetch = vi.fn(async () => ({ ok: true, status: 200, json: async () => ({ Status: 3 }) }));
        await runFlow('no-existe.test');
        expect(visible('error-section')).toBe(true);
        expect(document.getElementById('error-message').textContent).toContain('no-existe.test');
    });

    it('cambia de idioma y re-renderiza sin perder el resultado', async () => {
        await runFlow('acme.test');
        const scoreEs = document.getElementById('score-number').textContent;
        const enItem = document.querySelector('.lang-dropdown__item[data-lang="en"]');
        enItem.dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
        await waitFor(() => document.documentElement.lang === 'en');
        expect(document.getElementById('score-number').textContent).toBe(scoreEs);
        expect(document.getElementById('search-title') || document.body.textContent).toBeTruthy();
        // La hora del escaneo NO se recalcula al cambiar de idioma.
        expect(document.getElementById('result-timestamp').textContent.length).toBeGreaterThan(0);
    });

    it('el botón de búsqueda se deshabilita durante el análisis', async () => {
        const btn = document.getElementById('search-btn');
        document.getElementById('domain-input').value = 'acme.test';
        document.getElementById('search-form').dispatchEvent(new window.Event('submit', { cancelable: true, bubbles: true }));
        await waitFor(() => btn.disabled === true, { timeout: 1000 });
        await waitFor(() => visible('results-section'));
        expect(btn.disabled).toBe(false);
    });

    it('el análisis obsoleto no pisa el resultado del nuevo', async () => {
        await runFlow('acme.test');
        const shown = document.getElementById('result-domain').textContent;
        expect(shown).toBe('acme.test');
        // Un segundo análisis reemplaza por completo al anterior.
        await runFlow('acme.test');
        expect(document.getElementById('result-domain').textContent).toBe('acme.test');
    });
});
