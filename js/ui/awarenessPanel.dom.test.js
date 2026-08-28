// @vitest-environment jsdom
import { describe, it, expect, beforeEach } from 'vitest';
import { renderAwarenessVendors, analyzeHeaders } from './awarenessPanel.js';
import { translations } from '../i18n.js';
import { saveSettings, resetSettingsCache, DEFAULT_SETTINGS } from '../settings.js';

const t = translations.es;

const vendor = (over = {}) => ({
    vendor: 'knowbe4',
    displayName: 'KnowBe4 (KSAT)',
    score: 0.9,
    level: 'alta',
    evidence: [{ signal: 'spf_include', value: '_spf.psm.knowbe4.com', weight: 0.9 }],
    productConfirmed: true,
    notes: null,
    ...over
});

describe('panel de awareness', () => {
    beforeEach(() => {
        localStorage.setItem('lang', 'es');
        resetSettingsCache();
        saveSettings({ ...DEFAULT_SETTINGS });
        document.body.innerHTML = `
            <span id="awareness-badge"></span>
            <div id="awareness-body"></div>
            <div id="awareness-header-tool">
                <textarea id="awareness-header-input"></textarea>
                <div id="awareness-header-results"></div>
            </div>`;
    });

    it('mientras escanea muestra el estado de carga', () => {
        renderAwarenessVendors(null, 'es', t);
        expect(document.getElementById('awareness-body').textContent).toContain('Analizando');
        expect(document.getElementById('awareness-badge').textContent).toBe('...');
    });

    it('pinta una tarjeta por vendor detectado y lo cuenta en el badge', () => {
        renderAwarenessVendors({ domain: 'acme.test', detectedVendors: [vendor()], indirectSignals: [] }, 'es', t);
        const body = document.getElementById('awareness-body');
        expect(body.querySelectorAll('.awareness-vendor-card')).toHaveLength(1);
        expect(body.textContent).toContain('KnowBe4');
        expect(document.getElementById('awareness-badge').textContent).toContain('1');
        expect(body.querySelector('.awareness-indirect')).toBeNull();
    });

    it('las señales indirectas van a un bloque aparte y NO cuentan como detección', () => {
        renderAwarenessVendors({
            domain: 'acme.test',
            detectedVendors: [],
            indirectSignals: [vendor({
                vendor: 'proofpointSat',
                displayName: 'Proofpoint Security Awareness (ex-Wombat)',
                score: 0.4,
                level: 'baja',
                productConfirmed: false,
                evidence: [{ signal: 'mx_hint_substring', value: 'pphosted', weight: 0.3 }]
            })]
        }, 'es', t);
        const body = document.getElementById('awareness-body');
        const indirect = body.querySelector('.awareness-indirect');
        expect(indirect).toBeTruthy();
        expect(indirect.textContent).toContain('Proofpoint');
        expect(indirect.textContent).toContain('no concluyentes');
        // No hay tarjeta de detección...
        expect(body.querySelectorAll('.awareness-vendor-card')).toHaveLength(0);
        // ...pero el badge tampoco puede decir "Sin evidencia DNS" mientras lista una
        // señal indirecta justo debajo: se contradecía a sí mismo.
        const badge = document.getElementById('awareness-badge').textContent;
        expect(badge).toContain('1');
        expect(badge).toContain('indirectas');
        expect(badge).not.toContain('Sin evidencia');
    });

    it('NO pide cabeceras de una simulación: se auditan dominios de terceros', () => {
        // Nunca se va a disponer de un correo de simulación de un tercero, así que pedirlo
        // era un callejón sin salida — y encima señalaba a un panel oculto por defecto.
        renderAwarenessVendors({ domain: 'acme.test', detectedVendors: [], indirectSignals: [] }, 'es', t);
        const texto = document.getElementById('awareness-body').textContent;
        expect(texto).toContain('no deja ninguna huella en DNS');
        expect(texto).not.toContain('Pega las cabeceras');
        expect(texto).not.toContain('analizador de cabeceras');
    });

    it('menciona el analizador de cabeceras solo si la herramienta está activada', () => {
        saveSettings({ showHeaderAnalyzer: true });
        renderAwarenessVendors({ domain: 'acme.test', detectedVendors: [], indirectSignals: [] }, 'es', t);
        expect(document.getElementById('awareness-body').textContent).toContain('analizador de cabeceras');
    });

    it('un sondeo incompleto no se presenta como "no se detectó nada"', () => {
        // El error caro en preventa: dar por hecho que un dominio no usa nada cuando en
        // realidad parte de las consultas DNS no llegaron a resolverse.
        renderAwarenessVendors({
            domain: 'acme.test', detectedVendors: [], indirectSignals: [],
            dnsIncomplete: true, dnsFailedQueries: 7
        }, 'es', t);
        const texto = document.getElementById('awareness-body').textContent;
        expect(texto).toContain('7 consultas DNS');
        expect(texto).toContain('no es concluyente');
        expect(document.getElementById('awareness-badge').textContent).toContain('Sondeo incompleto');
    });

    it('avisa del PermError de SPF, que puede ocultar señales', () => {
        renderAwarenessVendors({ domain: 'acme.test', detectedVendors: [], indirectSignals: [], spfPermError: true }, 'es', t);
        expect(document.getElementById('awareness-body').querySelector('.awareness-alert--warning')).toBeTruthy();
    });

    it('escapa los datos del vendor (vienen de DNS remoto)', () => {
        renderAwarenessVendors({
            domain: 'acme.test',
            detectedVendors: [vendor({ displayName: '<img src=x onerror=alert(1)>' })],
            indirectSignals: []
        }, 'es', t);
        const html = document.getElementById('awareness-body').innerHTML;
        expect(html).not.toContain('<img src=x');
    });

    it('el analizador de cabeceras detecta un vendor a partir de una muestra', () => {
        document.getElementById('awareness-header-input').value = [
            'Return-Path: <bounce@psm.knowbe4.com>',
            'From: "IT" <it@acme.test>',
            'X-PHISHTEST: 1',
            'Subject: Revisa tu contraseña'
        ].join('\n');
        analyzeHeaders();
        expect(document.getElementById('awareness-header-results').textContent).toContain('KnowBe4');
    });

    it('el analizador avisa si no se pega nada', () => {
        document.getElementById('awareness-header-input').value = '';
        analyzeHeaders();
        expect(document.getElementById('awareness-header-results').querySelector('.no-data')).toBeTruthy();
    });
});
