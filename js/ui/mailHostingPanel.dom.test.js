// @vitest-environment jsdom
//
// El panel del proveedor ahora responde a DOS preguntas que antes se confundían en una:
// quién FILTRA el correo (el MX) y dónde VIVEN los buzones. Estos tests fijan lo que el
// panel puede y —sobre todo— lo que NO puede afirmar.
import { describe, it, expect, beforeEach } from 'vitest';
import { renderProviderPanel } from './mxPanel.js';
import { translations } from '../i18n.js';

const t = translations.es;

function build() {
    document.body.innerHTML = '<div id="provider-body"></div>';
    return document.getElementById('provider-body');
}

const base = {
    provider: 'Hornetsecurity',
    providerIdentified: true,
    providerSource: { key: 'evidence_mx', arg: 'mx01.hornetsecurity.com' }
};

beforeEach(() => { localStorage.setItem('lang', 'es'); });

describe('panel de proveedor: los dos ejes', () => {
    it('separa el filtro de entrada de la plataforma de buzón', () => {
        const el = build();
        renderProviderPanel({
            ...base,
            mailHosting: {
                kind: 'cloud', confidence: 0.95, level: 'alta', platform: 'm365',
                tenant: null, evidence: [{ signal: 'autodiscover_cloud', value: 'autodiscover.outlook.com', weight: 0.9 }],
                notes: [{ key: 'seg_fronting' }], incomplete: false
            }
        });
        expect(el.textContent).toContain(t.inbound_filter_label);
        expect(el.textContent).toContain('Hornetsecurity');
        expect(el.textContent).toContain(t.mailbox_platform_label);
        expect(el.textContent).toContain('Microsoft 365');
        expect(el.textContent).toContain(t.mail_hosting_cloud);
        // El aviso que cierra el hueco conceptual del informe.
        expect(el.textContent).toContain(t.mh_note_seg_fronting);
    });

    it('muestra el tenant cuando se ha descubierto', () => {
        const el = build();
        renderProviderPanel({
            ...base,
            mailHosting: {
                kind: 'hybrid', confidence: 0.85, level: 'alta', platform: 'm365',
                tenant: 'grupoinditex.onmicrosoft.com', evidence: [], notes: [], incomplete: false
            }
        });
        expect(el.textContent).toContain('grupoinditex.onmicrosoft.com');
        expect(el.textContent).toContain(t.mail_hosting_hybrid);
        // El híbrido no debe afirmar que el servidor local siga en uso.
        expect(el.textContent).toContain(t.mail_hosting_detail_hybrid);
    });

    it('traduce las señales de evidencia en vez de mostrar su clave interna', () => {
        const el = build();
        renderProviderPanel({
            ...base,
            mailHosting: {
                kind: 'on_premise', confidence: 0.9, level: 'alta', platform: 'own', tenant: null,
                evidence: [{ signal: 'autodiscover_own_asn', value: 'ASMERCADONA - Mercadona S.A, ES', weight: 0.9 }],
                notes: [], incomplete: false
            }
        });
        expect(el.textContent).toContain(t.mh_signal_autodiscover_own_asn);
        expect(el.textContent).toContain('ASMERCADONA');
        expect(el.textContent).not.toContain('autodiscover_own_asn');
    });
});

describe('panel de proveedor: lo que NO debe afirmar', () => {
    it('sin clasificación, no pinta nada de hospedaje (informes antiguos)', () => {
        const el = build();
        renderProviderPanel({ ...base, mailHosting: null });
        expect(el.textContent).toContain('Hornetsecurity');
        expect(el.textContent).not.toContain(t.panel_mail_hosting_label);
    });

    it('"no determinable" se presenta sin insignia ni porcentaje', () => {
        // Un "0%" junto a "no determinable" sugeriría una medición donde no hay ninguna.
        const el = build();
        renderProviderPanel({
            ...base,
            mailHosting: {
                kind: 'undetermined', confidence: 0, level: 'baja', platform: 'unknown',
                tenant: null, evidence: [], notes: [{ key: 'no_autodiscover' }], incomplete: false
            }
        });
        expect(el.textContent).toContain(t.mail_hosting_undetermined);
        expect(el.textContent).toContain(t.mail_hosting_detail_undetermined);
        expect(el.querySelector('.seg-confidence')).toBeNull();
        expect(el.textContent).not.toContain('0%');
        // Y explica que la ausencia de autodiscover no es indicio de nada.
        expect(el.textContent).toContain(t.mh_note_no_autodiscover);
    });

    it('avisa cuando la evidencia es escasa, en vez de presentarla como hecho', () => {
        const el = build();
        renderProviderPanel({
            ...base,
            mailHosting: {
                kind: 'hosted_third_party', confidence: 0.4, level: 'baja', platform: 'hosted',
                tenant: null, evidence: [], notes: [], incomplete: false
            }
        });
        expect(el.textContent).toContain(t.mh_low_confidence_note);
    });

    it('lleva siempre el aviso de que esto se deduce solo de DNS público', () => {
        const el = build();
        renderProviderPanel({
            ...base,
            mailHosting: { kind: 'cloud', confidence: 0.8, level: 'media', platform: 'google', tenant: null, evidence: [], notes: [], incomplete: false }
        });
        expect(el.textContent).toContain(t.mail_hosting_disclaimer);
    });
});

describe('panel de proveedor: entrega de HTML', () => {
    // El nombre del ASN y el del tenant son texto que controla un tercero (el DNS del
    // dominio auditado), así que son superficie de inyección real, no teórica.
    const PAYLOAD = '<img src=x onerror=alert(1)>';

    it('el marcado de un tercero entra como texto, nunca como elemento', () => {
        const el = build();
        renderProviderPanel({
            ...base,
            mailHosting: {
                kind: 'on_premise', confidence: 0.9, level: 'alta', platform: 'own',
                tenant: PAYLOAD,
                evidence: [{ signal: 'autodiscover_own_asn', value: PAYLOAD, weight: 0.9 }],
                notes: [], incomplete: false
            }
        });
        expect(el.querySelector('img'), 'se ha inyectado un elemento en el DOM').toBeNull();
        expect(el.querySelector('[onerror]'), 'ha entrado un manejador de evento').toBeNull();
        expect(el.textContent).toContain('<img src=x');
    });

    it('con datos limpios no se ven etiquetas HTML como texto', () => {
        const el = build();
        renderProviderPanel({
            ...base,
            mailHosting: {
                kind: 'hybrid', confidence: 0.85, level: 'alta', platform: 'm365',
                tenant: 'acme.onmicrosoft.com',
                evidence: [{ signal: 'dkim_tenant_m365', value: 'acme.onmicrosoft.com', weight: 0.85 }],
                notes: [{ key: 'seg_fronting' }], incomplete: false
            }
        });
        expect(el.textContent, 'se ven etiquetas HTML como texto').not.toMatch(/<\/?[a-z]+[ >]/i);
    });
});

describe('panel de proveedor: los tres idiomas', () => {
    it.each(['es', 'en', 'de'])('renderiza el veredicto en %s', (lang) => {
        localStorage.setItem('lang', lang);
        const el = build();
        renderProviderPanel({
            ...base,
            mailHosting: { kind: 'on_premise', confidence: 0.9, level: 'alta', platform: 'own', tenant: null, evidence: [], notes: [], incomplete: false }
        });
        expect(el.textContent).toContain(translations[lang].mail_hosting_on_premise);
        expect(el.textContent).toContain(translations[lang].mail_hosting_disclaimer);
    });
});

// El informe enumera los campos del result uno a uno, así que un campo nuevo se pierde
// en silencio si nadie lo añade. Este test es la red que lo detecta.
describe('informe exportado', () => {
    it('incluye el hospedaje, su evidencia y sus salvedades', async () => {
        const { generateReportHTML } = await import('../export.js');
        const { state } = await import('../state.js');
        localStorage.setItem('lang', 'es');
        state.currentDomain = 'inditex.com';
        state.currentResult = {
            ...base,
            segList: [], icesList: [], spfServices: [], mxRecords: [], spfEntries: [],
            dmarcRua: [], dmarcRuf: [], rblResults: [], scoreCard: { findings: [], grade: 'B', score: 70, cardClass: '' },
            scannedAt: new Date().toISOString(),
            mailHosting: {
                kind: 'hybrid', confidence: 0.85, level: 'alta', platform: 'm365',
                tenant: 'grupoinditex.onmicrosoft.com',
                evidence: [{ signal: 'autodiscover_own_asn', value: 'AS_INDITEX', weight: 0.9 }],
                notes: [{ key: 'seg_fronting' }], incomplete: false
            }
        };
        const report = generateReportHTML().toString();
        expect(report).toContain(t.mail_hosting_hybrid);
        expect(report).toContain('grupoinditex.onmicrosoft.com');
        expect(report).toContain(t.mh_signal_autodiscover_own_asn);
        expect(report).toContain(t.mail_hosting_disclaimer);
    });

    it('omite el bloque cuando no hay clasificación', async () => {
        const { generateReportHTML } = await import('../export.js');
        const { state } = await import('../state.js');
        state.currentResult = { ...state.currentResult, mailHosting: null };
        const report = generateReportHTML().toString();
        expect(report).not.toContain(t.mail_hosting_hybrid);
    });
});
