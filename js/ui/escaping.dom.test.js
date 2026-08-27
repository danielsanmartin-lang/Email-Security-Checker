// @vitest-environment jsdom
//
// Guarda contra las DOS formas de estropear la entrega de HTML, que son la misma
// moneda por sus dos caras:
//
//   a) escapar de más → las etiquetas se ven como texto («…vendor.</li><li>Solo…»),
//      que es lo que pasó al convertir los paneles al helper html`` dejando dentro
//      fragmentos anidados en plantilla plana;
//   b) escapar de menos → el marcado de un dominio auditado entra en el DOM, que es
//      lo que pasó al borrar los escapeHtml() de una función que no se convirtió.
//
// Cada panel se renderiza con datos que llevan '<' y se comprueban las dos cosas a la
// vez: ninguna etiqueta visible como texto, ningún elemento inyectado.
import { describe, it, expect, beforeEach } from 'vitest';
import { renderAwarenessVendors } from './awarenessPanel.js';
import { renderAdvancedDNS } from './advancedDnsPanel.js';
import { translations } from '../i18n.js';

const t = translations.es;
const PAYLOAD = '<img src=x onerror=alert(1)>';

// Con datos LIMPIOS, ninguna etiqueta debe verse como texto: si aparece, es que se
// escapó marcado que debía renderizarse (el bug de los `<li>` y los `<br>`).
function assertSinEtiquetasVisibles(el) {
    expect(el.textContent, 'se ven etiquetas HTML como texto').not.toMatch(/<\/?[a-z]+[ >]/i);
}

// Con datos que TRAEN marcado, ese marcado debe acabar como texto y nunca como
// elemento: es dato de un tercero (el DNS del dominio auditado).
// Se comprueba contra el DOM y no contra innerHTML: al re-serializar, los '<' que
// viven DENTRO de un atributo se devuelven sin escapar (ahí no hacen falta), y eso
// daría una falsa alarma aunque el valor esté guardado como texto inofensivo.
function assertSinInyeccion(el) {
    expect(el.querySelector('img'), 'se ha inyectado un elemento en el DOM').toBeNull();
    expect(el.querySelector('[onerror]'), 'ha entrado un manejador de evento').toBeNull();
    expect(el.textContent, 'el valor debería seguir viéndose, pero como texto').toContain('<img src=x');
}

describe('entrega de HTML en los paneles', () => {
    beforeEach(() => {
        localStorage.setItem('lang', 'es');
        document.body.innerHTML = `
            <span id="awareness-badge"></span>
            <div id="awareness-body"></div>
            <div id="advanced-dns-body"></div>`;
    });

    describe('panel de awareness', () => {
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

        it('las notas del informe se pintan como lista, no como texto con <li>', () => {
            renderAwarenessVendors({
                domain: 'acme.test',
                detectedVendors: [],
                indirectSignals: [],
                notes: ['Primera nota del análisis.', 'Segunda nota del análisis.']
            }, 'es', t);
            const body = document.getElementById('awareness-body');
            expect(body.querySelectorAll('.awareness-notes-list li')).toHaveLength(2);
            expect(body.textContent).not.toContain('<li>');
            assertSinEtiquetasVisibles(body);
        });

        it('un vendor con marcado en el nombre, la evidencia o las notas no inyecta nada', () => {
            // e.value puede traer el contenido CRUDO de un registro TXT del dominio
            // auditado (evidencia generic_dkim_probe): es dato de un tercero.
            renderAwarenessVendors({
                domain: 'acme.test',
                detectedVendors: [vendor({
                    displayName: `KnowBe4 ${PAYLOAD}`,
                    notes: `Nota ${PAYLOAD}`,
                    evidence: [{ signal: 'generic_dkim_probe', value: `s1._domainkey -> ${PAYLOAD}`, weight: 0.8 }]
                })],
                indirectSignals: [],
                notes: []
            }, 'es', t);
            const body = document.getElementById('awareness-body');
            assertSinInyeccion(body);
            expect(body.textContent).toContain('KnowBe4');
        });

        it('lo mismo en el bloque de señales indirectas', () => {
            renderAwarenessVendors({
                domain: 'acme.test',
                detectedVendors: [],
                indirectSignals: [vendor({
                    productConfirmed: false,
                    displayName: `Proofpoint ${PAYLOAD}`,
                    evidence: [{ signal: 'mx_hint_substring', value: `pphosted ${PAYLOAD}`, weight: 0.3 }]
                })],
                notes: []
            }, 'es', t);
            assertSinInyeccion(document.getElementById('awareness-body'));
        });
    });

    describe('panel de DNS avanzado', () => {
        const base = (over = {}) => ({
            mtaSts: null, tlsRpt: null, tlsrptReporters: [], nsProvider: null,
            nsRecords: [], srvRecords: {}, daneRecords: {}, dnssec: null,
            txtVerifications: [], mxRecords: [], ...over
        });

        it('TLS-RPT: los destinos y el reporter se pintan, no se escriben como etiquetas', () => {
            renderAdvancedDNS(base({
                tlsRpt: { record: 'v=TLSRPTv1; rua=mailto:t@acme.test', rua: ['mailto:t@acme.test'] },
                tlsrptReporters: [{ uri: 'mailto:t@acme.test', reporter: 'Informes Acme' }]
            }), 'es', t);
            const body = document.getElementById('advanced-dns-body');
            expect(body.querySelector('.reporting-item__service')).toBeTruthy();
            assertSinEtiquetasVisibles(body);
        });

        it('SRV: varios registros se separan con saltos de línea reales', () => {
            renderAdvancedDNS(base({
                srvRecords: {
                    autodiscover: [
                        { target: 'a.acme.test', port: '443', priority: '0', weight: '1' },
                        { target: 'b.acme.test', port: '443', priority: '10', weight: '1' }
                    ]
                }
            }), 'es', t);
            const body = document.getElementById('advanced-dns-body');
            expect(body.querySelectorAll('br').length).toBeGreaterThan(0);
            expect(body.textContent).not.toContain('<br>');
            assertSinEtiquetasVisibles(body);
        });

        it('DANE: idem, y sin dejar pasar marcado del registro TLSA', () => {
            renderAdvancedDNS(base({
                daneRecords: { 'mx.acme.test': ['3 1 1 abc123', `3 1 1 ${PAYLOAD}`] }
            }), 'es', t);
            const body = document.getElementById('advanced-dns-body');
            expect(body.querySelectorAll('br').length).toBeGreaterThan(0);
            assertSinInyeccion(body);
        });

        it('DNSSEC validado: el aviso es un elemento, no texto con <div>', () => {
            renderAdvancedDNS(base({ dnssec: { signed: true, hasDnskey: true, ad: true } }), 'es', t);
            const body = document.getElementById('advanced-dns-body');
            expect(body.querySelectorAll('.info-block__detail').length).toBeGreaterThan(1);
            assertSinEtiquetasVisibles(body);
        });

        it('proveedor DNS y tokens TXT con marcado no inyectan nada', () => {
            renderAdvancedDNS(base({
                nsProvider: { name: `Proveedor ${PAYLOAD}`, hint: PAYLOAD, ns: `ns1.acme.test${PAYLOAD}` },
                nsRecords: [`ns1.acme.test${PAYLOAD}`],
                txtVerifications: [{ name: `Vendor ${PAYLOAD}`, category: 'other', record: PAYLOAD }]
            }), 'es', t);
            assertSinInyeccion(document.getElementById('advanced-dns-body'));
        });
    });
});
