// @vitest-environment jsdom
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// El diccionario tiene una lista por señal (MX e includes SPF se consultan por
// separado y con formatos distintos). Estas pruebas fijan que una entrada añadida
// por el usuario acaba en la lista correcta y con la forma que espera identifyMX.
describe('entradas personalizadas del diccionario', () => {
    beforeEach(() => {
        localStorage.clear();
        vi.resetModules();
    });
    afterEach(() => localStorage.clear());

    it('rehidrata las entradas MX guardadas y las antepone a las de serie', async () => {
        localStorage.setItem('custom_kb_mx', JSON.stringify([
            { pattern: 'paypalcorp.com', name: 'PayPal (infra propia)', type: 'provider' }
        ]));
        const { KB } = await import('./knowledge.js');
        const { identifyMX } = await import('./analyzer.js');
        expect(KB.mx[0].pattern).toBe('paypalcorp.com');
        const id = identifyMX('mx1.paypalcorp.com', 'paypal.com');
        expect(id.name).toBe('PayPal (infra propia)');
        expect(id.type).toBe('provider');
    });

    it('sigue rehidratando las entradas SPF y no las mezcla con las MX', async () => {
        localStorage.setItem('custom_kb_spf', JSON.stringify([
            { pattern: 'envios.acme.net', name: 'Acme Mailer', category: 'marketing', cat_label: 'Marketing' }
        ]));
        const { KB } = await import('./knowledge.js');
        expect(KB.spf.some(e => e.pattern === 'envios.acme.net')).toBe(true);
        expect(KB.mx.some(e => e.pattern === 'envios.acme.net')).toBe(false);
    });

    it('ignora un localStorage corrupto sin tumbar el diccionario', async () => {
        localStorage.setItem('custom_kb_mx', '{no es json');
        const { KB } = await import('./knowledge.js');
        expect(Array.isArray(KB.mx)).toBe(true);
        expect(KB.mx.length).toBeGreaterThan(0);
    });
});

describe('openKbModal', () => {
    beforeEach(() => {
        document.body.innerHTML = `
            <div id="add-kb-modal" class="modal hidden">
                <input id="kb-domain"><input id="kb-name">
                <select id="kb-category">
                    <option value="provider" data-kb-for="mx">Proveedor</option>
                    <option value="marketing" data-kb-for="spf">Marketing</option>
                    <option value="seg">SEG</option>
                    <option value="ices">ICES</option>
                </select>
            </div>`;
    });

    it('para un MX ofrece solo proveedor/SEG/ICES', async () => {
        const { openKbModal } = await import('./ui.js');
        openKbModal('paypalcorp.com', 'mx');
        const visibles = [...document.getElementById('kb-category').options].filter(o => !o.hidden).map(o => o.value);
        expect(visibles).toEqual(['provider', 'seg', 'ices']);
        expect(document.getElementById('kb-category').value).toBe('seg');
        expect(document.getElementById('add-kb-modal').dataset.kbList).toBe('mx');
        expect(document.getElementById('kb-domain').value).toBe('paypalcorp.com');
    });

    it('para un include SPF oculta las categorías que solo valen para MX', async () => {
        const { openKbModal } = await import('./ui.js');
        openKbModal('envios.acme.net');
        const visibles = [...document.getElementById('kb-category').options].filter(o => !o.hidden).map(o => o.value);
        expect(visibles).not.toContain('provider');
        expect(visibles).toContain('marketing');
        expect(document.getElementById('add-kb-modal').dataset.kbList).toBe('spf');
    });
});
