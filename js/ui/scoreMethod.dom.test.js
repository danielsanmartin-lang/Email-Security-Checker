// @vitest-environment jsdom
import { describe, it, expect, beforeEach, afterEach, beforeAll } from 'vitest';
import { analyze, calculateScoreAndFindings, SCORE_WEIGHTS } from '../analyzer.js';
import { buildScoreMethod, renderScoreMethod } from './scoreMethod.js';
import { renderLookalikes } from './lookalikePanel.js';
import { generateReportHTML } from '../export.js';
import { state } from '../state.js';
import { setLanguage } from '../lang.js';
import { ensureLanguage } from '../i18n.js';

// Inglés y alemán se descargan bajo demanda.
beforeAll(() => Promise.all(['en', 'de'].map(ensureLanguage)));

const RSA_2048 = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmBBYI7zVX1AV5i/TYH8ujMlXkMfD7YzBoRnf1b34d5hhBa0RG3k7GT5Z8irrBPeP/ZIxKEIn4okhyhpd2NY0OP1RQsEEzDSnVQL5MmtINeyxY0bBALRL/maj6EtXrKrpAQvkfPOlEo9U4mRDJaLb0D0G6nxmqbztSlHToGlgp6B9EvDV/NNgYYhBVCaqfzVoJqgRzes5elhnODddSCw4burNfq+375sHa5vSlf6nZ38hz6witOE1NZEhI1MYIwiQhsfVy3tav9mdbL/YcW0gBmXMjq/03QlAQS8pUL4ZwGPhPjnt/0Q3X6jYforhfLIraQIrVRPhp5a6ilstNaZ8TQIDAQAB';

// Proofpoint en el MX, reject e informes, DKIM de 2048 y solo DNSSEC en transporte:
// 0,60·100 + 0,25·100 + 0,15·25 = 88,75 → 89 (A).
function resultWith(mxHosts, dmarc = 'v=DMARC1; p=reject; rua=mailto:d@acme.com') {
    const result = analyze(mxHosts.map((host, i) => ({ priority: 10 + i, host })), 'v=spf1 -all', dmarc, {
        domain: 'acme.com', mtaSts: null, tlsRpt: null, srvRecords: {}, daneRecords: {},
        dnssec: { signed: true, hasDnskey: true, ad: true, validationKnown: true }
    });
    Object.assign(result, {
        spfLookups: 1,
        spfTree: { domain: 'acme.com', lookups: 1, error: null, children: [] },
        dkimRecords: { records: [{ selector: 's1', record: `v=DKIM1; k=rsa; p=${RSA_2048}` }] },
        bimiRecord: null, rblResults: [], awarenessResult: null
    });
    result.scoreCard = calculateScoreAndFindings(result);
    return result;
}

const textOf = (safe) => {
    const div = document.createElement('div');
    div.innerHTML = safe.toString();
    return div.textContent.replace(/\s+/g, ' ');
};

describe('"¿Cómo se calcula la nota?"', () => {
    afterEach(() => setLanguage('es'));

    it('enseña la cuenta de este dominio con sus números reales', () => {
        const result = resultWith(['mxa-1.gslb.pphosted.com']);
        expect(result.scoreCard.score).toBe(89);
        const text = textOf(buildScoreMethod(result, 'es'));
        expect(text).toContain('Suplantación 100 × 60 % + Filtrado entrante 100 × 25 % + Transporte 25 × 15 % = 88,75');
        expect(text).toContain('Nota: 89 (A)');
        expect(text).toContain('Por encima de lo habitual');
    });

    it('explica el tope cuando se aplica', () => {
        const result = resultWith(['mxa-1.gslb.pphosted.com'], 'v=DMARC1; p=none; rua=mailto:d@acme.com');
        const text = textOf(buildScoreMethod(result, 'es'));
        expect(text).toContain('Después se aplica un tope.');
        expect(text).toContain('Nota: 45 (D)');
    });

    it('dice cuándo un eje no aplica y se reparte su peso', () => {
        const text = textOf(buildScoreMethod(resultWith([]), 'es'));
        expect(text).toContain('Suplantación 100 × 100 % = 100');
        expect(text).toContain('su peso se reparte entre los demás');
    });

    it('los puntos de la tabla salen de las constantes del motor', () => {
        const div = document.createElement('div');
        div.innerHTML = buildScoreMethod(resultWith(['acme-com.mail.protection.outlook.com']), 'es').toString();
        const rowFor = (label) => [...div.querySelectorAll('tr')].find(tr => tr.textContent.includes(label));
        expect(rowFor('Solo filtrado nativo').querySelector('.score-method__points').textContent).toBe(String(SCORE_WEIGHTS.filterNative));
        expect(rowFor('Subdominios sin protección').querySelector('.score-method__points').textContent).toBe(`−${Math.abs(SCORE_WEIGHTS.dmarcSpNone)}`);
        expect(rowFor('DKIM no detectado').querySelector('.score-method__points').textContent).toBe('No evaluable');
    });

    it('explica qué significa cada letra y lo que no puntúa', () => {
        const text = textOf(buildScoreMethod(resultWith(['mxa-1.gslb.pphosted.com']), 'es'));
        for (const grade of ['A+ (95–100)', 'A (85–94)', 'B (70–84)', 'C (55–69)', 'D (40–54)', 'F (0–39)']) {
            expect(text).toContain(grade);
        }
        expect(text).toContain('61 dominios');
        expect(text).toContain('Dominios parecidos: lo que registran otros');
    });

    it('sale en el idioma pedido (en, de)', () => {
        const result = resultWith(['mxa-1.gslb.pphosted.com']);
        const en = textOf(buildScoreMethod(result, 'en'));
        expect(en).toContain('What it measures and what it does not');
        expect(en).toContain('Spoofing 100 × 60% + Inbound filtering 100 × 25% + Transport 25 × 15% = 88.75');
        const de = textOf(buildScoreMethod(result, 'de'));
        expect(de).toContain('Was gemessen wird und was nicht');
        expect(de).toContain('= 88,75');
    });

    it('renderScoreMethod pinta el cuerpo del modal en el idioma activo', () => {
        document.body.innerHTML = '<div id="score-method-body"></div>';
        setLanguage('de');
        renderScoreMethod(resultWith(['mxa-1.gslb.pphosted.com']));
        expect(document.getElementById('score-method-body').textContent).toContain('Die Note dieser Domain');
    });
});

describe('panel de dominios parecidos', () => {
    beforeEach(() => {
        document.body.innerHTML = '<span id="lookalike-badge"></span><div id="lookalike-body"></div>';
    });

    it('mientras busca, lo dice', () => {
        renderLookalikes(undefined);
        expect(document.getElementById('lookalike-body').textContent).toContain('Buscando dominios parecidos');
    });

    it('si la búsqueda falla, lo dice', () => {
        renderLookalikes(null);
        expect(document.getElementById('lookalike-body').textContent).toContain('No se pudo completar');
    });

    it('lista lo encontrado con su estado, y el badge cuenta los que reciben correo sin vínculo', () => {
        renderLookalikes({
            checked: 42,
            unresolved: 2,
            found: [
                { domain: 'acme-es.com', technique: 'combo', mx: ['mail.evil.example', 'mx2.evil.example'], ns: [], kind: 'mx' },
                { domain: 'acrne.es', technique: 'homoglyph', mx: [], ns: [], kind: 'registered' },
                { domain: 'acme.com', technique: 'tld', mx: ['mx1.acme.es'], ns: [], kind: 'own' }
            ]
        });
        const body = document.getElementById('lookalike-body');
        expect(body.textContent).toContain('Se han comprobado 42 variantes');
        expect(body.textContent).toContain('2 variantes no se pudieron resolver');
        const text = (tr) => tr.textContent.replace(/\s+/g, ' ').trim();
        const rows = [...body.querySelectorAll(':scope > .lookalike-table-wrap tbody tr')].map(text);
        // Sin `cert`, la columna de certificado queda en "—".
        expect(rows[0]).toBe('acme-es.com País en el nombre mail.evil.example (+1) Recibe correo, sin vínculo visible —');
        expect(rows[1]).toContain('Probablemente propio');
        // Los registrados sin MX van plegados aparte, solo con dominio y técnica.
        const folded = body.querySelector('details.lookalike-more');
        expect(folded.open).toBe(false);
        expect(folded.querySelector('summary').textContent).toBe('Una variante más está registrada pero sin MX: hoy no recibe correo.');
        expect([...folded.querySelectorAll('tbody tr')].map(text)).toEqual(['acrne.es Homoglifo']);
        expect(document.getElementById('lookalike-badge').textContent).toBe('1 a vigilar');
    });

    it('si solo hay registrados sin MX, no los pliega', () => {
        renderLookalikes({
            checked: 10, unresolved: 0,
            found: [{ domain: 'acrne.es', technique: 'homoglyph', mx: [], ns: [], kind: 'registered' }]
        });
        const body = document.getElementById('lookalike-body');
        expect(body.querySelector('details')).toBeNull();
        expect(body.querySelector('tbody tr').textContent).toContain('Registrado, sin MX');
        expect(document.getElementById('lookalike-badge').textContent).toBe('Nada que vigilar');
    });

    it('muestra el certificado de los que se miran en CT, con su tono y la nota', () => {
        renderLookalikes({
            checked: 10, unresolved: 0,
            found: [
                { domain: 'a.com', technique: 'tld', mx: ['m.x'], ns: [], kind: 'mx', cert: { status: 'recent', days: 5, issuer: "Let's Encrypt", notBefore: '2026-10-14T00:00:00Z' } },
                { domain: 'b.com', technique: 'tld', mx: ['m.x'], ns: [], kind: 'mx', cert: { status: 'checking' } },
                { domain: 'c.com', technique: 'tld', mx: ['m.x'], ns: [], kind: 'mx', cert: { status: 'unchecked' } },
                { domain: 'd.com', technique: 'tld', mx: ['m.x'], ns: [], kind: 'mx', cert: { status: 'none' } }
            ]
        });
        const cells = [...document.querySelectorAll('#lookalike-body tbody tr td:last-child .tag')];
        expect(cells.map(c => c.textContent)).toEqual(['Reciente: hace 5 días', 'comprobando…', 'No comprobado', 'Sin certificados vigentes']);
        expect(cells[0].className).toContain('tag--danger');
        expect(cells[0].getAttribute('title')).toBe("Let's Encrypt");
        expect(document.getElementById('lookalike-body').textContent).toContain('Los 3 primeros que reciben correo');
    });

    it('parte los nombres por los puntos, no letra a letra', () => {
        renderLookalikes({
            checked: 1, unresolved: 0,
            found: [{ domain: 'salesforce.net', technique: 'tld', mx: ['salesforce-net.mail.protection.outlook.com', 'mx2.example'], ns: [], kind: 'mx' }]
        });
        const mx = document.querySelector('#lookalike-body .lookalike-mx');
        expect(mx.textContent).toBe('salesforce-net.mail.protection.outlook.com (+1)');
        expect(mx.querySelectorAll('wbr')).toHaveLength(4);
        expect(document.querySelector('#lookalike-body .lookalike-domain').querySelectorAll('wbr')).toHaveLength(1);
    });

    it('escapa lo que viene del DNS de terceros', () => {
        renderLookalikes({
            checked: 1, unresolved: 0,
            found: [{ domain: 'acme.com', technique: 'tld', mx: ['<img src=x onerror=alert(1)>'], ns: [], kind: 'mx' }]
        });
        expect(document.querySelector('#lookalike-body img')).toBeNull();
    });
});

describe('informe exportado', () => {
    it('lleva la cuenta de la nota y los dominios parecidos', () => {
        const result = resultWith(['mxa-1.gslb.pphosted.com']);
        result.lookalikeResult = {
            checked: 40, unresolved: 0,
            found: [{ domain: 'acme-com.com', technique: 'combo', mx: ['mail.evil.example'], ns: [], kind: 'mx' }]
        };
        state.currentResult = result;
        state.currentDomain = 'acme.com';
        const div = document.createElement('div');
        div.innerHTML = generateReportHTML().toString();
        const text = div.textContent.replace(/\s+/g, ' ');
        expect(text).toContain('Cómo se calcula la nota');
        expect(text).toContain('= 88,75');
        expect(text).toContain('Dominios parecidos que reciben correo, sin vínculo visible: 1');
        expect(text).toContain('acme-com.com');
    });
});
