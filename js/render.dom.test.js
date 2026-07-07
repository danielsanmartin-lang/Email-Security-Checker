// @vitest-environment jsdom
import { describe, it, expect, beforeEach } from 'vitest';
import { renderResults } from './ui.js';
import { analyze, calculateScoreAndFindings } from './analyzer.js';
import { generateReportHTML } from './export.js';
import { state } from './app.js';

const CONTAINER_IDS = [
    'result-domain', 'result-timestamp',
    'summary-provider-value', 'summary-security-value', 'summary-dmarc-value', 'summary-services-value',
    'mx-body', 'mx-count', 'provider-body', 'security-body',
    'spf-raw', 'spf-table-body', 'spf-services-summary', 'spf-tree-body',
    'dmarc-raw', 'dmarc-body', 'dmarc-reporting-body', 'spf-lookups-count',
    'dkim-body', 'bimi-body', 'reputation-body', 'reputation-status',
    'advanced-dns-body', 'awareness-body', 'awareness-badge', 'score-number', 'score-grade'
];

function buildDom() {
    let h = `<div id="score-card"><div class="score-card__title"></div><div id="score-ring-fill"></div><div id="score-findings"></div></div>`;
    h += CONTAINER_IDS.map(id => `<div id="${id}"></div>`).join('');
    document.body.innerHTML = h;
}

// Construye un result realista con payloads XSS en datos derivados de DNS.
function maliciousResult() {
    const XSS = '<script>alert(1)</script>';
    const mxRecords = [{ priority: 10, host: `${XSS}.evil.com` }];
    const spfRaw = 'v=spf1 include:evil.com ~all';
    const dmarcRaw = 'v=DMARC1; p=reject; rua=mailto:a@b.com';
    const result = analyze(mxRecords, spfRaw, dmarcRaw, {
        domain: 'evil.com',
        txtVerifications: [{ name: XSS, category: 'seg', record: XSS, fullRecord: XSS }],
        nsRecords: [`${XSS}.ns.com`],
        mtaSts: null,
        tlsRpt: null,
        srvRecords: {},
        daneRecords: {}
    });
    result.spfLookups = 1;
    result.spfTree = { domain: XSS, lookups: 1, error: null, children: [] };
    result.dkimRecords = { records: [{ selector: XSS, record: XSS }], errors: [] };
    result.bimiRecord = null;
    result.rblResults = [{ host: `${XSS}.evil.com`, ip: '1.2.3.4', checks: [{ listed: false, rbl: 'bl.spamcop.net' }] }];
    result.awarenessResult = null;
    result.scoreCard = calculateScoreAndFindings(result);
    return result;
}

// Result con un SEG cuya única evidencia es un token TXT y un MX que NO lo confirma
// (caso Amazon): la detección debe marcarlo unconfirmed y la UI/export avisarlo.
function unconfirmedSegResult() {
    const mxRecords = [{ priority: 5, host: 'acme-smtp.acme.com' }];
    const spfRaw = 'v=spf1 include:amazonses.com -all';
    const dmarcRaw = 'v=DMARC1; p=quarantine; rua=mailto:a@b.com';
    const result = analyze(mxRecords, spfRaw, dmarcRaw, {
        domain: 'acme.com',
        txtVerifications: [{ name: 'Barracuda', category: 'seg', record: 'barracuda-domain-verification=abc', fullRecord: 'barracuda-domain-verification=abc' }],
        nsRecords: [],
        mtaSts: null,
        tlsRpt: null,
        srvRecords: {},
        daneRecords: {}
    });
    result.spfLookups = 1;
    result.spfTree = { domain: 'acme.com', lookups: 1, error: null, children: [] };
    result.dkimRecords = { records: [], errors: [] };
    result.bimiRecord = null;
    result.rblResults = [];
    result.awarenessResult = null;
    result.scoreCard = calculateScoreAndFindings(result);
    return result;
}

describe('renderResults (jsdom, integración)', () => {
    beforeEach(buildDom);

    it('avisa "sin confirmar en el MX" para un SEG solo-TXT (UI y export)', () => {
        const result = unconfirmedSegResult();
        const barracuda = result.segList.find(s => s.name === 'Barracuda');
        expect(barracuda.unconfirmed).toBe(true);
        expect(barracuda.level).toBe('baja');

        renderResults('acme.com', result);
        expect(document.getElementById('security-body').innerHTML).toContain('Sin confirmar en el MX');

        state.currentResult = result;
        state.currentDomain = 'acme.com';
        const report = generateReportHTML().toString();
        expect(report).toContain('Sin confirmar en el MX');
    });

    it('renderiza sin lanzar y escapa los payloads XSS', () => {
        expect(() => renderResults('evil.com', maliciousResult())).not.toThrow();
        const body = document.body.innerHTML;
        // El payload nunca debe aparecer como etiqueta script ejecutable
        expect(body).not.toContain('<script>alert(1)</script>');
        // Debe aparecer escapado en alguna parte
        expect(body).toContain('&lt;script&gt;');
        // No debe haber nodos <script> reales inyectados
        expect(document.querySelectorAll('script').length).toBe(0);
    });

    it('muestra "No identificado" traducido cuando no hay proveedor', () => {
        const result = maliciousResult();
        renderResults('evil.com', result);
        const provVal = document.getElementById('summary-provider-value').textContent;
        expect(provVal.length).toBeGreaterThan(0);
    });

    it('generateReportHTML (export) corre y escapa los payloads', () => {
        state.currentResult = maliciousResult();
        state.currentDomain = 'evil.com';
        let report = '';
        expect(() => { report = generateReportHTML().toString(); }).not.toThrow();
        expect(report.length).toBeGreaterThan(100);
        expect(report).not.toContain('<script>alert(1)</script>');
        expect(report).toContain('&lt;script&gt;');
    });
});
