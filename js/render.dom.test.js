// @vitest-environment jsdom
import { describe, it, expect, beforeEach } from 'vitest';
import { renderResults } from './ui.js';
import { analyze, calculateScoreAndFindings } from './analyzer.js';
import { generateReportHTML } from './export.js';
import { state } from './state.js';
import { saveSettings, DEFAULT_SETTINGS } from './settings.js';

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
    // Modal de la KB, necesario para probar el flujo del botón "Añadir a BD".
    h += `<div id="add-kb-modal" class="hidden"><input id="kb-domain"><input id="kb-name"><select id="kb-category"><option value="marketing">Marketing</option></select></div>`;
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

    it('ICES de confianza baja (<50%) no se afirma como detectado', () => {
        const result = maliciousResult();
        result.segList = [];
        result.icesList = [{ name: 'Cisco Secure Email', level: 'baja', score: 0.35, evidence: [], source: 'cisco-ci-domain-verification' }];
        renderResults('acme.com', result);

        const secBody = document.getElementById('security-body').innerHTML;
        // No debe afirmar "ICES Detectado" para una confianza del 35%.
        expect(secBody).not.toContain('ICES Detectado');
        expect(secBody).toContain('sin evidencia concluyente');
        // El resumen marca la detección como "(posible)".
        expect(document.getElementById('summary-security-value').textContent).toContain('(posible)');
    });

    it('ICES de confianza alta (≥50%) sí se muestra como detectado', () => {
        const result = maliciousResult();
        result.segList = [];
        result.icesList = [{ name: 'Abnormal Security', level: 'alta', score: 0.85, evidence: [], source: 'mx' }];
        renderResults('acme.com', result);
        const secBody = document.getElementById('security-body').innerHTML;
        expect(secBody).toContain('ICES Detectado');
        expect(secBody).not.toContain('sin evidencia concluyente');
    });

    it('la tabla SPF no usa onclick inline y el payload con comillas llega intacto al modal (fix XSS)', () => {
        // encodeURIComponent no escapa comillas simples ni paréntesis: con el antiguo
        // onclick inline, este include ejecutaba alert(1) al pulsar "Añadir a BD".
        const PAYLOAD = "'-alert(1)-'.evil.com";
        const result = analyze(
            [{ priority: 10, host: 'mx.evil.com' }],
            `v=spf1 include:${PAYLOAD} ~all`,
            'v=DMARC1; p=reject; rua=mailto:a@b.com',
            { domain: 'evil.com', txtVerifications: [], nsRecords: [], mtaSts: null, tlsRpt: null, srvRecords: {}, daneRecords: {} }
        );
        result.spfLookups = 1;
        result.spfTree = { domain: 'evil.com', lookups: 1, error: null, children: [] };
        result.dkimRecords = { records: [], errors: [] };
        result.bimiRecord = null;
        result.rblResults = [];
        result.awarenessResult = null;
        result.scoreCard = calculateScoreAndFindings(result);

        renderResults('evil.com', result);
        const spfBody = document.getElementById('spf-table-body').innerHTML;
        expect(spfBody).not.toContain('onclick');

        const btn = document.querySelector('#spf-table-body button[data-kb-domain]');
        expect(btn).toBeTruthy();
        expect(btn.dataset.kbDomain).toBe(PAYLOAD);

        // El listener delegado abre el modal con el valor literal, sin evaluar JS.
        btn.click();
        expect(document.getElementById('kb-domain').value).toBe(PAYLOAD);
        expect(document.getElementById('add-kb-modal').classList.contains('hidden')).toBe(false);
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

    it('el informe incluye DNSSEC, DANE, SRV, árbol SPF y autorización DMARC externa', () => {
        const result = maliciousResult();
        result.dnssec = { signed: true, ad: true };
        result.daneRecords = { 'mx.evil.com': ['3 1 1 abcd'] };
        result.srvRecords = { submission: [{ target: 'smtp.evil.com', port: '587' }] };
        result.spfTree = { domain: 'evil.com', lookups: 2, error: null, children: [{ type: 'include', target: 'a.com', tree: { domain: 'a.com', lookups: 1, error: null, children: [] } }] };
        result.dmarcExternalAuth = [{ uri: 'mailto:r@ext.com', destDomain: 'ext.com', authorized: false }];
        state.currentResult = result;
        state.currentDomain = 'evil.com';
        const report = generateReportHTML().toString();
        // Secciones que antes faltaban en el informe:
        expect(report).toContain('DNSSEC');
        expect(report).toContain('DANE');
        expect(report).toContain('mx.evil.com');       // DANE por MX
        expect(report).toContain('smtp.evil.com');      // SRV
        expect(report).toContain('lookups');            // árbol SPF
        expect(report).toContain('ext.com');            // autorización DMARC externa
    });

    it('no deja títulos de sección del informe hardcodeados en inglés', () => {
        state.currentResult = maliciousResult();
        state.currentDomain = 'evil.com';
        const report = generateReportHTML().toString();
        expect(report).not.toContain('6. Advanced DNS');
        expect(report).not.toContain('>Name<');
        expect(report).not.toContain('DNS Lookups:');
    });
});

// ===========================================================================
// DMARC en la UI y en el informe: datos del registro auditado con marcado, t=y y
// política efectiva. Antes, p/sp/pct entraban crudos en el informe exportado.
// ===========================================================================
function dmarcResult(dmarcRaw, extra = {}) {
    const result = analyze([{ priority: 10, host: 'mx.acme.com' }], 'v=spf1 -all', dmarcRaw, {
        domain: 'acme.com', mtaSts: null, tlsRpt: null, srvRecords: {}, daneRecords: {}, ...extra
    });
    Object.assign(result, {
        spfLookups: 1,
        spfTree: { domain: 'acme.com', lookups: 1, error: null, children: [] },
        dkimRecords: { records: [], errors: [] },
        bimiRecord: null,
        rblResults: [],
        awarenessResult: null
    });
    result.scoreCard = calculateScoreAndFindings(result);
    return result;
}

describe('DMARC con marcado en las etiquetas (UI e informe)', () => {
    beforeEach(buildDom);

    const EVIL = 'v=DMARC1; p=<img data-evil=1 src=https://evil.example/p.gif>; sp=<b data-evil=1>sp</b>; np=<i data-evil=1>np</i>; t=<u data-evil=1>t</u>; psd=<s data-evil=1>psd</s>; pct=<em data-evil=1>9</em>; rua=mailto:a@acme.com';

    it('el informe exportado no inyecta ningún elemento del registro', () => {
        state.currentResult = dmarcResult(EVIL);
        state.currentDomain = 'acme.com';
        const container = document.createElement('div');
        container.innerHTML = generateReportHTML().toString();
        expect(container.querySelectorAll('[data-evil]').length).toBe(0);
        expect(container.querySelectorAll('img').length).toBe(0);
        expect(container.textContent).toContain('data-evil');
    });

    it('la interfaz tampoco', () => {
        renderResults('acme.com', dmarcResult(EVIL));
        expect(document.querySelectorAll('[data-evil]').length).toBe(0);
    });
});

describe('DMARC: la interfaz y el informe dicen la política que se aplica', () => {
    beforeEach(buildDom);

    it('p=reject; t=y se resume como quarantine en modo prueba', () => {
        const result = dmarcResult('v=DMARC1; p=reject; t=y; rua=mailto:a@acme.com');
        renderResults('acme.com', result);
        const summary = document.getElementById('summary-dmarc-value');
        expect(summary.textContent).toContain('Quarantine');
        expect(summary.textContent).toContain('REJECT');
        expect(summary.classList.contains('dmarc-policy--quarantine')).toBe(true);
        const body = document.getElementById('dmarc-body').textContent;
        expect(body).toContain('Modo prueba (t)');
        expect(body).toContain('Receptores RFC 9989: QUARANTINE');

        state.currentResult = result;
        state.currentDomain = 'acme.com';
        const report = generateReportHTML().toString();
        expect(report).toContain('REJECT en modo prueba');
    });

    it('un subdominio que hereda muestra de dónde y con qué etiqueta', () => {
        const result = dmarcResult('v=DMARC1; p=reject; sp=quarantine; rua=mailto:a@acme.com', {
            domain: 'shop.acme.com', dmarcInherited: true, dmarcInheritedFrom: 'acme.com',
            dmarcSource: 'org', dmarcPolicyDomain: 'acme.com', dmarcOrgDomain: 'acme.com'
        });
        renderResults('shop.acme.com', result);
        const body = document.getElementById('dmarc-body').textContent;
        expect(body).toContain('Heredada de acme.com (etiqueta sp)');
        expect(body).toContain('Dominio organizativo (Tree Walk, RFC 9989)');
        expect(document.getElementById('summary-dmarc-value').textContent).toContain('heredada de acme.com');
    });

    it('marca como no válido un rua sin mailto:', () => {
        renderResults('acme.com', dmarcResult('v=DMARC1; p=reject; rua=dmarc@acme.com'));
        expect(document.getElementById('dmarc-reporting-body').textContent).toContain('No válido');
    });
});

describe('desglose: el tope de la nota se explica', () => {
    beforeEach(buildDom);

    it('una nota topada en 94 dice por qué junto a la suma sin topes', () => {
        // Sin MX solo cuenta la suplantación: quarantine suma 95 y el A+ exige reject.
        const result = analyze([], 'v=spf1 -all', 'v=DMARC1; p=quarantine; rua=mailto:a@b.com', {
            domain: 'acme.com', mtaSts: null, tlsRpt: null, srvRecords: {}, daneRecords: {}
        });
        Object.assign(result, {
            spfLookups: 1,
            spfTree: { domain: 'acme.com', lookups: 1, error: null, children: [] },
            dkimRecords: { records: [], errors: [] },
            bimiRecord: null, rblResults: [], awarenessResult: null
        });
        result.scoreCard = calculateScoreAndFindings(result);
        expect(result.scoreCard.cap).toEqual({ key: 'unverified', value: 94 });
        document.body.insertAdjacentHTML('beforeend', '<span id="score-number"></span><div id="score-breakdown-body"></div>');
        renderResults('acme.com', result);
        const note = document.querySelector('#score-breakdown-body .score-cat__cap');
        expect(note).not.toBeNull();
        expect(note.textContent).toContain('94');
        expect(note.textContent).not.toContain('{cap}');
        expect(document.getElementById('score-number').textContent).toBe('94');
    });
});

describe('v5: pastilla y hallazgo de filtrado entrante', () => {
    beforeEach(buildDom);

    const withMx = (...hosts) => {
        const result = analyze(hosts.map((host, i) => ({ priority: 10 + i, host })), 'v=spf1 -all', 'v=DMARC1; p=reject; rua=mailto:a@acme.com', {
            domain: 'acme.com', mtaSts: null, tlsRpt: null, srvRecords: {}, daneRecords: {}
        });
        Object.assign(result, {
            spfLookups: 1,
            spfTree: { domain: 'acme.com', lookups: 1, error: null, children: [] },
            dkimRecords: { records: [], errors: [] },
            bimiRecord: null, rblResults: [], awarenessResult: null
        });
        result.scoreCard = calculateScoreAndFindings(result);
        return result;
    };
    const chips = () => [...document.querySelectorAll('.score-card__title .score-card__chip')];

    it('con Proofpoint en el MX: pastilla verde con el vendor y hallazgo en la tarjeta', () => {
        renderResults('acme.com', withMx('mxa-1.gslb.pphosted.com'));
        expect(chips()).toHaveLength(3);
        const chip = chips()[1];
        expect(chip.textContent).toBe('Filtrado: Reforzado · Proofpoint');
        expect(chip.classList.contains('tag--safe')).toBe(true);
        expect(document.getElementById('score-findings').textContent)
            .toContain('Capa extra de seguridad detectada: Proofpoint');
    });

    it('con el MX directo a Microsoft 365: pastilla ámbar "Solo nativo"', () => {
        renderResults('acme.com', withMx('acme-com.mail.protection.outlook.com'));
        const chip = chips()[1];
        expect(chip.textContent).toBe('Filtrado: Solo nativo · Microsoft 365');
        expect(chip.classList.contains('tag--warning')).toBe(true);
    });

    it('el informe exportado lleva la línea de filtrado entrante', () => {
        state.currentResult = withMx('mxa-1.gslb.pphosted.com');
        state.currentDomain = 'acme.com';
        const container = document.createElement('div');
        container.innerHTML = generateReportHTML().toString();
        const text = container.textContent;
        expect(text).toContain('Filtrado entrante: Reforzado · Proofpoint (100/100)');
        expect(text).toContain('Capa extra de seguridad detectada: Proofpoint');
    });

    it('el desglose enseña el peso de cada eje', () => {
        document.body.insertAdjacentHTML('beforeend', '<div id="score-breakdown-body"></div>');
        renderResults('acme.com', withMx('mxa-1.gslb.pphosted.com'));
        const shares = [...document.querySelectorAll('#score-breakdown-body .score-cat__share')].map(e => e.textContent);
        expect(shares).toEqual(['60 % de la nota', '25 % de la nota', '15 % de la nota']);
    });
});

describe('BIMI: el logo no se pide al dominio auditado sin permiso', () => {
    beforeEach(buildDom);

    const bimiResult = () => {
        const result = dmarcResult('v=DMARC1; p=reject; rua=mailto:a@acme.com');
        result.bimiRecord = { record: 'v=BIMI1; l=https://acme.com/logo.svg', logo: 'https://acme.com/logo.svg', vmc: null, declined: false };
        return result;
    };

    it('por defecto carga el logo, sin Referer', () => {
        renderResults('acme.com', bimiResult());
        const bimi = document.getElementById('bimi-body');
        const img = bimi.querySelector('img.bimi-logo');
        expect(img).not.toBeNull();
        expect(img.referrerPolicy).toBe('no-referrer');
        expect(bimi.querySelector('.bimi-logo-load')).toBeNull();
    });

    it('con loadBimiLogos apagado ofrece un botón en vez de cargar la imagen', () => {
        saveSettings({ loadBimiLogos: false });
        try {
            renderResults('acme.com', bimiResult());
            const bimi = document.getElementById('bimi-body');
            expect(bimi.querySelector('img.bimi-logo')).toBeNull();
            const btn = bimi.querySelector('.bimi-logo-load');
            expect(btn).not.toBeNull();
            btn.click();
            const img = bimi.querySelector('img.bimi-logo');
            expect(img).not.toBeNull();
            expect(img.referrerPolicy).toBe('no-referrer');
        } finally {
            saveSettings({ loadBimiLogos: DEFAULT_SETTINGS.loadBimiLogos });
        }
    });
});
