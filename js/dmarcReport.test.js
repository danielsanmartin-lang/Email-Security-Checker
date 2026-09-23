// @vitest-environment jsdom
import { describe, it, expect } from 'vitest';
// El File de jsdom no implementa arrayBuffer(); el de Node sí y es equivalente al
// del navegador para lo que aquí se prueba.
import { File } from 'node:buffer';
import { parseAggregateReport, extractReportXml, supportsDecompression } from './dmarcReport.js';

const REPORT_XML = `<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <report_id>1234567890</report_id>
    <date_range><begin>1767225600</begin><end>1767311999</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>acme.test</domain>
    <adkim>r</adkim><aspf>r</aspf>
    <p>reject</p><sp>reject</sp><pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>209.85.220.41</source_ip>
      <count>120</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>acme.test</header_from></identifiers>
    <auth_results>
      <dkim><domain>acme.test</domain><result>pass</result><selector>google</selector></dkim>
      <spf><domain>acme.test</domain><result>pass</result></spf>
    </auth_results>
  </record>
  <record>
    <row>
      <source_ip>203.0.113.9</source_ip>
      <count>30</count>
      <policy_evaluated><disposition>reject</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>
    </row>
    <identifiers><header_from>acme.test</header_from></identifiers>
    <auth_results>
      <spf><domain>otro.test</domain><result>fail</result></spf>
    </auth_results>
  </record>
  <record>
    <row>
      <source_ip>198.51.100.7</source_ip>
      <count>10</count>
      <policy_evaluated><disposition>quarantine</disposition><dkim>fail</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>news.acme.test</header_from></identifiers>
    <auth_results>
      <spf><domain>news.acme.test</domain><result>pass</result></spf>
    </auth_results>
  </record>
</feedback>`;

async function gzip(str) {
    const cs = new CompressionStream('gzip');
    const writer = cs.writable.getWriter();
    writer.write(new TextEncoder().encode(str));
    writer.close();
    const reader = cs.readable.getReader();
    const chunks = [];
    let total = 0;
    for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value);
        total += value.length;
    }
    const out = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) { out.set(chunk, offset); offset += chunk.length; }
    return out;
}

// Construye un ZIP mínimo (un fichero almacenado sin comprimir) para probar el
// lector del directorio central sin depender de librerías externas.
function buildStoredZip(name, content) {
    const enc = new TextEncoder();
    const nameBytes = enc.encode(name);
    const data = enc.encode(content);
    const local = new Uint8Array(30 + nameBytes.length + data.length);
    const lv = new DataView(local.buffer);
    lv.setUint32(0, 0x04034b50, true);
    lv.setUint16(4, 20, true);
    lv.setUint16(8, 0, true);            // método 0 = stored
    lv.setUint32(18, data.length, true); // tamaño comprimido
    lv.setUint32(22, data.length, true); // tamaño original
    lv.setUint16(26, nameBytes.length, true);
    local.set(nameBytes, 30);
    local.set(data, 30 + nameBytes.length);

    const central = new Uint8Array(46 + nameBytes.length);
    const cv = new DataView(central.buffer);
    cv.setUint32(0, 0x02014b50, true);
    cv.setUint16(10, 0, true);            // método 0
    cv.setUint32(20, data.length, true);  // tamaño comprimido
    cv.setUint32(24, data.length, true);
    cv.setUint16(28, nameBytes.length, true);
    cv.setUint32(42, 0, true);            // offset de la cabecera local
    central.set(nameBytes, 46);

    const eocd = new Uint8Array(22);
    const ev = new DataView(eocd.buffer);
    ev.setUint32(0, 0x06054b50, true);
    ev.setUint16(8, 1, true);             // entradas en este disco
    ev.setUint16(10, 1, true);            // entradas totales
    ev.setUint32(12, central.length, true);
    ev.setUint32(16, local.length, true); // offset del directorio central

    const out = new Uint8Array(local.length + central.length + eocd.length);
    out.set(local, 0);
    out.set(central, local.length);
    out.set(eocd, local.length + central.length);
    return out;
}

const fileOf = (bytes, name) => new File([bytes], name);

describe('parseAggregateReport', () => {
    const report = parseAggregateReport(REPORT_XML);

    it('lee los metadatos y la política publicada', () => {
        expect(report.org).toBe('google.com');
        expect(report.reportId).toBe('1234567890');
        expect(report.policy).toMatchObject({ domain: 'acme.test', p: 'reject', sp: 'reject', pct: '100' });
        expect(report.dateRange.begin).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    });

    it('suma los totales y la tasa de paso DMARC', () => {
        expect(report.totals.messages).toBe(160);
        expect(report.totals.dmarcPass).toBe(130); // 120 (pass) + 10 (spf pass)
        expect(report.totals.rejected).toBe(30);
        expect(report.totals.quarantined).toBe(10);
        expect(report.totals.passRate).toBeCloseTo(130 / 160, 5);
    });

    it('agrupa por IP de origen y ordena por volumen', () => {
        expect(report.sources.map(s => s.ip)).toEqual(['209.85.220.41', '203.0.113.9', '198.51.100.7']);
        const google = report.sources[0];
        expect(google.messages).toBe(120);
        expect(google.passRate).toBe(1);
        expect(google.dkimDomains).toContain('acme.test');
        const malo = report.sources[1];
        expect(malo.passRate).toBe(0);
        expect(malo.dispositions).toContain('reject');
    });

    it('agrupa por dominio del From de cabecera', () => {
        expect(report.headerFroms[0]).toEqual({ domain: 'acme.test', messages: 150 });
        expect(report.headerFroms[1]).toEqual({ domain: 'news.acme.test', messages: 10 });
    });

    it('rechaza un XML que no es un informe DMARC', () => {
        expect(() => parseAggregateReport('<otracosa/>')).toThrow();
    });

    it('rechaza XML malformado', () => {
        expect(() => parseAggregateReport('<feedback>')).toThrow();
    });
});

describe('extractReportXml', () => {
    it('lee un .xml plano', async () => {
        const xml = await extractReportXml(fileOf(new TextEncoder().encode(REPORT_XML), 'informe.xml'));
        expect(xml).toContain('<feedback>');
    });

    it('descomprime un .xml.gz', async () => {
        expect(supportsDecompression()).toBe(true);
        const xml = await extractReportXml(fileOf(await gzip(REPORT_XML), 'informe.xml.gz'));
        expect(parseAggregateReport(xml).totals.messages).toBe(160);
    });

    it('descomprime un .zip', async () => {
        const zip = buildStoredZip('informe.xml', REPORT_XML);
        const xml = await extractReportXml(fileOf(zip, 'informe.zip'));
        expect(parseAggregateReport(xml).org).toBe('google.com');
    });

    it('detecta la compresión por número mágico aunque la extensión mienta', async () => {
        const xml = await extractReportXml(fileOf(await gzip(REPORT_XML), 'informe.xml'));
        expect(xml).toContain('<feedback>');
    });

    it('falla con un ZIP corrupto en vez de devolver basura', async () => {
        const roto = new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0, 0, 0, 0]);
        await expect(extractReportXml(fileOf(roto, 'roto.zip'))).rejects.toThrow();
    });
});

// Muestra del Apéndice B de RFC 9990: espacio de nombres dmarc-2.0, <testing>,
// <discovery_method> y la disposición nueva "pass". El formato nuevo NO debe romper el
// visor: querySelector no distingue espacios de nombres.
const RFC9990_SAMPLE = `<feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0">
  <version>1.0</version>
  <report_metadata>
    <org_name>Sample Reporter</org_name>
    <email>report_sender@example-reporter.com</email>
    <report_id>3v98abbp8ya9n3va8yr8oa3ya</report_id>
    <date_range><begin>302832000</begin><end>302918399</end></date_range>
    <generator>Example DMARC Aggregate Reporter v1.2</generator>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <p>quarantine</p><sp>none</sp><np>none</np>
    <testing>n</testing>
    <discovery_method>treewalk</discovery_method>
  </policy_published>
  <record>
    <row>
      <source_ip>192.0.2.123</source_ip>
      <count>123</count>
      <policy_evaluated><disposition>pass</disposition><dkim>pass</dkim><spf>fail</spf></policy_evaluated>
    </row>
    <identifiers><envelope_from>example.com</envelope_from><header_from>example.com</header_from></identifiers>
    <auth_results>
      <dkim><domain>example.com</domain><result>pass</result><selector>abc123</selector></dkim>
      <spf><domain>example.com</domain><result>fail</result></spf>
    </auth_results>
  </record>
</feedback>`;

describe('informes en formato RFC 9990 (DMARCbis)', () => {
    it('se parsean igual que los de RFC 7489', () => {
        const report = parseAggregateReport(RFC9990_SAMPLE);
        expect(report.org).toBe('Sample Reporter');
        expect(report.policy).toMatchObject({ domain: 'example.com', p: 'quarantine', sp: 'none' });
        expect(report.totals).toMatchObject({ messages: 123, dmarcPass: 123, dkimPass: 123, spfPass: 0, quarantined: 0, rejected: 0 });
        expect(report.sources[0].dispositions).toEqual(['pass']);
    });
});
