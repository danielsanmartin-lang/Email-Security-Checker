// @vitest-environment jsdom
import { describe, it, expect, beforeEach } from 'vitest';
import { File } from 'node:buffer';
import { handleReportFile, initDmarcReportPanel } from './dmarcReportPanel.js';

const XML = `<?xml version="1.0"?>
<feedback>
  <report_metadata><org_name>google.com</org_name><report_id>1</report_id>
    <date_range><begin>1767225600</begin><end>1767311999</end></date_range></report_metadata>
  <policy_published><domain>acme.test</domain><p>reject</p><pct>100</pct></policy_published>
  <record><row><source_ip>209.85.220.41</source_ip><count>100</count>
    <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
    <identifiers><header_from>acme.test</header_from></identifiers>
    <auth_results><dkim><domain>acme.test</domain><result>pass</result></dkim></auth_results></record>
  <record><row><source_ip>45.9.148.99</source_ip><count>25</count>
    <policy_evaluated><disposition>reject</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
    <identifiers><header_from>acme.test</header_from></identifiers>
    <auth_results><spf><domain>malo.ru</domain><result>fail</result></spf></auth_results></record>
</feedback>`;

const fileOf = (content, name) => new File([content], name);

describe('panel del visor de informes DMARC (jsdom)', () => {
    beforeEach(() => {
        localStorage.setItem('lang', 'es');
        document.body.innerHTML = `
            <div class="rua-dropzone" id="rua-dropzone" tabindex="0"></div>
            <input type="file" id="rua-file">
            <div id="rua-results"></div>`;
    });

    it('pinta totales, remitentes y la tabla ordenada por volumen', async () => {
        await handleReportFile(fileOf(XML, 'informe.xml'));
        const out = document.getElementById('rua-results');
        expect(out.textContent).toContain('google.com');
        expect(out.textContent).toContain('acme.test');
        const rows = [...out.querySelectorAll('.rua-table tbody tr')];
        expect(rows).toHaveLength(2);
        expect(rows[0].children[0].textContent).toBe('209.85.220.41');
        expect(rows[0].children[1].textContent).toBe('100');
        // La IP sin autenticar debe verse como 0% de paso.
        expect(rows[1].children[0].textContent).toBe('45.9.148.99');
        expect(rows[1].textContent).toContain('0%');
    });

    it('escapa el contenido del informe (viene de un fichero ajeno)', async () => {
        const malicioso = XML.replace('<org_name>google.com</org_name>',
            '<org_name>&lt;img src=x onerror=alert(1)&gt;</org_name>');
        await handleReportFile(fileOf(malicioso, 'informe.xml'));
        const out = document.getElementById('rua-results');
        expect(out.innerHTML).not.toContain('<img src=x');
        expect(out.textContent).toContain('<img src=x');
    });

    it('avisa cuando el fichero no es un informe DMARC', async () => {
        await handleReportFile(fileOf('<nada/>', 'otro.xml'));
        expect(document.getElementById('rua-results').querySelector('.rua-error')).toBeTruthy();
    });

    it('avisa cuando el informe no tiene registros', async () => {
        await handleReportFile(fileOf('<feedback><report_metadata/></feedback>', 'vacio.xml'));
        expect(document.getElementById('rua-results').textContent).toMatch(/registros|records/i);
    });

    it('el arrastre marca la zona y procesa el fichero soltado', async () => {
        initDmarcReportPanel();
        const drop = document.getElementById('rua-dropzone');
        drop.dispatchEvent(new window.Event('dragover', { bubbles: true }));
        expect(drop.classList.contains('rua-dropzone--active')).toBe(true);

        const dropEvent = new window.Event('drop', { bubbles: true });
        dropEvent.dataTransfer = { files: [fileOf(XML, 'informe.xml')] };
        drop.dispatchEvent(dropEvent);
        expect(drop.classList.contains('rua-dropzone--active')).toBe(false);
        await new Promise(r => setTimeout(r, 20));
        expect(document.getElementById('rua-results').textContent).toContain('google.com');
    });

    it('la zona de arrastre se activa con teclado', () => {
        initDmarcReportPanel();
        const input = document.getElementById('rua-file');
        let clicked = 0;
        input.click = () => { clicked++; };
        document.getElementById('rua-dropzone').dispatchEvent(
            new window.KeyboardEvent('keydown', { key: 'Enter', bubbles: true })
        );
        expect(clicked).toBe(1);
    });
});
