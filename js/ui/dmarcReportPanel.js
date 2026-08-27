// ui/dmarcReportPanel.js
// Visor de informes agregados DMARC (RUA): zona de arrastre + tabla de remitentes.
// Todo el procesado ocurre en el navegador (ver dmarcReport.js): el fichero contiene
// el mapa de remitentes de una organización y no debe salir de la máquina.
import { html, raw } from '../utils.js';
import { translations } from '../i18n.js';
import { getLanguage } from '../lang.js';
import { readReportFile, supportsDecompression } from '../dmarcReport.js';

const pct = (n) => `${Math.round(n * 100)}%`;
const tone = (rate) => (rate >= 0.98 ? 'good' : rate >= 0.8 ? 'mid' : 'bad');

function renderReport(report, t) {
    const fmtDate = (iso) => (iso ? new Date(iso).toLocaleDateString(getLanguage() === 'es' ? 'es-ES' : 'en-US') : '—');
    const range = `${fmtDate(report.dateRange.begin)} – ${fmtDate(report.dateRange.end)}`;

    const stat = (label, value, cls = '') => html`<div class="rua-stat">
        <span class="rua-stat__label">${label}</span>
        <span class="rua-stat__value ${raw(cls)}">${value}</span>
    </div>`;

    const rows = report.sources.map(src => html`<tr>
        <td class="rua-ip">${src.ip}</td>
        <td class="rua-num">${src.messages.toLocaleString()}</td>
        <td>
            <span class="rua-bar"><span class="rua-bar__fill rua-bar__fill--${raw(tone(src.passRate))}" style="width:${pct(src.passRate)}"></span></span>
            <span class="rua-num">${pct(src.passRate)}</span>
        </td>
        <td class="rua-num">${pct(src.messages ? src.spfPass / src.messages : 0)}</td>
        <td class="rua-num">${pct(src.messages ? src.dkimPass / src.messages : 0)}</td>
        <td class="rua-domains">${[...new Set([...src.dkimDomains, ...src.spfDomains])].join(', ') || '—'}</td>
    </tr>`);

    return html`
        <div class="rua-meta">
            <span><strong>${t.rua_org}:</strong> ${report.org}</span>
            <span><strong>${t.rua_domain}:</strong> ${report.policy.domain || '—'}</span>
            <span><strong>${t.rua_period}:</strong> ${range}</span>
            <span><strong>${t.rua_policy}:</strong> p=${report.policy.p || '—'}${report.policy.pct ? ` pct=${report.policy.pct}` : ''}</span>
        </div>
        <div class="rua-stats">
            ${stat(t.rua_messages, report.totals.messages.toLocaleString())}
            ${stat(t.rua_dmarc_pass, pct(report.totals.passRate), `rua-stat__value--${tone(report.totals.passRate)}`)}
            ${stat(t.rua_spf_pass, pct(report.totals.messages ? report.totals.spfPass / report.totals.messages : 0))}
            ${stat(t.rua_dkim_pass, pct(report.totals.messages ? report.totals.dkimPass / report.totals.messages : 0))}
            ${stat(t.rua_quarantined, report.totals.quarantined.toLocaleString())}
            ${stat(t.rua_rejected, report.totals.rejected.toLocaleString())}
        </div>
        <p class="rua-hint">${t.rua_sources_hint}</p>
        <div class="rua-table-wrap">
            <table class="rua-table">
                <thead><tr>
                    <th>${t.rua_col_ip}</th>
                    <th>${t.rua_col_messages}</th>
                    <th>${t.rua_col_dmarc}</th>
                    <th>SPF</th>
                    <th>DKIM</th>
                    <th>${t.rua_col_domains}</th>
                </tr></thead>
                <tbody>${rows}</tbody>
            </table>
        </div>`;
}

/** Procesa el fichero soltado/elegido y pinta el resultado. */
export async function handleReportFile(file) {
    const out = document.getElementById('rua-results');
    if (!out) return;
    const t = translations[getLanguage()];
    out.innerHTML = html`<p class="no-data no-data--sm">${t.rua_reading}</p>`;
    try {
        const report = await readReportFile(file);
        if (report.totals.messages === 0) {
            out.innerHTML = html`<p class="no-data no-data--sm">${t.rua_empty}</p>`;
            return;
        }
        out.innerHTML = renderReport(report, t);
    } catch (err) {
        const msg = err.message === 'unsupported_compression' ? t.rua_no_decompression : err.message;
        out.innerHTML = html`<p class="no-data no-data--sm rua-error">${t.rua_error}: ${msg}</p>`;
    }
}

/** Cablea la zona de arrastre y el input de fichero. Se llama una sola vez. */
export function initDmarcReportPanel() {
    const drop = document.getElementById('rua-dropzone');
    const input = document.getElementById('rua-file');
    if (!drop || !input) return;

    if (!supportsDecompression()) {
        // Sin DecompressionStream solo se puede leer XML plano: mejor decirlo antes
        // de que el usuario suelte un .gz y vea un error.
        input.setAttribute('accept', '.xml,text/xml');
    }

    const pick = (files) => { if (files && files[0]) handleReportFile(files[0]); };

    drop.addEventListener('click', () => input.click());
    drop.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); }
    });
    input.addEventListener('change', () => pick(input.files));
    ['dragenter', 'dragover'].forEach(evt => drop.addEventListener(evt, (e) => {
        e.preventDefault();
        drop.classList.add('rua-dropzone--active');
    }));
    ['dragleave', 'drop'].forEach(evt => drop.addEventListener(evt, (e) => {
        e.preventDefault();
        drop.classList.remove('rua-dropzone--active');
    }));
    drop.addEventListener('drop', (e) => pick(e.dataTransfer?.files));
}
