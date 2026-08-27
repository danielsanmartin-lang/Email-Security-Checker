// ui/dkimBimiPanel.js
// Paneles DKIM y BIMI (incluida la comprobación del certificado VMC).
import { html, raw } from '../utils.js';
import { translations } from '../i18n.js';
import { getLanguage } from '../lang.js';

export function renderDkimBimiPanel(result) {
    const lang = getLanguage();
    const t = translations[lang];
    const dkimBody = document.getElementById('dkim-body');
    const dkimRecords = (result.dkimRecords && result.dkimRecords.records) || [];
    const dkimErrors = (result.dkimRecords && result.dkimRecords.errors) || [];
    const dkimList = dkimRecords.length > 0
        ? html`${dkimRecords.map(dkim => html`
            <div class="info-block dkim-record">
                <div class="info-block__label">Selector: ${dkim.selector}</div>
                <div class="info-block__value info-block__value--mono">${dkim.record}</div>
            </div>`)}`
        : html`<p class="no-data">${t.no_dkim_records}</p>`;
    const dkimErrHtml = dkimErrors.length > 0
        ? html`<div class="dkim-errors">${t.dkim_network_error}: ${dkimErrors.map(e => e.selector).join(', ')}</div>`
        : raw('');
    dkimBody.innerHTML = html`${dkimList}${dkimErrHtml}`;

    const bimiBody = document.getElementById('bimi-body');
    const bimi = result.bimiRecord;
    if (!bimi) {
        bimiBody.innerHTML = html`<p class="no-data">${t.no_bimi_record}</p>`;
    } else if (bimi.error) {
        bimiBody.innerHTML = html`<p class="no-data bimi-error">${t.bimi_error}: ${bimi.error}</p>`;
    } else {
        // El VMC (a=) es lo que separa "registro BIMI publicado" de "logotipo visible":
        // sin él los principales buzones ignoran el SVG.
        const vmcHtml = bimi.declined
            ? html`<div class="info-block__detail">${t.bimi_declined_label}</div>`
            : html`<div class="info-block__detail">${t.bimi_vmc_label}: ${bimi.vmc
                ? bimi.vmc
                : html`<span class="bimi-vmc-missing">${t.bimi_vmc_missing}</span>`}</div>`;
        const logoHtml = bimi.logo
            ? html`<div class="bimi-logo-wrap"><img class="bimi-logo" src="${bimi.logo}" alt="BIMI Logo"></div>`
            : raw('');
        bimiBody.innerHTML = html`
            <div class="info-block">
                <div class="info-block__label">${t.bimi_record_found}</div>
                <div class="info-block__value info-block__value--mono">${bimi.record}</div>
                ${vmcHtml}
                ${logoHtml}
            </div>`;
        // El logo se comprueba dejando que el navegador lo cargue: un fetch() previo
        // lo bloquearía CORS en la mayoría de dominios y daría un falso negativo.
        const img = bimiBody.querySelector('img.bimi-logo');
        if (img) {
            img.addEventListener('error', () => {
                img.remove();
                const warn = document.createElement('div');
                warn.className = 'info-block__detail bimi-vmc-missing';
                warn.textContent = t.bimi_logo_unreachable;
                bimiBody.querySelector('.info-block').appendChild(warn);
            });
        }
    }
}
