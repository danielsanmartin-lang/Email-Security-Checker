// ui/dkimBimiPanel.js
// Paneles DKIM y BIMI (incluida la comprobación del certificado VMC).
import { html, raw } from '../utils.js';
import { translations } from '../i18n.js';
import { getLanguage } from '../lang.js';
import { getSettings } from '../settings.js';

/**
 * Carga el logotipo BIMI. Se hace dejando que el navegador lo cargue: un fetch() previo lo
 * bloquearía CORS en la mayoría de dominios y daría un falso negativo. Sin Referer, para
 * que el servidor del dominio auditado no sepa desde qué página se le pide.
 */
function mountBimiLogo(container, logoUrl, t) {
    const img = document.createElement('img');
    img.className = 'bimi-logo';
    img.alt = 'BIMI Logo';
    img.referrerPolicy = 'no-referrer';
    img.addEventListener('error', () => {
        img.remove();
        const warn = document.createElement('div');
        warn.className = 'info-block__detail bimi-vmc-missing';
        warn.textContent = t.bimi_logo_unreachable;
        container.appendChild(warn);
    });
    img.src = logoUrl;
    container.appendChild(img);
}

const hostOf = (url) => {
    try { return new URL(url).host; } catch { return ''; }
};

/**
 * Texto del aviso de selectores sin comprobar. La causa dominante manda: si la zona del
 * dominio auditado devolvió SERVFAIL, eso es un dato sobre ELLOS; si solo hubo fallos de
 * transporte, el problema es de este navegador y lo que procede es reintentar.
 */
function resolveDkimErrorText(t, dkimErrors, result) {
    const servfails = dkimErrors.filter(e => e.code === 'servfail').length;
    const key = servfails > 0 ? t.dkim_unchecked_servfail : t.dkim_unchecked_network;
    // `attempted` puede faltar en resultados viejos (caché del navegador, export previo):
    // se cae al número de errores para no imprimir "N de undefined".
    const total = (result.dkimRecords && result.dkimRecords.attempted) || dkimErrors.length;
    return (key || '')
        .split('{n}').join(String(dkimErrors.length))
        .split('{total}').join(String(total));
}

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
    // Los selectores sin comprobar son un "no evaluable", no un fallo del dominio: se
    // enuncian como cuántos son sobre el total y por qué causa. Antes se listaban los
    // nombres crudos en rojo ("Errores de red en selectores: smg2, mail, …"), que no
    // decía ni qué había pasado ni qué hacer. Los nombres siguen ahí, plegados, para
    // quien continúe la auditoría a mano.
    const dkimErrHtml = dkimErrors.length > 0
        ? html`<div class="dkim-errors">
            <p class="dkim-errors__summary">${resolveDkimErrorText(t, dkimErrors, result)}</p>
            <details class="dkim-errors__detail">
                <summary>${t.dkim_unchecked_detail}</summary>
                <span class="dkim-errors__selectors">${dkimErrors.map(e => e.selector).join(', ')}</span>
            </details>
        </div>`
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
        // Cargar el logo es una petición del NAVEGADOR al servidor que elige el dominio
        // auditado. Va sin Referer y una imagen no lleva Origin: solo ve la IP. Con el
        // ajuste "cargar logotipos" apagado se ofrece un botón en su lugar.
        const contact = getSettings().loadBimiLogos;
        const logoHtml = bimi.logo
            ? html`<div class="bimi-logo-wrap">${contact ? raw('') : html`<button type="button" class="search-btn search-btn--ghost bimi-logo-load" title="${t.bimi_logo_load_hint.split('{host}').join(hostOf(bimi.logo))}">${t.bimi_logo_load}</button>`}</div>`
            : raw('');
        // Sin registro propio, el receptor usa el del dominio organizativo.
        const inheritedHtml = bimi.inheritedFrom
            ? html`<div class="info-block__detail bimi-inherited">${t.bimi_inherited_label.split('{org}').join(bimi.inheritedFrom)}</div>`
            : raw('');
        bimiBody.innerHTML = html`
            <div class="info-block">
                <div class="info-block__label">${t.bimi_record_found}</div>
                <div class="info-block__value info-block__value--mono">${bimi.record}</div>
                ${inheritedHtml}
                ${vmcHtml}
                ${logoHtml}
            </div>`;
        const wrap = bimiBody.querySelector('.bimi-logo-wrap');
        if (wrap && bimi.logo) {
            if (contact) {
                mountBimiLogo(wrap, bimi.logo, t);
            } else {
                const btn = wrap.querySelector('.bimi-logo-load');
                btn.addEventListener('click', () => {
                    btn.remove();
                    mountBimiLogo(wrap, bimi.logo, t);
                });
            }
        }
    }
}
