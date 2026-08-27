// ui/dmarcPanel.js
// Panel DMARC: registro crudo, etiquetas de la política y destinos de informe.
import { html, raw } from '../utils.js';
import { identifyDMARCReporter } from '../analyzer.js';
import { translations } from '../i18n.js';
import { getLanguage } from '../lang.js';

// Clase de color según la dureza de la política (p / sp / np comparten escala).
function policyClass(value) {
    if (value === 'reject') return 'dmarc-policy--reject';
    if (value === 'quarantine') return 'dmarc-policy--quarantine';
    return 'dmarc-policy--none';
}

function dmarcItem(label, tooltip, value, valueClass = '') {
    return html`<div class="dmarc-item">
        <div class="dmarc-item__label${raw(tooltip ? ' tooltip-trigger' : '')}" data-tooltip="${tooltip || ''}" tabindex="0">${label}</div>
        <div class="dmarc-item__value ${raw(valueClass)}">${value}</div>
    </div>`;
}

export function renderDmarcPanel(result) {
    const lang = getLanguage();
    const t = translations[lang];

    const dmarcRawEl = document.getElementById('dmarc-raw');
    if (result.dmarcData && result.dmarcData.records && result.dmarcData.records.length > 0) {
        if (result.dmarcData.multiple) {
            dmarcRawEl.innerHTML = html`${result.dmarcData.records.map(r => html`<div class="record-duplicate">${r}</div>`)}`;
        } else {
            dmarcRawEl.textContent = result.dmarcRaw;
        }
    } else {
        dmarcRawEl.textContent = t.no_dmarc_record;
    }

    const dmarcBody = document.getElementById('dmarc-body');
    if (result.dmarcParsed) {
        const d = result.dmarcParsed;
        const policyDesc = {
            'reject': t.dmarc_policy_desc_reject,
            'quarantine': t.dmarc_policy_desc_quarantine,
            'none': t.dmarc_policy_desc_none
        };

        const items = [dmarcItem(t.dmarc_policy_p, t.dmarc_tooltip_p, d.p || 'none', policyClass(d.p))];
        if (d.sp) items.push(dmarcItem(t.dmarc_policy_sp, t.dmarc_tooltip_sp, d.sp, policyClass(d.sp)));
        // np (DMARCbis): política para subdominios que no existen.
        if (d.np) items.push(dmarcItem(t.dmarc_policy_np, t.dmarc_tooltip_np, d.np, policyClass(d.np)));
        if (d.pct) items.push(dmarcItem(t.dmarc_policy_pct, t.dmarc_tooltip_pct, `${d.pct}%`));
        if (d.adkim) items.push(dmarcItem(t.dmarc_alignment_dkim, t.dmarc_tooltip_adkim, d.adkim === 's' ? 'Strict' : 'Relaxed'));
        if (d.aspf) items.push(dmarcItem(t.dmarc_alignment_spf, t.dmarc_tooltip_aspf, d.aspf === 's' ? 'Strict' : 'Relaxed'));

        dmarcBody.innerHTML = html`<div class="dmarc-grid">${items}</div>
            <div class="info-block info-block--spaced">
                <div class="info-block__detail">${policyDesc[d.p] || t.dmarc_policy_desc_unknown}</div>
            </div>`;
    } else {
        dmarcBody.innerHTML = html`<p class="no-data">${t.no_dmarc_record}</p>`;
    }

    const repBody = document.getElementById('dmarc-reporting-body');
    if (result.dmarcRua.length > 0 || result.dmarcRuf.length > 0) {
        const extAuth = {};
        (result.dmarcExternalAuth || []).forEach(d => { extAuth[d.uri] = d; });
        // Badge de autorización para destinos externos (RFC 7489 §7.1)
        const authBadge = (uri) => {
            const d = extAuth[uri];
            if (!d) return raw('');
            if (d.authorized === true) {
                return html`<div class="reporting-item__service reporting-item__service--ok">✓ ${t.dmarc_ext_authorized} (${d.destDomain})</div>`;
            }
            if (d.authorized === false) {
                return html`<div class="reporting-item__service reporting-item__service--bad">✗ ${t.dmarc_ext_unauthorized} (${d.destDomain})</div>`;
            }
            return html`<div class="reporting-item__service reporting-item__service--unknown">? ${t.dmarc_ext_unverifiable} (${d.destDomain})</div>`;
        };
        const reportingItem = (uri, typeLabel) => {
            const reporter = identifyDMARCReporter(uri);
            return html`<div class="reporting-item">
                <div class="reporting-item__type">${typeLabel}</div>
                <div class="reporting-item__value">${uri}</div>
                ${reporter ? html`<div class="reporting-item__service">${t.tool_label}: ${reporter}</div>` : raw('')}
                ${authBadge(uri)}
            </div>`;
        };
        repBody.innerHTML = html`
            ${result.dmarcRua.map(rua => reportingItem(rua, `RUA (${t.dmarc_aggregate})`))}
            ${result.dmarcRuf.map(ruf => reportingItem(ruf, `RUF (${t.dmarc_forensic})`))}`;
    } else {
        repBody.innerHTML = html`<p class="no-data">${t.no_dmarc_reporting}</p>`;
    }
}
