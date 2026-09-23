// ui/dmarcPanel.js
// Panel DMARC: registro crudo, etiquetas de la política, política que aplica de verdad
// (RFC 9989: herencia por Tree Walk y modo prueba) y destinos de informe.
import { html, raw } from '../utils.js';
import { identifyDMARCReporter } from '../analyzer.js';
import { translations } from '../i18n.js';
import { getLanguage } from '../lang.js';
import { lowerPolicy } from '../dmarc.js';

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

const fill = (text, replacements) => {
    let out = String(text || '');
    for (const [k, v] of Object.entries(replacements)) out = out.split(k).join(v);
    return out;
};

/**
 * Bloque "política que se aplica a este dominio". Solo aparece cuando NO coincide con lo
 * que se lee en la etiqueta p: al heredarla de su dominio organizativo (cuenta sp), en
 * modo prueba (t=y / pct=0), con un pct parcial, con valores no válidos o cuando el
 * dominio organizativo del Tree Walk no es el analizado. En el caso normal, repetir la p
 * solo sería ruido.
 */
function applicableBlock(result, domain, t) {
    const ev = result.dmarcEval;
    if (!ev) return raw('');
    const up = (p) => String(p || 'none').toUpperCase();
    const lines = [];
    if (ev.processing !== 'full') {
        lines.push(html`<div class="info-block__detail dmarc-applicable__warn">${t.dmarc_no_effect_label}</div>`);
    } else {
        if (ev.inherited) {
            lines.push(html`<div class="info-block__detail">${fill(t.dmarc_applicable_inherited, {
                '{org}': result.dmarcInheritedFrom || result.dmarcPolicyDomain || '',
                '{tag}': ev.applicableTag
            })}</div>`);
        }
        const split = ev.effective.rfc9989 !== ev.effective.rfc7489 || ev.effective.partialPct != null;
        if (split) {
            // Con pct parcial, RFC 7489 reparte: el pct % recibe la política y el resto la
            // inmediatamente inferior (§6.6.4).
            const pct = ev.effective.partialPct;
            const legacy = pct != null
                ? `${up(ev.applicable)} ${pct} % · ${up(lowerPolicy(ev.applicable))} ${100 - pct} %`
                : up(ev.effective.rfc7489);
            lines.push(html`<div class="info-block__detail">${fill(t.dmarc_effective_split, {
                '{bis}': up(ev.effective.rfc9989),
                '{legacy}': legacy
            })}</div>`);
        }
    }
    const org = result.dmarcOrgDomain;
    const showOrg = org && domain && org !== String(domain).toLowerCase();
    if (showOrg) {
        lines.push(html`<div class="info-block__detail">${t.dmarc_org_domain_label}: <span class="info-block__value--mono">${org}</span></div>`);
    }
    const differs = ev.processing !== 'full' || ev.inherited || ev.effective.floor !== ev.applicable
        || ev.effective.partialPct != null || ev.effective.rfc9989 !== ev.effective.rfc7489;
    if (!differs && !showOrg) return raw('');
    return html`<div class="info-block info-block--spaced dmarc-applicable">
        <div class="info-block__label">${t.dmarc_applicable_label}</div>
        <div class="info-block__value ${raw(policyClass(ev.effective.floor))}">${up(ev.effective.floor)}</div>
        ${lines}
    </div>`;
}

export function renderDmarcPanel(result, domain = '') {
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
        // Etiqueta eliminada en RFC 9989: se enseña, marcada, porque sigue rigiendo en los
        // receptores que no se han actualizado.
        const removedBadge = html` <span class="dmarc-tag-removed">${t.dmarc_tag_removed_badge}</span>`;

        const items = [dmarcItem(t.dmarc_policy_p, t.dmarc_tooltip_p, d.p || 'none', policyClass(d.p))];
        if (d.sp) items.push(dmarcItem(t.dmarc_policy_sp, t.dmarc_tooltip_sp, d.sp, policyClass(d.sp)));
        // np (RFC 9989): política para subdominios que no existen.
        if (d.np) items.push(dmarcItem(t.dmarc_policy_np, t.dmarc_tooltip_np, d.np, policyClass(d.np)));
        // t (RFC 9989): modo prueba; con t=y los receptores actualizados aplican un nivel menos.
        if (d.t) {
            items.push(dmarcItem(t.dmarc_policy_t, t.dmarc_tooltip_t,
                d.t === 'y' ? t.dmarc_testing_yes : t.dmarc_testing_no,
                d.t === 'y' ? 'dmarc-policy--quarantine' : ''));
        }
        if (d.psd) items.push(dmarcItem(t.dmarc_policy_psd, t.dmarc_tooltip_psd, d.psd));
        if (d.pct) items.push(dmarcItem(t.dmarc_policy_pct, t.dmarc_tooltip_pct, html`${d.pct}%${removedBadge}`));
        if (d.adkim) items.push(dmarcItem(t.dmarc_alignment_dkim, t.dmarc_tooltip_adkim, d.adkim === 's' ? 'Strict' : 'Relaxed'));
        if (d.aspf) items.push(dmarcItem(t.dmarc_alignment_spf, t.dmarc_tooltip_aspf, d.aspf === 's' ? 'Strict' : 'Relaxed'));

        // La descripción corresponde a la política que SE APLICA, no a la escrita en p.
        const applied = result.dmarcEval ? result.dmarcEval.effective.floor : d.p;
        dmarcBody.innerHTML = html`<div class="dmarc-grid">${items}</div>
            ${applicableBlock(result, domain, t)}
            <div class="info-block info-block--spaced">
                <div class="info-block__detail">${policyDesc[applied] || t.dmarc_policy_desc_unknown}</div>
            </div>`;
    } else {
        dmarcBody.innerHTML = html`<p class="no-data">${t.no_dmarc_record}</p>`;
    }

    const repBody = document.getElementById('dmarc-reporting-body');
    if (result.dmarcRua.length > 0 || result.dmarcRuf.length > 0) {
        const extAuth = {};
        (result.dmarcExternalAuth || []).forEach(d => { extAuth[d.uri] = d; });
        const invalidUris = new Set(result.dmarcEval
            ? [...result.dmarcEval.rua.invalid, ...result.dmarcEval.ruf.invalid]
            : []);
        // Badge de autorización para destinos externos (RFC 9990 §4)
        const authBadge = (uri) => {
            if (invalidUris.has(uri)) {
                return html`<div class="reporting-item__service reporting-item__service--bad">✗ ${t.dmarc_uri_invalid}</div>`;
            }
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
