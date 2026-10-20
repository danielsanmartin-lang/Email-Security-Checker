// ui/lookalikePanel.js
// Panel de dominios parecidos (typosquatting). Informa, no puntúa.
//
// Estados de `lookalike`:
//   undefined — la búsqueda sigue en marcha
//   null      — la búsqueda falló
//   objeto    — { checked, found: [{ domain, technique, mx, ns, kind, cert? }], unresolved }
//
// `cert` solo existe en los parecidos que se miran en Certificate Transparency (los
// primeros que reciben correo): { status: 'checking' | 'recent' | 'active' | 'none' |
// 'unchecked', notBefore?, issuer?, days?, firstSeen?, firstSeenDays? }. `age`, en los que
// reciben correo, es su fecha de registro (RDAP): { status: 'checking' | 'new' | 'old' |
// 'unknown', registered?, days? }. El panel se repinta cuando llega cada uno.
//
// Los nombres de los MX vienen del DNS de terceros: todo pasa por html``, que escapa.
import { html, raw, breakableHost } from '../utils.js';
import { translations } from '../i18n.js';
import { getLanguage, getLocale } from '../lang.js';
import { LOOKALIKE_CERT_MAX } from '../ct.js';
import { NEW_DOMAIN_DAYS } from '../rdap.js';
import { RISK_RANK } from '../lookalike.js';
import { lookalikeAgeView, lookalikeCertView, lookalikeRiskView, countText } from '../viewmodel.js';

export function renderLookalikes(lookalike) {
    const body = document.getElementById('lookalike-body');
    const badge = document.getElementById('lookalike-badge');
    if (!body) return;
    const t = translations[getLanguage()];

    if (lookalike === undefined) {
        if (badge) { badge.textContent = '...'; badge.className = 'panel__badge'; }
        body.innerHTML = html`<p class="no-data">${t.lookalike_scanning}</p>`;
        return;
    }
    if (lookalike === null) {
        if (badge) { badge.textContent = '—'; badge.className = 'panel__badge'; }
        body.innerHTML = html`<p class="no-data">${t.lookalike_failed}</p>`;
        return;
    }

    const locale = getLocale();
    // El veredicto de cada parecido (reglas fijas, ver assessLookalikeRisk) decide el orden
    // y la insignia: cuenta los de riesgo alto o, si no hay, los de medio.
    const risk = new Map(lookalike.found.map(f => [f, lookalikeRiskView(f, t, locale)]));
    const count = (level) => lookalike.found.filter(f => risk.get(f).level === level).length;
    const high = count('high');
    const medium = count('medium');
    if (badge) {
        badge.textContent = high > 0 ? countText(t, 'lookalike_badge_high', high)
            : medium > 0 ? countText(t, 'lookalike_badge_mx', medium)
                : count('pending') > 0 ? '...' : t.lookalike_badge_none;
        badge.className = `panel__badge${high > 0 ? ' panel__badge--danger' : medium > 0 ? ' panel__badge--warning' : ''}`;
    }

    const intro = html`<p class="lookalike-intro">${t.lookalike_intro.split('{checked}').join(String(lookalike.checked))}</p>`;
    const unresolved = lookalike.unresolved > 0
        ? html`<p class="lookalike-note">${countText(t, 'lookalike_unresolved', lookalike.unresolved)}</p>`
        : raw('');

    if (!lookalike.found.length) {
        body.innerHTML = html`${intro}<p class="no-data">${t.lookalike_none}</p>${unresolved}`;
        return;
    }

    const row = (f) => {
        const mx = f.mx.length
            ? html`${breakableHost(f.mx[0])}${f.mx.length > 1 ? ` (+${f.mx.length - 1})` : ''}`
            : '—';
        const certView = lookalikeCertView(f, t, locale);
        const ageView = lookalikeAgeView(f, t, locale);
        const riskView = risk.get(f);
        return html`<tr>
            <td class="lookalike-domain lookalike-domain--short">${f.domain}</td>
            <td>${t[`lookalike_technique_${f.technique}`] || f.technique}</td>
            <td class="lookalike-mx">${mx}</td>
            <td class="lookalike-risk">
                <span class="tag tag--${raw(riskView.tone)} lookalike-kind">${riskView.text}</span>
                ${riskView.reasons.length ? html`<span class="lookalike-reasons">${riskView.reasons.join(' · ')}</span>` : raw('')}
            </td>
            <td>${viewHtml(ageView)}</td>
            <td>${viewHtml(certView)}</td>
        </tr>`;
    };
    const certNote = lookalike.found.some(f => f.cert)
        ? html`<p class="lookalike-note">${t.lookalike_cert_note.split('{n}').join(String(LOOKALIKE_CERT_MAX))}</p>`
        : raw('');
    const ageNote = lookalike.found.some(f => f.age)
        ? html`<p class="lookalike-note">${t.lookalike_age_note.split('{days}').join(String(NEW_DOMAIN_DAYS))}</p>`
        : raw('');
    const riskNote = html`<p class="lookalike-note">${t.lookalike_risk_note.split('{days}').join(String(NEW_DOMAIN_DAYS))}</p>`;

    // Los registrados sin MX hoy no reciben correo, y suelen ser la mayoría: en una tabla
    // con los que sí lo reciben la alargaban hasta esconderlos. Se pliegan aparte, con solo
    // las columnas que dicen algo (MX, estado y certificado serían "—" en todas).
    const receiving = lookalike.found.filter(f => f.kind !== 'registered');
    const registered = lookalike.found.filter(f => f.kind === 'registered');
    const folded = receiving.length > 0 && registered.length > 0;
    // Lo más peligroso arriba; a igual nivel, el orden del generador.
    const main = (folded ? receiving : lookalike.found)
        .map((f, i) => [f, i])
        .sort(([a, i], [b, j]) => (RISK_RANK[risk.get(a).level] - RISK_RANK[risk.get(b).level]) || (i - j))
        .map(([f]) => f);
    const registeredHtml = folded
        ? html`<details class="lookalike-more">
            <summary>${countText(t, 'lookalike_registered_more', registered.length)}</summary>
            <div class="lookalike-table-wrap">
                <table class="lookalike-table">
                    <thead><tr>
                        <th>${t.lookalike_col_domain}</th>
                        <th>${t.lookalike_col_technique}</th>
                    </tr></thead>
                    <tbody>${registered.map(f => html`<tr>
                        <td class="lookalike-domain">${breakableHost(f.domain)}</td>
                        <td>${t[`lookalike_technique_${f.technique}`] || f.technique}</td>
                    </tr>`)}</tbody>
                </table>
            </div>
        </details>`
        : raw('');

    body.innerHTML = html`${intro}
        <div class="lookalike-table-wrap">
            <table class="lookalike-table">
                <thead><tr>
                    <th>${t.lookalike_col_domain}</th>
                    <th>${t.lookalike_col_technique}</th>
                    <th>${t.lookalike_col_mx}</th>
                    <th>${t.lookalike_col_risk}</th>
                    <th>${t.lookalike_col_age}</th>
                    <th>${t.lookalike_col_cert}</th>
                </tr></thead>
                <tbody>${main.map(row)}</tbody>
            </table>
        </div>
        ${riskNote}
        ${certNote}
        ${ageNote}
        ${registeredHtml}
        ${unresolved}`;
}

// Una celda de lookalikeAgeView / lookalikeCertView: etiqueta si tiene tono, texto si no,
// "—" si no hay nada que decir.
function viewHtml(view) {
    if (!view) return raw('—');
    const title = view.title ? html` title="${view.title}"` : raw('');
    return view.tone
        ? html`<span class="tag tag--${raw(view.tone)} lookalike-kind"${title}>${view.text}</span>`
        : html`<span class="lookalike-age"${title}>${view.text}</span>`;
}
