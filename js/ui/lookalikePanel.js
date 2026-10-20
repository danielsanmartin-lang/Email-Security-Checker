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
import { lookalikeAgeView, lookalikeCertView, countText } from '../viewmodel.js';

const KIND_TAG = { mx: 'warning', registered: 'unknown', own: 'provider' };

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

    const withMx = lookalike.found.filter(f => f.kind === 'mx').length;
    if (badge) {
        badge.textContent = withMx > 0
            ? t.lookalike_badge_mx.split('{n}').join(String(withMx))
            : t.lookalike_badge_none;
        badge.className = `panel__badge${withMx > 0 ? ' panel__badge--warning' : ''}`;
    }

    const intro = html`<p class="lookalike-intro">${t.lookalike_intro.split('{checked}').join(String(lookalike.checked))}</p>`;
    const unresolved = lookalike.unresolved > 0
        ? html`<p class="lookalike-note">${countText(t, 'lookalike_unresolved', lookalike.unresolved)}</p>`
        : raw('');

    if (!lookalike.found.length) {
        body.innerHTML = html`${intro}<p class="no-data">${t.lookalike_none}</p>${unresolved}`;
        return;
    }

    const locale = getLocale();
    const row = (f) => {
        const mx = f.mx.length
            ? html`${breakableHost(f.mx[0])}${f.mx.length > 1 ? ` (+${f.mx.length - 1})` : ''}`
            : '—';
        const certView = lookalikeCertView(f, t, locale);
        const ageView = lookalikeAgeView(f, t, locale);
        return html`<tr>
            <td class="lookalike-domain">${breakableHost(f.domain)}</td>
            <td>${t[`lookalike_technique_${f.technique}`] || f.technique}</td>
            <td class="lookalike-mx">${mx}</td>
            <td><span class="tag tag--${raw(KIND_TAG[f.kind] || 'unknown')} lookalike-kind"${f.kind === 'own' ? html` title="${t.lookalike_own_hint}"` : raw('')}>${t[`lookalike_kind_${f.kind}`]}</span></td>
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

    // Los registrados sin MX hoy no reciben correo, y suelen ser la mayoría: en una tabla
    // con los que sí lo reciben la alargaban hasta esconderlos. Se pliegan aparte, con solo
    // las columnas que dicen algo (MX, estado y certificado serían "—" en todas).
    const receiving = lookalike.found.filter(f => f.kind !== 'registered');
    const registered = lookalike.found.filter(f => f.kind === 'registered');
    const folded = receiving.length > 0 && registered.length > 0;
    const main = folded ? receiving : lookalike.found;
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
                    <th>${t.lookalike_col_status}</th>
                    <th>${t.lookalike_col_age}</th>
                    <th>${t.lookalike_col_cert}</th>
                </tr></thead>
                <tbody>${main.map(row)}</tbody>
            </table>
        </div>
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
