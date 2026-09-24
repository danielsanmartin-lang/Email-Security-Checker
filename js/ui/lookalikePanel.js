// ui/lookalikePanel.js
// Panel de dominios parecidos (typosquatting). Informa, no puntúa.
//
// Estados de `lookalike`:
//   undefined — la búsqueda sigue en marcha
//   null      — la búsqueda falló
//   objeto    — { checked, found: [{ domain, technique, mx, ns, kind }], unresolved }
//
// Los nombres de los MX vienen del DNS de terceros: todo pasa por html``, que escapa.
import { html, raw } from '../utils.js';
import { translations } from '../i18n.js';
import { getLanguage } from '../lang.js';

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
        ? html`<p class="lookalike-note">${t.lookalike_unresolved.split('{n}').join(String(lookalike.unresolved))}</p>`
        : raw('');

    if (!lookalike.found.length) {
        body.innerHTML = html`${intro}<p class="no-data">${t.lookalike_none}</p>${unresolved}`;
        return;
    }

    const rows = lookalike.found.map(f => {
        const mx = f.mx.length ? (f.mx.length > 1 ? `${f.mx[0]} (+${f.mx.length - 1})` : f.mx[0]) : '—';
        return html`<tr>
            <td class="lookalike-domain">${f.domain}</td>
            <td>${t[`lookalike_technique_${f.technique}`] || f.technique}</td>
            <td class="lookalike-mx">${mx}</td>
            <td><span class="tag tag--${raw(KIND_TAG[f.kind] || 'unknown')} lookalike-kind"${f.kind === 'own' ? html` title="${t.lookalike_own_hint}"` : raw('')}>${t[`lookalike_kind_${f.kind}`]}</span></td>
        </tr>`;
    });

    body.innerHTML = html`${intro}
        <div class="lookalike-table-wrap">
            <table class="lookalike-table">
                <thead><tr>
                    <th>${t.lookalike_col_domain}</th>
                    <th>${t.lookalike_col_technique}</th>
                    <th>${t.lookalike_col_mx}</th>
                    <th>${t.lookalike_col_status}</th>
                </tr></thead>
                <tbody>${rows}</tbody>
            </table>
        </div>
        ${unresolved}`;
}
