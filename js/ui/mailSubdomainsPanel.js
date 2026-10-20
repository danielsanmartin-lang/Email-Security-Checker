// ui/mailSubdomainsPanel.js
// Panel de subdominios con correo, sacados de Certificate Transparency. Informa, no puntúa.
//
// Estados de `data`:
//   undefined — la búsqueda sigue en marcha
//   null      — la búsqueda falló
//   objeto    — { ctNames, checked, found: [{ name, sends, receives, policy, inherited,
//               spoofable }], unresolved }
//
// Los nombres vienen de certificados públicos y del DNS: todo pasa por html``, que escapa.
import { html, raw } from '../utils.js';
import { translations } from '../i18n.js';
import { getLanguage } from '../lang.js';

const fill = (text, values) => Object.entries(values)
    .reduce((acc, [k, v]) => acc.split(`{${k}}`).join(String(v)), String(text || ''));

export function renderMailSubdomains(data) {
    const body = document.getElementById('mailsub-body');
    const badge = document.getElementById('mailsub-badge');
    if (!body) return;
    const t = translations[getLanguage()];

    if (data === undefined || data === null) {
        if (badge) { badge.textContent = data === undefined ? '...' : '—'; badge.className = 'panel__badge'; }
        body.innerHTML = html`<p class="no-data">${data === undefined ? t.mailsub_scanning : t.mailsub_failed}</p>`;
        return;
    }

    const spoofable = data.found.filter(f => f.spoofable === true).length;
    if (badge) {
        badge.textContent = spoofable > 0 ? fill(t.mailsub_badge_spoofable, { n: spoofable }) : t.mailsub_badge_ok;
        badge.className = `panel__badge${spoofable > 0 ? ' panel__badge--warning' : ''}`;
    }

    if (!data.ctNames) {
        body.innerHTML = html`<p class="no-data">${t.mailsub_no_ct}</p>`;
        return;
    }
    const intro = html`<p class="lookalike-intro">${fill(t.mailsub_intro, { names: data.ctNames, checked: data.checked })}</p>`;
    const unresolved = data.unresolved > 0
        ? html`<p class="lookalike-note">${fill(t.mailsub_unresolved, { n: data.unresolved })}</p>`
        : raw('');
    if (!data.found.length) {
        body.innerHTML = html`${intro}<p class="no-data">${t.mailsub_none}</p>${unresolved}`;
        return;
    }

    const rows = data.found.map((f) => {
        const mail = [f.sends ? t.mailsub_sends : null, f.receives ? t.mailsub_receives : null].filter(Boolean).join(' · ');
        const policy = f.policy === 'unknown' ? '—' : f.policy;
        const status = f.spoofable === null
            ? html`<span class="tag tag--unknown lookalike-kind">${t.mailsub_unknown}</span>`
            : f.spoofable
                ? html`<span class="tag tag--warning lookalike-kind">${t.mailsub_spoofable}</span>`
                : html`<span class="tag tag--provider lookalike-kind">${t.mailsub_protected}</span>`;
        return html`<tr>
            <td class="lookalike-domain">${f.name}</td>
            <td>${mail}</td>
            <td class="lookalike-mx">${policy}${f.inherited ? html` <span class="lookalike-note">(${t.mailsub_inherited})</span>` : raw('')}</td>
            <td>${status}</td>
        </tr>`;
    });

    body.innerHTML = html`${intro}
        <div class="lookalike-table-wrap">
            <table class="lookalike-table">
                <thead><tr>
                    <th>${t.mailsub_col_name}</th>
                    <th>${t.mailsub_col_mail}</th>
                    <th>${t.mailsub_col_policy}</th>
                    <th>${t.mailsub_col_status}</th>
                </tr></thead>
                <tbody>${rows}</tbody>
            </table>
        </div>
        ${unresolved}`;
}
