// ui/reputationPanel.js
// Panel de reputación: estado de las IPs de los MX en las DNSBL consultadas.
import { html, raw } from '../utils.js';
import { rblCheckStatus } from '../viewmodel.js';

export function renderReputation(rblResults, lang, t) {
    const body = document.getElementById('reputation-body');
    const badge = document.getElementById('reputation-status');
    if (!body || !badge) return;

    if (!rblResults || rblResults.length === 0) {
        body.innerHTML = html`<p class="no-data">${t.rbl_no_data || 'No MX servers found to check.'}</p>`;
        badge.textContent = '—';
        return;
    }

    let anyListed = false;
    let anyError = false;

    const items = rblResults.map(entry => {
        const checks = entry.checks.map(check => {
            // status: 'listed' | 'clean' | 'error' (inconcluso). Compat: si no hay status, usar listed.
            const status = rblCheckStatus(check);
            if (status === 'listed') anyListed = true;
            if (status === 'error') anyError = true;
            let cls = 'rbl-check__badge--clean';
            let label = t.rbl_clean || 'Clean';
            if (status === 'listed') { cls = 'rbl-check__badge--listed'; label = t.rbl_listed || 'Listed'; }
            else if (status === 'error') { cls = 'rbl-check__badge--error'; label = t.rbl_inconclusive || 'Inconclusive'; }
            return html`<div class="rbl-check">
                <span class="rbl-check__name">${check.rbl}</span>
                <span class="rbl-check__badge ${raw(cls)}">${label}</span>
            </div>`;
        });
        const ip = entry.ip ? entry.ip : (t.rbl_unresolved || 'Unresolved');
        return html`<div class="rbl-item">
            <div class="rbl-item__info">
                <div class="rbl-item__host">${entry.host}</div>
                <div class="rbl-item__ip">${ip}</div>
            </div>
            <div class="rbl-item__checks">${checks}</div>
        </div>`;
    });

    // Aviso best-effort: las DNSBL suelen rechazar consultas vía resolvers DoH públicos.
    body.innerHTML = html`${items}<p class="rbl-disclaimer">${t.rbl_disclaimer || ''}</p>`;

    badge.classList.remove('rbl-badge--listed', 'rbl-badge--inconclusive', 'rbl-badge--clean');
    if (anyListed) {
        badge.textContent = t.rbl_badge_listed || '\u26a0 Listed';
        badge.classList.add('rbl-badge--listed');
    } else if (anyError) {
        badge.textContent = t.rbl_badge_inconclusive || '? Inconclusive';
        badge.classList.add('rbl-badge--inconclusive');
    } else {
        badge.textContent = t.rbl_badge_clean || '\u2713 Clean';
        badge.classList.add('rbl-badge--clean');
    }
}
