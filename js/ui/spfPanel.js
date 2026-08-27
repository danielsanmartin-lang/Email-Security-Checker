// ui/spfPanel.js
// Panel SPF: registro crudo, tabla de mecanismos, servicios detectados, árbol de
// lookups y contador de consultas.
import { html, raw } from '../utils.js';
import { identifySPFService } from '../analyzer.js';
import { KB } from '../knowledge.js';
import { translations } from '../i18n.js';
import { getLanguage } from '../lang.js';
import { getCategoryLabel, spfQualifierResult } from '../viewmodel.js';

// Migrada al helper html`` (auto-escapa interpolaciones; XSS-safe por defecto).
export function renderSPFTree(tree) {
    if (!tree) return '';
    const lang = getLanguage();
    const t = translations[lang] || translations.es;

    let errorSpan = raw('');
    if (tree.error) {
        if (tree.error === 'loop') {
            const tooltipText = t.spf_loop_error_tooltip || '';
            errorSpan = html`<span class="tooltip-trigger spf-tree-error" data-tooltip="${tooltipText}" tabindex="0">[Error: ${t.spf_error_loop}]</span>`;
        } else {
            const errMap = {
                depth_exceeded: t.spf_error_depth,
                query_failed: t.spf_error_query,
                no_spf_record: t.spf_error_no_record
            };
            const errLabel = errMap[tree.error] || tree.errorDetail || tree.error;
            errorSpan = html`<span class="spf-tree-error">[Error: ${errLabel}]</span>`;
        }
    }

    const children = (tree.children && tree.children.length > 0)
        ? html`<ul>${tree.children.map(child => child.tree
            ? html`<li><span class="spf-tree-type tag tag--unknown">${child.type}</span>: ${renderSPFTree(child.tree)}</li>`
            : html`<li><span class="spf-tree-type tag tag--unknown">${child.type}</span>: ${child.target}</li>`)}</ul>`
        : raw('');

    return html`<ul class="spf-tree"><li><strong>${tree.domain}</strong> <span class="spf-tree-lookups">(${tree.lookups} lookups)</span> ${errorSpan}${children}</li></ul>`;
}

export function renderSpfPanel(result) {
    const lang = getLanguage();
    const t = translations[lang];
    const spfRawEl = document.getElementById('spf-raw');
    if (result.spfData && result.spfData.records && result.spfData.records.length > 0) {
        if (result.spfData.multiple) {
            spfRawEl.innerHTML = html`${result.spfData.records.map(r => html`<div class="record-duplicate">${r}</div>`)}`;
        } else {
            spfRawEl.textContent = result.spfRaw;
        }
        spfRawEl.classList.remove('hidden');
    } else {
        spfRawEl.textContent = t.no_spf_record;
    }

    const spfTbody = document.getElementById('spf-table-body');
    spfTbody.innerHTML = '';
    
    for (const entry of result.spfEntries) {
        const svc = identifySPFService(entry.value);
        const prefixDisplay = entry.qualifier === '+' ? '+' : entry.qualifier === '-' ? '-' : entry.qualifier === '~' ? '~' : entry.qualifier === '?' ? '?' : '';
        
        const spfRes = spfQualifierResult(entry.qualifier);
        let prefixClass = `spf-prefix--${spfRes.kind}`;
        let resultText = spfRes.text;
        
        if (entry.type === 'v') { resultText = ''; prefixClass = 'spf-prefix--neutral'; }
        if (entry.type === 'all' && entry.qualifier === '-') { resultText = 'Fail'; prefixClass = 'spf-prefix--fail'; }
        if (entry.type === 'all' && entry.qualifier === '~') { resultText = 'SoftFail'; prefixClass = 'spf-prefix--softfail'; }

        const resultClass = resultText === 'Pass' ? 'spf-result--pass' : resultText === 'Fail' ? 'spf-result--fail' : 'spf-result--softfail';

        // Tooltip for qualifier
        const qualifierTooltip = t[`spf_qualifier_${entry.qualifier || '+'}`] || '';
        // Tooltip for mechanism type
        const typeTooltip = t[`spf_type_${entry.type}`] || '';

        let svcHTML = html`<span class="no-data">—</span>`;
        if (svc) {
            const catClass = `cat--${svc.category}`;
            const localizedCatLabel = getCategoryLabel(svc, lang);
            if (svc.is_unknown) {
                // El dominio viaja en data-kb-domain (nunca en un onclick inline):
                // procede del registro SPF remoto y podría inyectar JS.
                svcHTML = html`<span class="spf-service">${svc.name}</span><button type="button" class="spf-service__category spf-service__category--btn ${raw(catClass)}" title="${t.add_to_db_tooltip}" data-kb-domain="${svc.search_query || ''}">${t.add_to_db}</button>`;
            } else {
                svcHTML = html`<span class="spf-service">${svc.name}</span><span class="spf-service__category ${raw(catClass)}">${localizedCatLabel}</span>`;
            }
        }
        if (entry.type === 'v') svcHTML = html`<span class="spf-cell-muted">${t.spf_version}</span>`;
        if (entry.type === 'all') svcHTML = html`<span class="spf-cell-muted">${t.spf_default_policy}</span>`;

        const row = document.createElement('tr');
        row.innerHTML = html`
            <td><span class="spf-prefix ${raw(prefixClass)}${raw(qualifierTooltip ? ' tooltip-trigger' : '')}" data-tooltip="${qualifierTooltip}"${raw(qualifierTooltip ? ' tabindex="0"' : '')}>${prefixDisplay || ''}</span></td>
            <td><span class="spf-type${raw(typeTooltip ? ' tooltip-trigger' : '')}" data-tooltip="${typeTooltip}"${raw(typeTooltip ? ' tabindex="0"' : '')}>${entry.type}</span></td>
            <td><span class="spf-value">${entry.value || '—'}</span></td>
            <td><span class="spf-result ${raw(resultClass)}">${resultText}</span></td>
            <td>${svcHTML}</td>`;
        spfTbody.appendChild(row);
    }

    const spfSummary = document.getElementById('spf-services-summary');
    if (result.spfServices.length > 0) {
        const pills = result.spfServices.map(svc => {
            const color = KB.categoryColors[svc.category] || '#64748b';
            const localizedCatLabel = getCategoryLabel(svc, lang);
            return html`<span class="service-pill">
                <span class="service-pill__dot" style="background:${color}"></span>
                ${svc.name} <small class="service-pill__cat">(${localizedCatLabel})</small>
            </span>`;
        });
        spfSummary.innerHTML = html`<div class="services-summary">${pills}</div>`;
    } else {
        spfSummary.innerHTML = html`<p class="no-data">${t.no_third_party_spf}</p>`;
    }

    const treeBody = document.getElementById('spf-tree-body');
    if (treeBody) {
        if (result.spfTree && result.spfTree.record) {
            treeBody.innerHTML = renderSPFTree(result.spfTree);
        } else {
            treeBody.innerHTML = html`<p class="no-data">${t.no_spf_tree}</p>`;
        }
    }

    // Contador de lookups SPF (10 es el límite duro del RFC 7208 §4.6.4).
    const lookupBadge = document.getElementById('spf-lookups-count');
    if (lookupBadge) {
        if (result.spfLookups !== undefined) {
            lookupBadge.textContent = `${result.spfLookups}/10 Lookups`;
            lookupBadge.classList.remove('lookups--ok', 'lookups--warn', 'lookups--over');
            lookupBadge.classList.add(result.spfLookups > 10 ? 'lookups--over' : result.spfLookups > 7 ? 'lookups--warn' : 'lookups--ok');
        } else {
            lookupBadge.textContent = '';
        }
    }
}
