// ui/mxPanel.js
// Panel de registros MX, proveedor identificado y capas de seguridad (SEG / ICES).
import { html, raw } from '../utils.js';
import { identifyMX } from '../analyzer.js';
import { translations } from '../i18n.js';
import { getLanguage } from '../lang.js';
import { displayProvider, formatProviderSource } from '../viewmodel.js';

export function renderMxPanel(domain, result) {
    const lang = getLanguage();
    const t = translations[lang];
    const mxBody = document.getElementById('mx-body');
    const recordWord = result.mxRecords.length === 1 ? t.singular_record : t.plural_records;
    document.getElementById('mx-count').textContent = `${result.mxRecords.length} ${recordWord}`;
    
    if (result.mxRecords.length === 0) {
        mxBody.innerHTML = html`<p class="no-data">${t.no_mx_records}</p>`;
    } else {
        mxBody.innerHTML = html`${result.mxRecords.map(mx => {
            const id = identifyMX(mx.host, domain);
            const tagClass = id.type === 'provider' ? 'tag--provider' : id.type === 'seg' ? 'tag--seg' : id.type === 'ices' ? 'tag--ices' : 'tag--unknown';
            return html`<div class="mx-record">
                <span class="mx-record__priority">${String(mx.priority)}</span>
                <span class="mx-record__host">${mx.host}</span>
                <span class="mx-record__tag ${raw(tagClass)}">${id.name}</span>
            </div>`;
        })}`;
    }
}


export function renderProviderPanel(result) {
    const t = translations[getLanguage()];
    const providerDisplay = displayProvider(result, t);
    const provBody = document.getElementById('provider-body');
    provBody.innerHTML = html`
        <div class="info-block">
            <div class="info-block__label">${t.provider_identified}</div>
            <div class="info-block__value">${providerDisplay}</div>
            <div class="info-block__detail">${formatProviderSource(result.providerSource, t)}</div>
        </div>`;
}

export function renderSecurityLayersPanel(result) {
    const t = translations[getLanguage()];
    const secBody = document.getElementById('security-body');
    const renderLayer = (entry, kind) => {
        const levelLabel = t[`awareness_level_${entry.level}`] || entry.level || '';
        const pct = typeof entry.score === 'number' ? `${Math.round(entry.score * 100)}%` : '';
        // Confianza < 50%: no afirmamos que se USE el producto; se presenta como
        // hipótesis ("posible — sin evidencia concluyente"), no como capa confirmada.
        const inconclusive = typeof entry.score === 'number' && entry.score < 0.5;
        const labelText = inconclusive
            ? (kind === 'seg' ? t.seg_inconclusive : t.ices_inconclusive)
            : (kind === 'seg' ? t.seg_detected : t.ices_detected);
        const evidence = Array.isArray(entry.evidence) ? entry.evidence : [];
        const badge = entry.level
            ? html`<span class="seg-confidence seg-confidence--${raw(entry.level)}" style="margin-left:8px;font-size:11px;padding:2px 8px;border-radius:6px;font-weight:600;background:rgba(99,102,241,0.12);color:var(--accent-violet);">${levelLabel}${pct ? ` · ${pct}` : ''}</span>`
            : raw('');
        const evidenceHtml = evidence.length
            ? html`<div class="info-block__detail">${t.evidence}: ${evidence.map((e, i) => html`${raw(i ? ' · ' : '')}${t[`seg_signal_${e.signal}`] || e.signal}: ${e.value}`)}</div>`
            : html`<div class="info-block__detail">${t.evidence}: ${entry.source}</div>`;
        const inconclusiveHtml = inconclusive
            ? html`<div class="info-block__detail" style="color:var(--accent-amber,#d97706);font-style:italic;">⚠ ${t.seg_low_confidence_note}</div>`
            : raw('');
        const unconfirmedHtml = entry.unconfirmed
            ? html`<div class="info-block__detail" style="color:var(--accent-amber,#d97706);font-style:italic;">⚠ ${t.seg_unconfirmed_mx}</div>`
            : raw('');
        return html`<div class="info-block">
            <div class="info-block__label">${labelText}</div>
            <div class="info-block__value">${entry.name}${badge}</div>
            ${evidenceHtml}
            ${inconclusiveHtml}
            ${unconfirmedHtml}
        </div>`;
    };

    if (result.segList.length > 0 || result.icesList.length > 0) {
        secBody.innerHTML = html`${result.segList.map(seg => renderLayer(seg, 'seg'))}${result.icesList.map(ices => renderLayer(ices, 'ices'))}`;
    } else {
        secBody.innerHTML = html`<div class="info-block">
            <div class="info-block__label">${t.no_evidence_dns}</div>
            <div class="info-block__value">${t.no_seg_ices_detected}</div>
            <div class="info-block__detail">${t.no_seg_ices_detail}</div>
        </div>
        <div class="info-block" style="margin-top:8px;">
            <div class="info-block__detail" style="color:var(--text-muted);font-style:italic;">${t.ices_api_blindspot}</div>
        </div>`;
    }
}
