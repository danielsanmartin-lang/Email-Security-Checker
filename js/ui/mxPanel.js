// ui/mxPanel.js
// Panel de registros MX, proveedor identificado y capas de seguridad (SEG / ICES).
import { html, raw } from '../utils.js';
import { identifyMX } from '../analyzer.js';
import { translations } from '../i18n.js';
import { getLanguage } from '../lang.js';
import { displayInboundFilter, inboundFilterSource, displayMailHosting, mailHostingDetail, mailHostingPlatform, mailHostingEvidence, mailHostingNotes } from '../viewmodel.js';

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
    const provBody = document.getElementById('provider-body');

    // Este panel respondía a "quién es el proveedor" con lo único que sabía leer: el MX.
    // Pero el MX es el FILTRO DE ENTRADA, no la plataforma de buzón, y con un gateway
    // delante las dos respuestas son distintas. Ahora se muestran los dos ejes por
    // separado, cada uno diciendo solo lo que su evidencia sostiene.
    const mh = result.mailHosting;

    const hostingHtml = mh
        ? html`<div class="info-block info-block--spaced">
            <div class="info-block__label">${t.mailbox_platform_label}</div>
            <div class="info-block__value">${mailHostingPlatform(mh, t)}${hostingBadge(mh, t)}</div>
            ${mh.tenant ? html`<div class="info-block__detail">${t.mh_tenant_label}: ${mh.tenant}</div>` : raw('')}
        </div>
        <div class="info-block info-block--spaced">
            <div class="info-block__label">${t.panel_mail_hosting_label}</div>
            <div class="info-block__value">${displayMailHosting(mh, t)}</div>
            <div class="info-block__detail">${mailHostingDetail(mh, t)}</div>
            ${hostingEvidenceHtml(mh, t)}
            ${hostingNotesHtml(mh, t)}
            <div class="info-block__detail info-block__detail--muted">${t.mail_hosting_disclaimer}</div>
        </div>`
        : raw('');

    provBody.innerHTML = html`
        <div class="info-block">
            <div class="info-block__label">${t.inbound_filter_label}</div>
            <div class="info-block__value">${displayInboundFilter(result, t)}</div>
            <div class="info-block__detail">${inboundFilterSource(result, t)}</div>
        </div>
        ${hostingHtml}`;
}

/**
 * Insignia de confianza. Se omite a propósito cuando el veredicto es 'undetermined':
 * poner "0%" junto a "no determinable" sugeriría una medición donde no hay ninguna.
 */
function hostingBadge(mh, t) {
    if (!mh || mh.kind === 'undetermined' || typeof mh.confidence !== 'number') return raw('');
    const levelLabel = t[`awareness_level_${mh.level}`] || mh.level || '';
    const pct = `${Math.round(mh.confidence * 100)}%`;
    return html`<span class="seg-confidence seg-confidence--${raw(mh.level)}" style="margin-left:8px;font-size:11px;padding:2px 8px;border-radius:6px;font-weight:600;background:rgba(99,102,241,0.12);color:var(--accent-violet);">${levelLabel} · ${pct}</span>`;
}

function hostingEvidenceHtml(mh, t) {
    const items = mailHostingEvidence(mh, t);
    if (!items.length) return raw('');
    return html`<div class="info-block__detail">${t.evidence}: ${items.map((e, i) => html`${raw(i ? ' · ' : '')}${e.label}: ${e.value}`)}</div>`;
}

function hostingNotesHtml(mh, t) {
    const notes = mailHostingNotes(mh, t);
    const low = mh && mh.kind !== 'undetermined' && mh.confidence < 0.55
        ? [t.mh_low_confidence_note]
        : [];
    const all = [...low, ...notes];
    if (!all.length) return raw('');
    return html`${all.map(text => html`<div class="info-block__detail" style="color:var(--accent-amber,#d97706);font-style:italic;">⚠ ${text}</div>`)}`;
}

export function renderSecurityLayersPanel(domain, result) {
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

    // MX que apuntan a un dominio externo que el diccionario no reconoce. NO se
    // afirma que sean un gateway (ese era justo el falso positivo): se describe lo
    // que se ve y se ofrece añadirlo al diccionario para que la próxima vez sí se
    // identifique con nombre y categoría.
    const unidentified = [];
    const seenRoots = new Set();
    for (const mx of result.mxRecords || []) {
        const id = identifyMX(mx.host, domain);
        if (id.type === 'unknown' && id.external && !seenRoots.has(id.name)) {
            seenRoots.add(id.name);
            unidentified.push(id);
        }
    }
    const unidentifiedHtml = unidentified.length
        ? html`${unidentified.map(id => html`<div class="info-block info-block--spaced">
            <div class="info-block__label">${t.mx_unidentified_label}</div>
            <div class="info-block__value">${id.name}</div>
            <div class="info-block__detail">${id.sameBrand ? t.mx_unidentified_same_brand : t.mx_unidentified_detail}</div>
            <button type="button" class="kb-add-btn" data-kb-domain="${id.name}" data-kb-list="mx"
                title="${t.add_to_db_tooltip}">${t.add_to_db}</button>
        </div>`)}`
        : raw('');

    if (result.segList.length > 0 || result.icesList.length > 0) {
        secBody.innerHTML = html`${result.segList.map(seg => renderLayer(seg, 'seg'))}${result.icesList.map(ices => renderLayer(ices, 'ices'))}${unidentifiedHtml}`;
    } else {
        secBody.innerHTML = html`<div class="info-block">
            <div class="info-block__label">${t.no_evidence_dns}</div>
            <div class="info-block__value">${t.no_seg_ices_detected}</div>
            <div class="info-block__detail">${t.no_seg_ices_detail}</div>
        </div>
        ${unidentifiedHtml}
        <div class="info-block info-block--spaced">
            <div class="info-block__detail info-block__detail--muted">${t.ices_api_blindspot}</div>
        </div>`;
    }
}
