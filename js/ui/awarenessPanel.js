// ui/awarenessPanel.js
// Panel del detector de plataformas de Awareness / Phishing Simulation.
import { html, raw } from '../utils.js';
import { detectFromHeaders } from '../headerAnalyzer.js';
import { translations } from '../i18n.js';
import { getLanguage } from '../lang.js';

function buildAwarenessCard(v, t) {
    const signalLabel = (sig) => t[`awareness_signal_${sig}`] || sig;
    const levelClass = { alta: 'awareness-level--alta', media: 'awareness-level--media', baja: 'awareness-level--baja' };
    const levelColorVar = { alta: 'var(--accent-emerald)', media: 'var(--accent-amber)', baja: 'var(--accent-rose)' };
    const lvlLabel = t[`awareness_level_${v.level}`] || v.level;
    const lvlClass = levelClass[v.level] || 'awareness-level--baja';
    const pct = Math.round(v.score * 100);
    const color = levelColorVar[v.level] || 'var(--accent-rose)';

    const sourceBadge = v.source === 'headers'
        ? `<span class="awareness-source-badge">✉ ${t.awareness_source_headers || 'headers'}</span>`
        : '';
    // Distingue "tiene el gateway del vendor" de "usa el módulo de awareness"
    const unconfirmed = (v.productConfirmed === false)
        ? `<div class="awareness-unconfirmed">${t.awareness_module_unconfirmed || ''}</div>`
        : '';

    return `
    <div class="awareness-vendor-card">
        <div class="awareness-vendor-card__header">
            <div class="awareness-vendor-card__name-row">
                <span class="awareness-vendor-card__name">${v.displayName}</span>
                ${sourceBadge}
                <span class="awareness-level-badge ${lvlClass}">${lvlLabel}</span>
            </div>
            <div class="awareness-vendor-card__score-row">
                <div class="awareness-score-bar-wrap">
                    <div class="awareness-score-bar" style="width:${pct}%; background:${color};"></div>
                </div>
                <span class="awareness-score-pct" style="color:${color};">${pct}%</span>
            </div>
        </div>
        <div class="awareness-vendor-card__body">
            ${unconfirmed}
            <div class="awareness-evidence-label">${t.awareness_evidence_label || 'Evidence'}</div>
            <div class="awareness-evidence-pills">
                ${v.evidence.map(e => `
                <span class="awareness-evidence-pill" title="${e.value} (${Math.round(e.weight * 100)}%)">
                    <span class="awareness-evidence-pill__signal">${signalLabel(e.signal)}</span>
                    <span class="awareness-evidence-pill__value">${e.value}</span>
                </span>`).join('')}
            </div>
            ${v.notes ? `
            <div class="awareness-vendor-notes">
                <span class="awareness-vendor-notes__label">${t.awareness_vendor_notes || 'Notes'}: </span>
                <span class="awareness-vendor-notes__text">${v.notes}</span>
            </div>` : ''}
        </div>
    </div>`;
}

// ---------------------------------------------------------------------------
// renderAwarenessVendors — Awareness / Phishing Simulation Detector panel
// ---------------------------------------------------------------------------
export function renderAwarenessVendors(result, lang, t) {
    const body = document.getElementById('awareness-body');
    if (!body) return;

    // Update header badge
    const badge = document.getElementById('awareness-badge');
    if (badge) {
        if (!result) {
            badge.textContent = '...';
            badge.style.cssText = '';
        } else if (result.detectedVendors && result.detectedVendors.length > 0) {
            const count = result.detectedVendors.length;
            badge.textContent = `${count} ${count === 1 ? (lang === 'es' ? 'detectado' : 'detected') : (lang === 'es' ? 'detectados' : 'detected')}`;
            badge.style.background = 'rgba(245,158,11,0.15)';
            badge.style.color = 'var(--accent-amber)';
            badge.style.border = '1px solid rgba(245,158,11,0.3)';
        } else {
            badge.textContent = lang === 'es' ? 'Sin evidencia DNS' : 'No DNS evidence';
            badge.style.background = 'rgba(100,116,139,0.1)';
            badge.style.color = 'var(--text-muted)';
            badge.style.border = '1px solid rgba(100,116,139,0.15)';
        }
    }

    if (!result) {
        body.innerHTML = html`<p class="no-data">${t.awareness_scanning || '...'}</p>`;
        return;
    }

    let out = '';

    // --- Vendors detectados ---
    if (result.detectedVendors && result.detectedVendors.length > 0) {
        out += '<div class="awareness-vendors-list">';
        for (const v of result.detectedVendors) {
            out += buildAwarenessCard(v, t);
        }
        out += '</div>';
    } else {
        out += html`<div class="awareness-empty">
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="1.5" stroke-linecap="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
            <p class="no-data" style="margin-top:10px;">${t.awareness_no_vendors}</p>
        </div>`;
    }

    // --- SPF PermError warning ---
    if (result.spfPermError) {
        out += html`<div class="awareness-alert awareness-alert--warning" style="margin-top:14px;">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            <span>${t.awareness_spf_perm_error}</span>
        </div>`;
    }

    // --- Blind spot: Microsoft ---
    out += html`<div class="awareness-alert awareness-alert--blind" style="margin-top:14px;">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
        <span><strong>${t.awareness_blind_spot}:</strong> ${t.awareness_blind_spot_ms}</span>
    </div>`;

    // --- Notes generales ---
    if (result.notes && result.notes.length > 0) {
        out += html`<div class="awareness-notes-section" style="margin-top:14px;">
            <div class="awareness-evidence-label" style="margin-bottom:6px;">${t.awareness_notes_title || 'Notes'}</div>
            <ul class="awareness-notes-list">
                ${result.notes.filter(n => !n.includes('Microsoft Attack Simulation')).map(n => `<li>${n}</li>`).join('')}
            </ul>
        </div>`;
    }

    body.innerHTML = raw(out);
}

// Analiza las cabeceras pegadas (herramienta estática del panel de Awareness) y
// renderiza los vendors detectados en #awareness-header-results. El listener se
// vincula una sola vez desde app.js.

export function analyzeHeaders() {
    const lang = getLanguage();
    const t = translations[lang];
    const input = document.getElementById('awareness-header-input');
    const out = document.getElementById('awareness-header-results');
    if (!input || !out) return;
    const res = detectFromHeaders(input.value);
    if (res.error || !res.detectedVendors.length) {
        const msg = res.error === 'empty' ? t.awareness_header_empty : t.awareness_header_none;
        out.innerHTML = html`<p class="no-data no-data--sm">${msg || ''}</p>`;
        return;
    }
    out.innerHTML = html`<div class="awareness-vendors-list awareness-vendors-list--spaced">${res.detectedVendors.map(v => raw(buildAwarenessCard(v, t)))}</div>`;
}
