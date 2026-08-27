// ui/advancedDnsPanel.js
// Panel de DNS avanzado: MTA-STS (incluida la cobertura de los MX), TLS-RPT, DNSSEC,
// DANE, SRV, proveedor de DNS y tokens de verificación TXT.
import { html, raw } from '../utils.js';

export function renderAdvancedDNS(result, lang, t) {
    const body = document.getElementById('advanced-dns-body');
    if (!body) return;

    let out = '<div class="advanced-dns-grid">';

    // === MTA-STS ===
    const mtaPolicyValid = result.mtaSts?.policy?.valid;
    // Que el navegador no pueda DESCARGAR la política (CORS/red) no la vuelve
    // inválida: es un límite del análisis desde cliente. El badge debe decir
    // "no evaluable", igual que hace el scoring, y no acusar al dominio.
    const mtaUnreachable = result.mtaSts?.policy?.validationReason === 'fetch_failed';
    const mtaPolicyPartial = result.mtaSts && !mtaPolicyValid && !mtaUnreachable;
    const mtaBadgeClass = mtaPolicyValid
        ? 'badge--success'
        : (mtaPolicyPartial ? 'badge--danger' : 'badge--neutral');
    const mtaBadgeText = mtaPolicyValid
        ? t.adv_mta_sts_enforced
        : (mtaUnreachable
            ? t.adv_mta_sts_unreachable
            : (result.mtaSts ? t.adv_mta_sts_policy_invalid : t.adv_mta_sts_not_configured));

    out += '<div class="advanced-dns-section">';
    out += html`<div class="advanced-dns-section__header">
        <h4 class="advanced-dns-section__title">${t.adv_mta_sts_title}</h4>
        <span class="advanced-dns-section__badge ${mtaBadgeClass}">${mtaBadgeText}</span>
    </div>`;
    if (result.mtaSts) {
        const policy = result.mtaSts.policy || {};
        out += html`<div class="advanced-dns-section__body">
            <div class="info-block">
                <div class="info-block__label">${t.adv_mta_sts_id}</div>
                <div class="info-block__value" style="font-family:'JetBrains Mono',monospace;font-size:13px;">${result.mtaSts.id || '—'}</div>
            </div>
            <div class="panel__raw-record" style="margin-top:8px;font-size:12px;">${result.mtaSts.record}</div>`;
        if (policy.url) {
            out += html`<div class="info-block" style="margin-top:12px;">
                <div class="info-block__label">${t.adv_mta_sts_policy_url}</div>
                <div class="info-block__value" style="font-family:'JetBrains Mono',monospace;font-size:12px;word-break:break-all;">${policy.url}</div>
            </div>`;
        }
        if (policy.httpStatus != null) {
            out += html`<div class="info-block" style="margin-top:8px;">
                <div class="info-block__label">${t.adv_mta_sts_policy_http}</div>
                <div class="info-block__value" style="font-family:'JetBrains Mono',monospace;font-size:13px;">${String(policy.httpStatus)}</div>
            </div>`;
        }
        if (policy.mode) {
            out += html`<div class="info-block" style="margin-top:8px;">
                <div class="info-block__label">${t.adv_mta_sts_policy_mode}</div>
                <div class="info-block__value" style="font-family:'JetBrains Mono',monospace;font-size:13px;">${policy.mode}</div>
            </div>`;
        } else if (mtaPolicyPartial && !policy.error) {
            out += html`<div class="info-block" style="margin-top:8px;">
                <div class="info-block__label">${t.adv_mta_sts_policy_mode}</div>
                <div class="info-block__value" style="font-size:13px;color:var(--accent-rose);">—</div>
            </div>`;
        }
        if (policy.error) {
            out += html`<div class="info-block" style="margin-top:8px;">
                <div class="info-block__label">${t.adv_mta_sts_policy_error}</div>
                <div class="info-block__value" style="font-size:13px;color:var(--accent-rose);">${policy.error}</div>
            </div>`;
        }
        if (policy.body && mtaPolicyValid) {
            out += html`<div class="panel__raw-record" style="margin-top:8px;font-size:12px;white-space:pre-wrap;">${policy.body.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</div>`;
        }
        out += html`</div>`;
    } else {
        out += html`<div class="advanced-dns-section__body"><p class="no-data" style="font-size:13px;">${t.adv_mta_sts_desc}</p></div>`;
    }
    out += '</div>';
    out += '</div>';

    // === TLS-RPT ===
    out += '<div class="advanced-dns-section">';
    out += html`<div class="advanced-dns-section__header">
        <h4 class="advanced-dns-section__title">${t.adv_tls_rpt_title}</h4>
        <span class="advanced-dns-section__badge ${result.tlsRpt ? 'badge--success' : 'badge--neutral'}">${result.tlsRpt ? t.adv_tls_rpt_configured : t.adv_tls_rpt_not_configured}</span>
    </div>`;
    if (result.tlsRpt) {
        let tlsBody = html`<div class="panel__raw-record" style="font-size:12px;margin-bottom:8px;">${result.tlsRpt.record}</div>`;
        if (result.tlsrptReporters && result.tlsrptReporters.length > 0) {
            tlsBody += html`<div style="display:flex;flex-direction:column;gap:6px;">`;
            for (const r of result.tlsrptReporters) {
                tlsBody += html`<div class="reporting-item" style="padding:8px 12px;">
                    <div class="reporting-item__type">${t.adv_tls_rpt_dest}</div>
                    <div class="reporting-item__value" style="font-size:13px;">${r.uri}</div>
                    ${r.reporter ? html`<div class="reporting-item__service">${t.adv_tls_rpt_reporter}: ${r.reporter}</div>` : raw('')}
                </div>`;
            }
            tlsBody += '</div>';
        }
        out += html`<div class="advanced-dns-section__body">${raw(tlsBody)}</div>`;
    } else {
        out += html`<div class="advanced-dns-section__body"><p class="no-data" style="font-size:13px;">${t.adv_tls_rpt_desc}</p></div>`;
    }
    out += '</div>';

    // === NS Provider ===
    out += '<div class="advanced-dns-section">';
    out += html`<div class="advanced-dns-section__header">
        <h4 class="advanced-dns-section__title">${t.adv_ns_title}</h4>
    </div>`;
    if (result.nsProvider) {
        let nsBody = html`<div class="info-block">
            <div class="info-block__value">${result.nsProvider.name}</div>
        </div>`;
        if (result.nsProvider.hint) {
            nsBody += html`<div class="info-block" style="margin-top:6px;">
                <div class="info-block__label">${t.adv_ns_hint}</div>
                <div class="info-block__detail" style="color:var(--accent-violet);">${result.nsProvider.hint}</div>
            </div>`;
        }
        if (result.nsRecords && result.nsRecords.length > 0) {
            nsBody += html`<div class="info-block" style="margin-top:6px;">
                <div class="info-block__label">${t.adv_ns_servers}</div>
                <div class="info-block__detail" style="font-family:'JetBrains Mono',monospace;font-size:12px;">${result.nsRecords.join(', ')}</div>
            </div>`;
        }
        out += html`<div class="advanced-dns-section__body">${raw(nsBody)}</div>`;
    } else if (result.nsRecords && result.nsRecords.length > 0) {
        out += html`<div class="advanced-dns-section__body">
            <div class="info-block">
                <div class="info-block__label">${t.adv_ns_servers}</div>
                <div class="info-block__detail" style="font-family:'JetBrains Mono',monospace;font-size:12px;">${result.nsRecords.join(', ')}</div>
            </div>
        </div>`;
    } else {
        out += html`<div class="advanced-dns-section__body"><p class="no-data">—</p></div>`;
    }
    out += '</div>';

    // === SRV Records ===
    out += '<div class="advanced-dns-section">';
    out += html`<div class="advanced-dns-section__header">
        <h4 class="advanced-dns-section__title">${t.adv_srv_title}</h4>
    </div>`;
    if (result.srvRecords && Object.keys(result.srvRecords).length > 0) {
        let srvBody = '<div style="display:flex;flex-direction:column;gap:8px;">';
        let foundSrv = false;
        for (const [key, records] of Object.entries(result.srvRecords)) {
            if (records && records.length > 0) {
                foundSrv = true;
                srvBody += html`<div class="info-block" style="margin-top:6px;">
                    <div class="info-block__label" style="text-transform: capitalize;">${key}</div>
                    <div class="info-block__detail" style="font-family:'JetBrains Mono',monospace;font-size:12px;">
                        ${records.map((r, i) => html`${raw(i ? '<br>' : '')}${r.target}:${r.port} (prio:${r.priority}, weight:${r.weight})`)}
                    </div>
                </div>`;
            }
        }
        srvBody += '</div>';
        if (foundSrv) {
            out += html`<div class="advanced-dns-section__body">${raw(srvBody)}</div>`;
        } else {
            out += html`<div class="advanced-dns-section__body"><p class="no-data" style="font-size:13px;">${t.adv_srv_none}</p></div>`;
        }
    } else {
        out += html`<div class="advanced-dns-section__body"><p class="no-data" style="font-size:13px;">${t.adv_srv_none}</p></div>`;
    }
    out += '</div>';

    // === DANE / TLSA ===
    let hasDane = false;
    if (result.daneRecords) {
        for (const mx in result.daneRecords) {
            if (result.daneRecords[mx] && result.daneRecords[mx].length > 0) {
                hasDane = true;
                break;
            }
        }
    }
    out += '<div class="advanced-dns-section">';
    out += html`<div class="advanced-dns-section__header">
        <h4 class="advanced-dns-section__title">${t.adv_dane_title}</h4>
        <span class="advanced-dns-section__badge ${hasDane ? 'badge--success' : 'badge--neutral'}">${hasDane ? t.adv_dane_configured : t.adv_dane_not_configured}</span>
    </div>`;
    if (hasDane) {
        let daneBody = '<div style="display:flex;flex-direction:column;gap:8px;">';
        for (const mx in result.daneRecords) {
            if (result.daneRecords[mx] && result.daneRecords[mx].length > 0) {
                daneBody += html`<div class="info-block" style="margin-top:6px;">
                    <div class="info-block__label">${mx}</div>
                    <div class="panel__raw-record" style="font-size:11px;font-family:'JetBrains Mono',monospace;word-break:break-all;margin-top:4px;">
                        ${result.daneRecords[mx].map((r, i) => html`${raw(i ? '<br>' : '')}${r}`)}
                    </div>
                </div>`;
            }
        }
        daneBody += '</div>';
        out += html`<div class="advanced-dns-section__body">${raw(daneBody)}</div>`;
    } else {
        out += html`<div class="advanced-dns-section__body"><p class="no-data" style="font-size:13px;">${t.adv_dane_none}</p></div>`;
    }
    out += '</div>';

    // === DNSSEC ===
    const dnssecSigned = result.dnssec && result.dnssec.signed;
    out += '<div class="advanced-dns-section">';
    out += html`<div class="advanced-dns-section__header">
        <h4 class="advanced-dns-section__title">${t.adv_dnssec_title}</h4>
        <span class="advanced-dns-section__badge ${dnssecSigned ? 'badge--success' : 'badge--neutral'}">${dnssecSigned ? t.adv_dnssec_signed : t.adv_dnssec_unsigned}</span>
    </div>`;
    if (dnssecSigned) {
        out += html`<div class="advanced-dns-section__body">
            <div class="info-block">
                <div class="info-block__detail">${t.adv_dnssec_signed_desc}</div>
                ${result.dnssec.ad ? html`<div class="info-block__detail" style="color:var(--accent-emerald);margin-top:4px;">${t.adv_dnssec_validated}</div>` : raw('')}
            </div>
        </div>`;
    } else {
        out += html`<div class="advanced-dns-section__body"><p class="no-data" style="font-size:13px;">${t.adv_dnssec_desc}</p></div>`;
    }
    out += '</div>';

    out += '</div>'; // close advanced-dns-grid

    // === TXT Verifications ===
    out += html`<div style="border-top:1px solid var(--border);margin-top:16px;padding-top:16px;">`;
    out += html`<h4 style="font-size:14px;font-weight:600;margin-bottom:12px;color:var(--text-primary);">${t.adv_txt_title}</h4>`;

    if (result.txtVerifications && result.txtVerifications.length > 0) {
        const securityTxt = result.txtVerifications.filter(v => ['seg', 'ices'].includes(v.category));
        const otherTxt = result.txtVerifications.filter(v => !['seg', 'ices'].includes(v.category));

        if (securityTxt.length > 0) {
            out += html`<div style="margin-bottom:12px;"><span style="font-size:12px;font-weight:600;color:var(--accent-violet);text-transform:uppercase;letter-spacing:0.5px;">${t.adv_txt_security_label}</span></div>`;
            out += '<div class="txt-verifications-grid">';
            for (const v of securityTxt) {
                const catColor = v.category === 'ices' ? 'var(--accent-violet)' : 'var(--accent-purple)';
                out += html`<div class="txt-verification-item txt-verification-item--security">
                    <div class="txt-verification-item__name">${v.name}</div>
                    <div class="txt-verification-item__category" style="color:${catColor};">${v.category.toUpperCase()}</div>
                    <div class="txt-verification-item__record">${v.record}</div>
                </div>`;
            }
            out += '</div>';
        }

        if (otherTxt.length > 0) {
            out += html`<div style="margin-top:${securityTxt.length > 0 ? '16px' : '0'};margin-bottom:12px;"><span style="font-size:12px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;">${t.adv_txt_other_label}</span></div>`;
            out += '<div class="txt-verifications-grid">';
            for (const v of otherTxt) {
                out += html`<div class="txt-verification-item">
                    <div class="txt-verification-item__name">${v.name}</div>
                    <div class="txt-verification-item__category">${v.category}</div>
                    <div class="txt-verification-item__record">${v.record}</div>
                </div>`;
            }
            out += '</div>';
        }
    } else {
        out += html`<p class="no-data">${t.adv_txt_none}</p>`;
    }

    out += '</div>';

    body.innerHTML = raw(out);
}

// Construye la tarjeta de un vendor (compartida por la detección DNS y la de cabeceras).
