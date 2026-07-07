import { state } from './state.js';
import { identifySPFService, identifyDMARCReporter } from './analyzer.js';
import { getLanguage } from './lang.js';
import { translations } from './i18n.js';
import { escapeHtml } from './parsers.js';
import {
    getCategoryLabel,
    formatProviderSource,
    displayProvider,
    resolveFindingText,
    displayDmarcPolicy,
    serviceDescription,
    rblListedCount,
    spfQualifierResult,
    rblCheckStatus
} from './viewmodel.js';

// Árbol de lookups SPF en tema claro (para el informe exportado, no la UI oscura).
function renderSpfTreeLight(tree) {
    if (!tree) return '';
    const err = tree.error ? ` <span style="color:#dc2626;">[${escapeHtml(tree.error)}]</span>` : '';
    const kids = (tree.children && tree.children.length)
        ? `<ul style="margin:2px 0 2px 0; padding-left:18px;">` + tree.children.map(c => c.tree
            ? `<li><span style="color:#4f46e5; font-weight:600;">${escapeHtml(c.type)}</span>: ${renderSpfTreeLight(c.tree)}</li>`
            : `<li><span style="color:#4f46e5; font-weight:600;">${escapeHtml(c.type)}</span>: ${escapeHtml(c.target || '')}</li>`).join('') + `</ul>`
        : '';
    return `<ul style="list-style:none; margin:0; padding-left:0; font-family:monospace; font-size:12px; color:#334155;">`
        + `<li><strong>${escapeHtml(tree.domain)}</strong> <span style="color:#64748b;">(${tree.lookups} lookups)</span>${err}${kids}</li></ul>`;
}

export function generateReportHTML() {
    if (!state.currentResult || !state.currentDomain) return '';
    const { currentResult, currentDomain } = state;
    const lang = getLanguage();
    const t = translations[lang];
    // Fecha del escaneo (no la de exportación): un informe generado más tarde debe
    // reflejar cuándo se hizo realmente el análisis.
    const d = (currentResult.scannedAt ? new Date(currentResult.scannedAt) : new Date())
        .toLocaleDateString(lang === 'es' ? 'es-ES' : 'en-US');
    
    const layerEvidence = (entry) => {
        const ev = Array.isArray(entry.evidence) ? entry.evidence : [];
        if (!ev.length) return escapeHtml(entry.source || '');
        return ev.map(e => `${escapeHtml(t[`seg_signal_${e.signal}`] || e.signal)}: ${escapeHtml(e.value)}`).join(' · ');
    };
    const layerLevel = (entry) => {
        const lvl = t[`awareness_level_${entry.level}`] || entry.level || '';
        const pct = typeof entry.score === 'number' ? ` ${Math.round(entry.score * 100)}%` : '';
        return lvl ? ` <span style="font-size:11px;color:#6366f1;font-weight:600;">(${t.confidence_label}: ${escapeHtml(lvl)}${escapeHtml(pct)})</span>` : '';
    };
    const layerUnconfirmed = (entry) =>
        entry.unconfirmed
            ? `<br><small style="color: #d97706; font-style: italic;">⚠ ${escapeHtml(t.seg_unconfirmed_mx)}</small>`
            : '';
    const layerItem = (entry, label) =>
        `<li style="margin-bottom: 10px;"><strong>${label}:</strong> <span style="color: #4f46e5; font-weight: bold;">${escapeHtml(entry.name)}</span>${layerLevel(entry)} <br><small style="color: #64748b;">${t.evidence}: ${layerEvidence(entry)}</small>${layerUnconfirmed(entry)}</li>`;

    let segHtml = '';
    if (currentResult.segList.length > 0 || currentResult.icesList.length > 0) {
        segHtml = `<h2 style="color: #1e3a8a; margin-top: 25px; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; font-family: sans-serif;">🛡️ ${t.panel_security_title}</h2><ul style="background-color: #f8fafc; border: 1px solid #e2e8f0; padding: 15px 15px 15px 35px; border-radius: 8px; font-family: sans-serif; font-size: 13px;">`;
        for (const seg of currentResult.segList) segHtml += layerItem(seg, t.report_seg_label);
        for (const ices of currentResult.icesList) segHtml += layerItem(ices, t.ices_detected);
        segHtml += `</ul>`;
    } else {
        segHtml = `<h2 style="color: #1e3a8a; margin-top: 25px; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; font-family: sans-serif;">🛡️ ${t.panel_security_title}</h2><p style="color: #64748b; font-style: italic; font-family: sans-serif; font-size: 13px;">${t.no_seg_ices_detected}. ${t.no_seg_ices_detail}</p><p style="color: #94a3b8; font-style: italic; font-family: sans-serif; font-size: 12px;">${t.ices_api_blindspot}</p>`;
    }

    let servicesHtml = '';
    if (currentResult.spfServices.length > 0) {
        servicesHtml = `<h2 style="color: #1e3a8a; margin-top: 25px; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; font-family: sans-serif;">${t.report_services_title}</h2><ul style="font-family: sans-serif; font-size: 13px; line-height: 1.5; padding-left: 20px;">`;
        for (const svc of currentResult.spfServices) {
            const desc = serviceDescription(t, svc);
            const localizedCatLabel = getCategoryLabel(svc, lang);
            servicesHtml += `<li style="margin-bottom: 12px;"><strong>${escapeHtml(svc.name)}</strong> - <span style="color: #0284c7; font-weight: 600;">${escapeHtml(localizedCatLabel)}</span><br><small style="color: #475569;">${desc} (${t.report_spf_rule}: <code>${escapeHtml(svc.raw)}</code>)</small></li>`;
        }
        servicesHtml += `</ul>`;
    }

    const levelColors = {
        alta: '#10b981',
        media: '#f59e0b',
        baja: '#f43f5e'
    };

    let awarenessHtml = '';
    let awarenessSummaryLine = '';
    if (currentResult.awarenessResult) {
        const ar = currentResult.awarenessResult;
        const panelTitle = t.panel_awareness_title || 'Security Awareness / Phishing Simulation Detector';
        
        let vendorsHtml = '';
        if (ar.detectedVendors && ar.detectedVendors.length > 0) {
            vendorsHtml = ar.detectedVendors.map(v => {
                const lvlLabel = t[`awareness_level_${v.level}`] || v.level;
                const pct = Math.round(v.score * 100);
                const color = levelColors[v.level] || '#f43f5e';
                
                const evidenceHtml = v.evidence.map(e => {
                    const signal = t[`awareness_signal_${e.signal}`] || e.signal;
                    return `<span style="display: inline-block; background-color: #f1f5f9; border: 1px solid #e2e8f0; border-radius: 4px; padding: 3px 8px; margin: 3px; font-size: 11px; color: #475569; font-family: sans-serif;"><strong>${escapeHtml(signal)}:</strong> ${escapeHtml(e.value)}</span>`;
                }).join('');
                
                const notesHtml = v.notes ? `
                    <div style="margin-top: 8px; font-size: 12px; color: #475569; border-top: 1px dashed #e2e8f0; padding-top: 6px; font-family: sans-serif;">
                        <strong>${t.awareness_vendor_notes || 'Notes'}:</strong> ${escapeHtml(v.notes)}
                    </div>
                ` : '';

                return `
                    <div style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 15px; margin-bottom: 15px; text-align: left;">
                        <table border="0" cellpadding="0" cellspacing="0" style="width: 100%; margin-bottom: 8px;">
                            <tr>
                                <td style="font-weight: bold; color: #1e293b; font-size: 14px; font-family: sans-serif; text-align: left;">${escapeHtml(v.displayName)}</td>
                                <td style="text-align: right; width: 150px;">
                                    <span style="background-color: ${color}; color: #ffffff; font-size: 11px; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-family: sans-serif; text-transform: uppercase;">${escapeHtml(lvlLabel)} (${pct}%)</span>
                                </td>
                            </tr>
                        </table>
                        <div style="background-color: #e2e8f0; height: 6px; border-radius: 3px; overflow: hidden; margin-bottom: 10px;">
                            <table border="0" cellpadding="0" cellspacing="0" style="width: 100%; height: 100%;">
                                <tr>
                                    <td style="background-color: ${color}; width: ${pct}%; height: 100%;"></td>
                                    <td style="width: ${100 - pct}%; height: 100%;"></td>
                                </tr>
                            </table>
                        </div>
                        <div style="font-family: sans-serif; font-size: 12px; font-weight: bold; color: #64748b; margin-bottom: 4px; text-align: left;">${t.awareness_evidence_label || 'Evidence'}:</div>
                        <div style="margin-left: -3px; margin-right: -3px; text-align: left;">
                            ${evidenceHtml}
                        </div>
                        ${notesHtml}
                    </div>
                `;
            }).join('');
        } else {
            vendorsHtml = `<p style="color: #64748b; font-style: italic; font-family: sans-serif; font-size: 13px; text-align: left;">${t.awareness_no_vendors}</p>`;
        }
        
        let warningsHtml = '';
        if (ar.spfPermError) {
            warningsHtml += `
                <div style="background-color: #fffbeb; border: 1px solid #fde68a; border-radius: 6px; padding: 10px; color: #b45309; font-size: 12px; font-family: sans-serif; margin-bottom: 10px; text-align: left; line-height: 1.4;">
                    <strong>⚠ SPF PermError:</strong> ${t.awareness_spf_perm_error || 'SPF chain exceeds 10 lookups.'}
                </div>
            `;
        }
        
        warningsHtml += `
            <div style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 10px; color: #64748b; font-size: 12px; font-family: sans-serif; margin-bottom: 10px; text-align: left; line-height: 1.4;">
                <strong>${t.awareness_blind_spot || 'Blind spot'}:</strong> ${t.awareness_blind_spot_ms}
            </div>
        `;
        
        let generalNotesHtml = '';
        if (ar.notes && ar.notes.length > 0) {
            const filteredNotes = ar.notes.filter(n => !n.includes('Microsoft Attack Simulation'));
            if (filteredNotes.length > 0) {
                generalNotesHtml = `
                    <div style="margin-top: 15px; text-align: left;">
                        <div style="font-family: sans-serif; font-size: 12.5px; font-weight: bold; color: #475569; margin-bottom: 6px; text-align: left;">${t.awareness_notes_title || 'Notes'}:</div>
                        <ul style="padding-left: 20px; font-family: sans-serif; font-size: 12px; color: #475569; line-height: 1.5; margin: 0; text-align: left;">
                            ${filteredNotes.map(n => `<li>${escapeHtml(n)}</li>`).join('')}
                        </ul>
                    </div>
                `;
            }
        }
        
        awarenessHtml = `
            <h2 style="color: #1e3a8a; margin-top: 25px; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; font-family: sans-serif;">👥 ${panelTitle}</h2>
            <div style="margin-top: 15px;">
                ${vendorsHtml}
                ${warningsHtml}
                ${generalNotesHtml}
            </div>
        `;

        const count = ar.detectedVendors ? ar.detectedVendors.length : 0;
        const valText = count > 0
            ? `${count} ${count === 1 ? t.report_detected_one : t.detected_plural} (${escapeHtml(ar.detectedVendors.map(v => v.displayName).join(', '))})`
            : t.report_none_detected_dns;
        awarenessSummaryLine = `<li><strong>${t.report_awareness_platforms}:</strong> ${valText}</li>`;
    }

    const providerDisplay = displayProvider(currentResult, t);
    const dmarcPolicyText = displayDmarcPolicy(t, currentResult.dmarcPolicy);

    const mainTitle = t.report_main_title;
    const dateLabel = t.report_date_label;
    const execSummaryLabel = t.report_exec_summary;
    const authorizedServicesLabel = t.report_authorized_services;
    const priorityLabel = t.report_priority;
    const rawRecordLabel = t.report_raw_record;

    // RBL and listings counts
    const rblListingsCount = rblListedCount(currentResult.rblResults);
    const rblSummaryLabel = t.report_rbl_title;
    const rblStatusVal = rblListingsCount > 0
        ? t.report_rbl_listed.replace('{n}', rblListingsCount)
        : t.report_rbl_clean;

    // Findings and score card
    let findingsListHtml = '';
    if (currentResult.scoreCard && currentResult.scoreCard.findings) {
        findingsListHtml = currentResult.scoreCard.findings.map(f => {
            let bulletChar = 'ℹ';
            let bulletColor = '#3b82f6';
            if (f.status === 'success') {
                bulletChar = '✔';
                bulletColor = '#10b981';
            } else if (f.status === 'warning') {
                bulletChar = '⚠';
                bulletColor = '#f59e0b';
            } else if (f.status === 'error') {
                bulletChar = '✖';
                bulletColor = '#ef4444';
            }
            
            const text = resolveFindingText(t, f);

            return `
                <div style="margin-bottom: 6px; font-size: 13px; font-family: sans-serif; color: #334155; line-height: 1.4;">
                    <span style="color: ${bulletColor}; font-weight: bold; margin-right: 8px; font-size: 14px;">${bulletChar}</span>
                    ${escapeHtml(text)}
                </div>
            `;
        }).join('');
    }

    let gradeBg = '#059669';
    const grade = currentResult.scoreCard ? currentResult.scoreCard.grade : 'F';
    const score = currentResult.scoreCard ? currentResult.scoreCard.score : 0;
    const cardClass = currentResult.scoreCard ? currentResult.scoreCard.cardClass : 'danger';
    
    if (cardClass === 'warning') {
        gradeBg = '#d97706';
    } else if (cardClass === 'danger') {
        gradeBg = '#dc2626';
    } else {
        gradeBg = '#059669';
    }

    // Dynamic RBL checks html
    let rblHtml = '';
    if (currentResult.rblResults && currentResult.rblResults.length > 0) {
        rblHtml = `
            <h2 style="color: #1e3a8a; margin-top: 25px; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; font-family: sans-serif;">🛡️ ${t.panel_reputation_title}</h2>
            <div style="margin-top: 15px;">
                ${currentResult.rblResults.map(mxRes => {
                    const checkLines = mxRes.checks ? mxRes.checks.map(check => {
                        const status = rblCheckStatus(check);
                        let statusBadge;
                        if (status === 'listed') {
                            statusBadge = `<span style="background-color: #fee2e2; color: #b91c1c; font-size: 11px; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-family: sans-serif;">${t.rbl_badge_listed}</span>`;
                        } else if (status === 'error') {
                            statusBadge = `<span style="background-color: #fef3c7; color: #b45309; font-size: 11px; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-family: sans-serif;">${t.rbl_badge_inconclusive}</span>`;
                        } else {
                            statusBadge = `<span style="background-color: #d1fae5; color: #065f46; font-size: 11px; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-family: sans-serif;">${t.rbl_badge_clean}</span>`;
                        }
                        return `
                            <tr style="border-bottom: 1px solid #f1f5f9;">
                                <td style="padding: 8px; color: #475569; font-family: sans-serif; font-size: 13px; text-align: left;">${escapeHtml(check.rbl)}</td>
                                <td style="padding: 8px; text-align: right; font-family: sans-serif;">${statusBadge}</td>
                            </tr>
                        `;
                    }).join('') : '';
                    return `
                        <div style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 15px; margin-bottom: 15px;">
                            <div style="font-weight: bold; color: #1e293b; font-size: 14px; font-family: sans-serif; margin-bottom: 8px; text-align: left;">
                                MX: <span style="color: #6366f1;">${escapeHtml(mxRes.host)}</span> ${mxRes.ip ? `(${escapeHtml(mxRes.ip)})` : ''}
                            </div>
                            <table border="0" cellpadding="0" cellspacing="0" style="width: 100%; border-collapse: collapse;">
                                ${checkLines}
                            </table>
                        </div>
                    `;
                }).join('')}
            </div>
        `;
    }

    // Advanced DNS HTML
    let advDnsHtml = `<h2 style="color: #1e3a8a; margin-top: 25px; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; font-family: sans-serif;">🌐 6. ${t.panel_advanced_dns_title}</h2>`;
    
    // MTA-STS
    advDnsHtml += `<div style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 15px; margin-top: 15px; text-align: left;">`;
    const mtaPolicyValid = currentResult.mtaSts?.policy?.valid;
    const mtaStsStatusColor = mtaPolicyValid ? '#059669' : (currentResult.mtaSts ? '#dc2626' : '#64748b');
    const mtaStsStatusLabel = mtaPolicyValid
        ? (t.adv_mta_sts_enforced || 'Enforce active')
        : (currentResult.mtaSts ? (t.adv_mta_sts_policy_invalid || 'Invalid HTTPS policy') : (t.adv_mta_sts_not_configured || 'Not configured'));
    advDnsHtml += `<h4 style="margin-top: 0; margin-bottom: 10px; font-family: sans-serif; color: #1e293b;">${t.adv_mta_sts_title || 'MTA-STS'} - <span style="color: ${mtaStsStatusColor}; font-size: 13px;">${mtaStsStatusLabel}</span></h4>`;
    if (currentResult.mtaSts) {
        const policy = currentResult.mtaSts.policy || {};
        advDnsHtml += `<p style="font-family: sans-serif; font-size: 13px; margin: 0 0 5px 0;"><strong>${t.adv_mta_sts_id || 'ID'}:</strong> ${escapeHtml(currentResult.mtaSts.id || '—')}</p>`;
        advDnsHtml += `<div style="background-color: #f1f5f9; border-radius: 4px; padding: 10px; font-family: monospace; font-size: 12px; border: 1px solid #e2e8f0; word-break: break-all; margin-bottom: 8px;">${escapeHtml(currentResult.mtaSts.record)}</div>`;
        if (policy.url) {
            advDnsHtml += `<p style="font-family: sans-serif; font-size: 13px; margin: 0 0 5px 0;"><strong>${t.adv_mta_sts_policy_url || 'Policy URL'}:</strong> ${escapeHtml(policy.url)}</p>`;
        }
        if (policy.httpStatus != null) {
            advDnsHtml += `<p style="font-family: sans-serif; font-size: 13px; margin: 0 0 5px 0;"><strong>${t.adv_mta_sts_policy_http || 'HTTP'}:</strong> ${escapeHtml(String(policy.httpStatus))}</p>`;
        }
        if (policy.mode) {
            advDnsHtml += `<p style="font-family: sans-serif; font-size: 13px; margin: 0 0 5px 0;"><strong>${t.adv_mta_sts_policy_mode || 'Mode'}:</strong> ${escapeHtml(policy.mode)}</p>`;
        }
        if (policy.error) {
            advDnsHtml += `<p style="font-family: sans-serif; font-size: 13px; margin: 0; color: #dc2626;"><strong>${t.adv_mta_sts_policy_error || 'Fetch error'}:</strong> ${escapeHtml(policy.error)}</p>`;
        }
    } else {
        advDnsHtml += `<p style="font-family: sans-serif; font-size: 13px; color: #64748b; margin: 0;">${t.adv_mta_sts_desc || 'Sin política estricta de transporte.'}</p>`;
    }
    advDnsHtml += `</div>`;

    // TLS-RPT
    advDnsHtml += `<div style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 15px; margin-top: 15px; text-align: left;">`;
    advDnsHtml += `<h4 style="margin-top: 0; margin-bottom: 10px; font-family: sans-serif; color: #1e293b;">${t.adv_tls_rpt_title || 'TLS-RPT'} - <span style="color: ${currentResult.tlsRpt ? '#059669' : '#64748b'}; font-size: 13px;">${currentResult.tlsRpt ? (t.adv_tls_rpt_configured || 'Configurado') : (t.adv_tls_rpt_not_configured || 'No configurado')}</span></h4>`;
    if (currentResult.tlsRpt) {
        advDnsHtml += `<div style="background-color: #f1f5f9; border-radius: 4px; padding: 10px; font-family: monospace; font-size: 12px; border: 1px solid #e2e8f0; word-break: break-all; margin-bottom: 10px;">${escapeHtml(currentResult.tlsRpt.record)}</div>`;
        if (currentResult.tlsrptReporters && currentResult.tlsrptReporters.length > 0) {
            currentResult.tlsrptReporters.forEach(r => {
                advDnsHtml += `<p style="font-family: sans-serif; font-size: 13px; margin: 0 0 5px 0;"><strong>${t.adv_tls_rpt_dest || 'Destino'}:</strong> ${escapeHtml(r.uri)}${r.reporter ? ` (${t.adv_tls_rpt_reporter || 'Reporter'}: ${escapeHtml(r.reporter)})` : ''}</p>`;
            });
        }
    } else {
        advDnsHtml += `<p style="font-family: sans-serif; font-size: 13px; color: #64748b; margin: 0;">${t.adv_tls_rpt_desc || 'No hay reportes de TLS.'}</p>`;
    }
    advDnsHtml += `</div>`;

    // NS Provider
    advDnsHtml += `<div style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 15px; margin-top: 15px; text-align: left;">`;
    advDnsHtml += `<h4 style="margin-top: 0; margin-bottom: 10px; font-family: sans-serif; color: #1e293b;">${t.adv_ns_title || 'Nameservers (NS)'}</h4>`;
    if (currentResult.nsProvider) {
        advDnsHtml += `<p style="font-family: sans-serif; font-size: 13px; margin: 0 0 5px 0;"><strong>${t.report_provider_label}:</strong> ${escapeHtml(currentResult.nsProvider.name)}</p>`;
        if (currentResult.nsProvider.hint) {
            advDnsHtml += `<p style="font-family: sans-serif; font-size: 13px; margin: 0 0 5px 0; color: #4f46e5;"><strong>${t.adv_ns_hint || 'Hint'}:</strong> ${escapeHtml(currentResult.nsProvider.hint)}</p>`;
        }
        if (currentResult.nsRecords && currentResult.nsRecords.length > 0) {
            advDnsHtml += `<p style="font-family: sans-serif; font-size: 13px; margin: 0 0 5px 0;"><strong>${t.adv_ns_servers || 'Servidores'}:</strong> <span style="font-family: monospace;">${escapeHtml(currentResult.nsRecords.join(', '))}</span></p>`;
        }
    } else if (currentResult.nsRecords && currentResult.nsRecords.length > 0) {
        advDnsHtml += `<p style="font-family: sans-serif; font-size: 13px; margin: 0;"><strong>${t.adv_ns_servers || 'Servidores'}:</strong> <span style="font-family: monospace;">${escapeHtml(currentResult.nsRecords.join(', '))}</span></p>`;
    } else {
        advDnsHtml += `<p style="font-family: sans-serif; font-size: 13px; color: #64748b; margin: 0;">—</p>`;
    }
    advDnsHtml += `</div>`;

    // TXT Verifications
    advDnsHtml += `<div style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 15px; margin-top: 15px; text-align: left;">`;
    advDnsHtml += `<h4 style="margin-top: 0; margin-bottom: 10px; font-family: sans-serif; color: #1e293b;">${t.adv_txt_title || 'Verificaciones TXT'}</h4>`;
    if (currentResult.txtVerifications && currentResult.txtVerifications.length > 0) {
        advDnsHtml += `<table border="1" cellpadding="8" cellspacing="0" style="width: 100%; border-collapse: collapse; border: 1px solid #e2e8f0; font-family: sans-serif; font-size: 13px; text-align: left;">
            <tr style="background-color: #f1f5f9;">
                <th style="padding: 8px; border: 1px solid #e2e8f0;">${t.report_col_name}</th>
                <th style="padding: 8px; border: 1px solid #e2e8f0;">${t.report_col_category}</th>
                <th style="padding: 8px; border: 1px solid #e2e8f0;">${t.report_col_record}</th>
            </tr>`;
        for (const v of currentResult.txtVerifications) {
            advDnsHtml += `<tr>
                <td style="padding: 8px; border: 1px solid #e2e8f0; font-weight: bold;">${escapeHtml(v.name)}</td>
                <td style="padding: 8px; border: 1px solid #e2e8f0; color: ${['seg', 'ices'].includes(v.category) ? '#8b5cf6' : '#64748b'}; text-transform: uppercase; font-size: 11px;">${escapeHtml(v.category)}</td>
                <td style="padding: 8px; border: 1px solid #e2e8f0; font-family: monospace; word-break: break-all;">${escapeHtml(v.record)}</td>
            </tr>`;
        }
        advDnsHtml += `</table>`;
    } else {
        advDnsHtml += `<p style="font-family: sans-serif; font-size: 13px; color: #64748b; margin: 0;">${t.adv_txt_none || 'No hay verificaciones'}</p>`;
    }
    advDnsHtml += `</div>`;

    const advBox = (title, statusLabel, statusColor, bodyHtml) => {
        const statusSpan = statusLabel ? ` - <span style="color: ${statusColor}; font-size: 13px;">${statusLabel}</span>` : '';
        return `<div style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 15px; margin-top: 15px; text-align: left;">`
            + `<h4 style="margin-top: 0; margin-bottom: 10px; font-family: sans-serif; color: #1e293b;">${title}${statusSpan}</h4>`
            + bodyHtml + `</div>`;
    };
    const advText = (txt, color = '#475569') => `<p style="font-family: sans-serif; font-size: 13px; color: ${color}; margin: 0 0 5px 0;">${txt}</p>`;

    // DNSSEC
    const dnssec = currentResult.dnssec;
    if (dnssec) {
        const signed = !!dnssec.signed;
        advDnsHtml += advBox(
            t.adv_dnssec_title,
            signed ? t.adv_dnssec_signed : t.adv_dnssec_unsigned,
            signed ? '#059669' : '#64748b',
            signed
                ? advText(t.adv_dnssec_signed_desc) + (dnssec.ad ? advText(t.adv_dnssec_validated, '#059669') : '')
                : advText(t.adv_dnssec_desc, '#64748b')
        );
    }

    // DANE / TLSA
    const dane = currentResult.daneRecords || {};
    const daneHosts = Object.keys(dane).filter(h => dane[h] && dane[h].length > 0);
    advDnsHtml += advBox(
        t.adv_dane_title,
        daneHosts.length ? t.adv_dane_configured : t.adv_dane_not_configured,
        daneHosts.length ? '#059669' : '#64748b',
        daneHosts.length
            ? daneHosts.map(h => advText(`<strong>${escapeHtml(h)}</strong>: ${dane[h].length} TLSA`)).join('')
            : advText(t.adv_dane_none, '#64748b')
    );

    // SRV
    const srv = currentResult.srvRecords || {};
    const srvKeys = Object.keys(srv).filter(k => srv[k] && srv[k].length > 0);
    advDnsHtml += advBox(
        t.adv_srv_title,
        null,
        null,
        srvKeys.length
            ? srvKeys.map(k => srv[k].map(r => advText(`<strong>${escapeHtml(k)}</strong>: ${escapeHtml(r.target || '')}:${escapeHtml(String(r.port || ''))}`)).join('')).join('')
            : advText(t.adv_srv_none, '#64748b')
    );

    return `
        <div style="font-family: Arial, sans-serif; color: #1e293b; max-width: 800px; margin: 0 auto; line-height: 1.5; text-align: left;">
            <p style="font-size: 22px; font-weight: bold; margin: 0 0 15px 0;">${currentDomain}</p>
            <!-- Header Banner -->
            <div style="background-color: #1e1b4b; background: linear-gradient(135deg, #1e1b4b 0%, #312e81 100%); padding: 30px; border-radius: 12px; color: #ffffff; margin-bottom: 30px; text-align: left;">
                <h1 style="margin: 0; font-size: 26px; font-weight: 700; font-family: sans-serif; letter-spacing: -0.5px;">${mainTitle}</h1>
                <p style="margin: 5px 0 0 0; color: #c7d2fe; font-size: 14px; font-family: sans-serif;">${dateLabel}: ${d} | ${t.report_domain_label}: <strong style="color: #ffffff;">${escapeHtml(currentDomain)}</strong></p>
            </div>
            
            <!-- Security Score Card Table -->
            <table border="0" cellpadding="0" cellspacing="0" style="width: 100%; background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 12px; margin-bottom: 30px; padding: 20px; text-align: left;">
                <tr>
                    <td style="width: 100px; vertical-align: middle; text-align: center; padding-right: 20px;">
                        <div style="background-color: ${gradeBg}; width: 80px; height: 80px; border-radius: 40px; display: inline-block; text-align: center; color: #ffffff; font-family: sans-serif;">
                            <div style="font-size: 28px; font-weight: 800; margin-top: 14px; line-height: 1;">${grade}</div>
                            <div style="font-size: 11px; font-weight: 600; opacity: 0.95; margin-top: 2px;">${score}/100</div>
                        </div>
                    </td>
                    <td style="vertical-align: top; padding-left: 10px; text-align: left;">
                        <h3 style="margin: 0 0 6px 0; color: #1e293b; font-size: 17px; font-weight: 700; font-family: sans-serif;">${t.score_title_panel}</h3>
                        <p style="margin: 0 0 12px 0; color: #64748b; font-size: 13px; font-family: sans-serif;">${t.score_desc_panel}</p>
                        ${findingsListHtml}
                    </td>
                </tr>
            </table>

            <!-- Executive Summary -->
            <h2 style="color: #1e3a8a; margin-top: 25px; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; font-family: sans-serif;">📋 ${execSummaryLabel}</h2>
            <ul style="padding-left: 20px; font-family: sans-serif; font-size: 13.5px; color: #334155; line-height: 1.6; text-align: left;">
                <li><strong>${t.score_title_panel}:</strong> <span style="background-color: ${gradeBg}; color: #ffffff; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 13px; display: inline-block; text-align: center;">${grade}</span> (${score}/100)</li>
                <li><strong>${t.summary_provider}:</strong> ${escapeHtml(providerDisplay)} <br><small style="color: #64748b;">(${escapeHtml(formatProviderSource(currentResult.providerSource, t))})</small></li>
                <li><strong>${t.summary_dmarc}:</strong> ${dmarcPolicyText}</li>
                <li><strong>${authorizedServicesLabel}:</strong> ${currentResult.spfServices.length} ${currentResult.spfServices.length === 1 ? (t.detected_singular || t.detected_plural) : t.detected_plural}</li>
                ${awarenessSummaryLine}
                <li><strong>${rblSummaryLabel}:</strong> ${rblStatusVal}</li>
            </ul>

            ${segHtml}
            ${servicesHtml}
            ${awarenessHtml}

            <!-- MX Records Section -->
            <h2 style="color: #1e3a8a; margin-top: 25px; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; font-family: sans-serif;">✉️ 1. ${t.panel_mx_title}</h2>
            <table border="1" cellpadding="8" cellspacing="0" style="width: 100%; border-collapse: collapse; border: 1px solid #e2e8f0; font-family: sans-serif; font-size: 13px; margin-top: 10px; text-align: left;">
                <tr style="background-color: #312e81; color: #ffffff;">
                    <th style="padding: 10px; border: 1px solid #e2e8f0; font-weight: bold; text-align: left; width: 80px;">${priorityLabel}</th>
                    <th style="padding: 10px; border: 1px solid #e2e8f0; font-weight: bold; text-align: left;">Host</th>
                </tr>
                ${currentResult.mxRecords.length > 0 ? currentResult.mxRecords.map(mx => `
                    <tr>
                        <td style="padding: 8px; border: 1px solid #e2e8f0; text-align: left;">${escapeHtml(String(mx.priority))}</td>
                        <td style="padding: 8px; border: 1px solid #e2e8f0; text-align: left;">${escapeHtml(mx.host)}</td>
                    </tr>
                `).join('') : `<tr><td colspan="2" style="padding: 8px; border: 1px solid #e2e8f0; text-align: center; color: #64748b; font-style: italic;">${t.no_mx_records}</td></tr>`}
            </table>

            <!-- SPF Records Section -->
            <h2 style="color: #1e3a8a; margin-top: 25px; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; font-family: sans-serif;">⚙️ 2. ${t.panel_spf_title}</h2>
            <p style="font-family: sans-serif; font-size: 13px; color: #475569; margin-bottom: 8px; text-align: left;"><strong>${rawRecordLabel}:</strong></p>
            <div style="background-color: #f1f5f9; border: 1px solid #e2e8f0; border-radius: 6px; padding: 10px; font-family: monospace; font-size: 12.5px; color: #1e293b; margin-bottom: 15px; word-break: break-all; text-align: left;">
                ${escapeHtml(currentResult.spfRaw) || t.no_spf_record}
            </div>
            ${currentResult.spfLookups !== undefined ? `
                <p style="font-family: sans-serif; font-size: 13px; color: #475569; text-align: left;">
                    <strong>${t.report_dns_lookups}:</strong>
                    <span style="color: ${currentResult.spfLookups > 10 ? '#dc2626' : currentResult.spfLookups > 7 ? '#d97706' : '#059669'}; font-weight: bold;">${currentResult.spfLookups}/10</span>
                </p>
            ` : ''}
            ${currentResult.spfTree ? `
                <p style="font-family: sans-serif; font-size: 13px; color: #475569; font-weight: bold; margin: 10px 0 4px 0; text-align: left;">${t.panel_spf_tree_title}:</p>
                <div style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 10px; text-align: left;">${renderSpfTreeLight(currentResult.spfTree)}</div>
            ` : ''}
            
            <table border="1" cellpadding="8" cellspacing="0" style="width: 100%; border-collapse: collapse; border: 1px solid #e2e8f0; font-family: sans-serif; font-size: 13px; margin-top: 10px; text-align: left;">
                <tr style="background-color: #312e81; color: #ffffff;">
                    <th style="padding: 10px; border: 1px solid #e2e8f0; font-weight: bold; text-align: left; width: 60px;">${t.spf_header_prefix}</th>
                    <th style="padding: 10px; border: 1px solid #e2e8f0; font-weight: bold; text-align: left; width: 90px;">${t.spf_header_type}</th>
                    <th style="padding: 10px; border: 1px solid #e2e8f0; font-weight: bold; text-align: left;">${t.spf_header_value}</th>
                    <th style="padding: 10px; border: 1px solid #e2e8f0; font-weight: bold; text-align: left; width: 80px;">${t.spf_header_result || 'Resultado'}</th>
                    <th style="padding: 10px; border: 1px solid #e2e8f0; font-weight: bold; text-align: left;">${t.spf_header_service}</th>
                </tr>
                ${currentResult.spfEntries.map(e => {
                    const svc = identifySPFService(e.value);
                    let svcName = '—';
                    if (svc) {
                        const localizedCatLabel = getCategoryLabel(svc, lang);
                        svcName = `${svc.name} (${localizedCatLabel})`;
                    } else if (e.type === 'v') {
                        svcName = t.spf_version;
                    } else if (e.type === 'all') {
                        svcName = t.spf_default_policy;
                    }

                    const SPF_RESULT_COLOR = { pass: '#059669', fail: '#dc2626', softfail: '#d97706', neutral: '#475569' };
                    const spfRes = spfQualifierResult(e.qualifier);
                    let resultText = spfRes.text;
                    let resultColor = SPF_RESULT_COLOR[spfRes.kind];

                    if (e.type === 'v') { resultText = ''; }
                    if (e.type === 'all' && e.qualifier === '-') { resultText = 'Fail'; resultColor = '#dc2626'; }
                    if (e.type === 'all' && e.qualifier === '~') { resultText = 'SoftFail'; resultColor = '#d97706'; }

                    return `
                        <tr>
                            <td style="padding: 8px; border: 1px solid #e2e8f0; font-weight: bold; text-align: center;">${escapeHtml(e.qualifier || '')}</td>
                            <td style="padding: 8px; border: 1px solid #e2e8f0; font-family: monospace; text-align: left;">${escapeHtml(e.type)}</td>
                            <td style="padding: 8px; border: 1px solid #e2e8f0; font-family: monospace; word-break: break-all; text-align: left;">${escapeHtml(e.value || '—')}</td>
                            <td style="padding: 8px; border: 1px solid #e2e8f0; font-weight: bold; color: ${resultColor}; text-align: left;">${escapeHtml(resultText)}</td>
                            <td style="padding: 8px; border: 1px solid #e2e8f0; text-align: left;">${escapeHtml(svcName)}</td>
                        </tr>
                    `;
                }).join('')}
            </table>

            <!-- DMARC Records Section -->
            <h2 style="color: #1e3a8a; margin-top: 25px; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; font-family: sans-serif;">🎯 3. ${t.panel_dmarc_title}</h2>
            <p style="font-family: sans-serif; font-size: 13px; color: #475569; margin-bottom: 8px; text-align: left;"><strong>${rawRecordLabel}:</strong></p>
            <div style="background-color: #f1f5f9; border: 1px solid #e2e8f0; border-radius: 6px; padding: 10px; font-family: monospace; font-size: 12.5px; color: #1e293b; margin-bottom: 15px; word-break: break-all; text-align: left;">
                ${escapeHtml(currentResult.dmarcRaw) || t.no_dmarc_record}
            </div>

            <!-- Parsed DMARC Details Grid -->
            ${(() => {
                if (currentResult.dmarcParsed) {
                    const d = currentResult.dmarcParsed;
                    const pClassColor = d.p === 'reject' ? '#dc2626' : d.p === 'quarantine' ? '#d97706' : '#2563eb';
                    const spClassColor = d.sp === 'reject' ? '#dc2626' : d.sp === 'quarantine' ? '#d97706' : '#2563eb';
                    
                    return `
                        <div style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 15px; margin-bottom: 15px; text-align: left;">
                            <h4 style="margin-top: 0; margin-bottom: 10px; font-family: sans-serif; color: #1e293b; font-size: 14px;">${t.report_dmarc_config_analyzed}</h4>
                            <table border="0" cellpadding="6" cellspacing="0" style="width: 100%; font-family: sans-serif; font-size: 13px; text-align: left;">
                                <tr>
                                    <td style="width: 180px; font-weight: bold; color: #475569;">${t.dmarc_policy_p || 'Política (p)'}:</td>
                                    <td style="font-weight: bold; color: ${pClassColor}; text-transform: uppercase;">${d.p || 'none'}</td>
                                </tr>
                                ${d.sp ? `
                                <tr>
                                    <td style="font-weight: bold; color: #475569;">${t.dmarc_policy_sp || 'Subdominios (sp)'}:</td>
                                    <td style="font-weight: bold; color: ${spClassColor}; text-transform: uppercase;">${d.sp}</td>
                                </tr>` : ''}
                                ${d.pct ? `
                                <tr>
                                    <td style="font-weight: bold; color: #475569;">${t.dmarc_policy_pct || 'Porcentaje (pct)'}:</td>
                                    <td>${d.pct}%</td>
                                </tr>` : ''}
                                ${d.adkim ? `
                                <tr>
                                    <td style="font-weight: bold; color: #475569;">${t.dmarc_alignment_dkim || 'Alineación DKIM'}:</td>
                                    <td>${d.adkim === 's' ? t.strict_label : t.relaxed_label}</td>
                                </tr>` : ''}
                                ${d.aspf ? `
                                <tr>
                                    <td style="font-weight: bold; color: #475569;">${t.dmarc_alignment_spf || 'Alineación SPF'}:</td>
                                    <td>${d.aspf === 's' ? t.strict_label : t.relaxed_label}</td>
                                </tr>` : ''}
                            </table>
                        </div>
                    `;
                }
                return '';
            })()}
            
            <p style="font-family: sans-serif; font-size: 13.5px; color: #334155; font-weight: bold; margin-bottom: 5px; text-align: left;">${t.panel_dmarc_reporting_title}</p>
            <ul style="padding-left: 20px; font-family: sans-serif; font-size: 13px; color: #475569; line-height: 1.5; text-align: left;">
                ${currentResult.dmarcRua.length > 0 ? currentResult.dmarcRua.map(r => {
                    const reporter = identifyDMARCReporter(r);
                    const reporterSuffix = reporter ? ` <strong style="color: #4f46e5;">(${t.tool_label}: ${escapeHtml(reporter)})</strong>` : '';
                    return `<li><strong>RUA (${t.dmarc_aggregate}):</strong> <code>${escapeHtml(r)}</code>${reporterSuffix}</li>`;
                }).join('') : ''}
                ${currentResult.dmarcRuf.length > 0 ? currentResult.dmarcRuf.map(r => {
                    const reporter = identifyDMARCReporter(r);
                    const reporterSuffix = reporter ? ` <strong style="color: #4f46e5;">(${t.tool_label}: ${escapeHtml(reporter)})</strong>` : '';
                    return `<li><strong>RUF (${t.dmarc_forensic}):</strong> <code>${escapeHtml(r)}</code>${reporterSuffix}</li>`;
                }).join('') : ''}
                ${currentResult.dmarcRua.length === 0 && currentResult.dmarcRuf.length === 0 ? `<li>${t.no_dmarc_reporting}</li>` : ''}
            </ul>
            ${(currentResult.dmarcExternalAuth && currentResult.dmarcExternalAuth.length > 0) ? `
                <p style="font-family: sans-serif; font-size: 13.5px; color: #334155; font-weight: bold; margin: 12px 0 5px 0; text-align: left;">${t.report_dmarc_ext_auth_title}</p>
                <ul style="padding-left: 20px; font-family: sans-serif; font-size: 13px; color: #475569; line-height: 1.5; text-align: left;">
                    ${currentResult.dmarcExternalAuth.map(a => {
                        const label = a.authorized === true ? t.report_dmarc_ext_authorized : a.authorized === false ? t.report_dmarc_ext_unauthorized : t.report_dmarc_ext_unknown;
                        const color = a.authorized === true ? '#059669' : a.authorized === false ? '#dc2626' : '#64748b';
                        return `<li><code>${escapeHtml(a.destDomain)}</code>: <strong style="color: ${color};">${label}</strong></li>`;
                    }).join('')}
                </ul>
            ` : ''}

            <!-- DKIM Records Section -->
            <h2 style="color: #1e3a8a; margin-top: 25px; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; font-family: sans-serif;">🔑 4. ${t.panel_dkim_title}</h2>
            <div style="margin-top: 15px; text-align: left;">
                ${currentResult.dkimRecords && currentResult.dkimRecords.records && currentResult.dkimRecords.records.length > 0 ? 
                    currentResult.dkimRecords.records.map(dkim => `
                        <div style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 15px; margin-bottom: 15px; text-align: left;">
                            <div style="font-weight: bold; color: #1e293b; font-size: 13.5px; font-family: sans-serif; margin-bottom: 6px; text-align: left;">
                                Selector: <span style="color: #4f46e5;">${escapeHtml(dkim.selector)}</span>
                            </div>
                            <div style="background-color: #f1f5f9; border-radius: 4px; padding: 10px; font-family: monospace; font-size: 12px; color: #334155; word-break: break-all; border: 1px solid #e2e8f0; text-align: left;">
                                ${escapeHtml(dkim.record)}
                            </div>
                        </div>
                    `).join('') : 
                    `<p style="color: #64748b; font-style: italic; font-family: sans-serif; font-size: 13px; text-align: left;">${t.no_dkim_records}</p>`
                }
            </div>

            <!-- BIMI Section -->
            <h2 style="color: #1e3a8a; margin-top: 25px; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; font-family: sans-serif;">🖼️ 5. ${t.panel_bimi_title}</h2>
            <div style="margin-top: 15px; text-align: left;">
                ${currentResult.bimiRecord && !currentResult.bimiRecord.error && currentResult.bimiRecord.record ? `
                    <div style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 15px; text-align: left;">
                        <div style="font-weight: bold; color: #16a34a; font-size: 13.5px; font-family: sans-serif; margin-bottom: 6px; text-align: left;">
                            ${t.bimi_record_found}
                        </div>
                        <div style="background-color: #f1f5f9; border-radius: 4px; padding: 10px; font-family: monospace; font-size: 12px; color: #334155; word-break: break-all; border: 1px solid #e2e8f0; text-align: left;">
                            ${escapeHtml(currentResult.bimiRecord.record)}
                        </div>
                    </div>
                ` : `
                    <p style="color: #64748b; font-style: italic; font-family: sans-serif; font-size: 13px; text-align: left;">${t.no_bimi_record}</p>
                `}
            </div>

            <!-- Advanced DNS Section -->
            ${advDnsHtml}

            <!-- RBL Reputation Section -->
            ${rblHtml}
            
            <!-- Footer -->
            <hr style="margin-top: 40px; border: 0; border-top: 1px solid #e2e8f0;">
            <p style="font-size: 11px; color: #94a3b8; text-align: center; font-family: sans-serif; margin-top: 15px; margin-bottom: 30px;">
                ${t.footer_text}
            </p>
        </div>
    `;
}

export async function exportToGoogle() {
    if (!state.currentDomain || !state.currentResult) return;
    const htmlContent = generateReportHTML();
    const btn = document.getElementById('export-google-btn');
    const originalHTML = btn.innerHTML;
    const lang = getLanguage();
    
    const t = translations[lang];
    try {
        const blobHtml = new Blob([htmlContent], { type: 'text/html' });
        const blobText = new Blob([t.report_clipboard_msg + state.currentDomain], { type: 'text/plain' });
        const clipboardItem = new ClipboardItem({
            'text/html': blobHtml,
            'text/plain': blobText
        });
        await navigator.clipboard.write([clipboardItem]);

        btn.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg> ${t.msg_copied}`;

        setTimeout(() => { btn.innerHTML = originalHTML; }, 6000);
        window.open('https://docs.new', '_blank');
    } catch (err) {
        console.error('Error copying to clipboard', err);
        alert(t.msg_export_clipboard_fail);
        window.open('https://docs.new', '_blank');
    }
}

export function exportToFile() {
    if (!state.currentDomain || !state.currentResult) return;
    const htmlContent = generateReportHTML();
    const lang = getLanguage();
    const t = translations[lang];
    const fileTitle = `${t.report_file_title_prefix} ${state.currentDomain}`;

    const docHtml = `<html xmlns:o='urn:schemas-microsoft-com:office:office' xmlns:w='urn:schemas-microsoft-com:office:word' xmlns='http://www.w3.org/TR/REC-html40'><head><meta charset='utf-8'><title>${fileTitle}</title></head><body>${htmlContent}</body></html>`;
    const blob = new Blob(['\ufeff', docHtml], { type: 'application/msword' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;

    const downloadName = `${t.report_download_prefix}${state.currentDomain}.doc`;
    link.download = downloadName;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

export function exportToPDF() {
    if (!state.currentDomain || !state.currentResult) {
        window.print();
        return;
    }

    const lang = getLanguage();
    const t = translations[lang];
    const fileTitle = `${t.pdf_doc_title} ${state.currentDomain}`;

    // Se imprime el MISMO informe que Word/Google Docs (generateReportHTML) dentro
    // de un iframe oculto, en vez de window.print() de la vista viva. Así los tres
    // formatos comparten una única fuente de contenido y no divergen.
    const reportHtml = generateReportHTML();
    const iframe = document.createElement('iframe');
    iframe.setAttribute('aria-hidden', 'true');
    iframe.style.cssText = 'position:fixed; right:0; bottom:0; width:0; height:0; border:0;';
    document.body.appendChild(iframe);

    const cleanup = () => {
        if (iframe.parentNode) iframe.parentNode.removeChild(iframe);
    };

    const doc = iframe.contentWindow.document;
    doc.open();
    doc.write(`<!DOCTYPE html><html lang="${lang}"><head><meta charset="utf-8"><title>${fileTitle}</title>
        <style>@page { margin: 16mm; } body { margin: 0; }</style>
        </head><body>${reportHtml}</body></html>`);
    doc.close();

    const printFrame = () => {
        try {
            iframe.contentWindow.focus();
            iframe.contentWindow.print();
        } catch (err) {
            console.error('PDF print failed, falling back to window.print()', err);
            window.print();
        }
        // Retira el iframe tras dar tiempo al diálogo de impresión.
        iframe.contentWindow.addEventListener('afterprint', cleanup);
        setTimeout(cleanup, 60000);
    };

    // Espera a que el iframe cargue su contenido antes de imprimir.
    if (iframe.contentWindow.document.readyState === 'complete') {
        setTimeout(printFrame, 100);
    } else {
        iframe.addEventListener('load', () => setTimeout(printFrame, 100));
    }
}
