import { state } from './app.js';
import { identifySPFService } from './analyzer.js';
import { getLanguage } from './lang.js';
import { translations } from './i18n.js';
import { getCategoryLabel } from './ui.js';

export function generateReportHTML() {
    if (!state.currentResult || !state.currentDomain) return '';
    const { currentResult, currentDomain } = state;
    const lang = getLanguage();
    const t = translations[lang];
    const d = new Date().toLocaleDateString(lang === 'es' ? 'es-ES' : 'en-US');
    
    let segHtml = '';
    if (currentResult.segList.length > 0 || currentResult.icesList.length > 0) {
        segHtml = `<h2 style="color: #1e3a8a; margin-top: 25px; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; font-family: sans-serif;">🛡️ ${t.panel_security_title}</h2><ul style="background-color: #f8fafc; border: 1px solid #e2e8f0; padding: 15px 15px 15px 35px; border-radius: 8px; font-family: sans-serif; font-size: 13px;">`;
        for (const seg of currentResult.segList) {
            segHtml += `<li style="margin-bottom: 10px;"><strong>Secure Email Gateway (SEG):</strong> <span style="color: #4f46e5; font-weight: bold;">${seg.name}</span> <br><small style="color: #64748b;">${t.evidence}: ${seg.source}</small></li>`;
        }
        for (const ices of currentResult.icesList) {
            segHtml += `<li style="margin-bottom: 10px;"><strong>${t.ices_detected}:</strong> <span style="color: #4f46e5; font-weight: bold;">${ices.name}</span> <br><small style="color: #64748b;">${t.evidence}: ${ices.source}</small></li>`;
        }
        segHtml += `</ul>`;
    } else {
        segHtml = `<h2 style="color: #1e3a8a; margin-top: 25px; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; font-family: sans-serif;">🛡️ ${t.panel_security_title}</h2><p style="color: #64748b; font-style: italic; font-family: sans-serif; font-size: 13px;">${t.no_seg_ices_detected}. ${t.no_seg_ices_detail}</p>`;
    }

    let servicesHtml = '';
    if (currentResult.spfServices.length > 0) {
        const servicesTitle = lang === 'es' ? '☁️ Servicios Terceros Identificados en SPF' : '☁️ Third-Party Services Identified in SPF';
        servicesHtml = `<h2 style="color: #1e3a8a; margin-top: 25px; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; font-family: sans-serif;">${servicesTitle}</h2><ul style="font-family: sans-serif; font-size: 13px; line-height: 1.5; padding-left: 20px;">`;
        for (const svc of currentResult.spfServices) {
            let desc = '';
            if (svc.category === 'marketing') desc = lang === 'es' ? 'Plataforma de Email Marketing y automatización de campañas.' : 'Email Marketing and campaign automation platform.';
            else if (svc.category === 'transactional') desc = lang === 'es' ? 'Proveedor de envío de correo transaccional (notificaciones, alertas).' : 'Transactional email delivery provider (notifications, alerts).';
            else if (svc.category === 'crm') desc = lang === 'es' ? 'Software de CRM (Gestión de relación con clientes).' : 'CRM software (Customer Relationship Management).';
            else if (svc.category === 'signatures') desc = lang === 'es' ? 'Servicio de inyección y gestión de firmas de correo corporativas.' : 'Corporate email signature injection and management service.';
            else if (svc.category === 'support') desc = lang === 'es' ? 'Plataforma de Helpdesk o atención al cliente.' : 'Helpdesk or customer support platform.';
            else if (svc.category === 'unknown') desc = lang === 'es' ? 'Servicio no identificado en la base de datos.' : 'Service not identified in the database.';
            else if (svc.category === 'other' && svc.name === 'KnowBe4') desc = lang === 'es' ? 'Plataforma de concienciación de seguridad y phishing simulado.' : 'Security awareness and simulated phishing platform.';
            else if (svc.category === 'other') desc = lang === 'es' ? 'Servicio corporativo externo autorizado para enviar correos.' : 'External corporate service authorized to send emails.';
            
            const localizedCatLabel = getCategoryLabel(svc, lang);
            servicesHtml += `<li style="margin-bottom: 12px;"><strong>${svc.name}</strong> - <span style="color: #0284c7; font-weight: 600;">${localizedCatLabel}</span><br><small style="color: #475569;">${desc} (Regla SPF: <code>${svc.raw}</code>)</small></li>`;
        }
        servicesHtml += `</ul>`;
    }

    let providerDisplay = currentResult.provider;
    if (providerDisplay === 'No identificado') {
        providerDisplay = t.unidentified_provider;
    }

    let dmarcPolicyText = currentResult.dmarcPolicy;
    if (dmarcPolicyText === 'reject') dmarcPolicyText = lang === 'es' ? 'Reject (Rechazar)' : 'Reject';
    else if (dmarcPolicyText === 'quarantine') dmarcPolicyText = lang === 'es' ? 'Quarantine (Cuarentena)' : 'Quarantine';
    else if (dmarcPolicyText === 'none') dmarcPolicyText = lang === 'es' ? 'None (Ninguna)' : 'None';
    else if (dmarcPolicyText === 'No configurado') dmarcPolicyText = t.no_dmarc_record;

    const mainTitle = lang === 'es' ? 'Auditoría de Seguridad de Correo' : 'Email Security Audit';
    const dateLabel = lang === 'es' ? 'Fecha de análisis' : 'Analysis Date';
    const execSummaryLabel = lang === 'es' ? 'Resumen Ejecutivo' : 'Executive Summary';
    const authorizedServicesLabel = lang === 'es' ? 'Servicios Externos Autorizados (SPF)' : 'Authorized External Services (SPF)';
    const priorityLabel = lang === 'es' ? 'Prioridad' : 'Priority';
    const rawRecordLabel = lang === 'es' ? 'Registro Raw' : 'Raw Record';

    // RBL and listings counts
    let rblListingsCount = 0;
    if (currentResult.rblResults) {
        currentResult.rblResults.forEach(r => {
            if (r.checks) {
                r.checks.forEach(c => {
                    if (c.listed) rblListingsCount++;
                });
            }
        });
    }
    const rblSummaryLabel = lang === 'es' ? 'Reputación en Listas Negras (RBL)' : 'Blacklist Reputation (RBL)';
    const rblStatusVal = rblListingsCount > 0 
        ? (lang === 'es' ? `⚠ Listado en ${rblListingsCount} lista(s)` : `⚠ Listed in ${rblListingsCount} list(s)`)
        : (lang === 'es' ? '✓ Limpio / Sin listados' : '✓ Clean / No listings');

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
            
            let text = t[f.key] || '';
            if (f.replacements) {
                for (const [placeholder, val] of Object.entries(f.replacements)) {
                    text = text.replace(placeholder, val);
                }
            }
            
            return `
                <div style="margin-bottom: 6px; font-size: 13px; font-family: sans-serif; color: #334155; line-height: 1.4;">
                    <span style="color: ${bulletColor}; font-weight: bold; margin-right: 8px; font-size: 14px;">${bulletChar}</span>
                    ${text}
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
                        const statusBadge = check.listed
                            ? `<span style="background-color: #fee2e2; color: #b91c1c; font-size: 11px; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-family: sans-serif;">${t.rbl_badge_listed}</span>`
                            : `<span style="background-color: #d1fae5; color: #065f46; font-size: 11px; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-family: sans-serif;">${t.rbl_badge_clean}</span>`;
                        return `
                            <tr style="border-bottom: 1px solid #f1f5f9;">
                                <td style="padding: 8px; color: #475569; font-family: sans-serif; font-size: 13px; text-align: left;">${check.rbl}</td>
                                <td style="padding: 8px; text-align: right; font-family: sans-serif;">${statusBadge}</td>
                            </tr>
                        `;
                    }).join('') : '';
                    return `
                        <div style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 15px; margin-bottom: 15px;">
                            <div style="font-weight: bold; color: #1e293b; font-size: 14px; font-family: sans-serif; margin-bottom: 8px; text-align: left;">
                                MX: <span style="color: #6366f1;">${mxRes.host}</span> ${mxRes.ip ? `(${mxRes.ip})` : ''}
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

    return `
        <div style="font-family: Arial, sans-serif; color: #1e293b; max-width: 800px; margin: 0 auto; line-height: 1.5; text-align: left;">
            <p style="font-size: 22px; font-weight: bold; margin: 0 0 15px 0;">${currentDomain}</p>
            <!-- Header Banner -->
            <div style="background: linear-gradient(135deg, #1e1b4b 0%, #312e81 100%); padding: 30px; border-radius: 12px; color: #ffffff; margin-bottom: 30px; text-align: left;">
                <h1 style="margin: 0; font-size: 26px; font-weight: 700; font-family: sans-serif; letter-spacing: -0.5px;">${mainTitle}</h1>
                <p style="margin: 5px 0 0 0; color: #c7d2fe; font-size: 14px; font-family: sans-serif;">${dateLabel}: ${d} | Dominio: <strong style="color: #ffffff;">${currentDomain}</strong></p>
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
                <li><strong>${t.summary_provider}:</strong> ${providerDisplay}</li>
                <li><strong>${t.summary_dmarc}:</strong> ${dmarcPolicyText}</li>
                <li><strong>${authorizedServicesLabel}:</strong> ${currentResult.spfServices.length} ${t.detected_plural}</li>
                <li><strong>${rblSummaryLabel}:</strong> ${rblStatusVal}</li>
            </ul>

            ${segHtml}
            ${servicesHtml}

            <!-- MX Records Section -->
            <h2 style="color: #1e3a8a; margin-top: 25px; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; font-family: sans-serif;">✉️ 1. ${t.panel_mx_title}</h2>
            <table border="1" cellpadding="8" cellspacing="0" style="width: 100%; border-collapse: collapse; border: 1px solid #e2e8f0; font-family: sans-serif; font-size: 13px; margin-top: 10px; text-align: left;">
                <tr style="background-color: #312e81; color: #ffffff;">
                    <th style="padding: 10px; border: 1px solid #e2e8f0; font-weight: bold; text-align: left; width: 80px;">${priorityLabel}</th>
                    <th style="padding: 10px; border: 1px solid #e2e8f0; font-weight: bold; text-align: left;">Host</th>
                </tr>
                ${currentResult.mxRecords.length > 0 ? currentResult.mxRecords.map(mx => `
                    <tr>
                        <td style="padding: 8px; border: 1px solid #e2e8f0; text-align: left;">${mx.priority}</td>
                        <td style="padding: 8px; border: 1px solid #e2e8f0; text-align: left;">${mx.host}</td>
                    </tr>
                `).join('') : `<tr><td colspan="2" style="padding: 8px; border: 1px solid #e2e8f0; text-align: center; color: #64748b; font-style: italic;">${t.no_mx_records}</td></tr>`}
            </table>

            <!-- SPF Records Section -->
            <h2 style="color: #1e3a8a; margin-top: 25px; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; font-family: sans-serif;">⚙️ 2. ${t.panel_spf_title}</h2>
            <p style="font-family: sans-serif; font-size: 13px; color: #475569; margin-bottom: 8px; text-align: left;"><strong>${rawRecordLabel}:</strong></p>
            <div style="background-color: #f1f5f9; border: 1px solid #e2e8f0; border-radius: 6px; padding: 10px; font-family: monospace; font-size: 12.5px; color: #1e293b; margin-bottom: 15px; word-break: break-all; text-align: left;">
                ${currentResult.spfRaw || t.no_spf_record}
            </div>
            ${currentResult.spfLookups !== undefined ? `
                <p style="font-family: sans-serif; font-size: 13px; color: #475569; text-align: left;">
                    <strong>DNS Lookups:</strong> 
                    <span style="color: ${currentResult.spfLookups > 10 ? '#dc2626' : currentResult.spfLookups > 7 ? '#d97706' : '#059669'}; font-weight: bold;">${currentResult.spfLookups}/10</span>
                </p>
            ` : ''}
            
            <table border="1" cellpadding="8" cellspacing="0" style="width: 100%; border-collapse: collapse; border: 1px solid #e2e8f0; font-family: sans-serif; font-size: 13px; margin-top: 10px; text-align: left;">
                <tr style="background-color: #312e81; color: #ffffff;">
                    <th style="padding: 10px; border: 1px solid #e2e8f0; font-weight: bold; text-align: left; width: 60px;">${t.spf_header_prefix}</th>
                    <th style="padding: 10px; border: 1px solid #e2e8f0; font-weight: bold; text-align: left; width: 90px;">${t.spf_header_type}</th>
                    <th style="padding: 10px; border: 1px solid #e2e8f0; font-weight: bold; text-align: left;">${t.spf_header_value}</th>
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
                    return `
                        <tr>
                            <td style="padding: 8px; border: 1px solid #e2e8f0; font-weight: bold; text-align: center;">${e.qualifier || ''}</td>
                            <td style="padding: 8px; border: 1px solid #e2e8f0; font-family: monospace; text-align: left;">${e.type}</td>
                            <td style="padding: 8px; border: 1px solid #e2e8f0; font-family: monospace; word-break: break-all; text-align: left;">${e.value || '—'}</td>
                            <td style="padding: 8px; border: 1px solid #e2e8f0; text-align: left;">${svcName}</td>
                        </tr>
                    `;
                }).join('')}
            </table>

            <!-- DMARC Records Section -->
            <h2 style="color: #1e3a8a; margin-top: 25px; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; font-family: sans-serif;">🎯 3. ${t.panel_dmarc_title}</h2>
            <p style="font-family: sans-serif; font-size: 13px; color: #475569; margin-bottom: 8px; text-align: left;"><strong>${rawRecordLabel}:</strong></p>
            <div style="background-color: #f1f5f9; border: 1px solid #e2e8f0; border-radius: 6px; padding: 10px; font-family: monospace; font-size: 12.5px; color: #1e293b; margin-bottom: 15px; word-break: break-all; text-align: left;">
                ${currentResult.dmarcRaw || t.no_dmarc_record}
            </div>
            
            <p style="font-family: sans-serif; font-size: 13.5px; color: #334155; font-weight: bold; margin-bottom: 5px; text-align: left;">${t.panel_dmarc_reporting_title}</p>
            <ul style="padding-left: 20px; font-family: sans-serif; font-size: 13px; color: #475569; line-height: 1.5; text-align: left;">
                ${currentResult.dmarcRua.length > 0 ? currentResult.dmarcRua.map(r => `<li><strong>RUA (Aggregate):</strong> <code>${r}</code></li>`).join('') : ''}
                ${currentResult.dmarcRuf.length > 0 ? currentResult.dmarcRuf.map(r => `<li><strong>RUF (Forensic):</strong> <code>${r}</code></li>`).join('') : ''}
                ${currentResult.dmarcRua.length === 0 && currentResult.dmarcRuf.length === 0 ? `<li>${t.no_dmarc_reporting}</li>` : ''}
            </ul>

            <!-- DKIM Records Section -->
            <h2 style="color: #1e3a8a; margin-top: 25px; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; font-family: sans-serif;">🔑 4. ${t.panel_dkim_title}</h2>
            <div style="margin-top: 15px; text-align: left;">
                ${currentResult.dkimRecords && currentResult.dkimRecords.records && currentResult.dkimRecords.records.length > 0 ? 
                    currentResult.dkimRecords.records.map(dkim => `
                        <div style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 15px; margin-bottom: 15px; text-align: left;">
                            <div style="font-weight: bold; color: #1e293b; font-size: 13.5px; font-family: sans-serif; margin-bottom: 6px; text-align: left;">
                                Selector: <span style="color: #4f46e5;">${dkim.selector}</span>
                            </div>
                            <div style="background-color: #f1f5f9; border-radius: 4px; padding: 10px; font-family: monospace; font-size: 12px; color: #334155; word-break: break-all; border: 1px solid #e2e8f0; text-align: left;">
                                ${dkim.record}
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
                            ${currentResult.bimiRecord.record}
                        </div>
                    </div>
                ` : `
                    <p style="color: #64748b; font-style: italic; font-family: sans-serif; font-size: 13px; text-align: left;">${t.no_bimi_record}</p>
                `}
            </div>

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
    
    try {
        const blobHtml = new Blob([htmlContent], { type: 'text/html' });
        const clipboardPlainMsg = lang === 'es' ? 'Reporte DNS de ' : 'DNS Report of ';
        const blobText = new Blob([clipboardPlainMsg + state.currentDomain], { type: 'text/plain' });
        const clipboardItem = new ClipboardItem({
            'text/html': blobHtml,
            'text/plain': blobText
        });
        await navigator.clipboard.write([clipboardItem]);
        
        const copiedLabel = lang === 'es' ? '¡Copiado!' : 'Copied!';
        btn.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg> ${copiedLabel}`;
        
        setTimeout(() => { btn.innerHTML = originalHTML; }, 6000);
        window.open('https://docs.new', '_blank');
    } catch (err) {
        console.error('Error copying to clipboard', err);
        const exportErrorMsg = lang === 'es' ? 'No se pudo copiar automáticamente. Se abrirá una pestaña en blanco en Google Docs.' : 'Could not copy automatically. Opening a blank Google Docs tab.';
        alert(exportErrorMsg);
        window.open('https://docs.new', '_blank');
    }
}

export function exportToFile() {
    if (!state.currentDomain || !state.currentResult) return;
    const htmlContent = generateReportHTML();
    const lang = getLanguage();
    const fileTitle = lang === 'es' ? `Reporte DNS - ${state.currentDomain}` : `DNS Report - ${state.currentDomain}`;
    
    const docHtml = `<html xmlns:o='urn:schemas-microsoft-com:office:office' xmlns:w='urn:schemas-microsoft-com:office:word' xmlns='http://www.w3.org/TR/REC-html40'><head><meta charset='utf-8'><title>${fileTitle}</title></head><body>${htmlContent}</body></html>`;
    const blob = new Blob(['\ufeff', docHtml], { type: 'application/msword' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    
    const downloadName = lang === 'es' ? `Reporte_DNS_${state.currentDomain}.doc` : `DNS_Report_${state.currentDomain}.doc`;
    link.download = downloadName;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

export function exportToPDF() {
    if (!state.currentDomain) {
        window.print();
        return;
    }
    
    const lang = getLanguage();
    const originalTitle = document.title;
    
    const fileTitle = lang === 'es' 
        ? `Auditoría de Seguridad de Correo: ${state.currentDomain}`
        : `Email Security Audit: ${state.currentDomain}`;
        
    document.title = fileTitle;
    
    window.print();
    
    const restoreTitle = () => {
        document.title = originalTitle;
        window.removeEventListener('afterprint', restoreTitle);
    };
    
    window.addEventListener('afterprint', restoreTitle);
    setTimeout(restoreTitle, 1000);
}
