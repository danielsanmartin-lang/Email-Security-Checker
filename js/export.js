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
        segHtml = `<h2 style="color: #7e22ce; margin-top: 20px;">🛡️ ${t.panel_security_title}</h2><ul style="background-color: #f3f4f6; padding: 15px 15px 15px 35px; border-radius: 8px;">`;
        for (const seg of currentResult.segList) {
            segHtml += `<li style="margin-bottom: 10px;"><strong>Secure Email Gateway (SEG):</strong> <span style="color: #9333ea; font-weight: bold;">${seg.name}</span> <br><small style="color: #6b7280;">${t.evidence}: ${seg.source}</small></li>`;
        }
        for (const ices of currentResult.icesList) {
            segHtml += `<li style="margin-bottom: 10px;"><strong>${t.ices_detected}:</strong> <span style="color: #7c3aed; font-weight: bold;">${ices.name}</span> <br><small style="color: #6b7280;">${t.evidence}: ${ices.source}</small></li>`;
        }
        segHtml += `</ul>`;
    } else {
        segHtml = `<h2 style="color: #374151; margin-top: 20px;">🛡️ ${t.panel_security_title}</h2><p style="color: #6b7280; font-style: italic;">${t.no_seg_ices_detected}. ${t.no_seg_ices_detail}</p>`;
    }

    let servicesHtml = '';
    if (currentResult.spfServices.length > 0) {
        const servicesTitle = lang === 'es' ? '☁️ Servicios Terceros Identificados en SPF' : '☁️ Third-Party Services Identified in SPF';
        servicesHtml = `<h2 style="color: #374151; margin-top: 20px;">${servicesTitle}</h2><ul>`;
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
            servicesHtml += `<li style="margin-bottom: 12px;"><strong>${svc.name}</strong> - <span style="color: #0284c7; font-weight: 600;">${localizedCatLabel}</span><br><small style="color: #4b5563;">${desc} (Regla SPF: <code>${svc.raw}</code>)</small></li>`;
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

    return `
        <div style="font-family: Arial, sans-serif; color: #111827;">
            <h1 style="color: #111827; border-bottom: 2px solid #6366f1; padding-bottom: 10px;">${mainTitle}: ${currentDomain}</h1>
            <p><strong>${dateLabel}:</strong> ${d}</p>
            
            <h2 style="color: #374151; margin-top: 20px;">${execSummaryLabel}</h2>
            <ul>
                <li><strong>${t.summary_provider}:</strong> ${providerDisplay}</li>
                <li><strong>${t.summary_dmarc}:</strong> ${dmarcPolicyText}</li>
                <li><strong>${authorizedServicesLabel}:</strong> ${currentResult.spfServices.length} ${t.detected_plural}</li>
            </ul>

            ${segHtml}
            ${servicesHtml}

            <h2 style="color: #374151; margin-top: 20px;">1. ${t.panel_mx_title}</h2>
            <table border="1" cellpadding="5" cellspacing="0" style="width: 100%; border-collapse: collapse; border-color: #e5e7eb;">
                <tr style="background-color: #f3f4f6;"><th>${priorityLabel}</th><th>Host</th></tr>
                ${currentResult.mxRecords.length > 0 ? currentResult.mxRecords.map(mx => `<tr><td>${mx.priority}</td><td>${mx.host}</td></tr>`).join('') : `<tr><td colspan="2">${t.no_mx_records}</td></tr>`}
            </table>

            <h2 style="color: #374151; margin-top: 20px;">2. ${t.panel_spf_title}</h2>
            <p><strong>${rawRecordLabel}:</strong> <code style="word-break: break-all;">${currentResult.spfRaw || t.no_spf_record}</code></p>
            ${currentResult.spfLookups !== undefined ? `<p><strong>DNS Lookups:</strong> <span style="color: ${currentResult.spfLookups > 10 ? '#e11d48' : currentResult.spfLookups > 7 ? '#ca8a04' : '#059669'}; font-weight: bold;">${currentResult.spfLookups}/10</span></p>` : ''}
            
            <table border="1" cellpadding="5" cellspacing="0" style="width: 100%; border-collapse: collapse; border-color: #e5e7eb; font-size: 14px;">
                <tr style="background-color: #f3f4f6;"><th>${t.spf_header_prefix}</th><th>${t.spf_header_type}</th><th>${t.spf_header_value}</th><th>${t.spf_header_service}</th></tr>
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
                    return `<tr><td>${e.qualifier || ''}</td><td>${e.type}</td><td style="word-break: break-all;">${e.value || '—'}</td><td>${svcName}</td></tr>`;
                }).join('')}
            </table>

            <h2 style="color: #374151; margin-top: 20px;">${t.panel_dmarc_title}</h2>
            <p><strong>${rawRecordLabel}:</strong> <code>${currentResult.dmarcRaw || t.no_dmarc_record}</code></p>
            
            <h3>${t.panel_dmarc_reporting_title}</h3>
            <ul>
                ${currentResult.dmarcRua.length > 0 ? currentResult.dmarcRua.map(r => `<li><strong>RUA:</strong> ${r}</li>`).join('') : ''}
                ${currentResult.dmarcRuf.length > 0 ? currentResult.dmarcRuf.map(r => `<li><strong>RUF:</strong> ${r}</li>`).join('') : ''}
                ${currentResult.dmarcRua.length === 0 && currentResult.dmarcRuf.length === 0 ? `<li>${t.no_dmarc_reporting}</li>` : ''}
            </ul>

            <h2 style="color: #374151; margin-top: 20px;">${t.panel_dkim_title}</h2>
            ${currentResult.dkimRecords && currentResult.dkimRecords.records && currentResult.dkimRecords.records.length > 0 ? 
                `<ul>${currentResult.dkimRecords.records.map(dkim => `<li><strong>Selector ${dkim.selector}:</strong> <code style="word-break: break-all;">${dkim.record}</code></li>`).join('')}</ul>` : 
                `<p>${t.no_dkim_records}</p>`
            }

            <h2 style="color: #374151; margin-top: 20px;">${t.panel_bimi_title}</h2>
            ${currentResult.bimiRecord && !currentResult.bimiRecord.error ? 
                `<p><strong>${t.bimi_record_found}:</strong> <code style="word-break: break-all;">${currentResult.bimiRecord.record}</code></p>` : 
                `<p>${t.no_bimi_record}</p>`
            }
            
            <hr style="margin-top: 30px;">
            <p style="font-size: 12px; color: #6b7280; text-align: center;">${t.footer_text}</p>
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
