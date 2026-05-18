import { state } from './app.js';
import { identifySPFService } from './analyzer.js';

export function generateReportHTML() {
    if (!state.currentResult || !state.currentDomain) return '';
    const { currentResult, currentDomain } = state;
    const d = new Date().toLocaleDateString('es-ES');
    
    let segHtml = '';
    if (currentResult.segList.length > 0 || currentResult.icesList.length > 0) {
        segHtml = `<h2 style="color: #374151; margin-top: 20px; color: #7e22ce;">🛡️ Capa de Seguridad (SEG / ICES)</h2><ul style="background-color: #f3f4f6; padding: 15px 15px 15px 35px; border-radius: 8px;">`;
        for (const seg of currentResult.segList) {
            segHtml += `<li style="margin-bottom: 10px;"><strong>Secure Email Gateway (SEG):</strong> <span style="color: #9333ea; font-weight: bold;">${seg.name}</span> <br><small style="color: #6b7280;">Evidencia DNS: ${seg.source}</small></li>`;
        }
        for (const ices of currentResult.icesList) {
            segHtml += `<li style="margin-bottom: 10px;"><strong>Seguridad Integrada (ICES):</strong> <span style="color: #7c3aed; font-weight: bold;">${ices.name}</span> <br><small style="color: #6b7280;">Evidencia DNS: ${ices.source}</small></li>`;
        }
        segHtml += `</ul>`;
    } else {
        segHtml = `<h2 style="color: #374151; margin-top: 20px;">🛡️ Capa de Seguridad (SEG / ICES)</h2><p style="color: #6b7280; font-style: italic;">No se detectó evidencia en DNS de Secure Email Gateways (SEG) ni soluciones ICES.</p>`;
    }

    let servicesHtml = '';
    if (currentResult.spfServices.length > 0) {
        servicesHtml = `<h2 style="color: #374151; margin-top: 20px;">☁️ Servicios Terceros Identificados en SPF</h2><ul>`;
        for (const svc of currentResult.spfServices) {
            let desc = 'Servicio de correo de terceros';
            if (svc.category === 'marketing') desc = 'Plataforma de Email Marketing y automatización de campañas.';
            else if (svc.category === 'transactional') desc = 'Proveedor de envío de correo transaccional (notificaciones, alertas).';
            else if (svc.category === 'crm') desc = 'Software de CRM (Gestión de relación con clientes).';
            else if (svc.category === 'signatures') desc = 'Servicio de inyección y gestión de firmas de correo corporativas.';
            else if (svc.category === 'support') desc = 'Plataforma de Helpdesk o atención al cliente.';
            else if (svc.category === 'unknown') desc = `Servicio no identificado en la base de datos.`;
            else if (svc.category === 'other' && svc.name === 'KnowBe4') desc = 'Plataforma de concienciación de seguridad y phishing simulado.';
            else if (svc.category === 'other') desc = 'Servicio corporativo externo autorizado para enviar correos.';
            
            servicesHtml += `<li style="margin-bottom: 12px;"><strong>${svc.name}</strong> - <span style="color: #0284c7; font-weight: 600;">${svc.cat_label}</span><br><small style="color: #4b5563;">${desc} (Regla SPF: <code>${svc.raw}</code>)</small></li>`;
        }
        servicesHtml += `</ul>`;
    }

    return `
        <div style="font-family: Arial, sans-serif; color: #111827;">
            <h1 style="color: #111827; border-bottom: 2px solid #6366f1; padding-bottom: 10px;">Auditoría de Seguridad de Correo: ${currentDomain}</h1>
            <p><strong>Fecha de análisis:</strong> ${d}</p>
            
            <h2 style="color: #374151; margin-top: 20px;">Resumen Ejecutivo</h2>
            <ul>
                <li><strong>Proveedor de Correo Principal:</strong> ${currentResult.provider}</li>
                <li><strong>Política DMARC:</strong> ${currentResult.dmarcPolicy}</li>
                <li><strong>Servicios Externos Autorizados (SPF):</strong> ${currentResult.spfServices.length} detectados</li>
            </ul>

            ${segHtml}
            ${servicesHtml}

            <h2 style="color: #374151; margin-top: 20px;">1. Registros MX (Mail Exchange)</h2>
            <table border="1" cellpadding="5" cellspacing="0" style="width: 100%; border-collapse: collapse; border-color: #e5e7eb;">
                <tr style="background-color: #f3f4f6;"><th>Prioridad</th><th>Host</th></tr>
                ${currentResult.mxRecords.length > 0 ? currentResult.mxRecords.map(mx => `<tr><td>${mx.priority}</td><td>${mx.host}</td></tr>`).join('') : '<tr><td colspan="2">No se encontraron registros MX</td></tr>'}
            </table>

            <h2 style="color: #374151; margin-top: 20px;">2. Registro SPF (Sender Policy Framework)</h2>
            <p><strong>Registro Raw:</strong> <code style="word-break: break-all;">${currentResult.spfRaw || 'No encontrado'}</code></p>
            ${currentResult.spfLookups !== undefined ? `<p><strong>DNS Lookups:</strong> <span style="color: ${currentResult.spfLookups > 10 ? '#e11d48' : currentResult.spfLookups > 7 ? '#ca8a04' : '#059669'}; font-weight: bold;">${currentResult.spfLookups}/10</span></p>` : ''}
            
            <table border="1" cellpadding="5" cellspacing="0" style="width: 100%; border-collapse: collapse; border-color: #e5e7eb; font-size: 14px;">
                <tr style="background-color: #f3f4f6;"><th>Prefijo</th><th>Tipo</th><th>Valor</th><th>Servicio Identificado</th></tr>
                ${currentResult.spfEntries.map(e => {
                    const svc = identifySPFService(e.value);
                    const svcName = svc ? `${svc.name} (${svc.cat_label})` : '—';
                    return `<tr><td>${e.qualifier || ''}</td><td>${e.type}</td><td style="word-break: break-all;">${e.value || '—'}</td><td>${svcName}</td></tr>`;
                }).join('')}
            </table>

            <h2 style="color: #374151; margin-top: 20px;">Estado DMARC</h2>
            <p><strong>Registro Raw:</strong> <code>${currentResult.dmarcRaw || 'No encontrado'}</code></p>
            
            <h3>Reportes DMARC</h3>
            <ul>
                ${currentResult.dmarcRua.length > 0 ? currentResult.dmarcRua.map(r => `<li><strong>RUA:</strong> ${r}</li>`).join('') : ''}
                ${currentResult.dmarcRuf.length > 0 ? currentResult.dmarcRuf.map(r => `<li><strong>RUF:</strong> ${r}</li>`).join('') : ''}
                ${currentResult.dmarcRua.length === 0 && currentResult.dmarcRuf.length === 0 ? '<li>No se encontraron direcciones de reporte (rua/ruf).</li>' : ''}
            </ul>

            <h2 style="color: #374151; margin-top: 20px;">Estado DKIM</h2>
            ${currentResult.dkimRecords && currentResult.dkimRecords.records && currentResult.dkimRecords.records.length > 0 ? 
                `<ul>${currentResult.dkimRecords.records.map(dkim => `<li><strong>Selector ${dkim.selector}:</strong> <code style="word-break: break-all;">${dkim.record}</code></li>`).join('')}</ul>` : 
                '<p>No se detectaron registros DKIM.</p>'
            }

            <h2 style="color: #374151; margin-top: 20px;">Estado BIMI</h2>
            ${currentResult.bimiRecord ? 
                `<p><strong>Registro Encontrado:</strong> <code style="word-break: break-all;">${currentResult.bimiRecord.record}</code></p>` : 
                '<p>No se encontró registro BIMI (default._bimi).</p>'
            }
            
            <hr style="margin-top: 30px;">
            <p style="font-size: 12px; color: #6b7280; text-align: center;">Reporte generado por Email Security Checker</p>
        </div>
    `;
}

export async function exportToGoogle() {
    if (!state.currentDomain || !state.currentResult) return;
    const htmlContent = generateReportHTML();
    const btn = document.getElementById('export-google-btn');
    const originalHTML = btn.innerHTML;
    
    try {
        const blobHtml = new Blob([htmlContent], { type: 'text/html' });
        const blobText = new Blob(['Reporte DNS de ' + state.currentDomain], { type: 'text/plain' });
        const clipboardItem = new ClipboardItem({
            'text/html': blobHtml,
            'text/plain': blobText
        });
        await navigator.clipboard.write([clipboardItem]);
        
        btn.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg> ¡Copiado!';
        
        setTimeout(() => { btn.innerHTML = originalHTML; }, 6000);
        window.open('https://docs.new', '_blank');
    } catch (err) {
        console.error('Error copiando al portapapeles', err);
        alert('No se pudo copiar automáticamente. Se abrirá una pestaña en blanco en Google Docs.');
        window.open('https://docs.new', '_blank');
    }
}

export function exportToFile() {
    if (!state.currentDomain || !state.currentResult) return;
    const htmlContent = generateReportHTML();
    const docHtml = `<html xmlns:o='urn:schemas-microsoft-com:office:office' xmlns:w='urn:schemas-microsoft-com:office:word' xmlns='http://www.w3.org/TR/REC-html40'><head><meta charset='utf-8'><title>Reporte DNS - ${state.currentDomain}</title></head><body>${htmlContent}</body></html>`;
    const blob = new Blob(['\ufeff', docHtml], { type: 'application/msword' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `Reporte_DNS_${state.currentDomain}.doc`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

export function exportToPDF() {
    window.print();
}
