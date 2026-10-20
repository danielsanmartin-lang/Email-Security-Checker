// docsExport.js
// "Exportar a Google Docs": copia el informe al portapapeles como HTML y abre un
// documento nuevo para pegarlo. Vive aparte de export.js porque export.js (el informe
// entero) se descarga bajo demanda, y Safari solo deja escribir en el portapapeles
// DENTRO del gesto del usuario: la escritura tiene que salir en el mismo clic, con el
// contenido como promesa que resuelve cuando el informe está listo.
import { translations } from './i18n.js';
import { getLanguage } from './lang.js';
import { html, raw } from './utils.js';

// Icono de confirmación del botón (SVG propio, estático).
const CHECK_ICON_SVG = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>';

/**
 * @param {string|Promise<string>} reportHtml el informe, o una promesa que lo dará
 * @param {string} domain dominio auditado (para el texto plano de respaldo)
 */
export async function copyReportToDocs(reportHtml, domain) {
    const btn = document.getElementById('export-google-btn');
    const originalHTML = btn.innerHTML;
    const t = translations[getLanguage()];
    try {
        const clipboardItem = new ClipboardItem({
            'text/html': Promise.resolve(reportHtml).then(h => new Blob([String(h)], { type: 'text/html' })),
            'text/plain': new Blob([t.report_clipboard_msg + domain], { type: 'text/plain' })
        });
        await navigator.clipboard.write([clipboardItem]);

        btn.innerHTML = html`${raw(CHECK_ICON_SVG)} ${t.msg_copied}`;

        setTimeout(() => { btn.innerHTML = originalHTML; }, 6000);
        window.open('https://docs.new', '_blank');
    } catch (err) {
        console.error('Error copying to clipboard', err);
        alert(t.msg_export_clipboard_fail);
        window.open('https://docs.new', '_blank');
    }
}
