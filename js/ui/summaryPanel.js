// ui/summaryPanel.js
// Cabecera del resultado (dominio + hora del escaneo) y las cuatro tarjetas resumen.
import { translations } from '../i18n.js';
import { getLanguage, getLocale } from '../lang.js';
import { displayProvider, displayDmarcPolicy } from '../viewmodel.js';

export function renderSummaryPanel(domain, result) {
    const lang = getLanguage();
    const t = translations[lang];
    document.getElementById('result-domain').textContent = domain;
    // Fecha real del escaneo (fijada en app.js), no la del render actual: cambiar de
    // idioma re-renderiza y no debe "mover" la hora del análisis.
    const scannedAt = result.scannedAt ? new Date(result.scannedAt) : new Date();
    document.getElementById('result-timestamp').textContent = scannedAt.toLocaleString(getLocale(lang));

    const providerDisplay = displayProvider(result, t);
    document.getElementById('summary-provider-value').textContent = providerDisplay;
    
    const secValue = document.getElementById('summary-security-value');
    // Marca las detecciones de confianza baja (<50%) como "(posible)" para no
    // afirmar en el resumen el uso de un producto que no está confirmado.
    const summaryName = (s) => (typeof s.score === 'number' && s.score < 0.5)
        ? `${s.name} (${t.label_possible})`
        : s.name;
    if (result.segList.length > 0) {
        secValue.textContent = result.segList.map(summaryName).join(', ');
    } else if (result.icesList.length > 0) {
        secValue.textContent = result.icesList.map(summaryName).join(', ');
    } else {
        secValue.textContent = t.no_evidence_dns;
    }

    const dmarcVal = document.getElementById('summary-dmarc-value');
    const dmarcPolicyText = displayDmarcPolicy(t, result.dmarcPolicy);

    dmarcVal.textContent = dmarcPolicyText;
    dmarcVal.className = 'summary-card__value';
    if (result.dmarcPolicyClass === 'reject') dmarcVal.classList.add('dmarc-policy--reject');
    else if (result.dmarcPolicyClass === 'quarantine') dmarcVal.classList.add('dmarc-policy--quarantine');
    else dmarcVal.classList.add('dmarc-policy--none');

    document.getElementById('summary-services-value').textContent = 
        result.spfServices.length > 0 ? `${result.spfServices.length} ${t.detected_plural}` : t.detected_none;
}
