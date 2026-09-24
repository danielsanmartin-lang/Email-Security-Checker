import { performAnalysis } from './analysis.js';
import { renderResults, renderAwarenessVendors, renderLookalikes, showSection, setStep } from './ui.js';
import { getLanguage } from './lang.js';
import { translations } from './i18n.js';
import { normalizeDomain, isValidDomain } from './utils.js';
import { state } from './state.js';

export { state };
// El análisis vive en analysis.js (sin interfaz); se re-exporta para quien lo importaba
// desde aquí.
export { performAnalysis };

// Token de la ejecución en curso. Si el usuario lanza un segundo análisis antes de
// que termine el primero, el viejo sigue resolviéndose (no se abortan las peticiones
// DNS en vuelo, sería un refactor desproporcionado) pero su resultado se DESCARTA:
// sin esto, el análisis más lento gana la pintada y muestra datos de otro dominio.
let _runId = 0;

export async function runAnalysis(domain, dkimSelector = null) {
    domain = normalizeDomain(domain);

    const input = document.getElementById('domain-input');
    if (input) {
        input.value = domain;
    }

    const lang = getLanguage();
    const t = translations[lang];

    // Validación de formato (IDN ya normalizado a punycode) antes de consultar nada.
    if (!isValidDomain(domain)) {
        document.getElementById('error-message').textContent = t.error_invalid_domain || t.error_default_message;
        showSection('error-section');
        return;
    }

    const myRun = ++_runId;
    const isStale = () => myRun !== _runId;

    const btn = document.getElementById('search-btn');
    btn.classList.add('loading');
    btn.disabled = true;
    const resultsSection = document.getElementById('results-section');
    if (resultsSection) resultsSection.setAttribute('aria-busy', 'true');
    showSection('loading-section');

    ['step-mx', 'step-spf', 'step-dmarc', 'step-dkim', 'step-bimi', 'step-advanced', 'step-analysis', 'step-awareness'].forEach(s => setStep(s, null));

    try {
        const { result, awarenessPromise, lookalikePromise } = await performAnalysis(domain, dkimSelector, {
            // Los pasos de un análisis obsoleto no deben tocar el indicador de progreso
            // del que está corriendo ahora.
            onStep: (step, stepState) => { if (!isStale()) setStep(step, stepState); }
        });
        if (isStale()) return;

        state.currentDomain = domain;
        state.currentResult = result;

        // Render progresivo: se muestran los resultados en cuanto está el análisis
        // principal; el panel de awareness aparece "escaneando" y se rellena solo
        // cuando la detección (lenta) termina, sin bloquear el resto.
        await new Promise(r => setTimeout(r, 300));
        if (isStale()) return;
        renderResults(domain, result);
        showSection('results-section');

        awarenessPromise.then((awarenessResult) => {
            result.awarenessResult = awarenessResult;
            // Solo repinta si el usuario sigue viendo este mismo resultado.
            if (!isStale() && state.currentResult === result) {
                renderAwarenessVendors(awarenessResult || null, getLanguage(), translations[getLanguage()]);
            }
        });
        // Dominios parecidos: mismo patrón. Hasta que resuelve, el panel dice "buscando".
        lookalikePromise.then((lookalikeResult) => {
            result.lookalikeResult = lookalikeResult;
            if (!isStale() && state.currentResult === result) renderLookalikes(lookalikeResult);
        });
    } catch (err) {
        if (isStale()) return;
        console.error(err);
        let message;
        if (err.code === 'nxdomain') {
            message = (t.error_domain_not_found || '').replace('{domain}', domain) || t.error_default_message;
        } else if (err.code === 'network') {
            message = t.error_network || t.error_default_message;
        } else if (err.code === 'servfail') {
            message = t.error_servfail || t.error_default_message;
        } else {
            message = err.message || t.error_default_message;
        }
        document.getElementById('error-message').textContent = message;
        showSection('error-section');
    } finally {
        // Solo la ejecución vigente devuelve el botón a su estado normal: si un
        // análisis viejo termina después, no debe reactivarlo a mitad del nuevo.
        if (!isStale()) {
            btn.classList.remove('loading');
            btn.disabled = false;
            if (resultsSection) resultsSection.setAttribute('aria-busy', 'false');
        }
    }
}
