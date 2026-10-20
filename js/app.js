import { performAnalysis } from './analysis.js';
import { renderResults, renderAwarenessVendors, renderLookalikes, renderMailSubdomains, renderProviderPanel, showSection, setStep } from './ui.js';
import { getLanguage } from './lang.js';
import { translations } from './i18n.js';
import { normalizeDomain, isValidDomain } from './utils.js';
import { state } from './state.js';

export { state };
// El análisis vive en analysis.js (sin interfaz); se re-exporta para quien lo importaba
// desde aquí.
export { performAnalysis };

// Token de la ejecución en curso. Si el usuario lanza un segundo análisis antes de
// que termine el primero, el viejo se CANCELA: lo que tenía en la cola DNS sale sin
// pedirse, así que el nuevo no espera detrás de él. Lo que ya estaba en vuelo termina
// (y se cachea), pero su resultado se DESCARTA: sin esto, el análisis más lento ganaría
// la pintada y mostraría datos de otro dominio.
let _runId = 0;
let _runController = null;

/** Cancela el análisis en curso, si lo hay (al lanzar otro o al desmontar la página). */
export function cancelAnalysis() {
    if (_runController) _runController.abort();
    _runController = null;
}

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

    cancelAnalysis();
    const myRun = ++_runId;
    const controller = new AbortController();
    _runController = controller;
    const isStale = () => myRun !== _runId;

    const btn = document.getElementById('search-btn');
    btn.classList.add('loading');
    btn.disabled = true;
    const resultsSection = document.getElementById('results-section');
    if (resultsSection) resultsSection.setAttribute('aria-busy', 'true');
    showSection('loading-section');

    ['step-mx', 'step-spf', 'step-dmarc', 'step-dkim', 'step-bimi', 'step-advanced', 'step-analysis', 'step-awareness'].forEach(s => setStep(s, null));

    try {
        const { result, awarenessPromise, lookalikePromise, lookalikeCertsPromise, mailSubdomainsPromise, mailHostingPromise } = await performAnalysis(domain, dkimSelector, {
            // Los pasos de un análisis obsoleto no deben tocar el indicador de progreso
            // del que está corriendo ahora.
            onStep: (step, stepState) => { if (!isStale()) setStep(step, stepState); },
            signal: controller.signal
        });
        if (isStale()) return;

        state.currentDomain = domain;
        state.currentResult = result;

        // Render progresivo: se muestran los resultados en cuanto está el análisis
        // principal; los paneles de segundo plano aparecen "escaneando" y se rellenan
        // cuando su detección termina, sin bloquear el resto.
        renderResults(domain, result);
        showSection('results-section');

        // Cada promesa de segundo plano guarda su dato en el result y repinta su panel,
        // pero solo si el usuario sigue viendo este mismo resultado.
        const whenCurrent = (promise, apply) => promise.then((value) => {
            if (isStale() || state.currentResult !== result) return;
            apply(value);
        });
        whenCurrent(awarenessPromise, (awarenessResult) => {
            result.awarenessResult = awarenessResult;
            renderAwarenessVendors(awarenessResult || null, getLanguage(), translations[getLanguage()]);
        });
        // Dominios parecidos: hasta que resuelve, el panel dice "buscando". Después llegan
        // los certificados de los que reciben correo y se repinta.
        whenCurrent(lookalikePromise, (lookalikeResult) => {
            result.lookalikeResult = lookalikeResult;
            renderLookalikes(lookalikeResult);
        });
        whenCurrent(lookalikeCertsPromise, (lookalikeResult) => {
            if (!lookalikeResult) return;
            result.lookalikeResult = lookalikeResult;
            renderLookalikes(lookalikeResult);
        });
        whenCurrent(mailSubdomainsPromise, (mailSubdomains) => {
            result.mailSubdomains = mailSubdomains;
            renderMailSubdomains(mailSubdomains);
        });
        // Con los nombres de los certificados, el hospedaje del correo puede afinarse.
        whenCurrent(mailHostingPromise, (mailHosting) => {
            if (!mailHosting) return;
            result.mailHosting = mailHosting;
            renderProviderPanel(result);
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
