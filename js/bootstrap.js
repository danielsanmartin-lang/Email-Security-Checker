// bootstrap.js
// Punto de entrada de la aplicación: cablea el DOM (formulario, idioma, modales,
// exportación) y delega TODA la lógica de análisis en app.js. Vive separado para que
// app.js quede como orquestación pura y testeable sin navegador: antes este bloque
// de ~250 líneas era la razón de que app.js tuviera un 36% de cobertura.
import { runAnalysis, state } from './app.js';
import { renderResults, showSection, closeKbModal, translateDOM, analyzeHeaders } from './ui.js';
import { exportToGoogle, exportToFile, exportToPDF } from './export.js';
import { KB } from './knowledge.js';
import { setLanguage } from './lang.js';
import { normalizeDomain, parseDkimSelectors } from './utils.js';
import { getSettings, saveSettings } from './settings.js';
import { initDmarcReportPanel } from './ui/dmarcReportPanel.js';
import { clearDnsCache } from './api.js';
import { loadFingerprintsFromUrl } from './awarenessDetector.js';
import { translations } from './i18n.js';
import { getLanguage } from './lang.js';

// Service worker: solo bajo http(s). Con file:// el navegador lo rechaza, y en
// desarrollo local sí interesa tenerlo para probar el modo sin conexión.
if ('serviceWorker' in navigator && location.protocol.startsWith('http')) {
    window.addEventListener('load', () => {
        navigator.serviceWorker.register('sw.js').catch(err => {
            console.warn('No se pudo registrar el service worker', err);
        });
    });
}

document.addEventListener('DOMContentLoaded', () => {
    // Initialize i18n
    translateDOM();

    // URL Params parsing
    const urlParams = new URLSearchParams(window.location.search);
    const domainParam = urlParams.get('domain');

    const form = document.getElementById('search-form');
    const input = document.getElementById('domain-input');
    const dkimInput = document.getElementById('dkim-input');

    // Language Selector UI Logic
    const langBtn = document.getElementById('lang-btn');
    const langSelector = document.getElementById('lang-selector');
    const langDropdown = document.getElementById('lang-dropdown');
    
    if (langBtn && langDropdown) {
        langBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            langSelector.classList.toggle('open');
            langDropdown.classList.toggle('hidden');
            const isOpen = langSelector.classList.contains('open');
            langBtn.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
        });
        
        document.querySelectorAll('.lang-dropdown__item').forEach(item => {
            item.addEventListener('click', (e) => {
                e.stopPropagation();
                const newLang = item.getAttribute('data-lang');
                setLanguage(newLang);
                langSelector.classList.remove('open');
                langDropdown.classList.add('hidden');
                langBtn.setAttribute('aria-expanded', 'false');
                
                // Translate static page
                translateDOM();
                
                // If results are currently showing, re-render them with new translations
                if (state.currentResult && state.currentDomain) {
                    renderResults(state.currentDomain, state.currentResult);
                }
            });
        });
        
        document.addEventListener('click', () => {
            if (langSelector) langSelector.classList.remove('open');
            if (langDropdown) langDropdown.classList.add('hidden');
            if (langBtn) langBtn.setAttribute('aria-expanded', 'false');
        });
    }

    // ===== Accesibilidad de modales: cierre con Escape y trampa de foco =====
    const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]):not([readonly]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
    document.addEventListener('keydown', (e) => {
        const modal = document.querySelector('.modal:not(.hidden)');
        if (!modal) return;
        if (e.key === 'Escape') {
            modal.classList.add('hidden');
            return;
        }
        if (e.key === 'Tab') {
            // Cicla el foco dentro del modal (no se escapa a la página de fondo).
            const items = [...modal.querySelectorAll(FOCUSABLE)].filter(el => el.offsetParent !== null);
            if (!items.length) return;
            const first = items[0];
            const last = items[items.length - 1];
            if (e.shiftKey && document.activeElement === first) {
                e.preventDefault();
                last.focus();
            } else if (!e.shiftKey && document.activeElement === last) {
                e.preventDefault();
                first.focus();
            }
        }
    });

    // DKIM UI Logic
    const dkimToggleBtn = document.getElementById('dkim-toggle-btn');
    const dkimCollapsible = document.getElementById('dkim-collapsible');
    const dkimInfoBtn = document.getElementById('dkim-info-btn');
    const dkimInfoModal = document.getElementById('dkim-info-modal');
    const dkimInfoClose = document.getElementById('dkim-info-close');
    const dkimInfoOverlay = document.getElementById('dkim-info-overlay');

    if (dkimToggleBtn) {
        dkimToggleBtn.addEventListener('click', () => {
            dkimCollapsible.classList.toggle('hidden');
            if (!dkimCollapsible.classList.contains('hidden')) {
                if (dkimInput) dkimInput.focus();
            }
        });
    }

    const closeDkimModal = () => { if (dkimInfoModal) dkimInfoModal.classList.add('hidden'); };
    if (dkimInfoBtn) {
        dkimInfoBtn.addEventListener('click', () => {
            if (dkimInfoModal) dkimInfoModal.classList.remove('hidden');
        });
        if (dkimInfoClose) dkimInfoClose.addEventListener('click', closeDkimModal);
        if (dkimInfoOverlay) dkimInfoOverlay.addEventListener('click', closeDkimModal);
    }

    if (domainParam) {
        input.value = domainParam;
        const dkimParam = parseDkimSelectors(urlParams.get('dkim'));
        if (dkimInput && dkimParam.length) dkimInput.value = dkimParam.join(', ');
        runAnalysis(domainParam, dkimParam.length ? dkimParam : null);
    }

    form.addEventListener('submit', e => {
        e.preventDefault();
        const domain = normalizeDomain(input.value);
        input.value = domain;
        // Acepta varios selectores separados por coma y descarta los que no tienen
        // forma de etiqueta DNS válida.
        const dkimSelectors = dkimInput ? parseDkimSelectors(dkimInput.value) : [];

        // Update URL to allow deep-linking. URLSearchParams escapa los valores: sin
        // ello un selector o dominio con '&' o '#' rompería el enlace.
        try {
            if (history.pushState) {
                const params = new URLSearchParams({ domain });
                if (dkimSelectors.length) params.set('dkim', dkimSelectors.join(','));
                const newurl = `${window.location.protocol}//${window.location.host}${window.location.pathname}?${params.toString()}`;
                window.history.pushState({path:newurl}, '', newurl);
            }
        } catch (err) {
            console.warn('history.pushState failed, usually because of file:// protocol', err);
        }

        if (domain) runAnalysis(domain, dkimSelectors.length ? dkimSelectors : null);
    });

    document.querySelectorAll('.search-hint').forEach(hint => {
        hint.addEventListener('click', () => {
            input.value = hint.dataset.domain;
            form.dispatchEvent(new Event('submit'));
        });
    });

    document.getElementById('new-scan-btn').addEventListener('click', () => {
        showSection(null);
        input.value = '';
        if (dkimInput) dkimInput.value = '';
        input.focus();
        window.scrollTo({ top: 0, behavior: 'smooth' });
    });

    const googleBtn = document.getElementById('export-google-btn');
    if (googleBtn) googleBtn.addEventListener('click', exportToGoogle);

    const fileBtn = document.getElementById('export-file-btn');
    if (fileBtn) fileBtn.addEventListener('click', exportToFile);

    const pdfBtn = document.getElementById('export-pdf-btn');
    if (pdfBtn) pdfBtn.addEventListener('click', exportToPDF);

    // Visor de informes agregados DMARC (RUA): colapsado, es una herramienta aparte
    // del análisis DNS y no todo el mundo tiene un informe a mano.
    const ruaToggle = document.getElementById('rua-toggle');
    const ruaBody = document.getElementById('rua-body');
    if (ruaToggle && ruaBody) {
        ruaToggle.addEventListener('click', () => {
            const expanded = ruaToggle.getAttribute('aria-expanded') === 'true';
            ruaToggle.setAttribute('aria-expanded', String(!expanded));
            ruaBody.hidden = expanded;
        });
        initDmarcReportPanel();
    }

    // ===== Panel de ajustes =====
    // Resolver DoH, proxy CORS (opt-in) y firmas de awareness. Todo se guarda en
    // localStorage y lo lee api.js en la siguiente consulta.
    const settingsModal = document.getElementById('settings-modal');
    if (settingsModal) {
        const openBtn = document.getElementById('settings-btn');
        const closeBtn = document.getElementById('settings-close');
        const overlay = document.getElementById('settings-overlay');
        const form = document.getElementById('settings-form');
        const resolverSel = document.getElementById('settings-resolver');
        const customGroup = document.getElementById('settings-custom-group');
        const customUrl = document.getElementById('settings-custom-url');
        const corsProxy = document.getElementById('settings-cors-proxy');
        const fingerprintsUrl = document.getElementById('settings-fingerprints-url');
        const statusEl = document.getElementById('settings-status');
        const refreshBtn = document.getElementById('settings-refresh');

        const say = (key, replacements = {}) => {
            const t = translations[getLanguage()];
            let text = t[key] || '';
            for (const [k, v] of Object.entries(replacements)) text = text.split(k).join(v);
            statusEl.textContent = text;
        };
        const syncCustomVisibility = () => {
            customGroup.classList.toggle('hidden', resolverSel.value !== 'custom');
        };
        const loadIntoForm = () => {
            const s = getSettings();
            resolverSel.value = s.resolver;
            customUrl.value = s.customResolverUrl;
            corsProxy.checked = s.allowCorsProxy;
            fingerprintsUrl.value = s.fingerprintsUrl;
            statusEl.textContent = '';
            syncCustomVisibility();
        };
        const close = () => settingsModal.classList.add('hidden');

        openBtn.addEventListener('click', () => {
            loadIntoForm();
            settingsModal.classList.remove('hidden');
            resolverSel.focus();
        });
        closeBtn.addEventListener('click', close);
        overlay.addEventListener('click', close);
        resolverSel.addEventListener('change', syncCustomVisibility);

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            saveSettings({
                resolver: resolverSel.value,
                customResolverUrl: customUrl.value.trim(),
                allowCorsProxy: corsProxy.checked,
                fingerprintsUrl: fingerprintsUrl.value.trim()
            });
            // Cambiar de resolver invalida lo cacheado: se resolvió con otro servidor.
            clearDnsCache();
            say('settings_saved');
            const url = fingerprintsUrl.value.trim();
            if (url) {
                try {
                    await loadFingerprintsFromUrl(url);
                    say('settings_fingerprints_ok');
                } catch (err) {
                    say('settings_fingerprints_err', { '{error}': err.message });
                }
            }
        });

        refreshBtn.addEventListener('click', () => {
            clearDnsCache();
            if (state.currentDomain) {
                say('settings_refresh_done');
                close();
                const selectors = dkimInput ? parseDkimSelectors(dkimInput.value) : [];
                runAnalysis(state.currentDomain, selectors.length ? selectors : null);
            } else {
                say('settings_refresh_empty');
            }
        });
    }

    // Desglose de la puntuación: colapsado por defecto (la nota se lee de un vistazo;
    // el desglose es para cuando hay que justificarla).
    const breakdownToggle = document.getElementById('score-breakdown-toggle');
    const breakdownBody = document.getElementById('score-breakdown-body');
    if (breakdownToggle && breakdownBody) {
        breakdownToggle.addEventListener('click', () => {
            const expanded = breakdownToggle.getAttribute('aria-expanded') === 'true';
            breakdownToggle.setAttribute('aria-expanded', String(!expanded));
            breakdownBody.hidden = expanded;
        });
    }

    // Analizador de cabeceras de correo (panel de Awareness) — se vincula una sola vez.
    const headerBtn = document.getElementById('awareness-header-btn');
    if (headerBtn) headerBtn.addEventListener('click', analyzeHeaders);

    // La herramienta de cabeceras es un complemento opcional (solo aplica si tienes una
    // muestra de correo en la mano), así que va colapsada y se despliega bajo demanda.
    const headerToggle = document.getElementById('awareness-header-toggle');
    const headerBody = document.getElementById('awareness-header-body');
    if (headerToggle && headerBody) {
        headerToggle.addEventListener('click', () => {
            const expanded = headerToggle.getAttribute('aria-expanded') === 'true';
            headerToggle.setAttribute('aria-expanded', String(!expanded));
            headerBody.hidden = expanded;
        });
    }

    document.getElementById('error-retry').addEventListener('click', () => {
        const domain = input.value.trim().toLowerCase();
        const dkimSelectors = dkimInput ? parseDkimSelectors(dkimInput.value) : [];
        if (domain) runAnalysis(domain, dkimSelectors.length ? dkimSelectors : null);
    });

    document.getElementById('add-kb-close').addEventListener('click', closeKbModal);
    document.getElementById('add-kb-overlay').addEventListener('click', closeKbModal);
    
    document.getElementById('add-kb-form').addEventListener('submit', (e) => {
        e.preventDefault();
        const pattern = document.getElementById('kb-domain').value.trim();
        const name = document.getElementById('kb-name').value.trim();
        const selectEl = document.getElementById('kb-category');
        const category = selectEl.value;
        // selectedIndex es -1 si el valor no corresponde a ninguna opción: leer
        // options[-1].text reventaba el guardado entero.
        const selected = selectEl.options[selectEl.selectedIndex];
        const cat_label = selected ? selected.text : category;

        if (!pattern || !name || !category) return;

        // El diccionario tiene una lista por señal: un MX identificado no debe acabar
        // en la de includes SPF, que es la que se consulta para otra cosa.
        const list = document.getElementById('add-kb-modal').dataset.kbList === 'mx' ? 'mx' : 'spf';
        const newEntry = list === 'mx'
            ? { pattern, name, type: category }        // KB.mx usa `type` (provider/seg/ices)
            : { pattern, name, category, cat_label };  // KB.spf usa `category` + etiqueta
        KB[list].push(newEntry);

        const storageKey = `custom_kb_${list}`;
        let customKB = [];
        try {
            const existing = localStorage.getItem(storageKey);
            if (existing) customKB = JSON.parse(existing);
        } catch (err) {
            /* localStorage corrupto o no disponible: se parte de una lista vacía */
        }
        customKB.push(newEntry);
        localStorage.setItem(storageKey, JSON.stringify(customKB));

        closeKbModal();
        
        if (state.currentDomain) {
            const selectors = dkimInput ? parseDkimSelectors(dkimInput.value) : [];
            runAnalysis(state.currentDomain, selectors.length ? selectors : null);
        }
    });
});
