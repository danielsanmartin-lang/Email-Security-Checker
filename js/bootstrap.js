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
        const category = document.getElementById('kb-category').value;
        const selectEl = document.getElementById('kb-category');
        const cat_label = selectEl.options[selectEl.selectedIndex].text;

        if (!pattern || !name) return;

        const newEntry = { pattern, name, category, cat_label };
        KB.spf.push(newEntry);
        
        let customKB = [];
        try {
            const existing = localStorage.getItem('custom_kb_spf');
            if (existing) customKB = JSON.parse(existing);
        } catch (err) {
            /* localStorage corrupto o no disponible: se parte de una lista vacía */
        }
        customKB.push(newEntry);
        localStorage.setItem('custom_kb_spf', JSON.stringify(customKB));

        closeKbModal();
        
        if (state.currentDomain) {
            const selectors = dkimInput ? parseDkimSelectors(dkimInput.value) : [];
            runAnalysis(state.currentDomain, selectors.length ? selectors : null);
        }
    });
});
