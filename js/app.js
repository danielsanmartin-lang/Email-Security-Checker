import { getMX, getSPF, getDMARC, getDKIM, getBIMI, getSPFLookupTree, getIPAddresses, checkRBL, getAllTXT, getMTASTS, getTLSRPT, getNS, getSRV, getDANE, getDNSSEC, checkDMARCExternalAuth, checkDomainExists } from './api.js';
import { analyze, calculateScoreAndFindings, identifyTXTVerifications, identifyNSProvider, analyzeTLSRPT, extractRootDomain } from './analyzer.js';
import { renderResults, renderAwarenessVendors, showSection, setStep, closeKbModal, translateDOM, analyzeHeaders } from './ui.js';
import { exportToGoogle, exportToFile, exportToPDF } from './export.js';
import { KB } from './knowledge.js';
import { getLanguage, setLanguage } from './lang.js';
import { translations } from './i18n.js';
import { detectAwarenessVendors } from './awarenessDetector.js';
import { normalizeDomain, isValidDomain } from './utils.js';
import { state } from './state.js';

export { state };

// Orquestación pura del análisis (sin DOM salvo el callback onStep). Devuelve el
// result principal ya puntuado + una promesa para la detección de awareness (la
// parte más lenta, por los CT logs), que el llamante renderiza en cuanto resuelve.
// Lanza errores con .code ('nxdomain' | 'servfail' | 'network') para que la capa
// de UI muestre el mensaje adecuado. Exportada para poder testear el flujo.
export async function performAnalysis(domain, dkimSelector = null, { onStep = () => {} } = {}) {
    // Comprobación de existencia del dominio (distingue NXDOMAIN de "sin registros").
    const exists = await checkDomainExists(domain);
    if (!exists) {
        const e = new Error('Domain not found');
        e.code = 'nxdomain';
        throw e;
    }

    // ===== Fase 1: consultas DNS independientes en paralelo =====
    ['step-mx', 'step-spf', 'step-dmarc', 'step-bimi', 'step-advanced'].forEach(s => onStep(s, 'active'));

    const mxP = getMX(domain).then(r => { onStep('step-mx', 'done'); return r; });
    const spfP = getSPF(domain);
    // DMARC con herencia del dominio organizativo (RFC 7489 §6.6.3): si el
    // subdominio no publica registro, la política se hereda del dominio raíz.
    const dmarcP = getDMARC(domain).then(async (r) => {
        if (!r.record) {
            const org = extractRootDomain(domain);
            if (org && org !== domain) {
                const orgDmarc = await getDMARC(org);
                if (orgDmarc.record) {
                    orgDmarc.inherited = true;
                    orgDmarc.inheritedFrom = org;
                    onStep('step-dmarc', 'done');
                    return orgDmarc;
                }
            }
        }
        onStep('step-dmarc', 'done');
        return r;
    });
    const bimiP = getBIMI(domain).then(r => { onStep('step-bimi', 'done'); return r; });
    const advancedP = Promise.all([
        getAllTXT(domain),
        getMTASTS(domain),
        getTLSRPT(domain),
        getNS(domain),
        getSRV(domain),
        getDNSSEC(domain)
    ]).then(r => { onStep('step-advanced', 'done'); return r; });

    // SPF tree, lookups y DKIM dependen del registro SPF
    const spfDerivedP = spfP.then(async (spfData) => {
        const spfRaw = spfData.record;
        const icesSelectors = KB.ices_dkim_selectors || [];
        onStep('step-dkim', 'active');
        const [spfTree, dkimRecords] = await Promise.all([
            spfRaw ? getSPFLookupTree(domain) : Promise.resolve(null),
            getDKIM(domain, dkimSelector, spfRaw, icesSelectors)
        ]);
        onStep('step-spf', 'done');
        onStep('step-dkim', 'done');
        return { spfData, spfRaw, spfTree, dkimRecords };
    });

    // Degradación resiliente: un fallo transitorio en una consulta no debe
    // descartar las demás. Solo se aborta si fallan a la vez MX y el TXT del
    // ápex (SPF), que son las consultas nucleares.
    const [mxS, spfS, dmarcS, bimiS, advS] = await Promise.allSettled([
        mxP, spfDerivedP, dmarcP, bimiP, advancedP
    ]);

    if (mxS.status === 'rejected' && spfS.status === 'rejected') {
        throw (mxS.reason && mxS.reason.code) ? mxS.reason : spfS.reason;
    }

    const mxRecords = mxS.status === 'fulfilled' ? mxS.value : [];
    const spfDerived = spfS.status === 'fulfilled'
        ? spfS.value
        : { spfData: { record: null, records: [], multiple: false }, spfRaw: null, spfTree: null, dkimRecords: { records: [], errors: [] }, unavailable: true };
    const { spfData, spfRaw, spfTree, dkimRecords } = spfDerived;
    const spfUnavailable = spfS.status === 'rejected';
    const dmarcData = dmarcS.status === 'fulfilled' ? dmarcS.value : { record: null, records: [], multiple: false };
    const dmarcUnavailable = dmarcS.status === 'rejected';
    const bimiRecord = bimiS.status === 'fulfilled' ? bimiS.value : null;
    const advanced = advS.status === 'fulfilled' ? advS.value : [[], null, null, [], {}, null];

    // Marca los pasos que fallaron para que no queden girando indefinidamente.
    if (mxS.status === 'rejected') onStep('step-mx', null);
    if (spfS.status === 'rejected') { onStep('step-spf', null); onStep('step-dkim', null); }
    if (dmarcS.status === 'rejected') onStep('step-dmarc', null);
    if (bimiS.status === 'rejected') onStep('step-bimi', null);
    if (advS.status === 'rejected') onStep('step-advanced', null);

    const spfLookups = spfTree ? spfTree.lookups : 0;
    const dmarcRaw = dmarcData.record;
    const [allTxtRecords, mtaSts, tlsRpt, nsRecords, srvRecords, dnssec] = advanced;

    // Process advanced data
    const txtVerifications = identifyTXTVerifications(allTxtRecords);
    const nsProvider = identifyNSProvider(nsRecords);
    const tlsrptReporters = analyzeTLSRPT(tlsRpt);

    onStep('step-analysis', 'active');

    // ===== Fase 2: DANE y reputación RBL (dependen de los MX) en paralelo =====
    const mxHosts = mxRecords.map(r => r.host);
    const RBL_LISTS = KB.rbl_lists || ['bl.spamcop.net', 'dnsbl.dronebl.org'];
    const [daneRecords, rblResults] = await Promise.all([
        getDANE(mxHosts),
        Promise.all(
            mxRecords.slice(0, 3).map(async (mx) => {
                const ips = await getIPAddresses(mx.host);
                const ip = ips[0] || null;
                // Una comprobación por lista RBL: marcada como listada si CUALQUIER
                // IP del host (IPv4 o IPv6) aparece en esa lista. El estado 'error'
                // (consulta rechazada por la DNSBL vía resolver público, o host sin
                // IPs) debe llegar a la UI como "inconcluso", nunca como "limpio".
                const checks = await Promise.all(RBL_LISTS.map(async (rbl) => {
                    if (!ips.length) return { status: 'error', listed: false, rbl };
                    const perIp = await Promise.all(ips.map(addr => checkRBL(addr, rbl)));
                    const hit = perIp.find(c => c.listed);
                    if (hit) return hit;
                    if (perIp.every(c => c.status === 'error')) return { status: 'error', listed: false, rbl };
                    return { status: 'clean', listed: false, rbl };
                }));
                return { host: mx.host, ip, ips, checks };
            })
        )
    ]);

    const result = analyze(mxRecords, spfRaw, dmarcRaw, {
        domain,
        txtVerifications,
        nsProvider,
        nsRecords,
        mtaSts,
        tlsRpt,
        tlsrptReporters,
        spfData,
        dmarcData,
        dmarcInherited: dmarcData.inherited || false,
        dmarcInheritedFrom: dmarcData.inheritedFrom || null,
        spfUnavailable,
        dmarcUnavailable,
        nullMx: !!mxRecords.nullMx,
        srvRecords,
        daneRecords,
        dnssec,
        spfTree,
        dkimSelectors: (dkimRecords.records || []).map(r => r.selector)
    });
    result.spfLookups = spfLookups;
    result.spfTree = spfTree;
    result.dkimRecords = dkimRecords;
    result.bimiRecord = bimiRecord;
    result.rblResults = rblResults;

    // Autorización de destinos de informe DMARC externos (RFC 7489 §7.1).
    const dmarcUris = [...(result.dmarcRua || []), ...(result.dmarcRuf || [])];
    try {
        result.dmarcExternalAuth = await checkDMARCExternalAuth(domain, dmarcUris);
    } catch (err) {
        console.warn('DMARC external auth check failed:', err);
        result.dmarcExternalAuth = [];
    }

    result.scoreCard = calculateScoreAndFindings(result);
    // Momento real del escaneo: se fija una vez en el propio result y no se
    // recalcula al re-renderizar (p. ej. al cambiar de idioma) ni al exportar.
    result.scannedAt = new Date().toISOString();
    result.awarenessResult = null;
    onStep('step-analysis', 'done');

    // Awareness / Phishing Simulation: la parte más lenta (CT logs). Se devuelve
    // como promesa para poder renderizar el resto de resultados sin esperarla.
    onStep('step-awareness', 'active');
    const awarenessPromise = detectAwarenessVendors(domain)
        .catch((err) => { console.warn('Awareness detection failed:', err); return null; })
        .then((a) => { onStep('step-awareness', 'done'); return a; });

    return { result, awarenessPromise };
}

async function runAnalysis(domain, dkimSelector = null) {
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

    const btn = document.getElementById('search-btn');
    btn.classList.add('loading');
    showSection('loading-section');

    ['step-mx', 'step-spf', 'step-dmarc', 'step-dkim', 'step-bimi', 'step-advanced', 'step-analysis', 'step-awareness'].forEach(s => setStep(s, null));

    try {
        const { result, awarenessPromise } = await performAnalysis(domain, dkimSelector, { onStep: setStep });

        state.currentDomain = domain;
        state.currentResult = result;

        // Render progresivo: se muestran los resultados en cuanto está el análisis
        // principal; el panel de awareness aparece "escaneando" y se rellena solo
        // cuando la detección (lenta) termina, sin bloquear el resto.
        await new Promise(r => setTimeout(r, 300));
        renderResults(domain, result);
        showSection('results-section');

        awarenessPromise.then((awarenessResult) => {
            result.awarenessResult = awarenessResult;
            // Solo repinta si el usuario sigue viendo este mismo resultado.
            if (state.currentResult === result) {
                renderAwarenessVendors(awarenessResult || null, getLanguage(), translations[getLanguage()]);
            }
        });
    } catch (err) {
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
        btn.classList.remove('loading');
    }
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
        runAnalysis(domainParam, urlParams.get('dkim') || null);
    }
    
    form.addEventListener('submit', e => {
        e.preventDefault();
        const domain = normalizeDomain(input.value);
        input.value = domain;
        let dkimSelector = null;
        if (dkimInput) {
            dkimSelector = dkimInput.value.trim().toLowerCase();
        }

        // Update URL to allow deep-linking
        try {
            if (history.pushState) {
                const newurl = window.location.protocol + "//" + window.location.host + window.location.pathname + `?domain=${domain}` + (dkimSelector ? `&dkim=${dkimSelector}` : '');
                window.history.pushState({path:newurl}, '', newurl);
            }
        } catch (err) {
            console.warn('history.pushState failed, usually because of file:// protocol', err);
        }

        if (domain) runAnalysis(domain, dkimSelector || null);
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
        const dkimSelector = dkimInput ? dkimInput.value.trim().toLowerCase() : null;
        if (domain) runAnalysis(domain, dkimSelector);
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
            runAnalysis(state.currentDomain, dkimInput ? dkimInput.value.trim() : null);
        }
    });
});
