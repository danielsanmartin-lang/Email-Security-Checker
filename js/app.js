import { getMX, getSPF, getDMARC, getDKIM, getBIMI, getSPFLookupTree, getIPAddress, checkRBL, getAllTXT, getMTASTS, getTLSRPT, getNS } from './api.js';
import { analyze, calculateScoreAndFindings, identifyTXTVerifications, identifyNSProvider, analyzeTLSRPT } from './analyzer.js';
import { renderResults, showSection, setStep, closeKbModal, translateDOM } from './ui.js';
import { exportToGoogle, exportToFile, exportToPDF } from './export.js';
import { KB } from './knowledge.js';
import { getLanguage, setLanguage } from './lang.js';
import { translations } from './i18n.js';

export const state = {
    currentDomain: '',
    currentResult: null
};

async function runAnalysis(domain, dkimSelector = null) {
    domain = domain.trim().toLowerCase();
    if (domain.includes('@')) {
        domain = domain.substring(domain.indexOf('@') + 1);
    }
    domain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');

    const input = document.getElementById('domain-input');
    if (input) {
        input.value = domain;
    }

    const btn = document.getElementById('search-btn');
    btn.classList.add('loading');
    showSection('loading-section');
    
    ['step-mx', 'step-spf', 'step-dmarc', 'step-dkim', 'step-bimi', 'step-advanced', 'step-analysis'].forEach(s => setStep(s, null));
    
    const lang = getLanguage();
    const t = translations[lang];
    
    try {
        setStep('step-mx', 'active');
        const mxRecords = await getMX(domain);
        setStep('step-mx', 'done');

        setStep('step-spf', 'active');
        const spfRaw = await getSPF(domain);
        const spfTree = spfRaw ? await getSPFLookupTree(domain) : null;
        const spfLookups = spfTree ? spfTree.lookups : 0;
        setStep('step-spf', 'done');

        setStep('step-dmarc', 'active');
        const dmarcRaw = await getDMARC(domain);
        setStep('step-dmarc', 'done');

        setStep('step-dkim', 'active');
        const icesSelectors = KB.ices_dkim_selectors || [];
        const dkimRecords = await getDKIM(domain, dkimSelector, spfRaw, icesSelectors);
        setStep('step-dkim', 'done');

        setStep('step-bimi', 'active');
        const bimiRecord = await getBIMI(domain);
        setStep('step-bimi', 'done');

        // NEW: Advanced DNS checks (parallel)
        setStep('step-advanced', 'active');
        const [allTxtRecords, mtaSts, tlsRpt, nsRecords] = await Promise.all([
            getAllTXT(domain),
            getMTASTS(domain),
            getTLSRPT(domain),
            getNS(domain)
        ]);

        // Process advanced data
        const txtVerifications = identifyTXTVerifications(allTxtRecords);
        const nsProvider = identifyNSProvider(nsRecords);
        const tlsrptReporters = analyzeTLSRPT(tlsRpt);
        setStep('step-advanced', 'done');

        setStep('step-analysis', 'active');
        await new Promise(r => setTimeout(r, 400));

        // Resolve MX IPs and check RBL lists in parallel
        const RBL_LISTS = ['bl.spamcop.net', 'dnsbl.sorbs.net', 'dnsbl.dronebl.org'];
        const rblResults = await Promise.all(
            mxRecords.slice(0, 3).map(async (mx) => {
                const ip = await getIPAddress(mx.host);
                const checks = ip
                    ? await Promise.all(RBL_LISTS.map(rbl => checkRBL(ip, rbl)))
                    : RBL_LISTS.map(rbl => ({ listed: false, rbl }));
                return { host: mx.host, ip, checks };
            })
        );
        
        const result = analyze(mxRecords, spfRaw, dmarcRaw, {
            txtVerifications,
            nsProvider,
            nsRecords,
            mtaSts,
            tlsRpt,
            tlsrptReporters
        });
        result.spfLookups = spfLookups;
        result.spfTree = spfTree;
        result.dkimRecords = dkimRecords;
        result.bimiRecord = bimiRecord;
        result.rblResults = rblResults;
        result.scoreCard = calculateScoreAndFindings(result);
        
        state.currentDomain = domain;
        state.currentResult = result;
        setStep('step-analysis', 'done');

        await new Promise(r => setTimeout(r, 300));
        renderResults(domain, result);
        showSection('results-section');
    } catch (err) {
        console.error(err);
        document.getElementById('error-message').textContent = err.message || t.error_default_message;
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
        let domain = input.value.trim().toLowerCase();
        if (domain.includes('@')) {
            domain = domain.substring(domain.indexOf('@') + 1);
        }
        domain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');
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
        } catch(err) {}
        customKB.push(newEntry);
        localStorage.setItem('custom_kb_spf', JSON.stringify(customKB));

        closeKbModal();
        
        if (state.currentDomain) {
            runAnalysis(state.currentDomain, dkimInput ? dkimInput.value.trim() : null);
        }
    });
});
