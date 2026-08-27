import { getMX, getSPF, getDMARC, getDKIM, getBIMI, getSPFLookupTree, getIPAddresses, checkRBL, getAllTXT, getMTASTS, getTLSRPT, getNS, getSRV, getDANE, getDNSSEC, checkDMARCExternalAuth, checkDomainExists } from './api.js';
import { analyze, calculateScoreAndFindings, identifyTXTVerifications, identifyNSProvider, analyzeTLSRPT, extractRootDomain } from './analyzer.js';
import { renderResults, renderAwarenessVendors, showSection, setStep } from './ui.js';
import { KB } from './knowledge.js';
import { getLanguage } from './lang.js';
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
        const { result, awarenessPromise } = await performAnalysis(domain, dkimSelector, {
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
