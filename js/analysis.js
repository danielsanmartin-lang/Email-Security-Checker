// analysis.js
// El análisis completo de un dominio, sin nada de interfaz: consulta el DNS, analiza y
// puntúa. Vive aparte de app.js (que pinta) para poder ejecutarse también fuera del
// navegador, por ejemplo en la calibración de las letras (scripts/calibrate.mjs).
import { getMX, getSPF, discoverDmarcPolicy, getDKIM, getBIMI, getSPFLookupTree, getIPAddresses, checkRBL, getAllTXT, getMTASTS, getTLSRPT, getNS, getSRV, getDANE, getDNSSEC, checkDMARCExternalAuth, checkDomainExists, getAutodiscover, getIpIntel, getDkimSelectorChain, checkLookalikes } from './api.js';
import { analyze, calculateScoreAndFindings, identifyTXTVerifications, identifyNSProvider, analyzeTLSRPT } from './analyzer.js';
import { KB } from './knowledge.js';
import { detectAwarenessVendors } from './awarenessDetector.js';
import { generateLookalikes } from './lookalike.js';
import { extractRootDomain } from './utils.js';

// Orquestación pura del análisis (sin DOM salvo el callback onStep). Devuelve el
// result principal ya puntuado + una promesa para la detección de awareness (la
// parte más lenta, por los CT logs), que el llamante renderiza en cuanto resuelve.
// Lanza errores con .code ('nxdomain' | 'servfail' | 'network') para que la capa
// de UI muestre el mensaje adecuado.
//
// `background: false` omite las detecciones en segundo plano (awareness y dominios
// parecidos): sus promesas resuelven a null sin tocar la red. Lo usa la calibración, que
// solo quiere la nota.
export async function performAnalysis(domain, dkimSelector = null, { onStep = () => {}, background = true } = {}) {
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
    // DMARC con el DNS Tree Walk de RFC 9989 §4.10: política del propio dominio o, si no
    // publica, la de su dominio organizativo (o su PSD). El organizativo se DESCUBRE por
    // DNS en vez de estimarse con una lista de sufijos, que fallaba con marcas cortas bajo
    // un ccTLD (correo.abc.es no heredaba nada).
    const dmarcP = discoverDmarcPolicy(domain).then((r) => {
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
        : { spfData: { record: null, records: [], multiple: false }, spfRaw: null, spfTree: null, dkimRecords: { records: [], errors: [], attempted: 0 }, unavailable: true };
    const { spfData, spfRaw, spfTree, dkimRecords } = spfDerived;
    const spfUnavailable = spfS.status === 'rejected';
    const dmarcData = dmarcS.status === 'fulfilled' ? dmarcS.value : { record: null, records: [], multiple: false };
    const dmarcUnavailable = dmarcS.status === 'rejected';
    let bimiRecord = bimiS.status === 'fulfilled' ? bimiS.value : null;
    // Sin BIMI propio, el receptor lo busca en el dominio organizativo (borrador BIMI,
    // "Organizational Domain" fallback): un subdominio hereda el logo de su marca.
    if (!(bimiRecord && bimiRecord.record) && dmarcData.orgDomain && dmarcData.orgDomain !== domain) {
        const orgBimi = await getBIMI(dmarcData.orgDomain).catch(() => null);
        if (orgBimi && orgBimi.record) bimiRecord = { ...orgBimi, inheritedFrom: dmarcData.orgDomain };
    }
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

    // ===== Fase 2b: señales de la plataforma de buzón =====
    // El MX dice quién FILTRA; estas sondas dicen dónde VIVEN los buzones. Se hacen aquí
    // porque analyze() es síncrona y pura. Un fallo degrada a "sin panel", nunca rompe
    // el análisis: por eso cada rama tiene su propio catch.
    let mailHostingSignals;
    try {
        const [autodiscover, dkimChains] = await Promise.all([
            getAutodiscover(domain),
            getDkimSelectorChain(domain)
        ]);
        // Las IPs de los MX ya las resolvió el paso de RBL: se reutilizan tal cual en vez
        // de volver a preguntar. Se perfilan como mucho 4 IPs para acotar el gasto.
        const mxIps = {};
        for (const r of rblResults) mxIps[r.host] = r.ips || [];
        const ipsToProfile = [...new Set([...autodiscover.ips, ...Object.values(mxIps).flat()])].slice(0, 4);
        const intelList = await Promise.all(ipsToProfile.map(ip => getIpIntel(ip).catch(() => null)));
        const ipIntel = {};
        for (const intel of intelList) if (intel) ipIntel[intel.ip] = intel;

        mailHostingSignals = {
            autodiscover,
            dkimChains,
            mxIps,
            ipIntel,
            daneRecords,
            googleDkim: (dkimRecords.records || []).some(r => r.selector === 'google')
        };
    } catch (err) {
        console.warn('Mail hosting signal gathering failed:', err);
        mailHostingSignals = undefined;
    }

    const result = analyze(mxRecords, spfRaw, dmarcRaw, {
        domain,
        mailHostingSignals,
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
        dmarcSource: dmarcData.source || null,
        dmarcPolicyDomain: dmarcData.policyDomain || null,
        dmarcOrgDomain: dmarcData.orgDomain || null,
        dmarcWalkIncomplete: !!dmarcData.incomplete,
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

    // Autorización de destinos de informe DMARC externos (RFC 9990 §4). Solo los URIs
    // válidos del registro que aplica: se antepone el dominio DONDE se encontró la política
    // y se compara contra su dominio organizativo.
    const ev = result.dmarcEval;
    const dmarcUris = ev ? [...ev.rua.valid, ...ev.ruf.valid] : [];
    try {
        result.dmarcExternalAuth = await checkDMARCExternalAuth(
            result.dmarcPolicyDomain || domain,
            dmarcUris,
            { orgDomain: result.dmarcOrgDomain }
        );
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
    if (!background) {
        return { result, awarenessPromise: Promise.resolve(null), lookalikePromise: Promise.resolve(null) };
    }
    onStep('step-awareness', 'active');
    // Se le pasa el árbol SPF ya resuelto: así el PermError del panel de awareness sale
    // de la misma cuenta de lookups que el panel SPF, en vez de contradecirlo.
    const awarenessPromise = detectAwarenessVendors(domain, { spfTree })
        .catch((err) => { console.warn('Awareness detection failed:', err); return null; })
        .then((a) => { onStep('step-awareness', 'done'); return a; });

    // Dominios parecidos (typosquatting), también en segundo plano: no puntúan y no deben
    // retrasar el resultado. Se comparan con el dominio organizativo, que es el que se
    // registra, y con sus MX y NS para reconocer los registros defensivos.
    const baseDomain = result.dmarcOrgDomain || extractRootDomain(domain);
    const lookalikePromise = checkLookalikes(generateLookalikes(baseDomain), {
        domain: baseDomain,
        mx: (result.mxRecords || []).map(r => r.host),
        ns: result.nsRecords || []
    }).catch((err) => { console.warn('Lookalike search failed:', err); return null; });

    return { result, awarenessPromise, lookalikePromise };
}
