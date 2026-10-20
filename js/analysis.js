// analysis.js
// El análisis completo de un dominio, sin nada de interfaz: consulta el DNS, analiza y
// puntúa. Vive aparte de app.js (que pinta) para poder ejecutarse también fuera del
// navegador, por ejemplo en la calibración de las letras (scripts/calibrate.mjs).
import { getMX, getSPF, discoverDmarcPolicy, getDKIM, getBIMI, getSPFLookupTree, getIPAddresses, checkRBL, getAllTXT, getMTASTS, getTLSRPT, getNS, getSRV, getDANE, getDNSSEC, checkDMARCExternalAuth, checkDomainExists, getAutodiscover, getIpIntel, getDkimSelectorChain, checkLookalikes, checkMailSubdomains, getEntraTenant, COMMON_DKIM_SELECTORS, discoverDKIMSelectors } from './api.js';
import { analyze, calculateScoreAndFindings, identifyTXTVerifications, identifyNSProvider, analyzeTLSRPT, reclassifyMailHosting } from './analyzer.js';
import { KB } from './knowledge.js';
import { generateLookalikes } from './lookalike.js';
import { getCtNames, markLookalikeCertChecks, checkLookalikeCerts } from './ct.js';
import { selectMailSubdomains } from './mailSubdomains.js';
import { getSettings } from './settings.js';
import { extractRootDomain, abortError, isAbortError, swallow } from './utils.js';
import { parseDMARC } from './parsers.js';
import { evaluateDmarc } from './dmarc.js';

// Orquestación pura del análisis (sin DOM salvo el callback onStep). Devuelve el
// result principal ya puntuado + promesas para las detecciones en segundo plano, que el
// llamante pinta en cuanto resuelven. Lanza errores con .code ('nxdomain' | 'servfail' |
// 'network' | 'aborted') para que la capa de UI muestre el mensaje adecuado.
//
// `background: false` omite todo lo que no da la nota: las detecciones en segundo plano
// (awareness, dominios parecidos, subdominios con correo) y las consultas a terceros que
// no son DNS (logs CT, tenant de Microsoft). Sus promesas resuelven a null sin tocar la
// red. Lo usa la calibración, que solo quiere la nota.
//
// `signal` cancela el análisis: lo que siga en la cola DNS sale sin llegar a pedirse. Lo
// usa la interfaz cuando el usuario lanza otro dominio antes de que acabe este.
//
// Cada consulta espera SOLO a lo que necesita: el resultado llega cuando termina la rama
// más lenta, no la suma de etapas. El orden en que se lanzan importa, porque la cola DNS
// es FIFO dentro de cada prioridad: primero lo que desbloquea más trabajo (NS, MX, TXT,
// _dmarc, autodiscover) y el abanico de selectores DKIM al final.
export async function performAnalysis(domain, dkimSelector = null, { onStep = () => {}, background = true, signal } = {}) {
    if (signal && signal.aborted) throw abortError();
    // Controlador propio, enlazado al del llamante: además de la cancelación desde fuera,
    // un análisis que muere a medias (NXDOMAIN, sin MX ni SPF) cancela lo que lanzó.
    const controller = new AbortController();
    if (signal) signal.addEventListener('abort', () => controller.abort(), { once: true });
    const opts = { signal: controller.signal };
    const fail = (err) => {
        controller.abort();
        throw err;
    };

    ['step-mx', 'step-spf', 'step-dmarc', 'step-dkim', 'step-bimi', 'step-advanced'].forEach(s => onStep(s, 'active'));

    // ===== Todo lo que solo depende del dominio, en t=0 =====
    // La existencia del dominio (distingue NXDOMAIN de "sin registros") ya no hace de
    // puerta: se pregunta a la vez que lo demás y se espera la primera.
    const existsP = checkDomainExists(domain, opts);
    const mxP = getMX(domain, opts).then(r => { onStep('step-mx', 'done'); return r; });
    const spfP = getSPF(domain, opts);
    // DMARC con el DNS Tree Walk de RFC 9989 §4.10: política del propio dominio o, si no
    // publica, la de su dominio organizativo (o su PSD). El organizativo se DESCUBRE por
    // DNS en vez de estimarse con una lista de sufijos, que fallaba con marcas cortas bajo
    // un ccTLD (correo.abc.es no heredaba nada).
    const dmarcP = discoverDmarcPolicy(domain, opts).then((r) => {
        onStep('step-dmarc', 'done');
        return r;
    });
    // El MX dice quién FILTRA; autodiscover, la cadena DKIM y el tenant de Entra dicen
    // dónde VIVEN los buzones.
    const autodiscoverP = getAutodiscover(domain, opts);
    const entraP = background && getSettings().lookupEntraTenant
        ? getEntraTenant(domain, opts).catch(() => null)
        : Promise.resolve(null);
    // Certificate Transparency: la consulta más lenta. Es HTTP (no ocupa la cola DNS) y la
    // comparten awareness, hospedaje y subdominios con correo, así que sale ya.
    const ctNamesP = background ? getCtNames(domain, opts) : null;
    const bimiP = getBIMI(domain, opts);
    const advancedP = Promise.all([
        getAllTXT(domain, opts),
        getMTASTS(domain, opts),
        getTLSRPT(domain, opts),
        getNS(domain, opts),
        getSRV(domain, opts),
        getDNSSEC(domain, opts)
    ]).then(r => { onStep('step-advanced', 'done'); return r; });

    // DKIM: los selectores fijos (comunes + ICES) no dependen de nada y salen ya, al final
    // de la cola. Solo los que se deducen del SPF esperan al SPF. Con selectores elegidos
    // por el usuario se consultan esos y nada más.
    const icesSelectors = KB.ices_dkim_selectors || [];
    const customDkim = (Array.isArray(dkimSelector) ? dkimSelector : [dkimSelector]).filter(Boolean);
    const fixedDkimP = getDKIM(domain, dkimSelector, null, icesSelectors, opts);
    const dkimChainsP = getDkimSelectorChain(domain, undefined, opts);

    // SPF tree y los selectores DKIM del SPF dependen del registro SPF.
    const spfDerivedP = spfP.then(async (spfData) => {
        const spfRaw = spfData.record;
        const fixed = new Set([...COMMON_DKIM_SELECTORS, ...icesSelectors]);
        const extra = customDkim.length ? [] : discoverDKIMSelectors(spfRaw).filter(s => !fixed.has(s));
        const [spfTree, extraDkim] = await Promise.all([
            spfRaw ? getSPFLookupTree(domain, undefined, undefined, { ...opts }) : null,
            extra.length ? getDKIM(domain, extra, null, [], opts) : null
        ]);
        onStep('step-spf', 'done');
        return { spfData, spfRaw, spfTree, extraDkim };
    });
    // Si falla la consulta del SPF, DKIM ya no se pierde con él: los selectores fijos no
    // lo necesitaban.
    const dkimP = Promise.all([fixedDkimP, spfDerivedP.then(d => d.extraDkim, () => null)])
        .then(([base, extra]) => {
            onStep('step-dkim', 'done');
            return extra
                ? { records: [...base.records, ...extra.records], errors: [...base.errors, ...extra.errors], attempted: base.attempted + extra.attempted }
                : base;
        });

    // ===== Lo que depende del MX =====
    const mxListP = mxP.then(mx => mx, () => []);
    const daneP = mxListP.then(mx => getDANE(mx.map(r => r.host), opts));
    // IPs de los MX (como mucho 3): las usan la reputación RBL y el perfil de IPs.
    const mxIpsP = mxListP.then(mx => Promise.all(mx.slice(0, 3).map(async (r) => ({ host: r.host, ips: await getIPAddresses(r.host, opts) }))));
    const RBL_LISTS = KB.rbl_lists || ['bl.spamcop.net', 'dnsbl.dronebl.org'];
    const rblP = mxIpsP.then(list => Promise.all(list.map(async ({ host, ips }) => {
        // Una comprobación por lista RBL: marcada como listada si CUALQUIER IP del host
        // (IPv4 o IPv6) aparece en esa lista. El estado 'error' (consulta rechazada por la
        // DNSBL vía resolver público, o host sin IPs) debe llegar a la UI como
        // "inconcluso", nunca como "limpio".
        const checks = await Promise.all(RBL_LISTS.map(async (rbl) => {
            if (!ips.length) return { status: 'error', listed: false, rbl };
            const perIp = await Promise.all(ips.map(addr => checkRBL(addr, rbl, opts)));
            const hit = perIp.find(c => c.listed);
            if (hit) return hit;
            if (perIp.every(c => c.status === 'error')) return { status: 'error', listed: false, rbl };
            return { status: 'clean', listed: false, rbl };
        }));
        return { host, ip: ips[0] || null, ips, checks };
    })));

    // ===== Señales de la plataforma de buzón =====
    // Se reúnen aquí porque analyze() es síncrona y pura. Un fallo degrada a "sin panel",
    // nunca rompe el análisis.
    const mailHostingP = Promise.all([autodiscoverP, dkimChainsP, mxIpsP, daneP, entraP]).then(async ([autodiscover, dkimChains, mxIpsList, daneRecords, entraTenant]) => {
        const mxIps = {};
        for (const r of mxIpsList) mxIps[r.host] = r.ips || [];
        // Se perfilan como mucho 4 IPs para acotar el gasto.
        const ipsToProfile = [...new Set([...autodiscover.ips, ...Object.values(mxIps).flat()])].slice(0, 4);
        const intelList = await Promise.all(ipsToProfile.map(ip => getIpIntel(ip, opts).catch(() => null)));
        const ipIntel = {};
        for (const intel of intelList) if (intel) ipIntel[intel.ip] = intel;
        return { autodiscover, dkimChains, mxIps, ipIntel, daneRecords, entraTenant };
    }).catch((err) => {
        if (!isAbortError(err)) console.warn('Mail hosting signal gathering failed:', err);
        return undefined;
    });

    // ===== Lo que depende de DMARC =====
    // Sin BIMI propio, el receptor lo busca en el dominio organizativo (borrador BIMI,
    // "Organizational Domain" fallback): un subdominio hereda el logo de su marca.
    const bimiFinalP = Promise.all([bimiP, dmarcP.catch(() => null)]).then(async ([bimi, dmarc]) => {
        if (!(bimi && bimi.record) && dmarc && dmarc.orgDomain && dmarc.orgDomain !== domain) {
            const orgBimi = await getBIMI(dmarc.orgDomain, opts).catch(() => null);
            if (orgBimi && orgBimi.record) return { ...orgBimi, inheritedFrom: dmarc.orgDomain };
        }
        return bimi;
    }).then((bimi) => {
        onStep('step-bimi', 'done');
        return bimi;
    });
    // Autorización de destinos de informe DMARC externos (RFC 9990 §4). Solo los URIs
    // válidos del registro que aplica —los mismos que dará analyze()—: se antepone el
    // dominio DONDE se encontró la política y se compara contra su dominio organizativo.
    const externalAuthP = dmarcP.then((dmarc) => {
        const parsed = dmarc.record ? parseDMARC(dmarc.record) : null;
        // Varios registros en el propio nombre se descartan todos (RFC 9989 §4.10).
        if (!parsed || (dmarc.multiple && dmarc.source === 'author')) return [];
        const ev = evaluateDmarc(parsed);
        return checkDMARCExternalAuth(dmarc.policyDomain || domain, [...ev.rua.valid, ...ev.ruf.valid], { ...opts, orgDomain: dmarc.orgDomain || null });
    }).catch((err) => {
        if (!isAbortError(err)) console.warn('DMARC external auth check failed:', err);
        return [];
    });

    // ===== Dominios parecidos (typosquatting), en segundo plano =====
    // No puntúan, pero arrancan en cuanto se conocen el dominio organizativo, los MX y los
    // NS: son otras zonas, así que aprovechan con prioridad baja los huecos que deja el
    // análisis. Se comparan con el dominio organizativo, que es el que se registra, y con
    // sus MX y NS para reconocer los registros defensivos.
    const lookalikePromise = background
        ? Promise.all([dmarcP.catch(() => null), mxListP, getNS(domain, opts)]).then(async ([dmarc, mx, ns]) => {
            const baseDomain = (dmarc && dmarc.orgDomain) || extractRootDomain(domain);
            const lookalike = await checkLookalikes(generateLookalikes(baseDomain), {
                domain: baseDomain,
                mx: mx.map(r => r.host),
                ns
            }, { ...opts, priority: 'low' });
            // Los que se van a mirar en CT salen ya marcados como "comprobando".
            markLookalikeCertChecks(lookalike);
            return lookalike;
        }).catch((err) => {
            if (!isAbortError(err)) console.warn('Lookalike search failed:', err);
            return null;
        })
        : Promise.resolve(null);
    // Certificados vigentes de los parecidos que reciben correo (como mucho 3, en serie):
    // rellena `cert` en el mismo objeto y resuelve con él para que se repinte.
    const lookalikeCertsPromise = lookalikePromise.then(lookalike => (lookalike ? checkLookalikeCerts(lookalike, opts) : null))
        .catch((err) => {
            if (!isAbortError(err)) console.warn('Lookalike certificate check failed:', err);
            return null;
        });

    // Nada de lo lanzado puede quedar como "unhandled rejection" mientras se espera a la
    // existencia del dominio: cada promesa se consume más abajo, pero no todavía.
    for (const p of [existsP, mxP, spfDerivedP, dmarcP, bimiFinalP, advancedP, dkimP, ctNamesP].filter(Boolean)) p.catch(swallow);

    let exists;
    try {
        exists = await existsP;
    } catch (err) {
        fail(err);
    }
    if (!exists) {
        const e = new Error('Domain not found');
        e.code = 'nxdomain';
        fail(e);
    }

    // Degradación resiliente: un fallo transitorio en una consulta no debe descartar las
    // demás. Solo se aborta si fallan a la vez MX y el TXT del ápex (SPF), que son las
    // consultas nucleares.
    const [mxS, spfS, dmarcS, bimiS, advS] = await Promise.allSettled([
        mxP, spfDerivedP, dmarcP, bimiFinalP, advancedP
    ]);
    if (controller.signal.aborted) throw abortError();

    if (mxS.status === 'rejected' && spfS.status === 'rejected') {
        fail((mxS.reason && mxS.reason.code) ? mxS.reason : spfS.reason);
    }

    const mxRecords = mxS.status === 'fulfilled' ? mxS.value : [];
    const spfDerived = spfS.status === 'fulfilled'
        ? spfS.value
        : { spfData: { record: null, records: [], multiple: false }, spfRaw: null, spfTree: null, unavailable: true };
    const { spfData, spfRaw, spfTree } = spfDerived;
    const spfUnavailable = spfS.status === 'rejected';
    const dmarcData = dmarcS.status === 'fulfilled' ? dmarcS.value : { record: null, records: [], multiple: false };
    const dmarcUnavailable = dmarcS.status === 'rejected';
    const bimiRecord = bimiS.status === 'fulfilled' ? bimiS.value : null;
    const advanced = advS.status === 'fulfilled' ? advS.value : [[], null, null, [], {}, null];

    // Marca los pasos que fallaron para que no queden girando indefinidamente.
    if (mxS.status === 'rejected') onStep('step-mx', null);
    if (spfS.status === 'rejected') onStep('step-spf', null);
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

    // Las ramas que quedan ya iban en marcha desde que se supo su dato de entrada.
    const [dkimRecords, daneRecords, rblResults, signals, dmarcExternalAuth] = await Promise.all([
        dkimP, daneP, rblP, mailHostingP, externalAuthP
    ]);
    if (controller.signal.aborted) throw abortError();
    const mailHostingSignals = signals && {
        ...signals,
        googleDkim: (dkimRecords.records || []).some(r => r.selector === 'google')
    };

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
    result.dmarcExternalAuth = dmarcExternalAuth;

    result.scoreCard = calculateScoreAndFindings(result);
    // Momento real del escaneo: se fija una vez en el propio result y no se
    // recalcula al re-renderizar (p. ej. al cambiar de idioma) ni al exportar.
    result.scannedAt = new Date().toISOString();
    result.awarenessResult = null;
    onStep('step-analysis', 'done');

    // Awareness / Phishing Simulation: la parte más lenta (CT logs). Se devuelve
    // como promesa para poder renderizar el resto de resultados sin esperarla. Arranca
    // ahora y no antes porque sus sondas son de la MISMA zona que el análisis principal
    // y le quitarían huecos.
    if (!background) {
        const none = Promise.resolve(null);
        return { result, awarenessPromise: none, lookalikePromise, lookalikeCertsPromise, mailSubdomainsPromise: none, mailHostingPromise: none };
    }
    onStep('step-awareness', 'active');
    // Se le pasa el árbol SPF ya resuelto: así el PermError del panel de awareness sale
    // de la misma cuenta de lookups que el panel SPF, en vez de contradecirlo. Y los
    // nombres CT que ya se estaban pidiendo.
    // El detector (y su diccionario de firmas) se descarga aparte: solo hace falta aquí,
    // con el resultado principal ya pintado.
    const awarenessPromise = import('./awarenessDetector.js')
        .then(({ detectAwarenessVendors }) => detectAwarenessVendors(domain, { spfTree, ctNames: ctNamesP, signal: controller.signal }))
        .catch((err) => {
            if (!isAbortError(err)) console.warn('Awareness detection failed:', err);
            return null;
        })
        .then((a) => { onStep('step-awareness', 'done'); return a; });

    // Con los nombres CT: el hospedaje del correo se vuelve a clasificar (null si no hay
    // nada que recalcular)…
    const mailHostingPromise = ctNamesP
        .then(names => reclassifyMailHosting(result, names))
        .catch(() => null);
    // …y se consultan los subdominios que parecen enviar o recibir correo. Son de la zona
    // auditada: por eso salen ahora, con el análisis principal ya terminado, y con
    // prioridad baja.
    const mailSubdomainsPromise = ctNamesP
        .then(async (names) => ({
            ctNames: names.length,
            ...(await checkMailSubdomains(selectMailSubdomains(names, domain), { ...opts, priority: 'low' }))
        }))
        .catch((err) => {
            if (!isAbortError(err)) console.warn('Mail subdomain check failed:', err);
            return null;
        });

    return { result, awarenessPromise, lookalikePromise, lookalikeCertsPromise, mailSubdomainsPromise, mailHostingPromise };
}
