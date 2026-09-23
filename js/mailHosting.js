/**
 * mailHosting.js
 * ¿Los buzones de este dominio viven en la nube o en un servidor propio?
 *
 * POR QUÉ ESTE MÓDULO EXISTE
 * El resto del analizador deduce el "proveedor de correo" del registro MX. Pero el MX
 * responde a quién FILTRA el correo entrante, que es otra pregunta. Cuando hay un SEG
 * delante (Proofpoint, Mimecast, Hornetsecurity, IronPort), el MX tapa por completo lo
 * que hay detrás: telefonica.es y mercadona.es tienen ambos un gateway en el MX, y sin
 * embargo una tiene los buzones en Microsoft 365 y la otra en su propio centro de datos.
 *
 * Este módulo cubre ese segundo eje —la PLATAFORMA DE BUZÓN— y lo mantiene separado del
 * primero. El filtro de entrada se sigue calculando donde siempre y no se toca aquí: este
 * módulo no lee, puntúa ni nombra ningún SEG.
 *
 * ES PURO: no hace red. Recibe señales ya resueltas y devuelve el veredicto, igual que
 * detectSecurityLayers, para poder testearse con objetos literales.
 *
 * NO ALIMENTA LA PUNTUACIÓN. Dónde guarda una empresa sus buzones no es un control de
 * seguridad: on-premise no es inseguro per se. Puntuarlo sería el mismo error de categoría
 * que confundir el MX con la plataforma, que es justo lo que este módulo viene a arreglar.
 *
 * LO QUE NO SE PUEDE SABER DESDE FUERA
 * Esta herramienta audita dominios de terceros sin ningún acceso privilegiado. No se ven
 * versiones de producto ni vulnerabilidades, y no se puede distinguir un híbrido activo de
 * un `autodiscover` que quedó apuntando a un servidor viejo tras migrar del todo a la nube:
 * en DNS son idénticos. Por eso `undetermined` es un resultado de primera clase y la
 * evidencia se devuelve siempre, para que quien lea juzgue por sí mismo.
 *
 * ---------------------------------------------------------------------------
 * TÉCNICAS DESCARTADAS — documentadas para que nadie las reintroduzca
 *
 * 1. Sondear `<dominio-con-guiones>.mail.protection.outlook.com` para "detectar el tenant"
 *    de Microsoft 365. Es un FALSO POSITIVO SISTEMÁTICO: medido en vivo, devuelve NOERROR
 *    para glovoapp-com y wallapop-com, que son Google Workspace puro, y también para
 *    mercadona-es, csic-es y ugr-es. Solo un dominio inventado da NXDOMAIN. No prueba nada.
 *
 * 2. Leer la AUSENCIA de `autodiscover` como indicio de on-premise. Es un protocolo de
 *    Microsoft: los dominios de Google Workspace no lo publican nunca. La ausencia no es
 *    evidencia en ninguna de las dos direcciones.
 *
 * 3. Leer los literales `ip4:` del SPF como indicio de buzones locales. Hablan del relé de
 *    SALIDA, que es otro eje. telefonica.es publica 17 rangos propios y tiene los buzones
 *    en Microsoft 365.
 * ---------------------------------------------------------------------------
 */

import { KB } from './knowledge.js';
import { extractRootDomain, isSameOrSubdomain } from './utils.js';

// Umbrales idénticos a los de _segLevel en analyzer.js: la confianza debe significar lo
// mismo en toda la interfaz. No se importa de allí porque analyzer.js importa este módulo
// y se formaría un ciclo.
export function hostingLevel(score) {
    if (score >= 0.85) return 'alta';
    if (score >= 0.55) return 'media';
    return 'baja';
}

// Mínimo de evidencia para AFIRMAR algo; coincide con el corte de "media" de arriba, para
// que las dos partes de la interfaz estén de acuerdo en qué merece afirmarse. Por debajo,
// el veredicto es 'undetermined': preferimos no decir nada antes que decir algo que no se
// sostiene. Varias señales pesan MENOS que este umbral a propósito, para que no puedan
// decidir solas (ver KB.mail_hosting_weights).
const CLAIM_THRESHOLD = 0.55;

/** Combina pesos independientes con noisy-OR, igual que detectSecurityLayers. */
function noisyOr(weights) {
    if (!weights.length) return 0;
    return Math.round((1 - weights.reduce((acc, w) => acc * (1 - w), 1)) * 100) / 100;
}

/**
 * ¿El nombre de una organización de ASN corresponde al dominio auditado?
 *
 * No sirve `isSameBrand` de analyzer.js: aquella compara etiquetas de DOMINIO, y el nombre
 * de un ASN no es un dominio sino texto libre ("AS_INDITEX - INDUSTRIA DE DISENO TEXTIL
 * SOCIEDAD ANONIMA, ES"). Se normaliza a alfanuméricos y se busca la etiqueta de marca
 * dentro, con el mismo mínimo de 4 caracteres que usa isSameBrand para no emparejar por
 * casualidad etiquetas cortas.
 *
 * Es la señal más fuerte de infraestructura propia que existe: cuando una empresa anuncia
 * sus propios rangos, el ASN lleva literalmente su nombre.
 *
 * La lista de palabras genéricas evita que un dominio llamado "mail.com" o "cloud.es"
 * empareje con medio registro de ASN del mundo.
 */
const GENERIC_BRAND_LABELS = new Set([
    'mail', 'email', 'correo', 'group', 'grupo', 'cloud', 'tech', 'global', 'data',
    'host', 'server', 'telecom', 'info', 'online', 'network', 'digital', 'system'
]);

export function asnMatchesBrand(asName, domain) {
    const brand = extractRootDomain(String(domain || '').toLowerCase()).split('.')[0]
        || String(domain || '').toLowerCase().split('.')[0];
    if (!brand || brand.length < 4 || GENERIC_BRAND_LABELS.has(brand)) return false;
    const norm = String(asName || '').toLowerCase().replace(/[^a-z0-9]+/g, '');
    return norm.includes(brand);
}

/** ¿Dos nombres cuelgan del mismo dominio raíz? */
function sameRoot(hostA, domain) {
    if (!hostA || !domain) return false;
    // Por etiquetas primero: autodiscover.ine.es es de ine.es aunque la heurística de
    // dominio raíz dude con marcas cortas.
    if (isSameOrSubdomain(hostA, domain)) return true;
    const a = extractRootDomain(String(hostA).toLowerCase());
    const b = extractRootDomain(String(domain).toLowerCase());
    return !!a && !!b && a === b;
}

/** Clasifica un ASN contra las listas del diccionario. */
function classifyAsn(asn) {
    if (!asn) return null;
    const id = String(asn);
    for (const list of ['cloud_asns', 'cdn_asns', 'hoster_asns']) {
        const hit = (KB[list] || []).find(e => e.asn === id);
        if (hit) return hit;
    }
    return null;
}

/** Busca el destino de un CNAME en el diccionario de plataformas de buzón. */
function matchPlatformCname(cname, source) {
    if (!cname) return null;
    const v = String(cname).toLowerCase();
    return (KB.mailbox_platform_cnames || []).find(e => e.source === source && v.includes(e.pattern)) || null;
}

/** Extrae el tenant de M365 del destino del CNAME de DKIM. */
function extractTenant(cname) {
    const m = String(cname || '').match(/([a-z0-9-]+\.onmicrosoft\.com)/i);
    return m ? m[1].toLowerCase() : null;
}

/**
 * Clasifica el hospedaje del correo a partir de señales DNS ya resueltas.
 *
 * @param {object} signals
 * @param {string}  signals.domain        dominio auditado
 * @param {Array}   signals.mxIds         por cada MX: { host, type, name } (salida de identifyMX)
 * @param {object}  signals.mxIps         mapa host MX → IPs ya resueltas
 * @param {object}  signals.autodiscover  { cname, ips, status } de autodiscover.<dominio>
 * @param {object}  signals.ipIntel       mapa ip → { asn, asName, ptr } (ver getIpIntel)
 * @param {Array}   signals.dkimChains    [{ selector, cname, hasKey }] con el CNAME conservado
 * @param {boolean} signals.googleDkim    hay clave en google._domainkey
 * @param {object}  signals.daneRecords   mapa host → registros TLSA
 * @param {Array}   signals.ctHostnames   nombres vistos en Certificate Transparency
 * @param {boolean} signals.segFronting   hay un SEG en el MX (solo para el aviso; no puntúa)
 * @returns {{kind, confidence, level, platform, tenant, evidence, notes, incomplete}}
 */
export function classifyMailHosting(signals = {}) {
    const {
        domain = '',
        mxIds = [],
        mxIps = {},
        autodiscover = { cname: null, ips: [], status: 'ok' },
        ipIntel = {},
        dkimChains = [],
        googleDkim = false,
        daneRecords = {},
        ctHostnames = [],
        segFronting = false
    } = signals;

    const W = { ...(KB.mail_hosting_weights || {}) };
    const cloud = [];   // evidencia de plataforma en la nube
    const own = [];     // evidencia de infraestructura propia
    const notes = [];   // avisos para la interfaz (no son evidencia, no puntúan)
    let platform = 'unknown';
    let tenant = null;
    let hosterName = null;

    const push = (bucket, signal, value) => {
        const weight = W[signal];
        if (!weight || !value) return;
        if (bucket.some(e => e.signal === signal && e.value === value)) return;
        bucket.push({ signal, value, weight });
    };

    // --- 1. autodiscover: el mejor indicador externo de dónde están los buzones -----
    const adCname = autodiscover && autodiscover.cname;
    const adIps = (autodiscover && autodiscover.ips) || [];
    const adStatus = (autodiscover && autodiscover.status) || 'ok';

    const platformHit = matchPlatformCname(adCname, 'autodiscover');
    if (platformHit) {
        platform = platformHit.platform;
        push(cloud, 'autodiscover_cloud', adCname);
    } else if (adCname && sameRoot(adCname, domain)) {
        // El CNAME apunta dentro del propio dominio: correo.congreso.es, phpnodes…csic.es.
        // Señal robusta y que no depende de ningún tercero.
        push(own, 'autodiscover_own_domain', adCname);
    }

    for (const ip of adIps) {
        const intel = ipIntel[ip] || {};
        const asnClass = classifyAsn(intel.asn);

        if (asnClass && asnClass.kind === 'cdn') {
            // Un proxy inverso no dice NADA de dónde está el servidor real. Se descarta
            // la señal explícitamente: leerla como "no es de un hiperescalar, luego es
            // propia" sería justo el falso positivo que hay que evitar.
            notes.push({ key: 'cdn_asn', value: asnClass.name });
            continue;
        }
        if (asnClass && asnClass.kind === 'cloud') {
            if (platform === 'unknown') platform = 'cloud';
            // Peso por debajo del umbral A PROPÓSITO: el ASN de Microsoft cubre Exchange
            // Online y también las máquinas Azure donde alguien corre su propio Exchange;
            // el de Amazon cubre SES y cualquier EC2 de cliente. Un ASN nunca decide solo.
            push(cloud, 'autodiscover_cloud_asn', intel.asName || asnClass.name);
            continue;
        }
        // Si el CNAME ya resolvió a una plataforma en la nube, el extremo de autodiscover
        // ESTÁ en la nube y sus IPs no pueden sostener una pata on-premise: saltarlas evita
        // fabricar un híbrido fantasma cuando el hiperescalar aún no está catalogado.
        if (platformHit) continue;

        if (asnClass && asnClass.kind === 'hoster') {
            hosterName = intel.asName || asnClass.name;
            continue;
        }
        // ASN no catalogado: puede ser de la propia empresa o de un operador local.
        if (asnMatchesBrand(intel.asName, domain)) {
            push(own, 'autodiscover_own_asn', intel.asName);
        }
        if (intel.ptr && sameRoot(intel.ptr, domain)) {
            push(own, 'autodiscover_own_ptr', intel.ptr);
        } else if (intel.ptr && (KB.isp_ptr_patterns || []).some(p => intel.ptr.includes(p))) {
            push(own, 'ptr_isp_static', intel.ptr);
        }
    }

    // --- 2. DKIM: demuestra que EXISTE un tenant, no dónde está el buzón -----------
    // Solo cuenta UNA vez: selector1 y selector2 apuntan al mismo tenant, así que son el
    // mismo hecho visto dos veces. Combinarlos con noisy-OR como si fueran evidencia
    // independiente inflaría la confianza sin aportar información nueva.
    for (const chain of dkimChains) {
        const hit = matchPlatformCname(chain.cname, 'dkim');
        if (!hit) continue;
        if (platform === 'unknown' || platform === 'cloud') platform = hit.platform;
        if (tenant) continue;
        tenant = extractTenant(chain.cname);
        push(cloud, 'dkim_tenant_m365', tenant || chain.cname);
    }
    if (googleDkim && platform === 'unknown') platform = 'google';

    // --- 3. MX: aporta al eje del buzón solo cuando es un proveedor, no un gateway --
    for (const id of mxIds) {
        if (id.type === 'self') {
            // Por sí solo no alcanza el umbral: un hostname propio puede ser un CNAME a
            // un hosting. Lo que confirma el servidor propio es dónde APUNTA esa IP.
            push(own, 'mx_self', id.host || id.name);
            const ips = mxIps[id.host] || [];
            for (const ip of ips) {
                const asnClass = classifyAsn((ipIntel[ip] || {}).asn);
                if (!asnClass) push(own, 'mx_self_own_asn', `${id.host} → ${ip}`);
            }
        } else if (id.type === 'provider') {
            push(cloud, 'mx_cloud', id.name);
            if (platform === 'unknown' || platform === 'cloud') {
                platform = /microsoft/i.test(id.name) ? 'm365'
                    : /google/i.test(id.name) ? 'google'
                        : 'cloud';
            }
        }
    }

    // --- 4. Señales de refuerzo ----------------------------------------------------
    // DANE: solo cuenta si el TLSA está en un MX PROPIO. Microsoft 365 sí publica TLSA en
    // sus MX con DNSSEC (*.mx.microsoft), así que "hay TLSA" ya no implica "MTA
    // autogestionado": leerlo así clasificaba como on-premise a clientes de M365.
    const selfMx = new Set(mxIds
        .filter(id => id.type === 'self')
        .map(id => String(id.host || id.name || '').toLowerCase())
        .filter(Boolean));
    const daneHosts = Object.keys(daneRecords || {})
        .filter(h => (daneRecords[h] || []).length && selfMx.has(h.toLowerCase()));
    if (daneHosts.length) push(own, 'dane', daneHosts[0]);

    // Certificate Transparency: un certificado prueba que el nombre existió, no que el
    // servicio siga activo. Por eso es la señal más débil y nunca decide por sí sola.
    // (Preparada, pero NO cableada en v1: crt.sh es frágil y activarla convertiría algún
    // 'undetermined' honesto en una conjetura. Ver el README del módulo.)
    const onpremHost = (ctHostnames || []).find(n => {
        const label = String(n).toLowerCase().split('.')[0];
        return (KB.onprem_ct_hostnames || []).includes(label) && sameRoot(n, domain);
    });
    if (onpremHost) push(own, 'ct_onprem_host', onpremHost);

    // --- 5. Veredicto --------------------------------------------------------------
    const ownScore = noisyOr(own.map(e => e.weight));
    const cloudScore = noisyOr(cloud.map(e => e.weight));

    // La evidencia de CT no puede sostener sola una afirmación (ver arriba).
    const ownHasStandalone = own.some(e => e.signal !== 'ct_onprem_host');
    const ownClaims = ownScore >= CLAIM_THRESHOLD && ownHasStandalone;
    const cloudClaims = cloudScore >= CLAIM_THRESHOLD;

    let kind;
    let confidence;
    if (ownClaims && cloudClaims) {
        kind = 'hybrid';
        // Un híbrido se afirma con la señal MÁS DÉBIL de las dos: hay que sostener ambas
        // mitades, así que la confianza no puede ser mayor que la peor de ellas.
        confidence = Math.min(ownScore, cloudScore);
        if (platform === 'unknown' || platform === 'cloud') platform = 'own';
    } else if (ownClaims) {
        kind = 'on_premise';
        confidence = ownScore;
        platform = 'own';
    } else if (cloudClaims) {
        kind = 'cloud';
        confidence = cloudScore;
    } else if (hosterName) {
        kind = 'hosted_third_party';
        confidence = 0.6;
        platform = 'hosted';
    } else {
        kind = 'undetermined';
        confidence = 0;
    }

    // Una consulta que no se pudo resolver NO es una consulta sin registros. Si el
    // veredicto se queda corto Y además faltaron sondas, hay que decir "no se pudo
    // comprobar", no "no se encontró nada".
    const incomplete = adStatus === 'unavailable';
    if (incomplete) notes.push({ key: 'dns_incomplete' });

    // La ausencia de autodiscover es lo NORMAL en Google Workspace: es un protocolo de
    // Microsoft. Que no aparezca no es indicio de nada y conviene decirlo, para que nadie
    // lo lea como una pista de servidor propio.
    if (!adCname && !adIps.length && !incomplete) notes.push({ key: 'no_autodiscover' });

    // El aviso que cierra el hueco conceptual del informe: el MX identifica el filtro de
    // entrada, no dónde están los buzones.
    if (segFronting) notes.push({ key: 'seg_fronting' });

    const evidence = [...own, ...cloud].sort((a, b) => b.weight - a.weight);

    return {
        kind,
        confidence,
        level: hostingLevel(confidence),
        platform,
        tenant,
        ...(hosterName ? { hoster: hosterName } : {}),
        evidence,
        notes,
        incomplete
    };
}
