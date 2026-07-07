import { parseMTASTSPolicy, validateMTASTSPolicy, extractTxtValue } from './parsers.js';

// ===== DNS Cache =====
const _dnsCache = new Map();
const DNS_CACHE_TTL = 5 * 60 * 1000; // 5 minutes

export function clearDnsCache() {
    _dnsCache.clear();
}

function _getCached(name, type) {
    const key = `${name}:${type}`;
    const cached = _dnsCache.get(key);
    if (cached && Date.now() - cached.ts < DNS_CACHE_TTL) return cached.data;
    if (cached) _dnsCache.delete(key);
    return null;
}

function _setCache(name, type, data) {
    const key = `${name}:${type}`;
    _dnsCache.set(key, { data, ts: Date.now() });
    // Prune old entries if cache grows too large
    if (_dnsCache.size > 500) {
        const now = Date.now();
        for (const [k, v] of _dnsCache) {
            if (now - v.ts > DNS_CACHE_TTL) _dnsCache.delete(k);
        }
    }
}

// ===== DNS Query with timeout and fallback =====
const DNS_TIMEOUT = 8000; // 8 seconds

// RCODEs concluyentes: 0 = NOERROR, 3 = NXDOMAIN ("no existe" es una respuesta
// válida). Cualquier otro Status (2 = SERVFAIL, 5 = REFUSED…) significa que el
// resolver NO pudo responder: tratarlo como "sin registros" produciría un falso
// diagnóstico (p. ej. "sin SPF/DMARC" en dominios con DNSSEC roto).
const DNS_CONCLUSIVE_STATUSES = [0, 3];

async function _fetchDoH(url, headers) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), DNS_TIMEOUT);
    try {
        const res = await fetch(url, { headers, signal: controller.signal });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return await res.json();
    } finally {
        clearTimeout(timeoutId);
    }
}

export async function queryDNS(name, type) {
    // Check cache first
    const cached = _getCached(name, type);
    if (cached) return cached;

    const providers = [
        { label: 'Google', url: `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}` },
        { label: 'Cloudflare', url: `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`, headers: { 'Accept': 'application/dns-json' } }
    ];

    let badStatus = null;
    for (const provider of providers) {
        let candidate;
        try {
            candidate = await _fetchDoH(provider.url, provider.headers);
        } catch (e) {
            console.warn(`${provider.label} DoH failed for ${name} (${type})`, e);
            continue;
        }
        if (typeof candidate.Status === 'number' && !DNS_CONCLUSIVE_STATUSES.includes(candidate.Status)) {
            console.warn(`${provider.label} DoH returned Status ${candidate.Status} for ${name} (${type})`);
            badStatus = candidate.Status;
            continue;
        }
        // Respuesta concluyente: cachear y devolver. Las respuestas de error no
        // se cachean, para no fijar un fallo transitorio durante 5 minutos.
        _setCache(name, type, candidate);
        return candidate;
    }

    if (badStatus !== null) {
        const e = new Error(`DNS resolvers could not resolve ${name} (${type}): RCODE ${badStatus}`);
        e.code = 'servfail';
        throw e;
    }
    const e = new Error(`DNS queries failed for ${name} (${type})`);
    e.code = 'network';
    throw e;
}

// DoH RCODE: 0 = NOERROR, 3 = NXDOMAIN (dominio inexistente).
// Devuelve false solo si el resolver confirma NXDOMAIN en el ápex del dominio.
export async function checkDomainExists(domain) {
    const data = await queryDNS(domain, 'NS');
    if (data && typeof data.Status === 'number' && data.Status === 3) return false;
    return true;
}

export async function getMX(domain) {
    const data = await queryDNS(domain, 'MX');
    const empty = [];
    if (!data.Answer) return empty;
    const raw = data.Answer
        .filter(a => a.type === 15 && a.data)
        .map(a => {
            const parts = a.data.trim().split(/\s+/);
            if (parts.length < 2) return null;
            return { priority: parseInt(parts[0], 10), host: parts[1].replace(/\.$/, '') };
        })
        .filter(Boolean);

    // Null MX (RFC 7505): un único registro "0 ." (host vacío tras quitar el punto)
    // declara explícitamente que el dominio NO recibe correo. Devolvemos un array
    // vacío marcado con .nullMx para que el análisis lo reconozca como configuración
    // correcta (dominios aparcados) en vez de auditar hosts vacíos.
    const nullMx = raw.length > 0 && raw.every(r => r.priority === 0 && r.host === '');
    const hosts = raw.filter(r => r.host !== '').sort((a, b) => a.priority - b.priority);
    if (nullMx) {
        hosts.nullMx = true;
    }
    return hosts;
}

export async function getSPF(domain) {
    const data = await queryDNS(domain, 'TXT');
    if (!data.Answer) return { record: null, records: [], multiple: false };
    const records = [];
    for (const a of data.Answer) {
        if (a.data) {
            const txt = extractTxtValue(a.data);
            if (txt.startsWith('v=spf1')) {
                records.push(txt);
            }
        }
    }
    const uniqueRecords = [...new Set(records)];
    return {
        record: uniqueRecords[0] || null,
        records: uniqueRecords,
        multiple: uniqueRecords.length > 1
    };
}

export async function getDMARC(domain) {
    const data = await queryDNS(`_dmarc.${domain}`, 'TXT');
    if (!data.Answer) return { record: null, records: [], multiple: false };
    const records = [];
    for (const a of data.Answer) {
        if (a.data) {
            const txt = extractTxtValue(a.data);
            if (txt.startsWith('v=DMARC1')) {
                records.push(txt);
            }
        }
    }
    const uniqueRecords = [...new Set(records)];
    return {
        record: uniqueRecords[0] || null,
        records: uniqueRecords,
        multiple: uniqueRecords.length > 1
    };
}


export const COMMON_DKIM_SELECTORS = ['google', 'default', 's1', 's2', 'k1', 'k2', 'm1', 'mail', 'selector1'];

export function discoverDKIMSelectors(spfRaw) {
    if (!spfRaw) return [];
    const selectors = [];
    const lower = spfRaw.toLowerCase();
    
    if (lower.includes('_spf.google.com') || lower.includes('google.com')) {
        selectors.push('google');
    }
    if (lower.includes('outlook.com') || lower.includes('spf.protection.outlook.com')) {
        selectors.push('selector1', 'selector2');
    }
    if (lower.includes('mandrillapp.com')) {
        selectors.push('mandrill');
    }
    if (lower.includes('mcsv.net')) {
        selectors.push('k1', 'k2', 'k3');
    }
    if (lower.includes('sendgrid.net')) {
        selectors.push('smtp', 's1', 's2', 'k1');
    }
    if (lower.includes('mailgun.org')) {
        selectors.push('mg', 'k1', 'pic');
    }
    if (lower.includes('mktomail.com')) {
        selectors.push('m1');
    }
    if (lower.includes('hubspotemail.net') || lower.includes('hubspot.com')) {
        selectors.push('hs1', 'hs2');
    }
    if (lower.includes('salesforce.com')) {
        selectors.push('salesforce');
    }
    if (lower.includes('zoho.com') || lower.includes('zoho.eu')) {
        selectors.push('zmail');
    }
    
    return [...new Set(selectors)];
}

export async function getDKIM(domain, customSelector = null, spfRaw = null, icesSelectors = []) {
    let selectors = customSelector ? [customSelector] : COMMON_DKIM_SELECTORS;
    if (!customSelector && spfRaw) {
        const discovered = discoverDKIMSelectors(spfRaw);
        selectors = [...new Set([...discovered, ...COMMON_DKIM_SELECTORS, ...icesSelectors])];
    } else if (!customSelector && icesSelectors.length > 0) {
        selectors = [...new Set([...COMMON_DKIM_SELECTORS, ...icesSelectors])];
    }
    const results = [];
    const errors = [];
    const promises = selectors.map(async (selector) => {
        try {
            const data = await queryDNS(`${selector}._domainkey.${domain}`, 'TXT');
            if (data && data.Answer) {
                for (const a of data.Answer) {
                    const txt = a.data.replace(/"/g, '');
                    if (txt.startsWith('v=DKIM1')) {
                        results.push({ selector, record: txt });
                    }
                }
            }
        } catch(e) {
            errors.push({ selector, error: e.message });
        }
    });
    await Promise.allSettled(promises);
    return { records: results, errors };
}

export async function getBIMI(domain) {
    try {
        const data = await queryDNS(`default._bimi.${domain}`, 'TXT');
        if (data && data.Answer) {
            for (const a of data.Answer) {
                const txt = a.data.replace(/"/g, '');
                if (txt.startsWith('v=BIMI1')) {
                    const match = txt.match(/l=([^;]+)/);
                    const logo = match ? match[1].trim() : null;
                    return { record: txt, logo };
                }
            }
        }
    } catch(e) {
        return { error: e.message };
    }
    return null;
}

export async function getSPFLookupTree(domain, cache = new Set(), depth = 0) {
    // node.error es un CÓDIGO neutral de idioma ('depth_exceeded' | 'loop' | 'query_failed').
    // node.errorDetail contiene el mensaje técnico original (si aplica).
    const node = { domain, lookups: 0, children: [], error: null, errorDetail: null, record: null };
    if (depth > 10) {
        node.error = 'depth_exceeded';
        return node;
    }
    if (cache.has(domain)) {
        node.error = 'loop';
        return node;
    }
    cache.add(domain);

    try {
        const spfData = await getSPF(domain);
        const spf = spfData.record;
        if (!spf) return node;
        node.record = spf;

        const tokens = spf.split(/\s+/);
        for (const token of tokens) {
            let t = token.toLowerCase();
            if (/^[+\-~?]/.test(t)) t = t.substring(1);

            if (t.startsWith('include:')) {
                node.lookups++;
                const includeDomain = t.substring(8);
                const child = await getSPFLookupTree(includeDomain, cache, depth + 1);
                node.children.push({ type: 'include', target: includeDomain, tree: child });
                node.lookups += child.lookups;
            } else if (t.startsWith('a') || t.startsWith('mx') || t.startsWith('ptr') || t.startsWith('exists:') || t.startsWith('redirect=')) {
                if (t === 'a' || t.startsWith('a:') || t === 'mx' || t.startsWith('mx:') || t === 'ptr' || t.startsWith('ptr:') || t.startsWith('exists:')) {
                    node.lookups++;
                    node.children.push({ type: t.split(':')[0] || t, target: t.includes(':') ? t.substring(t.indexOf(':') + 1) : '(self)' });
                }
                if (t.startsWith('redirect=')) {
                    node.lookups++;
                    const redirectDomain = t.substring(9);
                    const child = await getSPFLookupTree(redirectDomain, cache, depth + 1);
                    node.children.push({ type: 'redirect', target: redirectDomain, tree: child });
                    node.lookups += child.lookups;
                }
            }
        }
    } catch (e) {
        node.error = 'query_failed';
        node.errorDetail = e.message;
    }

    return node;
}

// Resuelve todas las IPs (IPv4 e IPv6) de un host.
export async function getIPAddresses(host) {
    const ips = [];
    try {
        const [aData, aaaaData] = await Promise.all([
            queryDNS(host, 'A').catch(() => null),
            queryDNS(host, 'AAAA').catch(() => null)
        ]);
        if (aData && aData.Answer) {
            for (const a of aData.Answer) {
                if (a.type === 1 && a.data) ips.push(a.data);
            }
        }
        if (aaaaData && aaaaData.Answer) {
            for (const a of aaaaData.Answer) {
                if (a.type === 28 && a.data) ips.push(a.data);
            }
        }
    } catch (e) {
        console.warn(`Failed to resolve IPs for ${host}`, e);
    }
    return [...new Set(ips)];
}

// Compat: devuelve la primera IP (preferentemente IPv4).
export async function getIPAddress(host) {
    const ips = await getIPAddresses(host);
    return ips[0] || null;
}

// Expande una dirección IPv6 a sus 32 nibbles en orden inverso (formato de query RBL/PTR).
function expandIPv6ForRbl(ip) {
    // Manejar la abreviatura "::"
    const [head, tail] = ip.split('::');
    const headGroups = head ? head.split(':').filter(Boolean) : [];
    const tailGroups = tail ? tail.split(':').filter(Boolean) : [];
    const missing = 8 - (headGroups.length + tailGroups.length);
    if (missing < 0) return null;
    const groups = [...headGroups, ...Array(ip.includes('::') ? missing : 0).fill('0'), ...tailGroups];
    if (groups.length !== 8) return null;
    // Cada grupo a 4 hex chars
    const fullHex = groups.map(g => g.padStart(4, '0')).join('');
    if (fullHex.length !== 32) return null;
    return fullHex.split('').reverse().join('.');
}

// Comprueba una IP contra una DNSBL.
// status: 'listed' | 'clean' | 'error'
//   - 'listed'  : respuesta 127.0.0.x (la IP está en la lista)
//   - 'clean'   : NXDOMAIN / sin respuesta (no listada)
//   - 'error'   : 127.255.255.x (resolver público bloqueado/cuota) o fallo de red →
//                 resultado NO concluyente. Muchas DNSBL (Spamhaus, SpamCop…) rechazan
//                 las consultas que llegan vía resolvers DoH públicos (Google/Cloudflare),
//                 por lo que estas comprobaciones son best-effort.
export async function checkRBL(ip, rblHost) {
    try {
        let queryName;
        if (ip.includes(':')) {
            const reversed = expandIPv6ForRbl(ip);
            if (!reversed) return { status: 'error', listed: false, rbl: rblHost };
            queryName = `${reversed}.${rblHost}`;
        } else {
            const reversedIp = ip.split('.').reverse().join('.');
            queryName = `${reversedIp}.${rblHost}`;
        }
        const data = await queryDNS(queryName, 'A');
        if (data && data.Answer && data.Answer.length > 0) {
            const codes = data.Answer.filter(a => a.type === 1 && a.data).map(a => a.data);
            // 127.255.255.x ⇒ código de error de la DNSBL (consulta rechazada / cuota / resolver público)
            if (codes.length && codes.every(c => c.startsWith('127.255.255.'))) {
                return { status: 'error', listed: false, rbl: rblHost, details: codes[0] };
            }
            const listedCode = codes.find(c => c.startsWith('127.') && !c.startsWith('127.255.255.'));
            if (listedCode) {
                return { status: 'listed', listed: true, rbl: rblHost, details: listedCode };
            }
            // Respuesta presente pero fuera de 127.0.0.0/8 ⇒ no concluyente
            return { status: 'error', listed: false, rbl: rblHost, details: codes[0] || null };
        }
    } catch (e) {
        // Fallo de red ⇒ no concluyente (NXDOMAIN no lanza: se trata como 'clean' abajo)
        return { status: 'error', listed: false, rbl: rblHost };
    }
    return { status: 'clean', listed: false, rbl: rblHost };
}

// ===== NEW: Advanced DNS queries for ICES detection =====

export async function getAllTXT(domain) {
    try {
        const data = await queryDNS(domain, 'TXT');
        if (!data.Answer) return [];
        return data.Answer
            .filter(a => a.type === 16)
            .map(a => extractTxtValue(a.data));
    } catch (e) {
        console.warn(`Failed to get all TXT for ${domain}`, e);
        return [];
    }
}

export async function fetchMTASTSPolicyFile(domain) {
    const url = `https://mta-sts.${domain}/.well-known/mta-sts.txt`;
    const base = {
        url,
        httpStatus: null,
        fetchOk: false,
        body: null,
        parsed: null,
        mode: null,
        valid: false,
        error: null,
        validationReason: null
    };

    let res;
    let body;
    let usedUrl = url;

    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 8000);
        res = await fetch(url, {
            method: 'GET',
            cache: 'no-store',
            redirect: 'follow',
            signal: controller.signal
        });
        clearTimeout(timeoutId);
        body = await res.text();
    } catch (e) {
        console.warn(`Direct fetch for MTA-STS failed (likely CORS or network error). Trying proxy fallback.`, e);
        try {
            const proxyUrl = `https://api.allorigins.win/get?url=${encodeURIComponent(url)}`;
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 8000);
            const proxyRes = await fetch(proxyUrl, { signal: controller.signal });
            clearTimeout(timeoutId);
            if (!proxyRes.ok) throw new Error(`Proxy HTTP error: ${proxyRes.status}`);
            const data = await proxyRes.json();
            if (!data || !data.contents) throw new Error(`Empty contents from proxy`);
            body = data.contents;
            res = { ok: true, status: 200 };
            usedUrl = `${url} (via CORS proxy)`;
        } catch (proxyErr) {
            const message = e.name === 'AbortError' || proxyErr.name === 'AbortError'
                ? 'Policy fetch timed out'
                : `Direct fetch failed (CORS/Network) and CORS proxy fallback failed: ${proxyErr.message}`;
            return {
                ...base,
                error: message,
                validationReason: 'fetch_failed'
            };
        }
    }

    try {
        const parsed = parseMTASTSPolicy(body);
        const mode = parsed?.mode ? String(parsed.mode).toLowerCase() : null;
        const policyFetch = {
            url: usedUrl,
            httpStatus: res.status,
            fetchOk: res.ok,
            body,
            parsed,
            mode,
            error: null
        };
        const validation = validateMTASTSPolicy(policyFetch);
        return {
            ...policyFetch,
            valid: validation.valid,
            validationReason: validation.reason
        };
    } catch (parseErr) {
        return {
            ...base,
            url: usedUrl,
            error: `Failed to parse policy: ${parseErr.message}`,
            validationReason: 'parse_error'
        };
    }
}

export async function getMTASTS(domain) {
    try {
        const data = await queryDNS(`_mta-sts.${domain}`, 'TXT');
        if (!data.Answer) return null;
        for (const a of data.Answer) {
            const txt = extractTxtValue(a.data);
            if (txt.startsWith('v=STSv1')) {
                const idMatch = txt.match(/id=([^;]+)/);
                const result = {
                    record: txt,
                    id: idMatch ? idMatch[1].trim() : null
                };
                result.policy = await fetchMTASTSPolicyFile(domain);
                return result;
            }
        }
    } catch (e) {
        console.warn(`Failed to get MTA-STS for ${domain}`, e);
    }
    return null;
}

export async function getTLSRPT(domain) {
    try {
        const data = await queryDNS(`_smtp._tls.${domain}`, 'TXT');
        if (!data.Answer) return null;
        for (const a of data.Answer) {
            const txt = extractTxtValue(a.data);
            if (txt.startsWith('v=TLSRPTv1')) {
                const ruaMatch = txt.match(/rua=([^;]+)/);
                const rua = ruaMatch ? ruaMatch[1].trim().split(',').map(s => s.trim()) : [];
                return { record: txt, rua };
            }
        }
    } catch (e) {
        console.warn(`Failed to get TLS-RPT for ${domain}`, e);
    }
    return null;
}

export async function getNS(domain) {
    try {
        const data = await queryDNS(domain, 'NS');
        if (!data.Answer) return [];
        return data.Answer
            .filter(a => a.type === 2)
            .map(a => a.data.replace(/\.$/, ''));
    } catch (e) {
        console.warn(`Failed to get NS for ${domain}`, e);
        return [];
    }
}

export async function getSRV(domain) {
    const srvRecords = {};
    const checks = [
        { key: 'autodiscover', record: `_autodiscover._tcp.${domain}` },
        { key: 'imaps', record: `_imaps._tcp.${domain}` },
        { key: 'submission', record: `_submission._tcp.${domain}` }
    ];
    
    await Promise.all(checks.map(async check => {
        try {
            const data = await queryDNS(check.record, 'SRV');
            if (data.Answer && data.Answer.length > 0) {
                srvRecords[check.key] = data.Answer
                    .filter(a => a.type === 33)
                    .map(a => {
                        const parts = a.data.split(' ');
                        return {
                            priority: parts[0],
                            weight: parts[1],
                            port: parts[2],
                            target: parts[3] ? parts[3].replace(/\.$/, '') : ''
                        };
                    });
            }
        } catch (e) {
            console.warn(`Failed to query SRV for ${check.record}`, e);
        }
    }));
    
    return srvRecords;
}

// Detecta si el dominio está firmado con DNSSEC.
//   signed : hay registros DNSKEY (type 48) publicados en el ápex
//   ad     : el resolver marcó la respuesta como Authenticated Data (validada)
export async function getDNSSEC(domain) {
    try {
        const data = await queryDNS(domain, 'DNSKEY');
        const hasDnskey = !!(data && data.Answer && data.Answer.some(a => a.type === 48));
        const ad = !!(data && data.AD);
        return { signed: hasDnskey || ad, hasDnskey, ad };
    } catch (e) {
        return { signed: false, hasDnskey: false, ad: false, error: e.message };
    }
}

// Verifica la autorización de destinos DMARC EXTERNOS (RFC 7489 §7.1):
// si rua/ruf apunta a un dominio distinto del analizado, ese dominio debe publicar
// `<dominio>._report._dmarc.<destino>` con un registro v=DMARC1, o los informes se descartan.
//   authorized: true | false | null (null = no se pudo comprobar / error de red)
export async function checkDMARCExternalAuth(domain, uris) {
    const results = [];
    if (!uris || uris.length === 0) return results;
    const analyzed = domain.toLowerCase().replace(/\.$/, '');
    const seen = new Set();
    for (const uri of uris) {
        const m = String(uri).match(/mailto:[^@\s]+@([^\s!,;]+)/i);
        if (!m) continue;
        const destDomain = m[1].toLowerCase().replace(/\.$/, '');
        if (destDomain === analyzed) continue; // mismo dominio: no requiere autorización
        if (seen.has(destDomain)) continue;
        seen.add(destDomain);
        try {
            const data = await queryDNS(`${analyzed}._report._dmarc.${destDomain}`, 'TXT');
            let authorized = false;
            if (data && data.Answer) {
                for (const a of data.Answer) {
                    if (/^v=DMARC1/i.test(extractTxtValue(a.data))) { authorized = true; break; }
                }
            }
            results.push({ uri, destDomain, authorized });
        } catch (e) {
            results.push({ uri, destDomain, authorized: null });
        }
    }
    return results;
}

export async function getDANE(mxHosts) {
    const daneRecords = {};
    if (!mxHosts || mxHosts.length === 0) return daneRecords;
    await Promise.all(mxHosts.map(async mx => {
        try {
            const data = await queryDNS(`_25._tcp.${mx}`, 'TLSA');
            if (data.Answer && data.Answer.length > 0) {
                daneRecords[mx] = data.Answer
                    .filter(a => a.type === 52 || a.type === 32768) // 52 is TLSA type
                    .map(a => a.data);
            }
        } catch (e) {
            console.warn(`Failed to query DANE for _25._tcp.${mx}`, e);
        }
    }));
    return daneRecords;
}

