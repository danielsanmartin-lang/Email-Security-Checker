import { parseMTASTSPolicy, validateMTASTSPolicy } from './parsers.js';

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

export async function queryDNS(name, type) {
    // Check cache first
    const cached = _getCached(name, type);
    if (cached) return cached;

    let data;
    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), DNS_TIMEOUT);
        const url = `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`;
        const res = await fetch(url, { signal: controller.signal });
        clearTimeout(timeoutId);
        if (!res.ok) throw new Error(`Google DNS failed: ${res.status}`);
        data = await res.json();
    } catch (e) {
        console.warn('Google DNS failed, falling back to Cloudflare DoH', e);
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), DNS_TIMEOUT);
            const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`;
            const res = await fetch(url, { headers: { 'Accept': 'application/dns-json' }, signal: controller.signal });
            clearTimeout(timeoutId);
            if (!res.ok) throw new Error(`Cloudflare DNS failed: ${res.status}`);
            data = await res.json();
        } catch (err) {
            throw new Error(`DNS queries failed for ${name} (${type})`);
        }
    }

    _setCache(name, type, data);
    return data;
}

export async function getMX(domain) {
    const data = await queryDNS(domain, 'MX');
    if (!data.Answer) return [];
    return data.Answer
        .filter(a => a.type === 15)
        .map(a => {
            const parts = a.data.split(' ');
            return { priority: parseInt(parts[0]), host: parts[1].replace(/\.$/, '') };
        })
        .sort((a, b) => a.priority - b.priority);
}

export async function getSPF(domain) {
    const data = await queryDNS(domain, 'TXT');
    if (!data.Answer) return { record: null, records: [], multiple: false };
    const records = [];
    for (const a of data.Answer) {
        if (a.data) {
            // A TXT record data field in Google/Cloudflare DoH may be enclosed in multiple quotes, e.g. "v=spf1 ..." "..."
            // Or simple quotes. We split by spaces outside quotes or match all quoted parts, but matching all parts inside double quotes is safest:
            const matches = [...a.data.matchAll(/"([^"\\]*(?:\\.[^"\\]*)*)"/g)];
            let txt = '';
            if (matches.length > 0) {
                txt = matches.map(m => m[1]).join('');
            } else {
                txt = a.data.replace(/"/g, '');
            }
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
            const matches = [...a.data.matchAll(/"([^"\\]*(?:\\.[^"\\]*)*)"/g)];
            let txt = '';
            if (matches.length > 0) {
                txt = matches.map(m => m[1]).join('');
            } else {
                txt = a.data.replace(/"/g, '');
            }
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
    const node = { domain, lookups: 0, children: [], error: null, record: null };
    if (depth > 10) {
        node.error = 'Límite de profundidad excedido (>10)';
        return node;
    }
    if (cache.has(domain)) {
        node.error = 'Loop detectado';
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
        node.error = e.message;
    }

    return node;
}

export async function getIPAddress(host) {
    try {
        const data = await queryDNS(host, 'A');
        if (data && data.Answer) {
            const aRecord = data.Answer.find(a => a.type === 1);
            if (aRecord) return aRecord.data;
        }
    } catch (e) {
        console.warn(`Failed to resolve IP for ${host}`, e);
    }
    return null;
}

export async function checkRBL(ip, rblHost) {
    try {
        const reversedIp = ip.split('.').reverse().join('.');
        const queryName = `${reversedIp}.${rblHost}`;
        const data = await queryDNS(queryName, 'A');
        if (data && data.Answer && data.Answer.length > 0) {
            return { listed: true, rbl: rblHost, details: data.Answer[0].data };
        }
    } catch (e) {
        // NXDOMAIN or DNS failure is normal, indicating clean status
    }
    return { listed: false, rbl: rblHost };
}

// ===== NEW: Advanced DNS queries for ICES detection =====

export async function getAllTXT(domain) {
    try {
        const data = await queryDNS(domain, 'TXT');
        if (!data.Answer) return [];
        return data.Answer
            .filter(a => a.type === 16)
            .map(a => a.data.replace(/"/g, ''));
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
            const matches = [...a.data.matchAll(/"([^"\\]*(?:\\.[^"\\]*)*)"/g)];
            let txt = '';
            if (matches.length > 0) {
                txt = matches.map(m => m[1]).join('');
            } else {
                txt = a.data.replace(/"/g, '');
            }
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
            const matches = [...a.data.matchAll(/"([^"\\]*(?:\\.[^"\\]*)*)"/g)];
            let txt = '';
            if (matches.length > 0) {
                txt = matches.map(m => m[1]).join('');
            } else {
                txt = a.data.replace(/"/g, '');
            }
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

