export async function queryDNS(name, type) {
    try {
        const url = `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`;
        const res = await fetch(url);
        if (!res.ok) throw new Error(`Google DNS failed: ${res.status}`);
        return await res.json();
    } catch (e) {
        console.warn('Google DNS failed, falling back to Cloudflare DoH', e);
        try {
            const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`;
            const res = await fetch(url, { headers: { 'Accept': 'application/dns-json' } });
            if (!res.ok) throw new Error(`Cloudflare DNS failed: ${res.status}`);
            return await res.json();
        } catch (err) {
            throw new Error(`DNS queries failed for ${name} (${type})`);
        }
    }
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
    if (!data.Answer) return null;
    for (const a of data.Answer) {
        const txt = a.data.replace(/"/g, '');
        if (txt.startsWith('v=spf1')) return txt;
    }
    return null;
}

export async function getDMARC(domain) {
    const data = await queryDNS(`_dmarc.${domain}`, 'TXT');
    if (!data.Answer) return null;
    for (const a of data.Answer) {
        const txt = a.data.replace(/"/g, '');
        if (txt.startsWith('v=DMARC1')) return txt;
    }
    return null;
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
        const spf = await getSPF(domain);
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

export async function getMTASTS(domain) {
    try {
        const data = await queryDNS(`_mta-sts.${domain}`, 'TXT');
        if (!data.Answer) return null;
        for (const a of data.Answer) {
            const txt = a.data.replace(/"/g, '');
            if (txt.startsWith('v=STSv1')) {
                const idMatch = txt.match(/id=([^;]+)/);
                return { record: txt, id: idMatch ? idMatch[1].trim() : null };
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
            const txt = a.data.replace(/"/g, '');
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

