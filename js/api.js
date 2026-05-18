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

export async function getDKIM(domain, customSelector = null) {
    const selectors = customSelector ? [customSelector] : COMMON_DKIM_SELECTORS;
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
