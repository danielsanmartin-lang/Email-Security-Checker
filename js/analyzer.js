import { KB } from './knowledge.js';
import { parseSPF, parseDMARC } from './parsers.js';

export function identifyMX(host) {
    const h = host.toLowerCase();
    for (const entry of KB.mx) {
        if (h.includes(entry.pattern)) return entry;
    }
    return { name: host, type: 'unknown' };
}

export function extractRootDomain(hostname) {
    if (!hostname) return '';
    const parts = hostname.split('.');
    if (parts.length <= 2) return hostname;
    const tld = parts[parts.length - 1];
    const sld = parts[parts.length - 2];
    if (tld.length === 2 && sld.length <= 3) {
        return parts.slice(-3).join('.');
    }
    return parts.slice(-2).join('.');
}

export function identifySPFService(value) {
    if (!value || value === '(self)') return null;
    const v = value.toLowerCase();
    for (const entry of KB.spf) {
        if (v.includes(entry.pattern)) return entry;
    }
    
    if (v.includes('.')) {
        const cleanDomain = v.replace(/^(include:|a:|mx:|ptr:)/, '');
        const rootDomain = extractRootDomain(cleanDomain);
        return {
            name: rootDomain,
            category: 'unknown',
            cat_label: 'Desconocido',
            is_unknown: true,
            search_query: cleanDomain
        };
    }
    return null;
}

export function identifyDMARCReporter(uri) {
    const u = uri.toLowerCase();
    for (const entry of KB.dmarc_reporters) {
        if (u.includes(entry.pattern)) return entry.name;
    }
    return null;
}

export function analyze(mxRecords, spfRaw, dmarcRaw) {
    const spfEntries = parseSPF(spfRaw);
    const dmarcParsed = parseDMARC(dmarcRaw);

    let provider = null;
    let providerSource = '';
    const segList = [];
    
    for (const mx of mxRecords) {
        const id = identifyMX(mx.host);
        if (id.type === 'provider' && !provider) {
            provider = id.name;
            providerSource = `MX apunta a ${mx.host}`;
        }
        if (id.type === 'seg') {
            segList.push({ name: id.name, source: `MX: ${mx.host}` });
        }
    }

    const spfServices = [];
    const icesList = [];
    
    for (const entry of spfEntries) {
        if (entry.type === 'include' || entry.type === 'a' || entry.type === 'redirect') {
            const svc = identifySPFService(entry.value);
            if (svc) {
                if (!provider && svc.category === 'email') {
                    provider = svc.name;
                    providerSource = `SPF include: ${entry.value}`;
                }
                if (svc.category === 'seg' && !segList.find(s => s.name === svc.name)) {
                    segList.push({ name: svc.name, source: `SPF: ${entry.value}` });
                }
                if (svc.category === 'ices') {
                    icesList.push({ name: svc.name, source: `SPF: ${entry.value}` });
                }
                spfServices.push({ ...svc, raw: entry.value });
            }
        }
    }

    if (!provider) {
        provider = 'No identificado';
        providerSource = 'No se encontraron indicadores claros en MX ni SPF';
    }

    let dmarcPolicy = 'No configurado';
    let dmarcPolicyClass = '';
    let dmarcRua = [];
    let dmarcRuf = [];
    let dmarcDetails = {};
    
    if (dmarcParsed) {
        const p = dmarcParsed.p || 'none';
        dmarcPolicy = p;
        dmarcPolicyClass = p;
        dmarcDetails = dmarcParsed;
        
        if (dmarcParsed.rua) {
            dmarcRua = dmarcParsed.rua.split(',').map(s => s.trim());
        }
        if (dmarcParsed.ruf) {
            dmarcRuf = dmarcParsed.ruf.split(',').map(s => s.trim());
        }
    }

    return {
        provider, providerSource, segList, icesList,
        spfRaw, spfEntries, spfServices,
        dmarcRaw, dmarcParsed, dmarcPolicy, dmarcPolicyClass,
        dmarcRua, dmarcRuf, dmarcDetails,
        mxRecords
    };
}

export function calculateScoreAndFindings(result) {
    let score = 0;
    const findings = [];

    // 1. SPF Check
    if (result.spfRaw) {
        score += 20;
        findings.push({
            status: 'success',
            key: 'finding_spf_ok'
        });
        
        const spfLookups = result.spfLookups || 0;
        if (spfLookups <= 10) {
            score += 10;
            findings.push({
                status: 'success',
                key: 'finding_spf_lookups_ok',
                replacements: { '{lookups}': spfLookups }
            });
        } else {
            findings.push({
                status: 'error',
                key: 'finding_spf_lookups_err',
                replacements: { '{lookups}': spfLookups }
            });
        }
    } else {
        findings.push({
            status: 'error',
            key: 'finding_spf_err'
        });
    }

    // 2. DMARC Check
    if (result.dmarcRaw) {
        score += 20;
        const policy = result.dmarcPolicy || 'none';
        findings.push({
            status: 'success',
            key: 'finding_dmarc_ok',
            replacements: { '{policy}': policy.toUpperCase() }
        });

        if (policy === 'reject') {
            score += 30;
            findings.push({
                status: 'success',
                key: 'finding_dmarc_policy_reject'
            });
        } else if (policy === 'quarantine') {
            score += 20;
            findings.push({
                status: 'warning',
                key: 'finding_dmarc_policy_quarantine'
            });
        } else if (policy === 'none') {
            score += 5;
            findings.push({
                status: 'warning',
                key: 'finding_dmarc_policy_none'
            });
        }

        // DMARC Reporting (rua/ruf)
        const hasRua = result.dmarcRua && result.dmarcRua.length > 0;
        const hasRuf = result.dmarcRuf && result.dmarcRuf.length > 0;
        if (hasRua || hasRuf) {
            score += 5;
            findings.push({
                status: 'success',
                key: 'finding_dmarc_reporting_ok'
            });
        } else {
            findings.push({
                status: 'warning',
                key: 'finding_dmarc_reporting_err'
            });
        }
    } else {
        findings.push({
            status: 'error',
            key: 'finding_dmarc_err'
        });
    }

    // 3. DKIM Check
    const dkimCount = (result.dkimRecords && result.dkimRecords.records) ? result.dkimRecords.records.length : 0;
    if (dkimCount > 0) {
        score += 10;
        findings.push({
            status: 'success',
            key: 'finding_dkim_ok',
            replacements: { '{count}': dkimCount }
        });
    } else {
        findings.push({
            status: 'warning',
            key: 'finding_dkim_err'
        });
    }

    // 4. BIMI Check
    const hasBimi = result.bimiRecord && !result.bimiRecord.error && result.bimiRecord.record;
    if (hasBimi) {
        score += 5;
        findings.push({
            status: 'success',
            key: 'finding_bimi_ok'
        });
    } else {
        findings.push({
            status: 'info',
            key: 'finding_bimi_err'
        });
    }

    // Determine Grade
    let grade = 'F';
    let cardClass = 'danger';
    if (score >= 95) { grade = 'A+'; cardClass = 'safe'; }
    else if (score >= 90) { grade = 'A'; cardClass = 'safe'; }
    else if (score >= 80) { grade = 'B'; cardClass = 'safe'; }
    else if (score >= 70) { grade = 'C'; cardClass = 'warning'; }
    else if (score >= 50) { grade = 'D'; cardClass = 'warning'; }
    else { grade = 'F'; cardClass = 'danger'; }

    return { score, grade, cardClass, findings };
}

