import { KB } from './knowledge.js';
import { parseSPF, parseDMARC } from './parsers.js';

export function identifyMX(host, domain) {
    const h = host.toLowerCase();
    // First label of the MX hostname (e.g. "esa01" from "esa01.arquia.es")
    const firstLabel = h.split('.')[0];
    for (const entry of KB.mx) {
        if (entry.matchType === 'hostname_prefix') {
            // Match if the first hostname label starts with the pattern (e.g. "esa" matches "esa01", "esa1", "esa-gw")
            if (firstLabel.startsWith(entry.pattern)) return entry;
        } else {
            if (h.includes(entry.pattern)) return entry;
        }
    }
    if (domain) {
        const mxRoot = extractRootDomain(h);
        const domainRoot = extractRootDomain(domain.toLowerCase());
        // If MX root matches the analyzed domain root, it's the company's own mail server — not a SEG
        if (domainRoot && mxRoot && mxRoot === domainRoot) {
            return { name: host, type: 'self' };
        }
        // Only flag as SEG if the MX clearly belongs to a different, external domain
        if (domainRoot && mxRoot && mxRoot !== domainRoot) {
            return { name: mxRoot, type: 'seg' };
        }
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

// NEW: Identify ICES/SEG/other services from TXT verification tokens
export function identifyTXTVerifications(txtRecords) {
    if (!txtRecords || txtRecords.length === 0) return [];
    const found = [];
    const seen = new Set();
    for (const txt of txtRecords) {
        const lower = txt.toLowerCase();
        // Skip SPF and DMARC records (already analyzed elsewhere)
        if (lower.startsWith('v=spf1') || lower.startsWith('v=dmarc1')) continue;
        for (const entry of KB.txt_verification) {
            if (lower.includes(entry.pattern.toLowerCase()) && !seen.has(entry.name)) {
                seen.add(entry.name);
                found.push({
                    name: entry.name,
                    category: entry.category,
                    record: txt.length > 80 ? txt.substring(0, 77) + '...' : txt,
                    fullRecord: txt
                });
            }
        }
    }
    return found;
}

// NEW: Identify DNS provider from NS records
export function identifyNSProvider(nsRecords) {
    if (!nsRecords || nsRecords.length === 0) return null;
    for (const ns of nsRecords) {
        const lower = ns.toLowerCase();
        for (const entry of KB.ns_providers) {
            if (lower.includes(entry.pattern)) {
                return { name: entry.name, hint: entry.hint, ns };
            }
        }
    }
    return null;
}

// NEW: Analyze TLS-RPT reporting destinations
export function analyzeTLSRPT(tlsrpt) {
    if (!tlsrpt || !tlsrpt.rua || tlsrpt.rua.length === 0) return [];
    const reporters = [];
    for (const rua of tlsrpt.rua) {
        const lower = rua.toLowerCase();
        let identified = null;
        for (const entry of KB.tlsrpt_reporters) {
            if (lower.includes(entry.pattern)) {
                identified = entry.name;
                break;
            }
        }
        reporters.push({ uri: rua, reporter: identified });
    }
    return reporters;
}

export function analyze(mxRecords, spfRaw, dmarcRaw, advancedData = {}) {
    const domain = advancedData.domain || '';
    const spfEntries = parseSPF(spfRaw);
    const dmarcParsed = parseDMARC(dmarcRaw);

    let provider = null;
    let providerSource = '';
    const segList = [];
    const icesList = [];
    
    for (const mx of mxRecords) {
        const id = identifyMX(mx.host, domain);
        if (id.type === 'provider' && !provider) {
            provider = id.name;
            providerSource = `MX apunta a ${mx.host}`;
        }
        if (id.type === 'seg') {
            segList.push({ name: id.name, source: `MX: ${mx.host}` });
        }
        if (id.type === 'ices') {
            if (!icesList.find(i => i.name === id.name)) {
                icesList.push({ name: id.name, source: `MX: ${mx.host}` });
            }
        }
    }

    const spfServices = [];
    
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
                if (svc.category === 'ices' && !icesList.find(i => i.name === svc.name)) {
                    icesList.push({ name: svc.name, source: `SPF: ${entry.value}` });
                }
                spfServices.push({ ...svc, raw: entry.value });
            }
        }
    }

    // NEW: Process TXT verification tokens
    const txtVerifications = advancedData.txtVerifications || [];
    for (const v of txtVerifications) {
        if (v.category === 'seg' && !segList.find(s => s.name === v.name)) {
            segList.push({ name: v.name, source: `TXT verification: ${v.record}` });
        }
        if (v.category === 'ices' && !icesList.find(i => i.name === v.name)) {
            icesList.push({ name: v.name, source: `TXT verification: ${v.record}` });
        }
    }

    // NEW: Process NS provider hints
    const nsProvider = advancedData.nsProvider || null;

    // NEW: Process TLS-RPT reporters
    const tlsrptReporters = advancedData.tlsrptReporters || [];

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
        spfData: advancedData.spfData || { record: spfRaw, records: spfRaw ? [spfRaw] : [], multiple: false },
        dmarcRaw, dmarcParsed, dmarcPolicy, dmarcPolicyClass,
        dmarcRua, dmarcRuf, dmarcDetails,
        dmarcData: advancedData.dmarcData || { record: dmarcRaw, records: dmarcRaw ? [dmarcRaw] : [], multiple: false },
        mxRecords,
        // New advanced data
        txtVerifications,
        nsProvider,
        nsRecords: advancedData.nsRecords || [],
        mtaSts: advancedData.mtaSts || null,
        tlsRpt: advancedData.tlsRpt || null,
        tlsrptReporters
    };
}

export function calculateScoreAndFindings(result) {
    let score = 0;
    const findings = [];

    // 1. SPF Check
    if (result.spfRaw) {
        if (result.spfData && result.spfData.multiple) {
            findings.push({
                status: 'error',
                key: 'finding_spf_multiple'
            });
            score -= 10;
        } else {
            score += 20;
            findings.push({
                status: 'success',
                key: 'finding_spf_ok'
            });
        }

        // SPF Qualifier check
        if (result.spfEntries) {
            const allEntry = result.spfEntries.find(e => e.type === 'all');
            if (allEntry) {
                if (allEntry.qualifier === '+') {
                    score -= 25;
                    findings.push({
                        status: 'error',
                        key: 'finding_spf_all_pass'
                    });
                } else if (allEntry.qualifier === '?' || allEntry.qualifier === '') {
                    score -= 15;
                    findings.push({
                        status: 'warning',
                        key: 'finding_spf_all_neutral'
                    });
                } else if (allEntry.qualifier === '~') {
                    findings.push({
                        status: 'success',
                        key: 'finding_spf_all_softfail'
                    });
                } else if (allEntry.qualifier === '-') {
                    findings.push({
                        status: 'success',
                        key: 'finding_spf_all_hardfail'
                    });
                }
            }
        }
        
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
        if (result.dmarcData && result.dmarcData.multiple) {
            findings.push({
                status: 'error',
                key: 'finding_dmarc_multiple'
            });
            score -= 10;
        } else {
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
        }

        // DMARC Syntax validation (new)
        if (result.dmarcParsed) {
            const v = result.dmarcParsed.v;
            const p = result.dmarcParsed.p;

            if (v !== 'DMARC1') {
                score -= 10;
                findings.push({
                    status: 'error',
                    key: 'finding_dmarc_version_invalid'
                });
            }

            if (!p || !['none', 'quarantine', 'reject'].includes(p.toLowerCase())) {
                score -= 25;
                findings.push({
                    status: 'error',
                    key: 'finding_dmarc_policy_invalid'
                });
            }
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

    // 5. MTA-STS Check (DNS TXT + HTTPS policy file with mode: enforce)
    if (!result.mtaSts) {
        findings.push({
            status: 'info',
            key: 'finding_mta_sts_err'
        });
    } else if (result.mtaSts.policy?.valid) {
        score += 5;
        findings.push({
            status: 'success',
            key: 'finding_mta_sts_ok'
        });
    } else {
        score -= 15;
        const policy = result.mtaSts.policy || {};
        const replacements = {};
        if (policy.httpStatus != null && policy.httpStatus !== 200) {
            replacements['{status}'] = String(policy.httpStatus);
        } else if (policy.mode) {
            replacements['{mode}'] = policy.mode;
        }
        findings.push({
            status: 'error',
            id: 'MTA_STS_POLICY_INVALID',
            type: 'error',
            key: 'finding_mta_sts_policy_invalid',
            message: 'MTA-STS TXT record exists but the HTTPS policy file is missing, invalid, or not set to enforce.',
            replacements: Object.keys(replacements).length ? replacements : undefined
        });
    }

    // 6. TLS-RPT Check (bonus)
    if (result.tlsRpt) {
        findings.push({
            status: 'success',
            key: 'finding_tls_rpt_ok'
        });
    } else {
        findings.push({
            status: 'info',
            key: 'finding_tls_rpt_err'
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


