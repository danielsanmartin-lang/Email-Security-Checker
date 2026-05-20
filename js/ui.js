import { KB } from './knowledge.js';
import { identifyMX, identifySPFService, identifyDMARCReporter } from './analyzer.js';
import { translations } from './i18n.js';
import { getLanguage } from './lang.js';

export function getCategoryLabel(svc, lang) {
    if (!svc) return '';
    const labelTranslations = {
        es: {
            'Proveedor Email': 'Proveedor Email',
            'Proveedor Email / Transaccional': 'Proveedor Email / Transaccional',
            'Transaccional': 'Transaccional',
            'Firmas Email': 'Firmas Email',
            'CRM': 'CRM',
            'CRM/Marketing': 'CRM/Marketing',
            'Marketing': 'Marketing',
            'Soporte': 'Soporte',
            'SEG': 'SEG',
            'ICES': 'ICES',
            'Concienciación': 'Concienciación',
            'Firmas Digitales': 'Firmas Digitales',
            'ERP/CRM': 'ERP/CRM',
            'RRHH': 'RRHH',
            'ITSM': 'ITSM',
            'Turismo/CRM': 'Turismo/CRM',
            'Soporte/ITSM': 'Soporte/ITSM',
            'Desconocido': 'Desconocido',
            'Otro / Varios': 'Otro / Varios'
        },
        en: {
            'Proveedor Email': 'Email Provider',
            'Proveedor Email / Transaccional': 'Email Provider / Transactional',
            'Transaccional': 'Transactional',
            'Firmas Email': 'Email Signatures',
            'CRM': 'CRM',
            'CRM/Marketing': 'CRM/Marketing',
            'Marketing': 'Marketing',
            'Soporte': 'Support',
            'SEG': 'SEG',
            'ICES': 'ICES',
            'Concienciación': 'Awareness Training',
            'Firmas Digitales': 'Digital Signatures',
            'ERP/CRM': 'ERP/CRM',
            'RRHH': 'HR',
            'ITSM': 'ITSM',
            'Turismo/CRM': 'Tourism/CRM',
            'Soporte/ITSM': 'Support/ITSM',
            'Desconocido': 'Unknown',
            'Otro / Varios': 'Other / Misc'
        }
    };
    
    const cat = svc.category;
    const catLabel = svc.cat_label || svc.catLabel || '';
    
    if (labelTranslations[lang] && labelTranslations[lang][catLabel]) {
        return labelTranslations[lang][catLabel];
    }
    
    const categoryDefaults = {
        es: {
            email: 'Proveedor Email',
            seg: 'SEG',
            ices: 'ICES',
            marketing: 'Marketing',
            transactional: 'Transaccional',
            crm: 'CRM',
            signatures: 'Firmas Email',
            support: 'Soporte',
            other: 'Otro',
            unknown: 'Desconocido'
        },
        en: {
            email: 'Email Provider',
            seg: 'SEG',
            ices: 'ICES',
            marketing: 'Marketing',
            transactional: 'Transactional',
            crm: 'CRM',
            signatures: 'Email Signatures',
            support: 'Support',
            other: 'Other',
            unknown: 'Unknown'
        }
    };
    
    return (categoryDefaults[lang] && categoryDefaults[lang][cat]) || catLabel || (lang === 'es' ? 'Desconocido' : 'Unknown');
}

export function openKbModal(domain) {
    document.getElementById('kb-domain').value = domain;
    document.getElementById('kb-name').value = '';
    document.getElementById('kb-category').value = 'marketing';
    document.getElementById('add-kb-modal').classList.remove('hidden');
    document.getElementById('kb-name').focus();
}

export function closeKbModal() {
    document.getElementById('add-kb-modal').classList.add('hidden');
}

window.openKbModal = openKbModal;

// ===== Global Tooltip System =====
let _tooltipEl = null;

function getTooltipEl() {
    if (!_tooltipEl) {
        _tooltipEl = document.createElement('div');
        _tooltipEl.className = 'tooltip-helper hidden';
        document.body.appendChild(_tooltipEl);

        document.addEventListener('mouseover', (e) => {
            const trigger = e.target.closest('[data-tooltip]');
            if (!trigger) { _tooltipEl.classList.add('hidden'); return; }
            const text = trigger.getAttribute('data-tooltip');
            if (!text) return;
            _tooltipEl.textContent = text;
            _tooltipEl.classList.remove('hidden');
        });

        document.addEventListener('mousemove', (e) => {
            if (_tooltipEl.classList.contains('hidden')) return;
            const margin = 12;
            let x = e.clientX + margin;
            let y = e.clientY + margin;
            const rect = _tooltipEl.getBoundingClientRect();
            if (x + rect.width > window.innerWidth - margin) x = e.clientX - rect.width - margin;
            if (y + rect.height > window.innerHeight - margin) y = e.clientY - rect.height - margin;
            _tooltipEl.style.left = `${x + window.scrollX}px`;
            _tooltipEl.style.top  = `${y + window.scrollY}px`;
        });

        document.addEventListener('mouseout', (e) => {
            if (!e.relatedTarget || !e.relatedTarget.closest('[data-tooltip]')) {
                _tooltipEl.classList.add('hidden');
            }
        });
    }
    return _tooltipEl;
}
// Ensure tooltip element exists on load
document.addEventListener('DOMContentLoaded', () => getTooltipEl());

export function showSection(id) {
    ['loading-section', 'error-section', 'results-section'].forEach(s => {
        document.getElementById(s).classList.add('hidden');
    });
    if (id) document.getElementById(id).classList.remove('hidden');
}

export function setStep(stepId, state) {
    const el = document.getElementById(stepId);
    if (!el) return;
    el.classList.remove('active', 'done');
    if (state) el.classList.add(state);
    const check = el.querySelector('.check-icon');
    if (check) {
        if (state === 'done') check.classList.remove('hidden');
        else check.classList.add('hidden');
    }
}

export function renderSPFTree(tree) {
    if (!tree) return '';
    let html = `<ul class="spf-tree">`;
    html += `<li><strong>${tree.domain}</strong> <span style="color:var(--text-muted)">(${tree.lookups} lookups)</span> ${tree.error ? `<span style="color:#ef4444; margin-left: 8px;">[Error: ${tree.error}]</span>` : ''}`;
    if (tree.children && tree.children.length > 0) {
        html += `<ul>`;
        for (const child of tree.children) {
            if (child.tree) {
                html += `<li><span class="spf-tree-type tag tag--unknown">${child.type}</span>: ${renderSPFTree(child.tree)}</li>`;
            } else {
                html += `<li><span class="spf-tree-type tag tag--unknown">${child.type}</span>: ${child.target}</li>`;
            }
        }
        html += `</ul>`;
    }
    html += `</li></ul>`;
    return html;
}

function translateProviderSource(source, lang) {
    if (!source) return '';
    const t = translations[lang];
    if (source.includes('MX apunta a')) {
        return source.replace('MX apunta a', t.evidence_mx);
    }
    if (source.includes('SPF include:')) {
        return source.replace('SPF include:', t.evidence_spf);
    }
    if (source.includes('No se encontraron indicadores claros en MX ni SPF')) {
        return t.unidentified_provider_detail;
    }
    return source;
}

export function translateDOM() {
    const lang = getLanguage();
    const t = translations[lang];
    if (!t) return;

    // Elements with data-i18n
    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        if (t[key]) {
            const pulseDot = el.querySelector('.pulse-dot');
            const svg = el.querySelector('svg');
            
            if (pulseDot || svg) {
                let hasUpdatedText = false;
                for (const node of el.childNodes) {
                    if (node.nodeType === Node.TEXT_NODE && node.textContent.trim() !== '') {
                        node.textContent = t[key];
                        hasUpdatedText = true;
                    }
                }
                if (!hasUpdatedText) {
                    const savedElements = [];
                    if (pulseDot) savedElements.push(pulseDot);
                    if (svg) savedElements.push(svg);
                    
                    el.innerHTML = '';
                    savedElements.forEach(se => el.appendChild(se));
                    if (savedElements.length > 0) {
                        el.appendChild(document.createTextNode(' '));
                    }
                    el.appendChild(document.createTextNode(t[key]));
                }
            } else {
                if (t[key].includes('<') && t[key].includes('>')) {
                    el.innerHTML = t[key];
                } else {
                    el.textContent = t[key];
                }
            }
        }
    });

    // Titles
    document.querySelectorAll('[data-i18n-title]').forEach(el => {
        const key = el.getAttribute('data-i18n-title');
        if (t[key]) {
            el.setAttribute('title', t[key]);
        }
    });

    // Placeholders
    document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
        const key = el.getAttribute('data-i18n-placeholder');
        if (t[key]) {
            el.setAttribute('placeholder', t[key]);
        }
    });

    // Update Language Selector button state (flag, text code)
    const btnFlag = document.getElementById('lang-btn-flag');
    const btnText = document.getElementById('lang-btn-text');
    
    if (btnText) btnText.textContent = lang.toUpperCase();
    if (btnFlag) {
        if (lang === 'es') {
            btnFlag.innerHTML = `<svg viewBox="0 0 3 2" width="20" height="13.3"><rect width="3" height="2" fill="#AD1519"/><rect height="1" y="0.5" width="3" fill="#FABD00"/></svg>`;
        } else {
            btnFlag.innerHTML = `<svg viewBox="0 0 60 30" width="20" height="10"><path fill="#012169" d="M0 0h60v30H0z"/><path fill="#FFF" d="m0 0 60 30h-7L0 3.5zM0 30 60 0h-7L0 26.5zM60 30 0 0h7l53 26.5zM60 0 0 30h7l53-26.5zM30 0h-6v30h6zm-30 12h60v6H0z"/><path fill="#FFF" d="M27 0h6v30h-6zm-27 12h60v6H0z"/><path fill="#C8102E" d="M28 0h4v30h-4zm-28 13h60v4H0z"/></svg>`;
        }
    }

    // Update active class in selector dropdown list
    document.querySelectorAll('.lang-dropdown__item').forEach(item => {
        if (item.getAttribute('data-lang') === lang) {
            item.classList.add('active');
        } else {
            item.classList.remove('active');
        }
    });
}

export function renderResults(domain, result) {
    const lang = getLanguage();
    const t = translations[lang];

    // Retrieve Security Score from result.scoreCard
    const { score, grade, cardClass, findings } = result.scoreCard || { score: 0, grade: 'F', cardClass: 'danger', findings: [] };

    // Render Score UI
    const scoreCard = document.getElementById('score-card');
    if (scoreCard) {
        scoreCard.className = `score-card ${cardClass}`;
        
        const scoreNumberEl = document.getElementById('score-number');
        const scoreGradeEl = document.getElementById('score-grade');
        const ringFillEl = document.getElementById('score-ring-fill');
        const findingsEl = document.getElementById('score-findings');

        if (scoreNumberEl) scoreNumberEl.textContent = score;
        if (scoreGradeEl) scoreGradeEl.textContent = grade;
        
        if (ringFillEl) {
            const circumference = 314;
            const offset = circumference - (score / 100) * circumference;
            ringFillEl.style.strokeDashoffset = offset;
        }

        if (findingsEl) {
            findingsEl.innerHTML = findings.map(f => {
                let iconColor = 'currentColor';
                let svgIcon = '';
                if (f.status === 'success') {
                    iconColor = '#10b981';
                    svgIcon = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="${iconColor}" stroke-width="3" stroke-linecap="round" stroke-linejoin="round">
                        <polyline points="20 6 9 17 5 12" />
                    </svg>`;
                } else if (f.status === 'warning') {
                    iconColor = '#f59e0b';
                    svgIcon = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="${iconColor}" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                        <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
                        <line x1="12" y1="9" x2="12" y2="13" />
                        <line x1="12" y1="17" x2="12.01" y2="17" />
                    </svg>`;
                } else if (f.status === 'error') {
                    iconColor = '#ef4444';
                    svgIcon = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="${iconColor}" stroke-width="3" stroke-linecap="round" stroke-linejoin="round">
                        <line x1="18" y1="6" x2="6" y2="18" />
                        <line x1="6" y1="6" x2="18" y2="18" />
                    </svg>`;
                } else {
                    iconColor = '#64748b';
                    svgIcon = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="${iconColor}" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                        <circle cx="12" cy="12" r="10" />
                        <line x1="12" y1="16" x2="12" y2="12" />
                        <line x1="12" y1="8" x2="12.01" y2="8" />
                    </svg>`;
                }
                
                let text = t[f.key] || '';
                if (f.replacements) {
                    for (const [placeholder, val] of Object.entries(f.replacements)) {
                        text = text.replace(placeholder, val);
                    }
                }

                return `<div class="finding-item">
                    <div class="finding-item__icon">${svgIcon}</div>
                    <span class="finding-item__text">${text}</span>
                </div>`;
            }).join('');
        }
    }

    document.getElementById('result-domain').textContent = domain;
    document.getElementById('result-timestamp').textContent = new Date().toLocaleString(lang === 'es' ? 'es-ES' : 'en-US');

    let providerDisplay = result.provider;
    if (providerDisplay === 'No identificado') {
        providerDisplay = t.unidentified_provider;
    }
    document.getElementById('summary-provider-value').textContent = providerDisplay;
    
    const secValue = document.getElementById('summary-security-value');
    if (result.segList.length > 0) {
        secValue.textContent = result.segList.map(s => s.name).join(', ');
    } else if (result.icesList.length > 0) {
        secValue.textContent = result.icesList.map(s => s.name).join(', ');
    } else {
        secValue.textContent = t.no_evidence_dns;
    }

    const dmarcVal = document.getElementById('summary-dmarc-value');
    let dmarcPolicyText = result.dmarcPolicy;
    if (dmarcPolicyText === 'reject') dmarcPolicyText = lang === 'es' ? 'Reject (Rechazar)' : 'Reject';
    else if (dmarcPolicyText === 'quarantine') dmarcPolicyText = lang === 'es' ? 'Quarantine (Cuarentena)' : 'Quarantine';
    else if (dmarcPolicyText === 'none') dmarcPolicyText = lang === 'es' ? 'None (Ninguna)' : 'None';
    else if (dmarcPolicyText === 'No configurado') dmarcPolicyText = t.no_dmarc_record;
    
    dmarcVal.textContent = dmarcPolicyText;
    dmarcVal.className = 'summary-card__value';
    if (result.dmarcPolicyClass === 'reject') dmarcVal.classList.add('dmarc-policy--reject');
    else if (result.dmarcPolicyClass === 'quarantine') dmarcVal.classList.add('dmarc-policy--quarantine');
    else dmarcVal.classList.add('dmarc-policy--none');

    document.getElementById('summary-services-value').textContent = 
        result.spfServices.length > 0 ? `${result.spfServices.length} ${t.detected_plural}` : t.detected_none;

    const mxBody = document.getElementById('mx-body');
    const recordWord = result.mxRecords.length === 1 ? t.singular_record : t.plural_records;
    document.getElementById('mx-count').textContent = `${result.mxRecords.length} ${recordWord}`;
    
    if (result.mxRecords.length === 0) {
        mxBody.innerHTML = `<p class="no-data">${t.no_mx_records}</p>`;
    } else {
        mxBody.innerHTML = result.mxRecords.map(mx => {
            const id = identifyMX(mx.host);
            const tagClass = id.type === 'provider' ? 'tag--provider' : id.type === 'seg' ? 'tag--seg' : 'tag--unknown';
            return `<div class="mx-record">
                <span class="mx-record__priority">${mx.priority}</span>
                <span class="mx-record__host">${mx.host}</span>
                <span class="mx-record__tag ${tagClass}">${id.name}</span>
            </div>`;
        }).join('');
    }

    const provBody = document.getElementById('provider-body');
    provBody.innerHTML = `
        <div class="info-block">
            <div class="info-block__label">${t.provider_identified}</div>
            <div class="info-block__value">${providerDisplay}</div>
            <div class="info-block__detail">${translateProviderSource(result.providerSource, lang)}</div>
        </div>`;

    const secBody = document.getElementById('security-body');
    if (result.segList.length > 0 || result.icesList.length > 0) {
        let html = '';
        for (const seg of result.segList) {
            html += `<div class="info-block">
                <div class="info-block__label">${t.seg_detected}</div>
                <div class="info-block__value">${seg.name}</div>
                <div class="info-block__detail">${t.evidence}: ${seg.source}</div>
            </div>`;
        }
        for (const ices of result.icesList) {
            html += `<div class="info-block">
                <div class="info-block__label">${t.ices_detected}</div>
                <div class="info-block__value">${ices.name}</div>
                <div class="info-block__detail">${t.evidence}: ${ices.source}</div>
            </div>`;
        }
        secBody.innerHTML = html;
    } else {
        secBody.innerHTML = `<div class="info-block">
            <div class="info-block__label">${t.no_evidence_dns}</div>
            <div class="info-block__value">${t.no_seg_ices_detected}</div>
            <div class="info-block__detail">${t.no_seg_ices_detail}</div>
        </div>`;
    }

    const spfRawEl = document.getElementById('spf-raw');
    if (result.spfRaw) {
        spfRawEl.textContent = result.spfRaw;
        spfRawEl.classList.remove('hidden');
    } else {
        spfRawEl.textContent = t.no_spf_record;
    }

    const spfTbody = document.getElementById('spf-table-body');
    spfTbody.innerHTML = '';
    
    for (const entry of result.spfEntries) {
        const svc = identifySPFService(entry.value);
        const prefixDisplay = entry.qualifier === '+' ? '+' : entry.qualifier === '-' ? '-' : entry.qualifier === '~' ? '~' : entry.qualifier === '?' ? '?' : '';
        
        let prefixClass = 'spf-prefix--pass';
        let resultText = 'Pass';
        if (entry.qualifier === '-') { prefixClass = 'spf-prefix--fail'; resultText = 'Fail'; }
        else if (entry.qualifier === '~') { prefixClass = 'spf-prefix--softfail'; resultText = 'SoftFail'; }
        else if (entry.qualifier === '?') { prefixClass = 'spf-prefix--neutral'; resultText = 'Neutral'; }
        
        if (entry.type === 'v') { resultText = ''; prefixClass = 'spf-prefix--neutral'; }
        if (entry.type === 'all' && entry.qualifier === '-') { resultText = 'Fail'; prefixClass = 'spf-prefix--fail'; }
        if (entry.type === 'all' && entry.qualifier === '~') { resultText = 'SoftFail'; prefixClass = 'spf-prefix--softfail'; }

        let resultClass = resultText === 'Pass' ? 'spf-result--pass' : resultText === 'Fail' ? 'spf-result--fail' : 'spf-result--softfail';

        // Tooltip for qualifier
        const qualifierTooltip = t[`spf_qualifier_${entry.qualifier || '+'}`] || '';
        // Tooltip for mechanism type
        const typeTooltip = t[`spf_type_${entry.type}`] || '';

        let svcHTML = '<span class="no-data">—</span>';
        if (svc) {
            const catClass = `cat--${svc.category}`;
            const localizedCatLabel = getCategoryLabel(svc, lang);
            if (svc.is_unknown) {
                svcHTML = `<span class="spf-service">${svc.name}</span><button type="button" class="spf-service__category ${catClass}" style="border:none; cursor:pointer;" title="${t.add_to_db_tooltip}" onclick="openKbModal('${svc.search_query}')">${t.add_to_db}</button>`;
            } else {
                svcHTML = `<span class="spf-service">${svc.name}</span><span class="spf-service__category ${catClass}">${localizedCatLabel}</span>`;
            }
        }
        if (entry.type === 'v') svcHTML = `<span style="color:var(--text-muted)">${t.spf_version}</span>`;
        if (entry.type === 'all') svcHTML = `<span style="color:var(--text-muted)">${t.spf_default_policy}</span>`;

        const row = document.createElement('tr');
        row.innerHTML = `
            <td><span class="spf-prefix ${prefixClass}${qualifierTooltip ? ' tooltip-trigger' : ''}"${qualifierTooltip ? ` data-tooltip="${qualifierTooltip}"` : ''}>${prefixDisplay || ''}</span></td>
            <td><span class="spf-type${typeTooltip ? ' tooltip-trigger' : ''}"${typeTooltip ? ` data-tooltip="${typeTooltip}"` : ''}>${entry.type}</span></td>
            <td><span class="spf-value">${entry.value || '—'}</span></td>
            <td><span class="spf-result ${resultClass}">${resultText}</span></td>
            <td>${svcHTML}</td>`;
        spfTbody.appendChild(row);
    }

    const spfSummary = document.getElementById('spf-services-summary');
    if (result.spfServices.length > 0) {
        const pills = result.spfServices.map(svc => {
            const color = KB.categoryColors[svc.category] || '#64748b';
            const localizedCatLabel = getCategoryLabel(svc, lang);
            return `<span class="service-pill">
                <span class="service-pill__dot" style="background:${color}"></span>
                ${svc.name} <small style="color:var(--text-muted)">(${localizedCatLabel})</small>
            </span>`;
        }).join('');
        spfSummary.innerHTML = `<div class="services-summary">${pills}</div>`;
    } else {
        spfSummary.innerHTML = `<p class="no-data">${t.no_third_party_spf}</p>`;
    }

    const treeBody = document.getElementById('spf-tree-body');
    if (treeBody) {
        if (result.spfTree && result.spfTree.record) {
            treeBody.innerHTML = renderSPFTree(result.spfTree);
        } else {
            treeBody.innerHTML = `<p class="no-data">${t.no_spf_tree}</p>`;
        }
    }

    const dmarcRawEl = document.getElementById('dmarc-raw');
    if (result.dmarcRaw) {
        dmarcRawEl.textContent = result.dmarcRaw;
    } else {
        dmarcRawEl.textContent = t.no_dmarc_record;
    }

    const dmarcBody = document.getElementById('dmarc-body');
    if (result.dmarcParsed) {
        const d = result.dmarcParsed;
        const pClass = d.p === 'reject' ? 'dmarc-policy--reject' : d.p === 'quarantine' ? 'dmarc-policy--quarantine' : 'dmarc-policy--none';
        const policyDesc = {
            'reject': t.dmarc_policy_desc_reject,
            'quarantine': t.dmarc_policy_desc_quarantine,
            'none': t.dmarc_policy_desc_none
        };
        
        let items = `<div class="dmarc-item">
            <div class="dmarc-item__label tooltip-trigger" data-tooltip="${t.dmarc_tooltip_p || ''}">${t.dmarc_policy_p}</div>
            <div class="dmarc-item__value ${pClass}">${d.p || 'none'}</div>
        </div>`;
        
        if (d.sp) {
            const spClass = d.sp === 'reject' ? 'dmarc-policy--reject' : d.sp === 'quarantine' ? 'dmarc-policy--quarantine' : 'dmarc-policy--none';
            items += `<div class="dmarc-item">
                <div class="dmarc-item__label tooltip-trigger" data-tooltip="${t.dmarc_tooltip_sp || ''}">${t.dmarc_policy_sp}</div>
                <div class="dmarc-item__value ${spClass}">${d.sp}</div>
            </div>`;
        }
        if (d.pct) {
            items += `<div class="dmarc-item">
                <div class="dmarc-item__label tooltip-trigger" data-tooltip="${t.dmarc_tooltip_pct || ''}">${t.dmarc_policy_pct}</div>
                <div class="dmarc-item__value">${d.pct}%</div>
            </div>`;
        }
        if (d.adkim) {
            items += `<div class="dmarc-item">
                <div class="dmarc-item__label tooltip-trigger" data-tooltip="${t.dmarc_tooltip_adkim || ''}">${t.dmarc_alignment_dkim}</div>
                <div class="dmarc-item__value">${d.adkim === 's' ? 'Strict' : 'Relaxed'}</div>
            </div>`;
        }
        if (d.aspf) {
            items += `<div class="dmarc-item">
                <div class="dmarc-item__label tooltip-trigger" data-tooltip="${t.dmarc_tooltip_aspf || ''}">${t.dmarc_alignment_spf}</div>
                <div class="dmarc-item__value">${d.aspf === 's' ? 'Strict' : 'Relaxed'}</div>
            </div>`;
        }

        dmarcBody.innerHTML = `<div class="dmarc-grid">${items}</div>
            <div class="info-block" style="margin-top:12px">
                <div class="info-block__detail">${policyDesc[d.p] || t.dmarc_policy_desc_unknown}</div>
            </div>`;
    } else {
        dmarcBody.innerHTML = `<p class="no-data">${t.no_dmarc_record}</p>`;
    }

    const repBody = document.getElementById('dmarc-reporting-body');
    if (result.dmarcRua.length > 0 || result.dmarcRuf.length > 0) {
        let html = '';
        for (const rua of result.dmarcRua) {
            const reporter = identifyDMARCReporter(rua);
            html += `<div class="reporting-item">
                <div class="reporting-item__type">RUA (${lang === 'es' ? 'Agregados' : 'Aggregate'})</div>
                <div class="reporting-item__value">${rua}</div>
                ${reporter ? `<div class="reporting-item__service">${lang === 'es' ? 'Herramienta' : 'Tool'}: ${reporter}</div>` : ''}
            </div>`;
        }
        for (const ruf of result.dmarcRuf) {
            const reporter = identifyDMARCReporter(ruf);
            html += `<div class="reporting-item">
                <div class="reporting-item__type">RUF (${lang === 'es' ? 'Forenses' : 'Forensic'})</div>
                <div class="reporting-item__value">${ruf}</div>
                ${reporter ? `<div class="reporting-item__service">${lang === 'es' ? 'Herramienta' : 'Tool'}: ${reporter}</div>` : ''}
            </div>`;
        }
        repBody.innerHTML = html;
    } else {
        repBody.innerHTML = `<p class="no-data">${t.no_dmarc_reporting}</p>`;
    }

    const lookupBadge = document.getElementById('spf-lookups-count');
    if (result.spfLookups !== undefined) {
        lookupBadge.textContent = `${result.spfLookups}/10 Lookups`;
        if (result.spfLookups > 10) {
            lookupBadge.style.backgroundColor = '#fecdd3';
            lookupBadge.style.color = '#e11d48';
        } else if (result.spfLookups > 7) {
            lookupBadge.style.backgroundColor = '#fef08a';
            lookupBadge.style.color = '#ca8a04';
        } else {
            lookupBadge.style.backgroundColor = '#d1fae5';
            lookupBadge.style.color = '#059669';
        }
    } else {
        lookupBadge.textContent = '';
    }

    const dkimBody = document.getElementById('dkim-body');
    let dkimHtml = '';
    if (result.dkimRecords && result.dkimRecords.records && result.dkimRecords.records.length > 0) {
        dkimHtml += result.dkimRecords.records.map(dkim => `
            <div class="info-block" style="margin-bottom:12px;">
                <div class="info-block__label">Selector: ${dkim.selector}</div>
                <div class="info-block__value" style="word-break:break-all; font-size:13px; font-family:monospace; margin-top:4px;">${dkim.record}</div>
            </div>`).join('');
    } else {
        dkimHtml += `<p class="no-data">${t.no_dkim_records}</p>`;
    }
    if (result.dkimRecords && result.dkimRecords.errors && result.dkimRecords.errors.length > 0) {
        dkimHtml += `<div style="margin-top: 12px; color: #ef4444; font-size: 13px;">${t.dkim_network_error}: ${result.dkimRecords.errors.map(e => e.selector).join(', ')}</div>`;
    }
    dkimBody.innerHTML = dkimHtml;

    const bimiBody = document.getElementById('bimi-body');
    if (result.bimiRecord) {
        if (result.bimiRecord.error) {
            bimiBody.innerHTML = `<p class="no-data" style="color:#ef4444">${t.bimi_error}: ${result.bimiRecord.error}</p>`;
        } else {
            let logoHtml = '';
            if (result.bimiRecord.logo) {
                logoHtml = `<div style="margin-top: 16px;"><img src="${result.bimiRecord.logo}" alt="BIMI Logo" style="max-width: 120px; max-height: 120px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);"></div>`;
            }
            bimiBody.innerHTML = `
                <div class="info-block">
                    <div class="info-block__label">${t.bimi_record_found}</div>
                    <div class="info-block__value" style="word-break:break-all; font-size:13px; font-family:monospace; margin-top:4px;">${result.bimiRecord.record}</div>
                    ${logoHtml}
                </div>`;
        }
    } else {
        bimiBody.innerHTML = `<p class="no-data">${t.no_bimi_record}</p>`;
    }

    // Render RBL reputation panel
    renderReputation(result.rblResults, lang, t);
}

export function renderReputation(rblResults, lang, t) {
    const body = document.getElementById('reputation-body');
    const badge = document.getElementById('reputation-status');
    if (!body || !badge) return;

    if (!rblResults || rblResults.length === 0) {
        body.innerHTML = `<p class="no-data">${t.rbl_no_data || 'No MX servers found to check.'}</p>`;
        badge.textContent = '—';
        return;
    }

    let anyListed = false;
    let html = '';

    for (const entry of rblResults) {
        let checksHTML = '';
        for (const check of entry.checks) {
            if (check.listed) anyListed = true;
            const cls = check.listed ? 'rbl-check__badge--listed' : 'rbl-check__badge--clean';
            const label = check.listed ? (t.rbl_listed || 'Listed') : (t.rbl_clean || 'Clean');
            checksHTML += `<div class="rbl-check">
                <span class="rbl-check__name">${check.rbl}</span>
                <span class="rbl-check__badge ${cls}">${label}</span>
            </div>`;
        }
        const ip = entry.ip ? entry.ip : (t.rbl_unresolved || 'Unresolved');
        html += `<div class="rbl-item">
            <div class="rbl-item__info">
                <div class="rbl-item__host">${entry.host}</div>
                <div class="rbl-item__ip">${ip}</div>
            </div>
            <div class="rbl-item__checks">${checksHTML}</div>
        </div>`;
    }

    body.innerHTML = html;

    if (anyListed) {
        badge.textContent = t.rbl_badge_listed || '⚠ Listed';
        badge.style.background = 'rgba(239,68,68,0.15)';
        badge.style.color = 'var(--accent-rose)';
    } else {
        badge.textContent = t.rbl_badge_clean || '✓ Clean';
        badge.style.background = 'rgba(16,185,129,0.15)';
        badge.style.color = 'var(--accent-emerald)';
    }
}
