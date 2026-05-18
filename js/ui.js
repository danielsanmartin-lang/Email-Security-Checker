import { KB } from './knowledge.js';
import { identifyMX, identifySPFService, identifyDMARCReporter } from './analyzer.js';

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

export function showSection(id) {
    ['loading-section', 'error-section', 'results-section'].forEach(s => {
        document.getElementById(s).classList.add('hidden');
    });
    if (id) document.getElementById(id).classList.remove('hidden');
}

export function setStep(stepId, state) {
    const el = document.getElementById(stepId);
    el.classList.remove('active', 'done');
    if (state) el.classList.add(state);
    const check = el.querySelector('.check-icon');
    if (state === 'done') check.classList.remove('hidden');
    else check.classList.add('hidden');
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

export function renderResults(domain, result) {
    document.getElementById('result-domain').textContent = domain;
    document.getElementById('result-timestamp').textContent = new Date().toLocaleString('es-ES');

    document.getElementById('summary-provider-value').textContent = result.provider;
    
    const secValue = document.getElementById('summary-security-value');
    if (result.segList.length > 0) {
        secValue.textContent = result.segList.map(s => s.name).join(', ');
    } else if (result.icesList.length > 0) {
        secValue.textContent = result.icesList.map(s => s.name).join(', ');
    } else {
        secValue.textContent = 'Sin evidencia DNS';
    }

    const dmarcVal = document.getElementById('summary-dmarc-value');
    dmarcVal.textContent = result.dmarcPolicy;
    dmarcVal.className = 'summary-card__value';
    if (result.dmarcPolicyClass === 'reject') dmarcVal.classList.add('dmarc-policy--reject');
    else if (result.dmarcPolicyClass === 'quarantine') dmarcVal.classList.add('dmarc-policy--quarantine');
    else dmarcVal.classList.add('dmarc-policy--none');

    document.getElementById('summary-services-value').textContent = 
        result.spfServices.length > 0 ? `${result.spfServices.length} detectados` : 'Ninguno';

    const mxBody = document.getElementById('mx-body');
    document.getElementById('mx-count').textContent = `${result.mxRecords.length} registro${result.mxRecords.length !== 1 ? 's' : ''}`;
    
    if (result.mxRecords.length === 0) {
        mxBody.innerHTML = '<p class="no-data">No se encontraron registros MX</p>';
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
            <div class="info-block__label">Proveedor Identificado</div>
            <div class="info-block__value">${result.provider}</div>
            <div class="info-block__detail">${result.providerSource}</div>
        </div>`;

    const secBody = document.getElementById('security-body');
    if (result.segList.length > 0 || result.icesList.length > 0) {
        let html = '';
        for (const seg of result.segList) {
            html += `<div class="info-block">
                <div class="info-block__label">SEG Detectado</div>
                <div class="info-block__value">${seg.name}</div>
                <div class="info-block__detail">Evidencia: ${seg.source}</div>
            </div>`;
        }
        for (const ices of result.icesList) {
            html += `<div class="info-block">
                <div class="info-block__label">ICES Detectado</div>
                <div class="info-block__value">${ices.name}</div>
                <div class="info-block__detail">Evidencia: ${ices.source}</div>
            </div>`;
        }
        secBody.innerHTML = html;
    } else {
        secBody.innerHTML = `<div class="info-block">
            <div class="info-block__label">Sin evidencia en DNS</div>
            <div class="info-block__value">No se detectó SEG ni ICES</div>
            <div class="info-block__detail">El dominio podría usar seguridad nativa del proveedor o una solución integrada por API que no deja rastro en DNS.</div>
        </div>`;
    }

    const spfRawEl = document.getElementById('spf-raw');
    if (result.spfRaw) {
        spfRawEl.textContent = result.spfRaw;
        spfRawEl.classList.remove('hidden');
    } else {
        spfRawEl.textContent = 'No se encontró registro SPF';
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

        let svcHTML = '<span class="no-data">—</span>';
        if (svc) {
            const catClass = `cat--${svc.category}`;
            if (svc.is_unknown) {
                svcHTML = `<span class="spf-service">${svc.name}</span><button type="button" class="spf-service__category ${catClass}" style="border:none; cursor:pointer;" title="Añadir a Base de Datos" onclick="openKbModal('${svc.search_query}')">➕ Añadir a DB</button>`;
            } else {
                svcHTML = `<span class="spf-service">${svc.name}</span><span class="spf-service__category ${catClass}">${svc.cat_label}</span>`;
            }
        }
        if (entry.type === 'v') svcHTML = '<span style="color:var(--text-muted)">Versión SPF</span>';
        if (entry.type === 'all') svcHTML = '<span style="color:var(--text-muted)">Política por defecto</span>';

        const row = document.createElement('tr');
        row.innerHTML = `
            <td><span class="spf-prefix ${prefixClass}">${prefixDisplay || ''}</span></td>
            <td><span class="spf-type">${entry.type}</span></td>
            <td><span class="spf-value">${entry.value || '—'}</span></td>
            <td><span class="spf-result ${resultClass}">${resultText}</span></td>
            <td>${svcHTML}</td>`;
        spfTbody.appendChild(row);
    }

    const spfSummary = document.getElementById('spf-services-summary');
    if (result.spfServices.length > 0) {
        const pills = result.spfServices.map(svc => {
            const color = KB.categoryColors[svc.category] || '#64748b';
            return `<span class="service-pill">
                <span class="service-pill__dot" style="background:${color}"></span>
                ${svc.name} <small style="color:var(--text-muted)">(${svc.cat_label})</small>
            </span>`;
        }).join('');
        spfSummary.innerHTML = `<div class="services-summary">${pills}</div>`;
    } else {
        spfSummary.innerHTML = '<p class="no-data">No se identificaron servicios de terceros en el SPF</p>';
    }

    const treeBody = document.getElementById('spf-tree-body');
    if (treeBody) {
        if (result.spfTree && result.spfTree.record) {
            treeBody.innerHTML = renderSPFTree(result.spfTree);
        } else {
            treeBody.innerHTML = '<p class="no-data">No se pudo generar el árbol de consultas SPF.</p>';
        }
    }

    const dmarcRawEl = document.getElementById('dmarc-raw');
    if (result.dmarcRaw) {
        dmarcRawEl.textContent = result.dmarcRaw;
    } else {
        dmarcRawEl.textContent = 'No se encontró registro DMARC';
    }

    const dmarcBody = document.getElementById('dmarc-body');
    if (result.dmarcParsed) {
        const d = result.dmarcParsed;
        const pClass = d.p === 'reject' ? 'dmarc-policy--reject' : d.p === 'quarantine' ? 'dmarc-policy--quarantine' : 'dmarc-policy--none';
        const policyDesc = {
            'reject': 'Rechazar correos no autenticados — máxima protección',
            'quarantine': 'Cuarentena — los correos sospechosos se envían a spam',
            'none': 'Solo monitorización — no se bloquea nada'
        };
        
        let items = `<div class="dmarc-item">
            <div class="dmarc-item__label">Política (p)</div>
            <div class="dmarc-item__value ${pClass}">${d.p || 'none'}</div>
        </div>`;
        
        if (d.sp) {
            const spClass = d.sp === 'reject' ? 'dmarc-policy--reject' : d.sp === 'quarantine' ? 'dmarc-policy--quarantine' : 'dmarc-policy--none';
            items += `<div class="dmarc-item">
                <div class="dmarc-item__label">Subdominios (sp)</div>
                <div class="dmarc-item__value ${spClass}">${d.sp}</div>
            </div>`;
        }
        if (d.pct) {
            items += `<div class="dmarc-item">
                <div class="dmarc-item__label">Porcentaje (pct)</div>
                <div class="dmarc-item__value">${d.pct}%</div>
            </div>`;
        }
        if (d.adkim) {
            items += `<div class="dmarc-item">
                <div class="dmarc-item__label">DKIM Alignment</div>
                <div class="dmarc-item__value">${d.adkim === 's' ? 'Strict' : 'Relaxed'}</div>
            </div>`;
        }
        if (d.aspf) {
            items += `<div class="dmarc-item">
                <div class="dmarc-item__label">SPF Alignment</div>
                <div class="dmarc-item__value">${d.aspf === 's' ? 'Strict' : 'Relaxed'}</div>
            </div>`;
        }

        dmarcBody.innerHTML = `<div class="dmarc-grid">${items}</div>
            <div class="info-block" style="margin-top:12px">
                <div class="info-block__detail">${policyDesc[d.p] || 'Política desconocida'}</div>
            </div>`;
    } else {
        dmarcBody.innerHTML = '<p class="no-data">No se encontró registro DMARC. El dominio no tiene protección DMARC configurada.</p>';
    }

    const repBody = document.getElementById('dmarc-reporting-body');
    if (result.dmarcRua.length > 0 || result.dmarcRuf.length > 0) {
        let html = '';
        for (const rua of result.dmarcRua) {
            const reporter = identifyDMARCReporter(rua);
            html += `<div class="reporting-item">
                <div class="reporting-item__type">RUA (Agregados)</div>
                <div class="reporting-item__value">${rua}</div>
                ${reporter ? `<div class="reporting-item__service">Herramienta: ${reporter}</div>` : ''}
            </div>`;
        }
        for (const ruf of result.dmarcRuf) {
            const reporter = identifyDMARCReporter(ruf);
            html += `<div class="reporting-item">
                <div class="reporting-item__type">RUF (Forenses)</div>
                <div class="reporting-item__value">${ruf}</div>
                ${reporter ? `<div class="reporting-item__service">Herramienta: ${reporter}</div>` : ''}
            </div>`;
        }
        repBody.innerHTML = html;
    } else {
        repBody.innerHTML = '<p class="no-data">No se encontraron direcciones de reporte (rua/ruf). El dominio no está recopilando informes DMARC.</p>';
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
        dkimHtml += '<p class="no-data">No se detectaron registros DKIM usando los selectores consultados.</p>';
    }
    if (result.dkimRecords && result.dkimRecords.errors && result.dkimRecords.errors.length > 0) {
        dkimHtml += `<div style="margin-top: 12px; color: #ef4444; font-size: 13px;">Errores de red en selectores: ${result.dkimRecords.errors.map(e => e.selector).join(', ')}</div>`;
    }
    dkimBody.innerHTML = dkimHtml;

    const bimiBody = document.getElementById('bimi-body');
    if (result.bimiRecord) {
        if (result.bimiRecord.error) {
            bimiBody.innerHTML = `<p class="no-data" style="color:#ef4444">Error al consultar BIMI: ${result.bimiRecord.error}</p>`;
        } else {
            let logoHtml = '';
            if (result.bimiRecord.logo) {
                logoHtml = `<div style="margin-top: 16px;"><img src="${result.bimiRecord.logo}" alt="BIMI Logo" style="max-width: 120px; max-height: 120px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);"></div>`;
            }
            bimiBody.innerHTML = `
                <div class="info-block">
                    <div class="info-block__label">Registro BIMI Encontrado</div>
                    <div class="info-block__value" style="word-break:break-all; font-size:13px; font-family:monospace; margin-top:4px;">${result.bimiRecord.record}</div>
                    ${logoHtml}
                </div>`;
        }
    } else {
        bimiBody.innerHTML = '<p class="no-data">No se encontró registro BIMI (default._bimi).</p>';
    }
}
