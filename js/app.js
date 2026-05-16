/* ===== DNS Query Engine ===== */
async function queryDNS(name, type) {
    const url = `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`;
    const res = await fetch(url);
    if (!res.ok) throw new Error(`DNS query failed: ${res.status}`);
    return res.json();
}

async function getMX(domain) {
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

async function getSPF(domain) {
    const data = await queryDNS(domain, 'TXT');
    if (!data.Answer) return null;
    for (const a of data.Answer) {
        const txt = a.data.replace(/"/g, '');
        if (txt.startsWith('v=spf1')) return txt;
    }
    return null;
}

async function getDMARC(domain) {
    const data = await queryDNS(`_dmarc.${domain}`, 'TXT');
    if (!data.Answer) return null;
    for (const a of data.Answer) {
        const txt = a.data.replace(/"/g, '');
        if (txt.startsWith('v=DMARC1')) return txt;
    }
    return null;
}

/* ===== SPF Parser ===== */
function parseSPF(raw) {
    if (!raw) return [];
    const tokens = raw.split(/\s+/);
    const entries = [];
    for (const token of tokens) {
        if (token === 'v=spf1') {
            entries.push({ prefix: '', type: 'v', value: 'spf1', qualifier: '' });
            continue;
        }
        let qualifier = '+';
        let t = token;
        if (/^[+\-~?]/.test(t)) { qualifier = t[0]; t = t.substring(1); }
        
        if (t.startsWith('include:')) {
            entries.push({ prefix: qualifier, type: 'include', value: t.substring(8), qualifier });
        } else if (t.startsWith('a:')) {
            entries.push({ prefix: qualifier, type: 'a', value: t.substring(2), qualifier });
        } else if (t.startsWith('mx:')) {
            entries.push({ prefix: qualifier, type: 'mx', value: t.substring(3), qualifier });
        } else if (t.startsWith('ip4:')) {
            entries.push({ prefix: qualifier, type: 'ip4', value: t.substring(4), qualifier });
        } else if (t.startsWith('ip6:')) {
            entries.push({ prefix: qualifier, type: 'ip6', value: t.substring(4), qualifier });
        } else if (t.startsWith('redirect=')) {
            entries.push({ prefix: qualifier, type: 'redirect', value: t.substring(9), qualifier });
        } else if (t.startsWith('exists:')) {
            entries.push({ prefix: qualifier, type: 'exists', value: t.substring(7), qualifier });
        } else if (t === 'a') {
            entries.push({ prefix: qualifier, type: 'a', value: '(self)', qualifier });
        } else if (t === 'mx') {
            entries.push({ prefix: qualifier, type: 'mx', value: '(self)', qualifier });
        } else if (t === 'all') {
            entries.push({ prefix: qualifier, type: 'all', value: '', qualifier });
        } else if (t === 'ptr') {
            entries.push({ prefix: qualifier, type: 'ptr', value: '', qualifier });
        } else if (t.startsWith('ptr:')) {
            entries.push({ prefix: qualifier, type: 'ptr', value: t.substring(4), qualifier });
        }
    }
    return entries;
}

/* ===== DMARC Parser ===== */
function parseDMARC(raw) {
    if (!raw) return null;
    const result = {};
    const tags = raw.split(';').map(s => s.trim()).filter(Boolean);
    for (const tag of tags) {
        const eq = tag.indexOf('=');
        if (eq > 0) {
            result[tag.substring(0, eq).trim()] = tag.substring(eq + 1).trim();
        }
    }
    return result;
}

/* ===== Service Identification ===== */
function identifyMX(host) {
    const h = host.toLowerCase();
    for (const entry of KB.mx) {
        if (h.includes(entry.pattern)) return entry;
    }
    return { name: host, type: 'unknown' };
}

function extractRootDomain(hostname) {
    if (!hostname) return '';
    const parts = hostname.split('.');
    if (parts.length <= 2) return hostname;
    const tld = parts[parts.length - 1];
    const sld = parts[parts.length - 2];
    // Simple heuristic for .co.uk style TLDs
    if (tld.length === 2 && sld.length <= 3) {
        return parts.slice(-3).join('.');
    }
    return parts.slice(-2).join('.');
}

function identifySPFService(value) {
    if (!value || value === '(self)') return null;
    const v = value.toLowerCase();
    for (const entry of KB.spf) {
        if (v.includes(entry.pattern)) return entry;
    }
    
    // Fallback: If not in KB but it looks like a domain
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

function identifyDMARCReporter(uri) {
    const u = uri.toLowerCase();
    for (const entry of KB.dmarc_reporters) {
        if (u.includes(entry.pattern)) return entry.name;
    }
    return null;
}

/* ===== Analysis Engine ===== */
function analyze(mxRecords, spfRaw, dmarcRaw) {
    const spfEntries = parseSPF(spfRaw);
    const dmarcParsed = parseDMARC(dmarcRaw);

    // Determine provider from MX
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

    // Check SPF for additional info
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

    // DMARC analysis
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

/* ===== Rendering ===== */
function renderResults(domain, result) {
    // Domain header
    document.getElementById('result-domain').textContent = domain;
    document.getElementById('result-timestamp').textContent = new Date().toLocaleString('es-ES');

    // Summary cards
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

    // MX Panel
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

    // Provider Panel
    const provBody = document.getElementById('provider-body');
    provBody.innerHTML = `
        <div class="info-block">
            <div class="info-block__label">Proveedor Identificado</div>
            <div class="info-block__value">${result.provider}</div>
            <div class="info-block__detail">${result.providerSource}</div>
        </div>`;

    // Security Panel
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
            <div class="info-block__detail">El dominio podría usar seguridad nativa del proveedor (ej. Microsoft Defender for Office 365, Google Advanced Protection) o una solución ICES integrada por API (ej. Avanan, Abnormal Security, Ironscales) que no deja rastro en DNS.</div>
        </div>`;
    }

    // SPF Panel
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

        const descMap = {
            'v': 'Versión del registro SPF',
            'include': 'Dominio autorizado para enviar',
            'a': 'IP del registro A autorizada',
            'mx': 'IPs de los MX autorizadas',
            'ip4': 'Dirección IPv4 autorizada',
            'ip6': 'Dirección IPv6 autorizada',
            'all': 'Regla final para el resto',
            'redirect': 'Redirigir evaluación SPF',
            'exists': 'Verificación de existencia',
            'ptr': 'Búsqueda inversa (deprecated)'
        };

        const row = document.createElement('tr');
        row.innerHTML = `
            <td><span class="spf-prefix ${prefixClass}">${prefixDisplay || ''}</span></td>
            <td><span class="spf-type">${entry.type}</span></td>
            <td><span class="spf-value">${entry.value || '—'}</span></td>
            <td><span class="spf-result ${resultClass}">${resultText}</span></td>
            <td>${svcHTML}</td>`;
        spfTbody.appendChild(row);
    }

    // SPF Services Summary
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

    // DMARC Panel
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

    // DMARC Reporting Panel
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
}

/* ===== Global State ===== */
let currentDomain = '';
let currentResult = null;

/* ===== Export Functionality ===== */
/* ===== Export Functionality ===== */
function generateReportHTML() {
    const d = new Date().toLocaleDateString('es-ES');
    
    let segHtml = '';
    if (currentResult.segList.length > 0 || currentResult.icesList.length > 0) {
        segHtml = `<h2 style="color: #374151; margin-top: 20px; color: #7e22ce;">🛡️ Capa de Seguridad (SEG / ICES)</h2><ul style="background-color: #f3f4f6; padding: 15px 15px 15px 35px; border-radius: 8px;">`;
        for (const seg of currentResult.segList) {
            segHtml += `<li style="margin-bottom: 10px;"><strong>Secure Email Gateway (SEG):</strong> <span style="color: #9333ea; font-weight: bold;">${seg.name}</span> <br><small style="color: #6b7280;">Evidencia DNS: ${seg.source}</small></li>`;
        }
        for (const ices of currentResult.icesList) {
            segHtml += `<li style="margin-bottom: 10px;"><strong>Seguridad Integrada (ICES):</strong> <span style="color: #7c3aed; font-weight: bold;">${ices.name}</span> <br><small style="color: #6b7280;">Evidencia DNS: ${ices.source}</small></li>`;
        }
        segHtml += `</ul>`;
    } else {
        segHtml = `<h2 style="color: #374151; margin-top: 20px;">🛡️ Capa de Seguridad (SEG / ICES)</h2><p style="color: #6b7280; font-style: italic;">No se detectó evidencia en DNS de Secure Email Gateways (SEG) ni soluciones ICES.</p>`;
    }

    let servicesHtml = '';
    if (currentResult.spfServices.length > 0) {
        servicesHtml = `<h2 style="color: #374151; margin-top: 20px;">☁️ Servicios Terceros Identificados en SPF</h2><ul>`;
        for (const svc of currentResult.spfServices) {
            let desc = 'Servicio de correo de terceros';
            if (svc.category === 'marketing') desc = 'Plataforma de Email Marketing y automatización de campañas.';
            else if (svc.category === 'transactional') desc = 'Proveedor de envío de correo transaccional (notificaciones, alertas).';
            else if (svc.category === 'crm') desc = 'Software de CRM (Gestión de relación con clientes).';
            else if (svc.category === 'signatures') desc = 'Servicio de inyección y gestión de firmas de correo corporativas.';
            else if (svc.category === 'support') desc = 'Plataforma de Helpdesk o atención al cliente.';
            else if (svc.category === 'unknown') desc = `Servicio no identificado en la base de datos.`;
            else if (svc.category === 'other' && svc.name === 'KnowBe4') desc = 'Plataforma de concienciación de seguridad y phishing simulado.';
            else if (svc.category === 'other') desc = 'Servicio corporativo externo autorizado para enviar correos.';
            
            servicesHtml += `<li style="margin-bottom: 12px;"><strong>${svc.name}</strong> - <span style="color: #0284c7; font-weight: 600;">${svc.cat_label}</span><br><small style="color: #4b5563;">${desc} (Regla SPF: <code>${svc.raw}</code>)</small></li>`;
        }
        servicesHtml += `</ul>`;
    }

    return `
        <div style="font-family: Arial, sans-serif; color: #111827;">
            <h1 style="color: #111827; border-bottom: 2px solid #6366f1; padding-bottom: 10px;">Auditoría de Seguridad de Correo: ${currentDomain}</h1>
            <p><strong>Fecha de análisis:</strong> ${d}</p>
            
            <h2 style="color: #374151; margin-top: 20px;">Resumen Ejecutivo</h2>
            <ul>
                <li><strong>Proveedor de Correo Principal:</strong> ${currentResult.provider}</li>
                <li><strong>Política DMARC:</strong> ${currentResult.dmarcPolicy}</li>
                <li><strong>Servicios Externos Autorizados (SPF):</strong> ${currentResult.spfServices.length} detectados</li>
            </ul>

            ${segHtml}
            ${servicesHtml}

            <h2 style="color: #374151; margin-top: 20px;">1. Registros MX (Mail Exchange)</h2>
            <table border="1" cellpadding="5" cellspacing="0" style="width: 100%; border-collapse: collapse; border-color: #e5e7eb;">
                <tr style="background-color: #f3f4f6;"><th>Prioridad</th><th>Host</th></tr>
                ${currentResult.mxRecords.length > 0 ? currentResult.mxRecords.map(mx => `<tr><td>${mx.priority}</td><td>${mx.host}</td></tr>`).join('') : '<tr><td colspan="2">No se encontraron registros MX</td></tr>'}
            </table>

            <h2 style="color: #374151; margin-top: 20px;">2. Registro SPF (Sender Policy Framework)</h2>
            <p><strong>Registro Raw:</strong> <code style="word-break: break-all;">${currentResult.spfRaw || 'No encontrado'}</code></p>
            
            <table border="1" cellpadding="5" cellspacing="0" style="width: 100%; border-collapse: collapse; border-color: #e5e7eb; font-size: 14px;">
                <tr style="background-color: #f3f4f6;"><th>Prefijo</th><th>Tipo</th><th>Valor</th><th>Servicio Identificado</th></tr>
                ${currentResult.spfEntries.map(e => {
                    const svc = identifySPFService(e.value);
                    const svcName = svc ? `${svc.name} (${svc.cat_label})` : '—';
                    return `<tr><td>${e.qualifier || ''}</td><td>${e.type}</td><td style="word-break: break-all;">${e.value || '—'}</td><td>${svcName}</td></tr>`;
                }).join('')}
            </table>

            <h2 style="color: #374151; margin-top: 20px;">Estado DMARC</h2>
            <p><strong>Registro Raw:</strong> <code>${currentResult.dmarcRaw || 'No encontrado'}</code></p>
            
            <h3>Reportes DMARC</h3>
            <ul>
                ${currentResult.dmarcRua.length > 0 ? currentResult.dmarcRua.map(r => `<li><strong>RUA:</strong> ${r}</li>`).join('') : ''}
                ${currentResult.dmarcRuf.length > 0 ? currentResult.dmarcRuf.map(r => `<li><strong>RUF:</strong> ${r}</li>`).join('') : ''}
                ${currentResult.dmarcRua.length === 0 && currentResult.dmarcRuf.length === 0 ? '<li>No se encontraron direcciones de reporte (rua/ruf).</li>' : ''}
            </ul>
            
            <hr style="margin-top: 30px;">
            <p style="font-size: 12px; color: #6b7280; text-align: center;">Reporte generado por Email Security Checker</p>
        </div>
    `;
}

async function exportToGoogle() {
    if (!currentDomain || !currentResult) return;
    const htmlContent = generateReportHTML();
    const btn = document.getElementById('export-google-btn');
    const originalHTML = btn.innerHTML;
    
    try {
        const blobHtml = new Blob([htmlContent], { type: 'text/html' });
        const blobText = new Blob(['Reporte DNS de ' + currentDomain], { type: 'text/plain' });
        const clipboardItem = new ClipboardItem({
            'text/html': blobHtml,
            'text/plain': blobText
        });
        await navigator.clipboard.write([clipboardItem]);
        
        btn.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg> ¡Copiado! Usa Cmd+V en Docs';
        
        setTimeout(() => { btn.innerHTML = originalHTML; }, 6000);
        window.open('https://docs.new', '_blank');
    } catch (err) {
        console.error('Error copiando al portapapeles', err);
        alert('No se pudo copiar automáticamente. Se abrirá una pestaña en blanco en Google Docs.');
        window.open('https://docs.new', '_blank');
    }
}

function exportToFile() {
    if (!currentDomain || !currentResult) return;
    const htmlContent = generateReportHTML();
    const docHtml = `<html xmlns:o='urn:schemas-microsoft-com:office:office' xmlns:w='urn:schemas-microsoft-com:office:word' xmlns='http://www.w3.org/TR/REC-html40'><head><meta charset='utf-8'><title>Reporte DNS - ${currentDomain}</title></head><body>${htmlContent}</body></html>`;
    const blob = new Blob(['\ufeff', docHtml], { type: 'application/msword' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `Reporte_DNS_${currentDomain}.doc`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

/* ===== Modal and KB Logic ===== */
function openKbModal(domain) {
    document.getElementById('kb-domain').value = domain;
    document.getElementById('kb-name').value = '';
    document.getElementById('kb-category').value = 'marketing';
    document.getElementById('add-kb-modal').classList.remove('hidden');
    document.getElementById('kb-name').focus();
}

function closeKbModal() {
    document.getElementById('add-kb-modal').classList.add('hidden');
}

/* ===== UI State Machine ===== */
function showSection(id) {
    ['loading-section', 'error-section', 'results-section'].forEach(s => {
        document.getElementById(s).classList.add('hidden');
    });
    if (id) document.getElementById(id).classList.remove('hidden');
}

function setStep(stepId, state) {
    const el = document.getElementById(stepId);
    el.classList.remove('active', 'done');
    if (state) el.classList.add(state);
    const check = el.querySelector('.check-icon');
    if (state === 'done') check.classList.remove('hidden');
    else check.classList.add('hidden');
}

async function runAnalysis(domain) {
    const btn = document.getElementById('search-btn');
    btn.classList.add('loading');
    showSection('loading-section');
    
    // Reset steps
    ['step-mx', 'step-spf', 'step-dmarc', 'step-analysis'].forEach(s => setStep(s, null));
    
    try {
        // Step 1: MX
        setStep('step-mx', 'active');
        const mxRecords = await getMX(domain);
        setStep('step-mx', 'done');

        // Step 2: SPF
        setStep('step-spf', 'active');
        const spfRaw = await getSPF(domain);
        setStep('step-spf', 'done');

        // Step 3: DMARC
        setStep('step-dmarc', 'active');
        const dmarcRaw = await getDMARC(domain);
        setStep('step-dmarc', 'done');

        // Step 4: Analyze
        setStep('step-analysis', 'active');
        await new Promise(r => setTimeout(r, 400));
        const result = analyze(mxRecords, spfRaw, dmarcRaw);
        currentDomain = domain;
        currentResult = result;
        setStep('step-analysis', 'done');

        await new Promise(r => setTimeout(r, 300));
        renderResults(domain, result);
        showSection('results-section');
    } catch (err) {
        console.error(err);
        document.getElementById('error-message').textContent = err.message || 'No se pudieron obtener los registros DNS.';
        showSection('error-section');
    } finally {
        btn.classList.remove('loading');
    }
}

/* ===== Event Listeners ===== */
document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('search-form');
    const input = document.getElementById('domain-input');
    
    form.addEventListener('submit', e => {
        e.preventDefault();
        let domain = input.value.trim().toLowerCase();
        domain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');
        if (domain) runAnalysis(domain);
    });

    document.querySelectorAll('.search-hint').forEach(hint => {
        hint.addEventListener('click', () => {
            input.value = hint.dataset.domain;
            form.dispatchEvent(new Event('submit'));
        });
    });

    document.getElementById('new-scan-btn').addEventListener('click', () => {
        showSection(null);
        input.value = '';
        input.focus();
        window.scrollTo({ top: 0, behavior: 'smooth' });
    });

    const googleBtn = document.getElementById('export-google-btn');
    if (googleBtn) {
        googleBtn.addEventListener('click', exportToGoogle);
    }

    const fileBtn = document.getElementById('export-file-btn');
    if (fileBtn) {
        fileBtn.addEventListener('click', exportToFile);
    }

    document.getElementById('error-retry').addEventListener('click', () => {
        const domain = input.value.trim().toLowerCase();
        if (domain) runAnalysis(domain);
    });

    /* Modal Listeners */
    document.getElementById('add-kb-close').addEventListener('click', closeKbModal);
    document.getElementById('add-kb-overlay').addEventListener('click', closeKbModal);
    
    document.getElementById('add-kb-form').addEventListener('submit', (e) => {
        e.preventDefault();
        const pattern = document.getElementById('kb-domain').value.trim();
        const name = document.getElementById('kb-name').value.trim();
        const category = document.getElementById('kb-category').value;
        const selectEl = document.getElementById('kb-category');
        const cat_label = selectEl.options[selectEl.selectedIndex].text;

        if (!pattern || !name) return;

        const newEntry = { pattern, name, category, cat_label };
        
        // Add to KB in memory
        KB.spf.push(newEntry);
        
        // Save to localStorage
        let customKB = [];
        try {
            const existing = localStorage.getItem('custom_kb_spf');
            if (existing) customKB = JSON.parse(existing);
        } catch(err) {}
        customKB.push(newEntry);
        localStorage.setItem('custom_kb_spf', JSON.stringify(customKB));

        closeKbModal();
        
        // Re-analyze
        if (currentDomain) {
            runAnalysis(currentDomain);
        }
    });
});
