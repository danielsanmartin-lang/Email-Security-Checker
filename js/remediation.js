// remediation.js
// Registros de corrección para el anexo del informe exportado: a partir de lo observado,
// los registros DNS (y el fichero de política MTA-STS) que dejarían el dominio bien
// configurado, listos para copiar. Lógica pura, sin red: trabaja sobre el result.
//
// Cada propuesta es honesta sobre lo que no puede saber desde fuera: qué servicios envían
// en nombre del dominio, o qué buzón debe recibir los informes. Lo que es un ejemplo va
// marcado como tal en su nota.
import { checkMtaStsMxCoverage } from './parsers.js';

const TXT_CHUNK = 255;
const SPF_LOOKUP_LIMIT = 10;
const MTA_STS_MAX_AGE = 604800;

/**
 * @typedef {object} Remediation
 * @property {string} id      identificador estable de la propuesta
 * @property {string} host    nombre DNS (o URL, para el fichero MTA-STS)
 * @property {'TXT'|'HTTPS'} type
 * @property {string} value   el valor a publicar (TXT ya partido en cadenas si hace falta)
 * @property {Array<{key: string, vars?: object}>} notes  notas traducibles
 */

const note = (key, vars) => (vars ? { key, vars } : { key });

/**
 * Parte un TXT de más de 255 caracteres en cadenas por límites de mecanismo, como se
 * publica en el DNS: "parte 1" "parte 2". Devuelve el valor tal cual si cabe en una.
 */
export function splitTxt(value) {
    if (value.length <= TXT_CHUNK) return { value, split: false };
    const chunks = [];
    let current = '';
    for (const token of value.split(' ')) {
        const next = current ? `${current} ${token}` : token;
        if (next.length > TXT_CHUNK && current) {
            chunks.push(`${current} `);
            current = token;
        } else {
            current = next;
        }
    }
    if (current) chunks.push(current);
    return { value: chunks.map(c => `"${c}"`).join(' '), split: true };
}

const receivesMail = (result) => (result.mxRecords || []).length > 0 && !result.nullMx;

// ===== DMARC =====

function dmarcRemediations(result, domain) {
    const out = [];
    const ev = result.dmarcEval || null;
    const floor = ev && ev.processing === 'full' ? ev.effective.floor : 'none';
    const partial = !!ev && (ev.testing || ev.effective.partialPct != null);
    if (floor === 'reject' && ev.enforcement && !partial) return out;

    const rua = ev && ev.rua.valid.length ? ev.rua.valid : null;
    const ruaValue = rua ? rua.join(',') : `mailto:dmarc-reports@${domain}`;
    const extras = [];
    if (ev && ev.ruf.valid.length) {
        extras.push(`ruf=${ev.ruf.valid.join(',')}`);
        // fo (cuándo se genera un informe forense) solo tiene sentido con ruf: se conserva.
        const fo = result.dmarcParsed && result.dmarcParsed.fo;
        if (fo && /^[01ds](:[01ds])*$/i.test(String(fo).trim())) extras.push(`fo=${String(fo).trim()}`);
    }
    if (ev && ev.adkim === 's') extras.push('adkim=s');
    if (ev && ev.aspf === 's') extras.push('aspf=s');
    const record = (p) => ['v=DMARC1', `p=${p}`, `rua=${ruaValue}`, ...extras].join('; ');
    const host = `_dmarc.${domain}`;

    // La escalera habitual: observar, cuarentena, rechazo. Se empieza en el peldaño que
    // aún no está dado del todo (en modo prueba o con pct parcial, el actual se repite
    // sin esas etiquetas).
    if (floor === 'none') {
        out.push({ id: 'dmarc_monitor', host, type: 'TXT', value: record('none'), notes: [note('rem_dmarc_monitor')] });
    }
    if (floor === 'none' || (floor === 'quarantine' && partial)) {
        out.push({ id: 'dmarc_quarantine', host, type: 'TXT', value: record('quarantine'), notes: [note('rem_dmarc_quarantine')] });
    }
    // El paso final. Sin sp ni np: por defecto heredan p, así que el rechazo cubre también
    // los subdominios y los nombres inexistentes.
    const weakChildren = floor === 'reject' && !partial && !ev.enforcement;
    out.push({ id: 'dmarc_reject', host, type: 'TXT', value: record('reject'), notes: [note(weakChildren ? 'rem_dmarc_subdomains' : 'rem_dmarc_reject')] });
    // El buzón inventado se avisa una vez, en el primer registro que se propone.
    if (!rua) out[0].notes.push(note('rem_example_mailbox'));
    return out;
}

function dmarcExternalAuthRemediations(result, domain) {
    const policyDomain = result.dmarcPolicyDomain || domain;
    return (result.dmarcExternalAuth || [])
        .filter(a => a.authorized === false)
        .map(a => ({
            id: `dmarc_external_${a.destDomain}`,
            host: `${policyDomain}._report._dmarc.${a.destDomain}`,
            type: 'TXT',
            value: 'v=DMARC1',
            notes: [note('rem_dmarc_external', { dest: a.destDomain, domain: policyDomain })]
        }));
}

// ===== SPF =====

// El include del proveedor del buzón, para la plantilla de un dominio sin SPF.
function providerInclude(result) {
    const platform = result.mailHosting && result.mailHosting.platform;
    const provider = String(result.provider || '');
    if (platform === 'm365' || /microsoft|office 365|outlook/i.test(provider)) return 'include:spf.protection.outlook.com';
    if (platform === 'google' || /google/i.test(provider)) return 'include:_spf.google.com';
    return 'mx';
}

const isAllToken = (tok) => /^[+\-~?]?all$/i.test(tok);

/**
 * Las IP de un subárbol SPF si se puede aplanar entero: solo ip4/ip6 e includes que a su
 * vez se pueden aplanar. Cualquier a/mx/ptr/exists/redirect exige resolver en el momento
 * de la evaluación y lo hace no aplanable (null).
 */
function flattenTree(tree) {
    if (!tree || tree.error || !tree.record) return null;
    const ips = [];
    for (const tok of tree.record.split(/\s+/).slice(1)) {
        const t = tok.replace(/^[+]/, '').toLowerCase();
        if (isAllToken(tok) || t.startsWith('exp=')) continue;
        if (t.startsWith('ip4:') || t.startsWith('ip6:')) {
            if (/^[-~?]/.test(tok)) return null; // un -ip4 no se puede trasladar tal cual
            ips.push(t);
            continue;
        }
        if (t.startsWith('include:')) {
            const child = (tree.children || []).find(c => c.type === 'include' && c.target === t.slice(8));
            const nested = child ? flattenTree(child.tree) : null;
            if (!nested) return null;
            ips.push(...nested);
            continue;
        }
        return null;
    }
    return ips;
}

function spfRemediations(result, domain) {
    const spfData = result.spfData || {};
    const records = spfData.records && spfData.records.length ? spfData.records : (result.spfRaw ? [result.spfRaw] : []);
    const host = domain;

    if (!records.length) {
        if (!receivesMail(result) && !(result.spfServices || []).length) {
            return [{ id: 'spf_none', host, type: 'TXT', value: 'v=spf1 -all', notes: [note('rem_spf_none_nomail')] }];
        }
        return [{ id: 'spf_none', host, type: 'TXT', value: `v=spf1 ${providerInclude(result)} ~all`, notes: [note('rem_spf_none')] }];
    }

    const notes = [];
    let tokens;
    if (records.length > 1) {
        // Fusión: los mecanismos de todos, sin repetir, y el `all` más estricto.
        const all = records.flatMap(r => r.split(/\s+/).slice(1));
        const qualifiers = all.filter(isAllToken).map(a => (/^[-~?+]/.test(a) ? a[0] : '+'));
        const strictest = qualifiers.includes('-') ? '-all' : '~all';
        tokens = [...new Set(all.filter(tok => !isAllToken(tok) && !/^redirect=/i.test(tok)))];
        tokens.push(strictest);
        notes.push(note('rem_spf_merge'));
    } else {
        tokens = records[0].split(/\s+/).slice(1).filter(Boolean);
    }

    // include rotos (su destino no publica SPF): PermError para cualquier receptor.
    const tree = result.spfTree;
    const broken = ((tree && tree.children) || [])
        .filter(c => (c.type === 'include' || c.type === 'redirect') && c.tree && c.tree.error === 'no_spf_record')
        .map(c => c.target);
    if (broken.length) {
        tokens = tokens.filter(tok => {
            const t = tok.replace(/^[+\-~?]/, '').toLowerCase();
            return !broken.some(b => t === `include:${b}` || t === `redirect=${b}`);
        });
        notes.push(note('rem_spf_broken', { targets: broken.join(', ') }));
    }

    // Sin `all`, o con uno que deja pasar a cualquiera.
    const allIdx = tokens.findIndex(isAllToken);
    const allTok = allIdx >= 0 ? tokens[allIdx] : null;
    if (!allTok || /^[+?]?all$/i.test(allTok)) {
        if (allIdx >= 0) tokens.splice(allIdx, 1);
        tokens.push('~all');
        notes.push(note('rem_spf_all'));
    }

    // Más de 10 consultas: se aplanan los include más caros que se puedan aplanar.
    const lookups = typeof result.spfLookups === 'number' ? result.spfLookups : (tree ? tree.lookups : 0);
    if (lookups > SPF_LOOKUP_LIMIT && tree) {
        const candidates = (tree.children || [])
            .filter(c => c.type === 'include' && c.tree && !broken.includes(c.target))
            .map(c => ({ target: c.target, cost: 1 + (c.tree.lookups || 0), ips: flattenTree(c.tree) }))
            .filter(c => c.ips && c.ips.length)
            .sort((a, b) => b.cost - a.cost);
        let remaining = lookups;
        const flattened = [];
        for (const c of candidates) {
            if (remaining <= SPF_LOOKUP_LIMIT) break;
            const idx = tokens.findIndex(tok => tok.replace(/^[+]/, '').toLowerCase() === `include:${c.target}`);
            if (idx < 0) continue;
            tokens.splice(idx, 1, ...c.ips.filter(ip => !tokens.includes(ip)));
            remaining -= c.cost;
            flattened.push(c.target);
        }
        if (flattened.length) notes.push(note('rem_spf_flatten', { lookups, targets: flattened.join(', ') }));
        if (remaining > SPF_LOOKUP_LIMIT) notes.push(note('rem_spf_flatten_partial'));
    }

    if (!notes.length) return [];
    const { value, split } = splitTxt(['v=spf1', ...tokens].join(' '));
    if (split) notes.push(note('rem_split_note'));
    return [{ id: 'spf_fix', host, type: 'TXT', value, notes }];
}

// ===== MTA-STS y TLS-RPT =====

const policyFile = (mode, mxHosts) => [
    'version: STSv1',
    `mode: ${mode}`,
    ...mxHosts.map(h => `mx: ${h}`),
    `max_age: ${MTA_STS_MAX_AGE}`
].join('\n');

const policyId = (now) => {
    const d = new Date(now);
    const pad = (n) => String(n).padStart(2, '0');
    return `${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}01`;
};

function mtaStsRemediations(result, domain, now) {
    if (!receivesMail(result)) return [];
    const mxHosts = (result.mxRecords || []).map(r => r.host);
    const url = `https://mta-sts.${domain}/.well-known/mta-sts.txt`;
    const txt = { id: 'mtasts_txt', host: `_mta-sts.${domain}`, type: 'TXT', value: `v=STSv1; id=${policyId(now)}`, notes: [note('rem_mtasts_txt')] };
    const file = (mode, key) => ({ id: 'mtasts_file', host: url, type: 'HTTPS', value: policyFile(mode, mxHosts), notes: [note(key)] });

    const sts = result.mtaSts;
    if (!sts) return [txt, file('testing', 'rem_mtasts_testing')];
    const policy = sts.policy || {};
    // El host de la política ni siquiera resuelve: hay que publicarla.
    if (policy.validationReason === 'host_missing') return [file('testing', 'rem_mtasts_testing')];
    const parsed = policy.parsed;
    // Sin la política descargada (lo normal: por privacidad, por defecto no se contacta con
    // el dominio auditado) no se sabe qué corregir.
    if (!parsed || !policy.fetchOk) return [];

    const mode = String(parsed.mode || '').toLowerCase();
    const coverage = checkMtaStsMxCoverage(parsed.mx || [], mxHosts);
    const maxAge = parseInt(parsed.max_age, 10);
    const needsFix = coverage.uncovered.length > 0 || !(maxAge >= MTA_STS_MAX_AGE);
    if (needsFix) return [txt, file(mode === 'enforce' ? 'enforce' : 'testing', 'rem_mtasts_fix')];
    if (mode === 'testing') return [txt, file('enforce', 'rem_mtasts_enforce')];
    return [];
}

function tlsRptRemediations(result, domain) {
    if (!receivesMail(result) || result.tlsRpt) return [];
    return [{
        id: 'tlsrpt',
        host: `_smtp._tls.${domain}`,
        type: 'TXT',
        value: `v=TLSRPTv1; rua=mailto:tls-reports@${domain}`,
        notes: [note('rem_tlsrpt'), note('rem_example_mailbox')]
    }];
}

/**
 * Registros de corrección para el dominio auditado, en el orden en que conviene aplicarlos.
 * Vacío si no hay nada que corregir en lo evaluado.
 *
 * @param {object} result  el result del análisis
 * @param {string} domain  el dominio auditado
 * @param {{ now?: number }} [opts] `now` fija la fecha del id de MTA-STS (tests)
 * @returns {Remediation[]}
 */
export function buildRemediation(result, domain, { now = Date.now() } = {}) {
    if (!result || !domain) return [];
    return [
        ...dmarcRemediations(result, domain),
        ...dmarcExternalAuthRemediations(result, domain),
        ...spfRemediations(result, domain),
        ...mtaStsRemediations(result, domain, now),
        ...tlsRptRemediations(result, domain)
    ];
}
