// viewmodel.js
// Capa de presentación COMPARTIDA por ui.js (DOM en vivo) y export.js (informe).
// Toma los datos crudos/normalizados del analyzer y produce texto ya traducido,
// evitando que cada renderizador re-derive y re-traduzca la misma información.

import { translations } from './i18n.js';
import { isDnssecValidated } from './parsers.js';
import { GRADE_CALIBRATION } from './analyzer.js';
import { NEW_DOMAIN_DAYS } from './rdap.js';
import { assessLookalikeRisk } from './lookalike.js';

// Sustituye los {marcadores} de una cadena traducida (las claves van sin llaves).
const fillVars = (text, values) => Object.entries(values)
    .reduce((acc, [k, v]) => acc.split(`{${k}}`).join(String(v)), String(text || ''));

/**
 * Etiqueta de categoría de servicio localizada.
 * @param {object} svc  servicio identificado (con .category y .cat_label)
 * @param {string} lang 'es' | 'en'
 */
export function getCategoryLabel(svc, lang) {
    if (!svc) return '';
    const t = translations[lang] || translations.es;
    const catLabel = svc.cat_label || svc.catLabel || '';
    if (t.category_labels && t.category_labels[catLabel]) {
        return t.category_labels[catLabel];
    }
    const byCat = t.category_defaults && t.category_defaults[svc.category];
    return byCat || catLabel || t.category_fallback || '';
}

/** Nombre del proveedor a mostrar (o "No identificado" traducido). */
export function displayProvider(result, t) {
    if (result.providerIdentified === false) return t.unidentified_provider;
    // Compatibilidad con el antiguo sentinel
    if (!result.provider || result.provider === 'No identificado') return t.unidentified_provider;
    return result.provider;
}

/**
 * Formatea la fuente de detección del proveedor a partir de la estructura neutral
 * { key, arg } emitida por el analyzer. Acepta también el formato string antiguo.
 */
export function formatProviderSource(source, t) {
    if (!source) return '';
    if (typeof source === 'string') return source; // compat
    if (source.key === 'provider_none') return t.unidentified_provider_detail;
    const label = t[source.key] || '';
    return source.arg ? `${label} ${source.arg}` : label;
}

/**
 * La capa a la que entrega el MX: un SEG (Proofpoint, Mimecast…) o un ICES en modo
 * inline (Avanan, Perception Point…). null si el MX no apunta a ninguna.
 */
function mxGateway(result) {
    const layers = [...(result.segList || []), ...(result.icesList || [])];
    return layers.find(s => (s.evidence || []).some(e => e.signal === 'mx')) || null;
}

/**
 * Quién filtra el correo entrante y qué lo dice: { name, source }. Responde solo el MX.
 *
 * - Si el MX entrega a un gateway, es ese gateway aunque se haya identificado un
 *   proveedor: `provider` puede venir del SPF (un `include:_spf.google.com` con el MX en
 *   Proofpoint, caso salesforce.com), y el SPF dice quién ENVÍA, no quién recibe.
 * - Si el proveedor sale del MX, es el proveedor.
 * - Si no, se nombra el MX, propio o no reconocido. Un Exchange híbrido con el MX en casa y
 *   Microsoft 365 en el SPF no filtra la entrada en Microsoft 365.
 * - Sin MX, no aplica.
 */
function resolveInboundFilter(result, t) {
    const gateway = mxGateway(result);
    if (gateway) {
        const ev = gateway.evidence.find(e => e.signal === 'mx');
        return { name: gateway.name, source: `${t.evidence_mx} ${ev.value}` };
    }
    const fromProvider = { name: displayProvider(result, t), source: formatProviderSource(result.providerSource, t) };
    const src = result.providerSource;
    // Sin la lista de MX, o con la fuente en el formato antiguo (texto), no se sabe de
    // dónde salió el proveedor: se muestra como antes.
    if (!Array.isArray(result.mxRecords) || typeof src === 'string') return fromProvider;
    if (src && src.key === 'evidence_mx') return fromProvider;
    if (!result.mxRecords.length || result.nullMx) {
        return { name: t.transport_not_applicable, source: result.nullMx ? 'Null MX (RFC 7505)' : t.no_mx_records };
    }
    const mx = [...result.mxRecords].sort((a, b) => a.priority - b.priority)[0];
    const own = ((result.inboundFilter && result.inboundFilter.ownMx) || []).includes(mx.host);
    return { name: own ? t.inbound_filter_own : t.unidentified_provider, source: `${t.evidence_mx} ${mx.host}` };
}

/** Nombre del filtro de entrada (ver resolveInboundFilter). */
export function displayInboundFilter(result, t) {
    return resolveInboundFilter(result, t).name;
}

/** Fuente de la identificación del filtro de entrada, coherente con displayInboundFilter. */
export function inboundFilterSource(result, t) {
    return resolveInboundFilter(result, t).source;
}

/**
 * Veredicto de hospedaje traducido ('En la nube', 'Híbrido', 'Servidor propio'…).
 * Devuelve '' si no hay clasificación, para que quien renderiza pueda omitir el bloque
 * entero en vez de pintar un hueco vacío.
 */
export function displayMailHosting(mailHosting, t) {
    if (!mailHosting || !mailHosting.kind) return '';
    return t[`mail_hosting_${mailHosting.kind}`] || mailHosting.kind;
}

/** Explicación larga del veredicto: qué significa, y qué NO se puede saber desde fuera. */
export function mailHostingDetail(mailHosting, t) {
    if (!mailHosting || !mailHosting.kind) return '';
    return t[`mail_hosting_detail_${mailHosting.kind}`] || '';
}

/** Plataforma de buzón traducida ('Microsoft 365', 'Infraestructura propia'…). */
export function mailHostingPlatform(mailHosting, t) {
    if (!mailHosting || !mailHosting.platform) return t.mh_platform_unknown || '';
    return t[`mh_platform_${mailHosting.platform}`] || mailHosting.platform;
}

/**
 * Evidencia como lista de pares ya traducidos, lista para pintar.
 * Se comparte con el informe exportado para que ambos digan exactamente lo mismo.
 */
export function mailHostingEvidence(mailHosting, t) {
    const ev = (mailHosting && Array.isArray(mailHosting.evidence)) ? mailHosting.evidence : [];
    return ev.map(e => ({ label: t[`mh_signal_${e.signal}`] || e.signal, value: e.value }));
}

/** Avisos traducidos (CDN descartado, sin autodiscover, SEG delante, consultas fallidas). */
export function mailHostingNotes(mailHosting, t) {
    const notes = (mailHosting && Array.isArray(mailHosting.notes)) ? mailHosting.notes : [];
    return notes.map(n => t[`mh_note_${n.key}`]).filter(Boolean);
}

/**
 * Línea del tenant de Microsoft Entra ("<id> · región Europa. Estar en un tenant solo
 * indica…"), o '' si no lo hay. La comparten el panel y el informe.
 */
export function entraTenantText(mailHosting, t) {
    const entra = mailHosting && mailHosting.entraTenant;
    if (!entra || !entra.id) return '';
    const region = entra.region ? (t[`entra_region_${entra.region}`] || entra.region) : t.entra_region_unknown;
    return fillVars(t.mh_entra_note, { id: entra.id, region });
}

/** Resuelve el texto de un finding (clave i18n + reemplazos). Idéntico en ui y export. */
export function resolveFindingText(t, finding) {
    let text = t[finding.key] || finding.message || '';
    if (finding.replacements) {
        for (const [placeholder, val] of Object.entries(finding.replacements)) {
            text = text.split(placeholder).join(val);
        }
    }
    return text;
}

/** Texto largo de la política DMARC para resúmenes. */
export function displayDmarcPolicy(t, policy) {
    switch (policy) {
        case 'reject': return t.dmarc_reject_full;
        case 'quarantine': return t.dmarc_quarantine_full;
        case 'none': return t.dmarc_none_full;
        case 'No configurado':
        case 'not_configured':
        case null:
        case undefined:
            return t.no_dmarc_record;
        default:
            return policy;
    }
}

const fill = (text, replacements) => {
    let out = String(text || '');
    for (const [k, v] of Object.entries(replacements)) out = out.split(k).join(v);
    return out;
};

/**
 * Política DMARC para los resúmenes (tarjeta y informe): la EFECTIVA —la más débil que
 * aplicaría alguna generación de receptores— con el matiz que la explica: solicitada en
 * modo prueba (t=y / pct=0), heredada del dominio organizativo o sin efecto por valores
 * no válidos. Así el resumen no dice "Reject" de un registro que en la práctica no lo es.
 */
export function dmarcPolicySummary(result, t) {
    const base = displayDmarcPolicy(t, result.dmarcPolicy);
    const ev = result.dmarcEval;
    if (!ev) return base;
    if (ev.processing !== 'full') return t.dmarc_summary_invalid;
    const notes = [];
    if (ev.effective.floor !== ev.applicable) {
        notes.push(fill(t.dmarc_summary_lowered, { '{requested}': ev.applicable.toUpperCase() }));
    }
    if (ev.inherited && result.dmarcInheritedFrom) {
        notes.push(fill(t.dmarc_summary_inherited, { '{org}': result.dmarcInheritedFrom }));
    }
    return notes.length ? `${base} (${notes.join('; ')})` : base;
}

/**
 * Estado de MTA-STS en un solo identificador, compartido por el panel y el informe para
 * que ambos digan lo mismo. `testing` y `mode_none` son políticas VÁLIDAS que no se
 * aplican; `unreachable` y `not_fetched` son límites del análisis, no fallos del dominio.
 */
export function mtaStsState(result) {
    const m = result.mtaSts;
    if (!m) return 'not_configured';
    const p = m.policy || {};
    if (p.valid) return 'enforced';
    if (p.validationReason === 'fetch_failed') return 'unreachable';
    if (p.validationReason === 'not_fetched') return 'not_fetched';
    if (p.validationReason === 'host_missing') return 'host_missing';
    if (p.validationReason === 'mode_not_enforce' && p.httpStatus === 200) {
        if (p.mode === 'testing') return 'testing';
        if (p.mode === 'none') return 'mode_none';
    }
    return 'invalid';
}

// Presentación de cada estado: tono de la insignia (UI), color (informe) y clave i18n.
export const MTA_STS_STATE_VIEW = {
    enforced: { tone: 'success', color: '#059669', key: 'adv_mta_sts_enforced' },
    testing: { tone: 'warning', color: '#d97706', key: 'adv_mta_sts_testing' },
    mode_none: { tone: 'neutral', color: '#64748b', key: 'adv_mta_sts_mode_none' },
    unreachable: { tone: 'neutral', color: '#64748b', key: 'adv_mta_sts_unreachable' },
    not_fetched: { tone: 'neutral', color: '#64748b', key: 'adv_mta_sts_not_fetched' },
    host_missing: { tone: 'danger', color: '#dc2626', key: 'adv_mta_sts_host_missing' },
    invalid: { tone: 'danger', color: '#dc2626', key: 'adv_mta_sts_policy_invalid' },
    not_configured: { tone: 'neutral', color: '#64748b', key: 'adv_mta_sts_not_configured' }
};

/**
 * Estado DNSSEC: 'validated' (firmada y la cadena valida), 'unvalidated' (hay DNSKEY pero
 * el resolver no la valida: falta el DS en la zona padre o la cadena está rota) o
 * 'unsigned'. Misma regla que el scoring (isDnssecValidated, en parsers.js).
 */
export function dnssecState(dnssec) {
    if (!dnssec || !dnssec.signed) return 'unsigned';
    return isDnssecValidated(dnssec) ? 'validated' : 'unvalidated';
}

/** Descripción de un servicio de terceros (informe). */
export function serviceDescription(t, svc) {
    const map = {
        marketing: 'svc_desc_marketing',
        transactional: 'svc_desc_transactional',
        crm: 'svc_desc_crm',
        signatures: 'svc_desc_signatures',
        support: 'svc_desc_support',
        unknown: 'svc_desc_unknown'
    };
    if (map[svc.category]) return t[map[svc.category]];
    if (svc.category === 'other' && svc.name === 'KnowBe4') return t.svc_desc_awareness;
    if (svc.category === 'other') return t.svc_desc_other;
    return '';
}

/** Número de listados RBL (entre todos los MX comprobados). */
export function rblListedCount(rblResults) {
    if (!rblResults) return 0;
    let count = 0;
    for (const r of rblResults) {
        if (r.checks) for (const c of r.checks) if (c.listed) count++;
    }
    return count;
}

/** Texto del grado de postura de seguridad. */
export function postureText(t, posture) {
    if (!posture) return '';
    return t[`posture_${posture.key}`] || posture.grade || '';
}

/**
 * Estado del eje de filtrado entrante con lo que lo explica: "Reforzado · Proofpoint",
 * "Solo nativo · Microsoft 365", "Sin identificar" o "No aplica". Compartido por la
 * pastilla de la tarjeta y el informe exportado.
 */
export function filteringText(t, filtering) {
    if (!filtering || !filtering.applicable) return t.transport_not_applicable;
    if (filtering.state === 'reinforced') return `${t.filtering_reinforced} · ${filtering.vendors.join(', ')}`;
    if (filtering.state === 'native') {
        return filtering.provider ? `${t.filtering_native} · ${filtering.provider}` : t.filtering_native;
    }
    return t.filtering_unidentified;
}

/**
 * La cuenta que da la nota, con los números de este dominio: "Suplantación 97 × 60 % +
 * Filtrado entrante 100 × 25 % + Transporte 25 × 15 % = 86,95". Compartida por el apartado
 * "¿Cómo se calcula la nota?" y el informe exportado, para que digan lo mismo.
 * @returns {{ formula: string, cap: string|null, final: string }|null}
 */
export function scoreFormula(t, scoreCard, locale = 'es-ES') {
    if (!scoreCard || !scoreCard.breakdown) return null;
    const num = (n) => Number(n).toLocaleString(locale, { maximumFractionDigits: 2 });
    const pct = (n) => (t.pct_fmt || '{n} %').split('{n}').join(String(n));
    const parts = scoreCard.breakdown
        .filter(c => c.counted)
        .map(c => `${t[c.labelKey] || c.id} ${c.score} × ${pct(c.share)}`);
    const weighted = typeof scoreCard.weighted === 'number' ? scoreCard.weighted : scoreCard.score;
    const formula = parts.length ? `${parts.join(' + ')} = ${num(weighted)}` : '';
    const cap = scoreCard.cap
        ? (t[`score_cap_${scoreCard.cap.key}`] || '').split('{cap}').join(String(scoreCard.cap.value))
        : null;
    const final = (t.method_final || '{score} ({grade})')
        .split('{score}').join(String(scoreCard.score))
        .split('{grade}').join(scoreCard.grade);
    return { formula, cap, final };
}

/** Qué significa una letra, en una frase. */
export function gradeMeaning(t, grade) {
    return t[`method_grade_${grade === 'A+' ? 'Aplus' : grade}`] || '';
}

/** Tono de la pastilla de filtrado: verde reforzado, ámbar solo nativo, gris el resto. */
export function filteringTone(filtering) {
    if (!filtering || !filtering.applicable) return 'unknown';
    if (filtering.state === 'reinforced') return filtering.bypass ? 'warning' : 'safe';
    if (filtering.state === 'native') return 'warning';
    return 'unknown';
}

// Mapeo qualifier SPF → resultado de evaluación. Compartido por ui.js (clase CSS
// spf-prefix--<kind>) y export.js (color). Antes estaba duplicado en ambos.
const SPF_QUALIFIER_RESULT = {
    '+': { kind: 'pass', text: 'Pass' },
    '-': { kind: 'fail', text: 'Fail' },
    '~': { kind: 'softfail', text: 'SoftFail' },
    '?': { kind: 'neutral', text: 'Neutral' }
};
export function spfQualifierResult(qualifier) {
    return SPF_QUALIFIER_RESULT[qualifier] || SPF_QUALIFIER_RESULT['+'];
}

/** Estado normalizado de una comprobación RBL: 'listed' | 'clean' | 'error'. */
export function rblCheckStatus(check) {
    if (!check) return 'error';
    return check.status || (check.listed ? 'listed' : 'clean');
}

// ===== Comparación con la muestra de calibración =====
// Las letras se calibraron con una muestra de grandes empresas (GRADE_CALIBRATION en
// analyzer.js), de la que solo se conserva el reparto por letra. La comparación es por
// letra, no por puntos: es lo que la muestra permite decir sin inventar.
const GRADE_ORDER = ['F', 'D', 'C', 'B', 'A', 'A+'];

/**
 * Qué parte de la muestra queda por debajo, igual y por encima de una letra (en %).
 * @returns {{ below: number, same: number, above: number, sample: number, date: string }|null}
 */
export function benchmarkFor(grade, calibration = GRADE_CALIBRATION) {
    const idx = GRADE_ORDER.indexOf(grade);
    if (idx < 0 || !calibration || !calibration.sample) return null;
    const shares = calibration.shares || {};
    // Los repartos están redondeados y pueden sumar 101: se acota a 100.
    const sum = (grades) => Math.min(100, grades.reduce((n, g) => n + (shares[g] || 0), 0));
    return {
        below: sum(GRADE_ORDER.slice(0, idx)),
        same: shares[grade] || 0,
        above: sum(GRADE_ORDER.slice(idx + 1)),
        sample: calibration.sample,
        date: calibration.date
    };
}

/** La comparación en una frase ("Mejor que el 20 % de una muestra de 61 grandes empresas…"). */
export function benchmarkText(t, grade, calibration = GRADE_CALIBRATION) {
    const b = benchmarkFor(grade, calibration);
    if (!b) return '';
    const pct = (n) => fillVars(t.pct_fmt || '{n} %', { n });
    const key = b.same === 0 ? 'benchmark_line_unique' : b.below === 0 ? 'benchmark_line_bottom' : 'benchmark_line';
    return fillVars(t[key], { below: pct(b.below), same: pct(b.same), sample: b.sample, grade });
}

/** "hoy", "hace 1 día", "hace 5 días". */
export function daysAgoText(t, days) {
    if (days === 0) return t.days_ago_today;
    if (days === 1) return t.days_ago_one;
    return fillVars(t.days_ago, { days });
}

/** Una cadena con {n}, en singular (su clave `_one`) cuando n es 1. */
export function countText(t, key, n) {
    const text = n === 1 && t[`${key}_one`] ? t[`${key}_one`] : t[key];
    return fillVars(text, { n });
}

// La fecha de registro (RDAP) manda. Sin ella, un historial de certificados más largo que
// NEW_DOMAIN_DAYS también dice que el nombre no es nuevo; uno corto no dice nada (puede
// ser un dominio antiguo que nunca tuvo web).
const domainIsNew = (f) => !!(f.age && f.age.status === 'new');
const oldByCt = (f) => !domainIsNew(f) && !!(f.cert && f.cert.firstSeen && f.cert.firstSeenDays > NEW_DOMAIN_DAYS);
const domainIsOld = (f) => !!(f.age && f.age.status === 'old') || oldByCt(f);

/**
 * Antigüedad de un dominio parecido, para la columna "Registrado": { text, tone, title }.
 * `tone` es el de la etiqueta (null: texto sin etiqueta); `title`, el detalle al pasar el
 * ratón. null si no se ha comprobado (no recibe correo).
 */
export function lookalikeAgeView(f, t, locale = 'es-ES') {
    const date = (iso) => new Date(iso).toLocaleDateString(locale);
    const age = f.age;
    if (age && age.status === 'checking') return { text: t.lookalike_cert_checking, tone: null };
    if (domainIsNew(f)) return { text: fillVars(t.lookalike_age_new, { ago: daysAgoText(t, age.days) }), tone: 'danger', title: date(age.registered) };
    if (age && age.status === 'old') return { text: date(age.registered), tone: null };
    if (oldByCt(f)) return { text: fillVars(t.lookalike_age_ct, { date: date(f.cert.firstSeen) }), tone: null };
    if (!age) return null;
    return { text: '—', tone: null, title: t.lookalike_age_unknown_hint };
}

const RISK_TONE = { high: 'danger', medium: 'warning', low: 'unknown', own: 'provider', pending: 'unknown' };

/**
 * Riesgo de un dominio parecido (assessLookalikeRisk), traducido: { level, text, tone,
 * reasons }. `reasons` son frases cortas, en orden de peso, para pintar bajo la etiqueta.
 */
export function lookalikeRiskView(f, t, locale = 'es-ES') {
    const { level, reasons } = assessLookalikeRisk(f);
    const reasonText = (r) => {
        switch (r.key) {
            case 'own': return t.lookalike_own_hint;
            case 'new': return fillVars(t.risk_reason_new, { ago: daysAgoText(t, r.days) });
            case 'cert_new': return fillVars(t.risk_reason_cert_new, { ago: daysAgoText(t, r.days) });
            case 'first_cert': return fillVars(t.risk_reason_first_cert, { ago: daysAgoText(t, r.days) });
            case 'mailbox': return fillVars(t.risk_reason_mailbox, { provider: r.provider });
            case 'sends': return fillVars(t.risk_reason_sends, { what: r.what === 'servers' ? t.risk_what_servers : r.what });
            case 'old': return fillVars(t.risk_reason_old, { date: new Date(r.registered).toLocaleDateString(locale) });
            default: return t[`risk_reason_${r.key}`] || r.key;
        }
    };
    return { level, text: t[`risk_${level}`], tone: RISK_TONE[level], reasons: reasons.map(reasonText) };
}

/**
 * Certificado de un dominio parecido, en pocas palabras: { text, tone, title }. Un
 * certificado de hace menos de 30 días solo es alarma en un dominio nuevo: en uno antiguo
 * es casi siempre una renovación (Let's Encrypt renueva cada 60 días), y si no se sabe la
 * antigüedad se dice sin alarmar. null si no se ha mirado en CT.
 */
export function lookalikeCertView(f, t, locale = 'es-ES') {
    const cert = f.cert;
    if (!cert) return null;
    const issuer = cert.issuer || undefined;
    switch (cert.status) {
        case 'recent': {
            const ago = daysAgoText(t, cert.days);
            if (domainIsNew(f)) return { text: fillVars(t.lookalike_cert_recent, { ago }), tone: 'danger', title: issuer };
            if (domainIsOld(f)) return { text: fillVars(t.lookalike_cert_renewed, { ago }), tone: 'warning', title: issuer };
            return { text: fillVars(t.lookalike_cert_issued, { ago }), tone: 'warning', title: [issuer, t.lookalike_cert_issued_hint].filter(Boolean).join(' · ') };
        }
        case 'active': return { text: fillVars(t.lookalike_cert_active, { date: new Date(cert.notBefore).toLocaleDateString(locale) }), tone: 'warning', title: issuer };
        case 'none': return { text: t.lookalike_cert_none, tone: 'provider' };
        case 'unchecked': return { text: t.lookalike_cert_unchecked, tone: 'unknown' };
        default: return { text: t.lookalike_cert_checking, tone: 'unknown' };
    }
}
