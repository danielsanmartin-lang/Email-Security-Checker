// viewmodel.js
// Capa de presentación COMPARTIDA por ui.js (DOM en vivo) y export.js (informe).
// Toma los datos crudos/normalizados del analyzer y produce texto ya traducido,
// evitando que cada renderizador re-derive y re-traduzca la misma información.

import { translations } from './i18n.js';

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
