// dmarc.js
// Semántica DMARC según RFC 9989 (DMARCbis, mayo de 2026), que sustituye a RFC 7489.
//
// Módulo PURO: no consulta DNS ni toca el DOM. api.js hace el Tree Walk con estas piezas
// y analyzer.js puntúa con evaluateDmarc(). Vive aparte porque la transición entre las
// dos normas tiene reglas propias que no caben en el scoring sin enturbiarlo:
//
//   · RFC 9989 elimina `pct` (las etiquetas desconocidas se ignoran, §4.7) y añade `t`:
//     con t=y el receptor aplica un nivel MENOS de la política (§4.7).
//   · Los receptores que siguen en RFC 7489 hacen lo contrario: respetan `pct` (y con
//     pct=0 aplican también un nivel menos, §6.6.4) e ignoran `t`.
//
// Mientras convivan (a 09/2026 la inmensa mayoría de emisores de informes sigue en
// RFC 7489), el veredicto es CONSERVADOR: cuenta la política más débil que aplicaría
// alguna de las dos generaciones de receptores.

export const POLICY_RANK = { none: 0, quarantine: 1, reject: 2 };

const POLICIES = new Set(Object.keys(POLICY_RANK));

// Registro de etiquetas de RFC 9989 §9. Las eliminadas se reconocen aparte: no son
// erratas, son restos de un registro escrito para RFC 7489.
const KNOWN_TAGS = new Set(['v', 'p', 'sp', 'np', 't', 'psd', 'adkim', 'aspf', 'rua', 'ruf', 'fo']);
const REMOVED_TAGS = ['pct', 'ri', 'rf'];

export function isPolicy(value) {
    return POLICIES.has(value);
}

/** Política un nivel por debajo: la que aplica t=y (RFC 9989 §4.7) o pct=0 (RFC 7489 §6.6.4). */
export function lowerPolicy(policy) {
    return policy === 'reject' ? 'quarantine' : 'none';
}

/** La más débil de dos políticas válidas. */
export function weakerPolicy(a, b) {
    return POLICY_RANK[a] <= POLICY_RANK[b] ? a : b;
}

const labelsOf = (name) => String(name || '').toLowerCase().replace(/\.$/, '').split('.').filter(Boolean);

/**
 * Nombres que consulta el DNS Tree Walk DESPUÉS del dominio de partida (RFC 9989 §4.10,
 * pasos 3–7): se quita una etiqueta cada vez hasta llegar al TLD. Con 8 etiquetas o más
 * se salta directamente a las 7 últimas, para que ningún nombre cueste más de 8 consultas.
 * @param {string} domain
 * @returns {string[]} del más largo al más corto (incluye el TLD)
 */
export function treeWalkTargets(domain) {
    const labels = labelsOf(domain);
    if (labels.length < 2) return [];
    let current = labels.length >= 8 ? labels.slice(-7) : labels.slice(1);
    const out = [];
    while (current.length >= 1) {
        out.push(current.join('.'));
        current = current.slice(1);
    }
    return out;
}

/**
 * Dominio Organizativo según RFC 9989 §4.10.2, a partir de los registros VÁLIDOS que ha
 * encontrado el Tree Walk (incluido, si lo hay, el del dominio de partida). Se recorren
 * del más largo al más corto: `psd=n` lo declara; `psd=y` (salvo en el de partida) marca
 * un sufijo público y el organizativo es el nombre justo por debajo; si no, el de menos
 * etiquetas. Sin registros, el organizativo es el propio dominio de partida.
 * @param {Array<{name: string, psd?: string|null}>} found
 * @param {string} start
 */
export function selectOrgDomain(found, start) {
    const origin = labelsOf(start).join('.');
    const sorted = [...(found || [])].sort((a, b) => labelsOf(b.name).length - labelsOf(a.name).length);
    for (const entry of sorted) {
        const name = labelsOf(entry.name).join('.');
        if (entry.psd === 'n') return name;
        if (entry.psd === 'y' && name !== origin) {
            const depth = labelsOf(name).length + 1;
            return labelsOf(origin).slice(-depth).join('.');
        }
    }
    if (sorted.length > 0) return labelsOf(sorted[sorted.length - 1].name).join('.');
    return origin;
}

/**
 * Separa una lista de URIs de informe en válidos e inválidos. Válido = `mailto:` con
 * una dirección, o `https:`. El sufijo de tamaño `!10m` se tolera (RFC 9989 §4.8 lo
 * declara obsoleto: los emisores lo ignoran). El error típico que caza esto es
 * `rua=dmarc@dominio` sin el esquema `mailto:`: los receptores lo descartan en silencio.
 */
export function splitReportUris(list) {
    const valid = [];
    const invalid = [];
    for (const raw of list || []) {
        const uri = String(raw || '').trim();
        if (!uri) continue;
        const bare = uri.replace(/![0-9]+[kmgt]?$/i, '');
        if (/^mailto:[^@\s]+@[^@\s]+\.[^@\s]+$/i.test(bare) || /^https:\/\/\S+$/i.test(bare)) {
            valid.push(uri);
        } else {
            invalid.push(uri);
        }
    }
    return { valid, invalid };
}

const splitList = (value) => String(value || '').split(',').map(s => s.trim()).filter(Boolean);
const norm = (value) => (value == null ? null : String(value).trim().toLowerCase());

/**
 * Evalúa un registro DMARC ya parseado según RFC 9989 y su convivencia con RFC 7489.
 *
 * @param {object} parsed  salida de parseDMARC (o un objeto equivalente)
 * @param {object} [ctx]
 * @param {'author'|'org'|'psd'|null} [ctx.source]  dónde se encontró el registro respecto
 *        del dominio auditado: en él mismo, en su dominio organizativo o en un PSD
 * @param {boolean} [ctx.isOrgDomain]  el dominio auditado ES su dominio organizativo
 * @param {string[]} [ctx.rua]  destinos rua ya separados; si no se dan, se leen de `parsed.rua`
 * @param {string[]} [ctx.ruf]
 */
export function evaluateDmarc(parsed, ctx = {}) {
    if (!parsed) return null;
    const source = ctx.source || 'author';
    const inherited = source === 'org' || source === 'psd';
    // El sp/np de un registro publicado en un SUBdominio no rige nada: la búsqueda de
    // política de sus hijos sube hasta el dominio organizativo (RFC 9989 §4.7, nota de sp).
    const orgLevel = inherited || ctx.isOrgDomain !== false;

    const requested = { p: norm(parsed.p), sp: norm(parsed.sp), np: norm(parsed.np) };
    const invalidPolicyTags = ['p', 'sp', 'np'].filter(k => requested[k] != null && !isPolicy(requested[k]));

    const listOf = (given, raw) => (Array.isArray(given) && given.length > 0 ? given : splitList(raw));
    const rua = splitReportUris(listOf(ctx.rua, parsed.rua));
    const ruf = splitReportUris(listOf(ctx.ruf, parsed.ruf));

    // RFC 9989 §4.10.1: un p no válido, o un sp/np no válidos, hacen que TODO el registro
    // se trate como p=none si hay al menos un rua válido; sin él, no se aplica DMARC.
    let processing = 'full';
    if (invalidPolicyTags.length > 0) processing = rua.valid.length > 0 ? 'as_none' : 'none';

    // Valores de las demás etiquetas: un error de sintaxis se descarta en favor del valor
    // por defecto (RFC 9989 §4.8), pero se señala porque casi siempre es una errata.
    const invalidTags = [...invalidPolicyTags];
    const pick = (key, allowed, fallback) => {
        const value = norm(parsed[key]);
        if (value == null) return fallback;
        if (allowed.includes(value)) return value;
        invalidTags.push(key);
        return fallback;
    };
    const t = pick('t', ['y', 'n'], 'n');
    const psd = pick('psd', ['y', 'n', 'u'], null);
    const adkim = pick('adkim', ['r', 's'], 'r');
    const aspf = pick('aspf', ['r', 's'], 'r');

    let pct = null;
    if (parsed.pct != null) {
        const raw = String(parsed.pct).trim();
        const n = /^\d{1,3}$/.test(raw) ? parseInt(raw, 10) : NaN;
        if (Number.isFinite(n) && n >= 0 && n <= 100) pct = n;
        else invalidTags.push('pct');
    }

    const testing = t === 'y';
    const valid = (v) => (isPolicy(v) ? v : null);
    const p = processing === 'full' ? (valid(requested.p) || 'none') : 'none';
    const sp = processing === 'full' ? (valid(requested.sp) || p) : 'none';
    const np = processing === 'full' ? (valid(requested.np) || sp) : 'none';

    // Lo que aplica cada generación de receptores a una política dada.
    const applyTransition = (policy) => {
        const rfc9989 = testing ? lowerPolicy(policy) : policy;
        const rfc7489 = pct === 0 ? lowerPolicy(policy) : policy;
        return { requested: policy, rfc9989, rfc7489, floor: weakerPolicy(rfc9989, rfc7489) };
    };

    // El dominio auditado existe (si no, el análisis se habría detenido en NXDOMAIN), así
    // que cuando hereda la política le corresponde sp, no np (RFC 9989 §4.10.1).
    const applicableTag = inherited && requested.sp != null && processing === 'full' ? 'sp' : 'p';
    const applicable = inherited ? sp : p;
    const effective = {
        ...applyTransition(applicable),
        partialPct: pct != null && pct > 0 && pct < 100 ? pct : null
    };
    // Las tres políticas del registro tras la transición: p para el propio dominio, sp
    // para sus subdominios existentes y np para los inexistentes.
    const policies = { p: applyTransition(p), sp: applyTransition(sp), np: applyTransition(np) };

    // Enforcement (RFC 9989 §3.2.9): el dominio y todo lo que cuelga de él fuera de p=none.
    // Con un pct parcial no se llega: en los receptores RFC 7489 parte del correo que falla
    // recibe la política inferior.
    const enforcement = processing === 'full'
        && effective.floor !== 'none'
        && effective.partialPct == null
        && (!orgLevel || (policies.sp.floor !== 'none' && policies.np.floor !== 'none'));

    const presentKeys = Object.keys(parsed);
    const obsoleteTags = REMOVED_TAGS.filter(k => parsed[k] != null);
    const unknownTags = presentKeys.filter(k => !KNOWN_TAGS.has(k) && !REMOVED_TAGS.includes(k));

    return {
        source,
        inherited,
        orgLevel,
        processing,
        requested,
        invalidTags,
        applicableTag,
        applicable,
        testing,
        pct,
        effective,
        policies,
        enforcement,
        psd,
        adkim,
        aspf,
        obsoleteTags,
        unknownTags,
        // fo solo tiene sentido con ruf (RFC 9989 §4.7): sin él, se ignora.
        foIgnored: parsed.fo != null && ruf.valid.length === 0,
        rua,
        ruf
    };
}
