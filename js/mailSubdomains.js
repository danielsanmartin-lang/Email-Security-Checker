// mailSubdomains.js
// Subdominios con correo, a partir de los nombres que aparecen en Certificate
// Transparency. Lógica pura: qué nombres merece la pena consultar y cómo leer lo que
// devuelven. Las consultas viven en api.js (checkMailSubdomains).
//
// Para qué: la política DMARC del dominio protege a sus subdominios con `sp` (y a los que
// no existen con `np`). Un `p=reject` con `sp=none` deja suplantable justo el subdominio
// que la empresa usa para enviar boletines o notificaciones, y desde el ápex no se ve.
// Los certificados públicos dicen qué subdominios existen sin tocar ningún servidor del
// dominio auditado. Informa, no puntúa.
import { isSameOrSubdomain } from './utils.js';
import { parseDMARC } from './parsers.js';
import { evaluateDmarc } from './dmarc.js';

// Primeras etiquetas que suelen usarse para ENVIAR correo (boletines, notificaciones,
// rebotes de plataformas de marketing). Se consultan primero.
export const SENDING_LABELS = [
    'mail', 'email', 'news', 'newsletter', 'info', 'marketing', 'mkt', 'notificaciones',
    'notifications', 'noreply', 'no-reply', 'bounce', 'bounces', 'em', 'envios', 'correo',
    'smtp', 'alerts', 'mailing', 'comunicaciones'
];

// Cuántos subdominios se consultan como mucho: cada uno cuesta tres consultas DNS.
export const MAX_MAIL_SUBDOMAINS = 15;

/**
 * Elige qué subdominios consultar: solo nombres concretos (sin comodines) que cuelgan del
 * dominio auditado, sin repetir. Primero los de etiquetas de envío y, para llenar el
 * cupo, los demás de menos niveles a más.
 *
 * @param {string[]} names nombres vistos en CT
 * @param {string} domain dominio auditado
 * @returns {string[]}
 */
export function selectMailSubdomains(names, domain, max = MAX_MAIL_SUBDOMAINS) {
    const base = String(domain || '').toLowerCase().replace(/\.$/, '');
    const seen = new Set();
    const candidates = [];
    for (const raw of names || []) {
        const name = String(raw).trim().toLowerCase().replace(/\.$/, '');
        if (!name || name.includes('*') || name === base || seen.has(name)) continue;
        if (!isSameOrSubdomain(name, base)) continue;
        seen.add(name);
        candidates.push(name);
    }
    const rank = (name) => (SENDING_LABELS.includes(name.split('.')[0]) ? 0 : 1);
    const depth = (name) => name.split('.').length;
    candidates.sort((a, b) => (rank(a) - rank(b)) || (depth(a) - depth(b)) || a.localeCompare(b));
    return candidates.slice(0, max);
}

/**
 * Lee lo que devolvieron las consultas de un subdominio.
 *
 * @param {string} name
 * @param {{ spf: string|null, mx: string[], dmarc: object|null, dmarcUnavailable?: boolean }} data
 *        `dmarc` es la salida de discoverDmarcPolicy (con su herencia por `sp`). Si su
 *        consulta falló, `dmarcUnavailable`: la política queda 'unknown' y no se acusa de
 *        nada (un fallo de DNS no es un "sin DMARC").
 * @returns {{ name, sends: boolean, receives: boolean, spf: string|null, policy: string,
 *   inherited: boolean, spoofable: boolean|null }}
 */
export function classifyMailSubdomain(name, { spf = null, mx = [], dmarc = null, dmarcUnavailable = false } = {}) {
    // `v=spf1 -all` (o sin mecanismos) declara que NO envía: no cuenta como remitente.
    const sends = !!spf && !/^v=spf1(\s+-all)?\s*$/i.test(spf.trim());
    const receives = (mx || []).length > 0;
    if (dmarcUnavailable) {
        return { name, sends, receives, spf: spf || null, policy: 'unknown', inherited: false, spoofable: null };
    }
    let policy = 'none';
    let enforced = false;
    if (dmarc && dmarc.record && !(dmarc.multiple && dmarc.source === 'author')) {
        const ev = evaluateDmarc(parseDMARC(dmarc.record), { source: dmarc.source || 'author', isOrgDomain: false });
        if (ev) {
            policy = ev.effective.floor;
            enforced = ev.processing === 'full' && ev.effective.floor !== 'none';
        }
    }
    return {
        name,
        sends,
        receives,
        spf: spf || null,
        policy,
        inherited: !!(dmarc && dmarc.inherited),
        spoofable: !enforced
    };
}
