// Shared utility helpers
import { escapeHtml } from './parsers.js';

/**
 * Marca un fragmento como HTML ya seguro (no se volverá a escapar al interpolarlo
 * dentro de un template html``). Úsalo solo con HTML que tú controlas.
 */
export class SafeHtml {
    constructor(value) {
        this.value = value == null ? '' : String(value);
    }
    toString() {
        return this.value;
    }
}

export function raw(value) {
    return new SafeHtml(value);
}

function renderValue(v) {
    if (v == null || v === false) return '';
    if (v instanceof SafeHtml) return v.value;
    if (Array.isArray(v)) return v.map(renderValue).join('');
    return escapeHtml(v);
}

/**
 * Tagged template que escapa AUTOMÁTICAMENTE cada interpolación (XSS-safe por defecto).
 * - Strings/números se escapan.
 * - Valores envueltos en raw()/SafeHtml o producidos por otro html`` no se re-escapan.
 * - Arrays se renderizan concatenando cada elemento con la misma regla.
 * Devuelve un SafeHtml; al asignarlo a innerHTML o a `${}` se coacciona a string vía toString().
 *
 * Ejemplo:
 *   el.innerHTML = html`<span>${userValue}</span>`;            // userValue escapado
 *   const row = html`<tr>${cells.map(c => html`<td>${c}</td>`)}</tr>`; // anidado seguro
 */
export function html(strings, ...values) {
    let out = strings[0];
    for (let i = 0; i < values.length; i++) {
        out += renderValue(values[i]) + strings[i + 1];
    }
    return new SafeHtml(out);
}


/**
 * Normaliza la entrada del usuario a un nombre de dominio limpio.
 * Acepta direcciones de correo, URLs con esquema, prefijo www y rutas.
 * @param {string} input
 * @returns {string} dominio en minúsculas sin esquema, www, ruta ni email local-part
 */
export function normalizeDomain(input) {
    if (!input) return '';
    let domain = String(input).trim().toLowerCase();
    if (domain.includes('@')) {
        domain = domain.substring(domain.indexOf('@') + 1);
    }
    domain = domain
        .replace(/^https?:\/\//, '')
        .replace(/\/.*$/, '')
        .replace(/^www\./, '');
    return domain;
}
