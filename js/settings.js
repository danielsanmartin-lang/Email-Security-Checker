// settings.js
// Preferencias del usuario, persistidas en localStorage. Existen porque esta
// herramienta se usa también en auditorías confidenciales: quién resuelve el DNS y
// si el dominio pasa por un proxy público de terceros no puede ser una decisión
// tomada en el código.
const STORAGE_KEY = 'esc_settings';

export const DEFAULT_SETTINGS = {
    // Resolver DoH primario: 'google' | 'cloudflare' | 'quad9' | 'custom'
    resolver: 'google',
    // URL base del resolver propio (formato JSON de DoH). Ej.: https://dns.midominio.com/resolve
    customResolverUrl: '',
    // Proxy CORS público (api.allorigins.win) para descargar la política MTA-STS.
    // Por defecto DESACTIVADO: envía el dominio auditado a un tercero. Sin él, la
    // política que el navegador no pueda descargar queda "no evaluable" (no penaliza).
    allowCorsProxy: false,
    // URL de un JSON de fingerprints de awareness para mantener las firmas al día.
    fingerprintsUrl: ''
};

// Resolvers conocidos. `headers` es lo que exige cada uno para responder en JSON.
// Nota: los que se añadan aquí deben estar también en el connect-src del CSP de
// index.html, o el navegador bloqueará la petición.
export const RESOLVERS = {
    google: {
        label: 'Google',
        url: (name, type) => `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`
    },
    cloudflare: {
        label: 'Cloudflare',
        url: (name, type) => `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
        headers: { 'Accept': 'application/dns-json' }
    },
    quad9: {
        label: 'Quad9',
        url: (name, type) => `https://dns.quad9.net:5053/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
        headers: { 'Accept': 'application/dns-json' }
    }
};

let _cache = null;

export function getSettings() {
    if (_cache) return _cache;
    _cache = { ...DEFAULT_SETTINGS };
    if (typeof localStorage === 'undefined') return _cache;
    try {
        const raw = localStorage.getItem(STORAGE_KEY);
        if (raw) {
            const stored = JSON.parse(raw);
            // Solo se aceptan claves conocidas: un localStorage manipulado no debe
            // colar campos arbitrarios en la configuración.
            for (const key of Object.keys(DEFAULT_SETTINGS)) {
                if (stored[key] !== undefined) _cache[key] = stored[key];
            }
        }
    } catch {
        /* JSON corrupto o almacenamiento no disponible: se usan los valores por defecto */
    }
    return _cache;
}

export function saveSettings(patch) {
    const next = { ...getSettings(), ...patch };
    _cache = next;
    if (typeof localStorage !== 'undefined') {
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
        } catch {
            /* modo privado o cuota agotada: la sesión sigue con los valores en memoria */
        }
    }
    return next;
}

/** Descarta la copia en memoria (tests y cambios externos de localStorage). */
export function resetSettingsCache() {
    _cache = null;
}

/**
 * Lista ordenada de resolvers a usar: primero el elegido, luego los demás como
 * respaldo. Con un resolver PROPIO no hay respaldo público: quien lo configura lo
 * hace justamente para que el dominio auditado no salga de su infraestructura.
 * @returns {Array<{label: string, url: string, headers?: object}>}
 */
export function resolverChain(name, type) {
    const s = getSettings();
    if (s.resolver === 'custom' && s.customResolverUrl) {
        const base = s.customResolverUrl.replace(/\?.*$/, '').replace(/\/$/, '');
        return [{
            label: 'Custom',
            url: `${base}?name=${encodeURIComponent(name)}&type=${type}`,
            headers: { 'Accept': 'application/dns-json' }
        }];
    }
    const primary = RESOLVERS[s.resolver] ? s.resolver : DEFAULT_SETTINGS.resolver;
    const order = [primary, ...Object.keys(RESOLVERS).filter(k => k !== primary)];
    return order.map(key => {
        const r = RESOLVERS[key];
        return { label: r.label, url: r.url(name, type), ...(r.headers ? { headers: r.headers } : {}) };
    });
}
