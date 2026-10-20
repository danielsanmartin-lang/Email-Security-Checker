// i18n.js
// Diccionario de la interfaz, un fichero por idioma en js/i18n/. El español viaja siempre
// con la app: es el idioma por defecto, el del HTML estático y el respaldo si algo falla.
// Inglés y alemán (dos tercios del diccionario) se descargan solo cuando se usan.
import es from './i18n/es.js';

/** Diccionarios cargados, por idioma. `es` siempre; los demás tras ensureLanguage(). */
export const translations = { es };

// Mapa explícito y no un import() con plantilla: el empaquetador necesita ver cada ruta
// para generar su trozo.
const LOADERS = {
    en: () => import('./i18n/en.js'),
    de: () => import('./i18n/de.js')
};
const _loading = {};

/**
 * Carga el diccionario de `lang` si aún no está. Resuelve a true cuando queda disponible
 * y a false si no se pudo cargar (sin conexión justo tras un despliegue, p. ej.): en ese
 * caso la interfaz sigue en español en vez de romperse.
 * @returns {Promise<boolean>}
 */
export function ensureLanguage(lang) {
    if (translations[lang]) return Promise.resolve(true);
    const loader = LOADERS[lang];
    if (!loader) return Promise.resolve(false);
    if (!_loading[lang]) {
        _loading[lang] = loader()
            .then((mod) => {
                translations[lang] = mod.default;
                return true;
            })
            .catch((err) => {
                delete _loading[lang];
                console.warn('No se pudo cargar el idioma %s', lang, err);
                return false;
            });
    }
    return _loading[lang];
}
