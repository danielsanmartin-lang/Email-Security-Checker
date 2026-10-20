// Language state manager
import { translations } from './i18n.js';

// Idiomas con diccionario completo en js/i18n/. Cualquier otro valor guardado en
// localStorage (una versión anterior de la app, un retoque a mano) cae a español
// en lugar de dejar la interfaz sin traducir.
export const SUPPORTED_LANGS = ['es', 'en', 'de'];

// Locale BCP-47 para fechas y horas: el código de idioma no basta para formatear
// los timestamps con las convenciones del país.
const LOCALES = { es: 'es-ES', en: 'en-US', de: 'de-DE' };

/** El idioma que eligió el usuario, esté o no cargado ya su diccionario. */
export function getStoredLanguage() {
    const stored = localStorage.getItem('lang');
    return SUPPORTED_LANGS.includes(stored) ? stored : 'es';
}

/**
 * El idioma en el que pintar AHORA: el elegido si su diccionario ya está cargado y, si
 * no, español. El inglés y el alemán se descargan aparte (ensureLanguage en i18n.js):
 * mientras llegan, la interfaz se ve en español en vez de romperse por un diccionario que
 * aún no existe, y se vuelve a traducir cuando llega.
 */
export function getLanguage() {
    const stored = getStoredLanguage();
    return translations[stored] ? stored : 'es';
}

export function setLanguage(lang) {
    localStorage.setItem('lang', lang);
}

export function getLocale(lang = getLanguage()) {
    return LOCALES[lang] || LOCALES.es;
}
