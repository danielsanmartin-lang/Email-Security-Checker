// Language state manager
// Idiomas con diccionario completo en i18n.js. Cualquier otro valor guardado en
// localStorage (una versión anterior de la app, un retoque a mano) cae a español
// en lugar de dejar la interfaz sin traducir.
export const SUPPORTED_LANGS = ['es', 'en', 'de'];

// Locale BCP-47 para fechas y horas: el código de idioma no basta para formatear
// los timestamps con las convenciones del país.
const LOCALES = { es: 'es-ES', en: 'en-US', de: 'de-DE' };

export function getLanguage() {
    const stored = localStorage.getItem('lang');
    return SUPPORTED_LANGS.includes(stored) ? stored : 'es';
}

export function setLanguage(lang) {
    localStorage.setItem('lang', lang);
}

export function getLocale(lang = getLanguage()) {
    return LOCALES[lang] || LOCALES.es;
}
