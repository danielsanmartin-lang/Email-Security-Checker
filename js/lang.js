// Language state manager
export function getLanguage() {
    return localStorage.getItem('lang') || 'es';
}

export function setLanguage(lang) {
    localStorage.setItem('lang', lang);
}
