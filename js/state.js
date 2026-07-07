// Estado global compartido de la sesión de análisis.
// Vive en su propio módulo (no en app.js) para evitar el ciclo de imports
// app.js ↔ export.js: export.js necesita el estado, y app.js importa export.js.
export const state = {
    currentDomain: '',
    currentResult: null
};
