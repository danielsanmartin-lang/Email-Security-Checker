import { describe, it, expect } from 'vitest';
import { translations } from './i18n.js';
import { SUPPORTED_LANGS, getLocale } from './lang.js';

// El diccionario es la única fuente de las cadenas de la interfaz: una clave que
// falte en un idioma no rompe nada visiblemente, sencillamente deja ese trozo de
// UI en blanco. Estos tests lo convierten en un fallo de build.

const LANGS = Object.keys(translations);
const REFERENCE = 'es';
const referenceKeys = Object.keys(translations[REFERENCE]).sort();

// Marcadores de posición que rellena el código en tiempo de ejecución ({policy},
// {n}, {selectors}…). Si una traducción los pierde o los renombra, el usuario ve
// el hueco vacío o un literal sin sustituir.
const placeholders = (value) =>
    typeof value === 'string' ? (value.match(/\{[a-zA-Z_]+\}/g) || []).sort().join(',') : '';

describe('diccionario i18n', () => {
    it('expone exactamente los idiomas declarados como soportados', () => {
        expect(LANGS.sort()).toEqual([...SUPPORTED_LANGS].sort());
    });

    it.each(LANGS)('%s tiene el mismo juego de claves que %s', (lang) => {
        expect(Object.keys(translations[lang]).sort()).toEqual(referenceKeys);
    });

    it.each(LANGS)('%s no deja ninguna cadena vacía', (lang) => {
        const empty = referenceKeys.filter((key) => {
            const value = translations[lang][key];
            return typeof value === 'string' && value.trim() === '';
        });
        expect(empty).toEqual([]);
    });

    it.each(LANGS)('%s conserva los marcadores de posición de %s', (lang) => {
        const mismatched = referenceKeys.filter(
            (key) => placeholders(translations[REFERENCE][key]) !== placeholders(translations[lang][key])
        );
        expect(mismatched).toEqual([]);
    });

    it.each(LANGS)('%s traduce las mismas categorías que %s', (lang) => {
        expect(Object.keys(translations[lang].category_labels).sort()).toEqual(
            Object.keys(translations[REFERENCE].category_labels).sort()
        );
        expect(Object.keys(translations[lang].category_defaults).sort()).toEqual(
            Object.keys(translations[REFERENCE].category_defaults).sort()
        );
    });
});

describe('getLocale', () => {
    it.each(LANGS)('%s tiene un locale BCP-47 propio', (lang) => {
        expect(getLocale(lang)).toMatch(/^[a-z]{2}-[A-Z]{2}$/);
    });

    it('cae a español ante un idioma desconocido', () => {
        expect(getLocale('xx')).toBe('es-ES');
    });
});
