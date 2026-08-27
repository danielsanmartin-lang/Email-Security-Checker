import { describe, it, expect } from 'vitest';
import { KB, KB_VERSION, KB_UPDATED_AT } from './knowledge.js';
import { AWARENESS_FINGERPRINTS, AWARENESS_DICT_VERSION } from './awarenessDetector.js';
import { HEADER_FINGERPRINTS } from './headerAnalyzer.js';

// El KB es un diccionario de datos que se edita a mano y a menudo: un patrón
// duplicado o un `type` mal escrito no rompe ningún test funcional, simplemente
// hace que una detección deje de dispararse en silencio. Estas comprobaciones
// son la red que evita esa clase de fallo.
describe('esquema de la base de conocimiento', () => {
    it('declara versión y fecha de actualización', () => {
        expect(KB_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
        expect(KB_UPDATED_AT).toMatch(/^\d{4}-\d{2}-\d{2}$/);
        expect(KB.version).toBe(KB_VERSION);
        expect(KB.updatedAt).toBe(KB_UPDATED_AT);
    });

    const LISTS_WITH_PATTERN = ['mx', 'spf', 'txt_verification', 'ns_providers', 'tlsrpt_reporters', 'dmarc_reporters'];
    for (const list of LISTS_WITH_PATTERN) {
        it(`KB.${list}: cada entrada tiene pattern y name no vacíos`, () => {
            expect(Array.isArray(KB[list])).toBe(true);
            expect(KB[list].length).toBeGreaterThan(0);
            for (const entry of KB[list]) {
                expect(typeof entry.pattern, `${list} → ${JSON.stringify(entry)}`).toBe('string');
                expect(entry.pattern.trim().length).toBeGreaterThan(0);
                expect(typeof entry.name).toBe('string');
                expect(entry.name.trim().length).toBeGreaterThan(0);
            }
        });
    }

    it('KB.mx usa solo tipos conocidos', () => {
        const VALID = new Set(['provider', 'seg', 'ices', 'self', 'unknown']);
        for (const entry of KB.mx) {
            expect(VALID.has(entry.type), `${entry.pattern} → ${entry.type}`).toBe(true);
        }
    });

    it('KB.mx no repite patrones (el primero gana y el resto sería código muerto)', () => {
        const seen = new Map();
        for (const entry of KB.mx) {
            const key = `${entry.matchType || 'contains'}:${entry.pattern.toLowerCase()}`;
            expect(seen.has(key), `patrón duplicado: ${key} (${seen.get(key)} vs ${entry.name})`).toBe(false);
            seen.set(key, entry.name);
        }
    });

    it('KB.spf no repite patrones', () => {
        const seen = new Set();
        for (const entry of KB.spf) {
            const key = entry.pattern.toLowerCase();
            expect(seen.has(key), `patrón SPF duplicado: ${key}`).toBe(false);
            seen.add(key);
        }
    });

    it('KB.txt_verification declara categorías válidas y pesos en rango', () => {
        const VALID = new Set(['seg', 'ices', 'email', 'marketing', 'transactional', 'crm', 'signatures', 'support', 'other', 'unknown']);
        for (const entry of KB.txt_verification) {
            expect(VALID.has(entry.category), `${entry.name} → ${entry.category}`).toBe(true);
            if (entry.weight != null) {
                expect(entry.weight).toBeGreaterThan(0);
                expect(entry.weight).toBeLessThanOrEqual(1);
            }
        }
    });

    it('KB.rbl_lists son hostnames válidos', () => {
        for (const rbl of KB.rbl_lists) {
            expect(rbl).toMatch(/^[a-z0-9.-]+\.[a-z]{2,}$/i);
        }
    });
});

describe('esquema de los diccionarios de awareness', () => {
    it('el diccionario DNS declara versión', () => {
        expect(AWARENESS_DICT_VERSION).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    });

    it('cada fingerprint DNS tiene displayName y pesos en rango', () => {
        for (const [key, fp] of Object.entries(AWARENESS_FINGERPRINTS)) {
            expect(typeof fp.displayName, key).toBe('string');
            expect(fp.displayName.length).toBeGreaterThan(0);
            for (const [signal, w] of Object.entries(fp.weights || {})) {
                expect(w, `${key}.${signal}`).toBeGreaterThan(0);
                expect(w, `${key}.${signal}`).toBeLessThanOrEqual(1);
            }
        }
    });

    it('cada fingerprint de cabeceras declara al menos un patrón', () => {
        for (const [key, fp] of Object.entries(HEADER_FINGERPRINTS)) {
            expect(typeof fp.displayName, key).toBe('string');
            const patterns = (fp.headerPatterns || []).length + (fp.textPatterns || []).length;
            expect(patterns, `${key} no tiene ningún patrón`).toBeGreaterThan(0);
            expect(fp.weight).toBeGreaterThan(0);
            expect(fp.weight).toBeLessThanOrEqual(1);
        }
    });
});
