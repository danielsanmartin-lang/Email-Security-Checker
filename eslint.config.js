// ESLint flat config (ESLint 9+)
import js from '@eslint/js';
import globals from 'globals';

export default [
    js.configs.recommended,
    {
        files: ['js/**/*.js'],
        ignores: ['graphify-out/**', 'node_modules/**'],
        languageOptions: {
            ecmaVersion: 2022,
            sourceType: 'module',
            globals: {
                ...globals.browser
            }
        },
        rules: {
            'no-unused-vars': ['warn', { args: 'none', caughtErrors: 'none' }],
            'no-undef': 'error',
            'prefer-const': 'warn',
            eqeqeq: ['warn', 'smart'],
            'no-var': 'error'
        }
    },
    {
        // Archivos de test: añadir globals de Vitest y Node.
        files: ['js/**/*.test.js'],
        languageOptions: {
            globals: {
                ...globals.node,
                describe: 'readonly',
                it: 'readonly',
                expect: 'readonly',
                vi: 'readonly',
                beforeEach: 'readonly',
                afterEach: 'readonly'
            }
        }
    }
];
