// ESLint flat config (ESLint 9+)
export default [
    {
        files: ['js/**/*.js'],
        ignores: ['graphify-out/**', 'node_modules/**'],
        languageOptions: {
            ecmaVersion: 2022,
            sourceType: 'module',
            globals: {
                // Navegador
                window: 'readonly',
                document: 'readonly',
                localStorage: 'readonly',
                fetch: 'readonly',
                AbortController: 'readonly',
                Blob: 'readonly',
                URL: 'readonly',
                ClipboardItem: 'readonly',
                navigator: 'readonly',
                history: 'readonly',
                setTimeout: 'readonly',
                clearTimeout: 'readonly',
                console: 'readonly',
                alert: 'readonly',
                Node: 'readonly',
                URLSearchParams: 'readonly',
                Event: 'readonly',
                encodeURIComponent: 'readonly',
                decodeURIComponent: 'readonly'
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
        // Archivos de test: añadir globals de Vitest
        files: ['js/**/*.test.js'],
        languageOptions: {
            globals: {
                describe: 'readonly',
                it: 'readonly',
                expect: 'readonly',
                vi: 'readonly',
                beforeEach: 'readonly',
                afterEach: 'readonly',
                global: 'readonly',
                globalThis: 'readonly'
            }
        }
    }
];
