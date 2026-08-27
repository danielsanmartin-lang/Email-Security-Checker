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
            'no-var': 'error',
            // XSS: nunca asignar a innerHTML/outerHTML una plantilla o concatenación
            // construida a mano. Los valores vienen de DNS remoto, así que deben pasar
            // por el tagged template html`` de utils.js, que escapa cada interpolación.
            'no-restricted-syntax': ['error',
                {
                    selector: "AssignmentExpression[left.property.name=/^(inner|outer)HTML$/] > TemplateLiteral",
                    message: 'Usa el tagged template html`` (utils.js) en vez de una plantilla cruda: escapa las interpolaciones automáticamente.'
                },
                {
                    selector: "AssignmentExpression[left.property.name=/^(inner|outer)HTML$/] > BinaryExpression[operator='+']",
                    message: 'Usa el tagged template html`` (utils.js) en vez de concatenar HTML a mano.'
                }
            ]
        }
    },
    {
        // Service worker: se ejecuta en su propio contexto (self, caches, clients).
        files: ['sw.js'],
        languageOptions: {
            ecmaVersion: 2022,
            sourceType: 'script',
            globals: {
                ...globals.serviceworker
            }
        },
        rules: {
            'no-undef': 'error',
            'prefer-const': 'warn',
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
