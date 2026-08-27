import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        environment: 'node',
        include: ['js/**/*.test.js'],
        globals: false,
        coverage: {
            provider: 'v8',
            reporter: ['text', 'html', 'lcov'],
            include: ['js/**/*.js'],
            exclude: ['js/**/*.test.js', 'js/i18n.js', 'js/lang.js', 'js/state.js'],
            // Umbrales conservadores (por debajo de lo actual) para congelar lo
            // ganado sin romper el build; suben a medida que crece la cobertura.
            // v3: el test de integración con jsdom (integration.dom.test.js) recorre
            // el flujo completo, lo que subió app.js del 36% al 92% y permitió elevar
            // el suelo global del 68% al 85%.
            thresholds: {
                statements: 85,
                branches: 70,
                functions: 90,
                lines: 85,
                // Módulos de lógica ya maduros: se protegen a su nivel alto.
                'js/analyzer.js': { statements: 94, branches: 85 },
                'js/parsers.js': { statements: 94 },
                'js/utils.js': { statements: 95 },
                'js/headerAnalyzer.js': { statements: 90 },
                'js/awarenessDetector.js': { statements: 94 },
                'js/viewmodel.js': { statements: 95 },
                'js/app.js': { statements: 88 },
                'js/ui/**': { statements: 85 }
            }
        }
    }
});
