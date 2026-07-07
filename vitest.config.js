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
            thresholds: {
                statements: 68,
                branches: 60,
                functions: 70,
                lines: 68,
                // Módulos de lógica ya maduros: se protegen a su nivel alto.
                'js/analyzer.js': { statements: 90, branches: 78 },
                'js/parsers.js': { statements: 90 },
                'js/utils.js': { statements: 95 },
                'js/headerAnalyzer.js': { statements: 90 },
                'js/awarenessDetector.js': { statements: 90 },
                'js/viewmodel.js': { statements: 95 }
            }
        }
    }
});
