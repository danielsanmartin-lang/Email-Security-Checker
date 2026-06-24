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
            exclude: ['js/**/*.test.js', 'js/i18n.js', 'js/lang.js']
            // Reporte informativo; no se fija umbral para no romper el build
            // mientras se amplía la cobertura de los módulos de UI/export.
        }
    }
});
