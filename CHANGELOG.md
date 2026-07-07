# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es/1.1.0/)
y [Versionado Semántico](https://semver.org/lang/es/).

## [2.6.2] - 2026-07-07

### UI / Accesibilidad
- `role`/`aria-live` en las secciones asíncronas (carga, error, resultados) para
  que los lectores de pantalla anuncien el progreso.
- Los ejemplos de dominio pasan de `<span>` a `<button>` (foco por teclado y
  `:focus-visible`).
- `<html lang>` se sincroniza con el idioma activo.
- Modales con `role="dialog"`, `aria-modal`, cierre con Escape y trampa de foco.
- `--text-muted` aclarado a ratio de contraste ≥ 4.5:1 (WCAG AA).

### Testing / CI / higiene
- ESLint ahora extiende `@eslint/js` recommended (caza `no-dupe-keys`,
  `no-unreachable`, `no-empty`, etc.) y usa el paquete `globals` en vez de una
  lista manual de globales.
- `npm run lint` es bloqueante (`--max-warnings=0`).
- CI: `npm ci` (en vez de `npm install`), caché de npm, matriz Node 20/22 y
  cobertura con umbrales bloqueantes.
- Umbrales de cobertura en `vitest.config.js` (global + por módulo maduro).
- Eliminado `playwright` de devDependencies (no se usaba).
- Añadido `LICENSE` (MIT) y campo `license` en `package.json`.

## [2.6.1] - 2026-07-07

### Exportación y arquitectura
- El informe incluye ahora DNSSEC, DANE/TLSA, SRV, árbol de lookups SPF y
  autorización de destinos DMARC externos (RFC 7489 §7.1).
- PDF unificado: `exportToPDF` imprime el mismo `generateReportHTML()` en un
  iframe oculto, en vez de `window.print()` de la vista viva.
- Traducidas las cadenas del informe que quedaban fijas en inglés; corregido el
  plural «1 detectados» → «1 detectado».
- Banner del informe con color sólido de reserva (Word no soporta gradientes).
- Estado global extraído a `state.js`, rompiendo el ciclo `app.js ↔ export.js`.

## [2.6.0] - 2026-07-07

### Motor DNS (robustez y precisión)
- Degradación resiliente: la fase 1 usa `Promise.allSettled`; solo aborta si
  fallan a la vez MX y el TXT del ápex. SPF/DMARC no resueltos se marcan «no
  disponible» en vez de penalizarse como ausentes.
- Árbol de lookups SPF: resuelve cada nivel en paralelo, cuenta los mecanismos
  con máscara CIDR (`a/24`, `mx/24`) y distingue bucle real de include repetido.
- MTA-STS: no sigue redirects (RFC 8461 §3.3) y usa el código HTTP real del
  proxy.
- Deduplicación de consultas DoH en vuelo.
- Parseo TXT multi-string unificado (`extractTxtValue`) en DKIM/BIMI/awareness.

## [2.5.3] - 2026-07-07

### Robustez
- Herencia DMARC del dominio organizativo (RFC 7489 §6.6.3) para subdominios.
- Reconocimiento de Null MX (RFC 7505).
- FQDN con punto final (`example.com.`) ya no se rechaza.
- La hora del escaneo se fija una vez y no se recalcula al re-renderizar/exportar.

## [2.5.2] - 2026-07-07

### Seguridad
- Corregido XSS por clic en la tabla SPF (onclick inline → `data-` + listener).
- `queryDNS` valida el `Status` DoH: SERVFAIL/REFUSED ya no se reportan como
  «sin registros» ni se cachean.
- RBL: el estado inconcluso se propaga en vez de mostrarse como «Limpio».
- Nuevo workflow de despliegue a GitHub Pages con gate de lint+tests; deja de
  publicarse `graphify-out/` (contenía rutas locales).

## [2.5.1] y anteriores

Ver el historial en `README.md`.
