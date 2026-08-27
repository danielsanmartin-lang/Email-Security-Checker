# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es/1.1.0/)
y [Versionado Semántico](https://semver.org/lang/es/).

## [3.0.0] - 2026-08-27

### ⚠️ Cambio incompatible: nueva puntuación

El modelo aditivo anterior saturaba: SPF + DMARC `reject` + DKIM ya sumaban 95/100, así que
MTA-STS, DNSSEC, DANE y BIMI no movían la nota y un dominio sin transporte endurecido salía
A+. **Las notas de v3 no son comparables con las de v2.x.**

- Tres categorías con presupuesto propio: **Autenticación 60** (SPF 22 / DMARC 23 / DKIM 15),
  **Transporte 25** (MTA-STS 10 / DNSSEC 8 / DANE 7) e **Higiene 15** (informes DMARC 8 /
  TLS-RPT 4 / BIMI 3).
- El grado está **acotado por el ratio de Autenticación**: DNSSEC, DANE o BIMI ya no
  compensan un dominio suplantable. Con `p=none` o un PermError de SPF no se llega a A.
- Los controles **no evaluables** (DKIM no detectado por selectores comunes, SPF/DMARC sin
  resolver, política MTA-STS inalcanzable por CORS, BIMI declinado) **salen del denominador**
  en vez de contar como cero: se mantiene la regla de que la ausencia de DKIM no penaliza.
- Un control roto sí resta dentro de su categoría (una política inválida puntúa peor que su
  ausencia), pero ninguna categoría baja de 0 ni ningún check supera su presupuesto.
- `scoreCard.breakdown` alimenta el nuevo panel de desglose de la interfaz.

### Motor de análisis
- **SPF**: PermError cuando el destino de un `include`/`redirect` no publica SPF (fallo
  silencioso y frecuente); contaje de **void lookups** (RFC 7208 §4.6.4); mecanismos
  inalcanzables tras `all`; varios `all`; aviso de registro >255 caracteres.
- **MTA-STS**: se contrasta la lista `mx:` de la política con los MX reales (comodín de una
  etiqueta, RFC 8461 §4.1). Una política que no se puede descargar pasa a ser *no evaluable*
  en vez de penalizar como inválida — también en el panel.
- **TLS-RPT**: se valida que los destinos `rua` sean `mailto:` o `https:` (RFC 8460).
- **BIMI**: parseo por etiquetas — certificado **VMC/CMC** (`a=`), declinación explícita
  (`l=` vacío) y aviso si la URL no es HTTPS. El logotipo avisa si no se puede cargar.
- **DKIM**: soporte **Ed25519** (RFC 8463). El umbral de "clave débil <1024 bits" ya solo
  aplica a RSA; antes una Ed25519 se habría marcado como débil. El campo admite varios
  selectores separados por coma.
- **DMARC**: `np` (DMARCbis), `pct` marcado como obsoleto, `fo`/`ri` informativos y aviso
  con más de dos destinos `rua`.

### Nuevo
- **Herramientas avanzadas apagadas por defecto**, con una casilla por herramienta en
  Ajustes: el visor de informes DMARC, el selector DKIM y el analizador de cabeceras exigen
  algo que solo tiene quien administra el correo del dominio (los informes agregados, el
  nombre del selector, una muestra de correo). Se activan y aparecen al instante, sin
  recargar. Un deep-link `?dkim=` se sigue honrando aunque el campo esté oculto.
- **Visor de informes agregados DMARC (RUA)**: arrastra un `.xml`, `.xml.gz` o `.zip` y
  obtén remitentes por IP, volumen y tasas de paso SPF/DKIM/DMARC. Descompresión y parseo
  100% en el navegador, sin red (ni siquiera PTR sobre las IPs).
- **Panel de ajustes**: resolver DoH elegible (Google / Cloudflare / Quad9 / propio, sin
  respaldo público si es propio), proxy CORS público **opt-in y apagado por defecto**,
  refresco forzado que salta la caché de 5 minutos y URL de firmas de awareness.
- **Desglose de la puntuación** por categoría y control, con marca de *no evaluable*.
- **PWA**: manifest e `sw.js` que cachea el app shell. El tráfico externo (DoH, CT logs,
  MTA-STS) **nunca** se cachea: un análisis servido de caché daría un diagnóstico viejo.

### Corregido
- **`google.com` aparecía usando «Cisco Secure Email».** El disparador era el token TXT
  `cisco-ci-domain-verification`, que es la verificación de dominio de **Webex Control Hub**
  («CI» = Common Identity): prueba que alguien dio de alta el dominio en una organización de
  Webex y la propia documentación de Cisco dice que se puede borrar del DNS una vez
  verificado. No dice nada del correo — el MX de Google es suyo. Pasa a categoría
  informativa, sigue visible entre los tokens TXT. Igual con `spycloud-domain-verification`
  (monitorización de credenciales, no un filtro de correo). Regla nueva en el diccionario: un
  token solo es `seg`/`ices` si el producto que verifica es de seguridad de CORREO.
- **Las sospechas de awareness llegaban a confianza «alta» sin una sola prueba.** El score
  era un noisy-OR de todas las señales, así que tres indirectas (0,5 · 0,4 · 0,3) daban 0,79
  → badge «alta», con el aviso de «no confirmado» justo debajo contradiciéndolo. Ahora, sin
  evidencia directa el score se acota a 0,4 («baja»), Certificate Transparency deja de sumar
  y esos vendors salen de `detectedVendors` a una lista `indirectSignals` aparte, que la UI y
  el informe pintan como «señales indirectas (no concluyentes)».
- **Falso positivo sistemático de SEG**: cualquier MX cuyo dominio raíz no coincidiera con
  el analizado se anunciaba como capa de seguridad, con el dominio como "nombre de
  producto" (paypal.com → «paypalcorp.com», acme.com → «acmegroup.net», empresa.es →
  «empresa.com»). Los SEG reales los reconoce el diccionario antes de llegar a ese
  atajo, así que no aportaba ninguna detección: solo afirmaciones insostenibles. Ahora
  esos MX se presentan como **«MX externo no identificado»**, con la pista de si comparte
  nombre de marca con el dominio (probable infraestructura propia) y un botón para
  añadirlo al diccionario.
- El diccionario acepta entradas propias también en la lista **MX** (antes todo iba a la
  de includes SPF, que no se consulta para el correo entrante), con las categorías
  filtradas por lista: a un MX solo se le puede asignar proveedor, SEG o ICES.
- Guardar en el diccionario reventaba si el `<select>` no tenía una opción coincidente.
- La **ausencia** de SEG/ICES ya no fuerza la postura a «débil»: los ICES modernos son
  API-based y no dejan rastro en DNS (punto ciego documentado de la herramienta).
- El service worker servía módulos de caché mientras traía otros de red, y tras un
  despliegue podía mezclar versiones y romper la app. El HTML, el CSS y los `.js` van
  ahora a red primero, con la caché como respaldo sin conexión.
- Los análisis obsoletos ya no pisan al vigente: `runAnalysis` usa un token de ejecución y
  deshabilita el botón mientras trabaja.
- El deep-link se construye con `URLSearchParams` (antes interpolaba dominio y selector sin
  escapar) y el selector DKIM se valida.
- Un `data-tooltip` vacío dejaba visible el tooltip del elemento anterior.

### Privacidad y accesibilidad
- Tipografías **autoalojadas** (92 KB, subsets latin): ninguna petición a Google Fonts.
- **CSP** declarada en `index.html` con `default-src 'self'`, `script-src 'self'`,
  `base-uri 'none'` y `form-action 'none'`. `connect-src` enumera los servicios usados
  y admite además `https:`: la política MTA-STS vive en `mta-sts.<dominio-auditado>`, un
  host que solo se conoce en ejecución y que CSP no puede expresar con comodín.
- Tooltips accesibles: aparecen al enfocar, se cierran con Escape y usan `role="tooltip"`
  con `aria-describedby`. Sus disparadores son enfocables.
- Etiquetas (`sr-only`) para los campos de dominio y selector DKIM; el `aria-label` de la
  región de resultados se traduce.
- Favicon, `meta description` y tarjetas Open Graph/Twitter.

### Arquitectura, calidad y CI
- `js/bootstrap.js` separa el cableado del DOM de la orquestación; `ui.js` pasa de 1088 a
  ~205 líneas y los paneles viven en `js/ui/` (10 módulos).
- Todo el HTML dinámico se construye con el tagged template `html``` (auto-escapado), con
  una **regla ESLint** que prohíbe asignar a `innerHTML` plantillas o concatenaciones crudas.
  Los estilos en línea de la UI pasan a clases.
- `knowledge.js` declara `KB_VERSION`/`KB_UPDATED_AT` y hay tests de esquema de las firmas.
- Nuevo `integration.dom.test.js`: monta `index.html` en jsdom con DoH simulado y recorre el
  flujo completo. Cobertura global 78% → **88%** (`app.js` 36% → 93%); umbrales elevados.
- `pages.yml` publicaba solo `index.html`, `css/*.css` y `js/*.js`: ahora incluye `js/ui/`,
  las fuentes, el manifest, el service worker y el icono, y falla si falta algo del shell.

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
