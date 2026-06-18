# Propuestas de mejora — Email Security Checker

Análisis de la base de código (vanilla JS, ES modules, sin build, ~5.700 LOC en `js/`). No se ha modificado ningún archivo; esto es solo un conjunto de propuestas priorizadas.

---

## 🔴 Prioridad alta (corrección / bugs)

### 1. El score no está acotado a 0–100
En `analyzer.js > calculateScoreAndFindings`, el `score` se acumula sin límite superior. Sumando todos los positivos (SPF 30 + DMARC 55 + DKIM 10 + BIMI 5 + MTA-STS 5 + DANE 5) un dominio puede superar **110 puntos**, mientras que el grado A+ exige `>= 95`. El número mostrado pierde sentido.
**Propuesta:** `score = Math.max(0, Math.min(100, score))` antes de calcular el grado, o normalizar sobre un máximo definido.

### 2. Strings en español "hardcodeados" como datos (rompe i18n)
`analyze()` asigna literales como `provider = 'No identificado'`, `providerSource = 'No se encontraron indicadores...'`, y `getSPFLookupTree` mete errores en español (`'Loop detectado'`, `'Límite de profundidad excedido'`). Estos valores se renderizan tal cual aunque el usuario tenga la UI en inglés.
**Propuesta:** devolver claves de i18n (o un código de estado) y traducir en la capa de `ui.js`, igual que ya se hace con `findings.key`.

### 3. `checkRBL` / `getIPAddress` solo soportan IPv4 y una sola IP
- `getIPAddress` solo devuelve el primer registro `A`; ignora `AAAA` y MX con varias IPs.
- `checkRBL` hace `ip.split('.').reverse()`, que falla silenciosamente con IPv6.
- Las RBL están hardcodeadas y alguna está obsoleta (p. ej. **SORBS** se cerró en 2024).
**Propuesta:** soportar AAAA, iterar todas las IPs, externalizar la lista de RBL a `knowledge.js` y revisar su vigencia.

### 4. Lógica de normalización de dominio duplicada
El bloque que limpia `@`, `https://`, `www.` y la ruta aparece dos veces idéntico en `app.js` (en `runAnalysis` líneas ~16-20 y en el `submit` líneas ~229-233).
**Propuesta:** extraer a `normalizeDomain(input)` reutilizable (idealmente en `parsers.js` o un `utils.js`).

---

## 🟠 Prioridad media (calidad / mantenibilidad)

### 5. `package.json` incompleto y tests sin ejecutar
`package.json` solo declara `playwright`, pero `awarenessDetector.test.js` importa de **vitest**, que no es dependencia ni tiene script. Faltan `name`, `version`, `"type": "module"` y `scripts.test`.
**Propuesta:** añadir vitest como devDependency, `"type": "module"`, y `"scripts": { "test": "vitest" }`. Sin esto los tests no corren ni en CI.

### 6. Cobertura de tests muy parcial
Solo `awarenessDetector` tiene tests. La lógica más crítica y propensa a regresiones —`calculateScoreAndFindings` (scoring), `parseSPF`, `parseDMARC`, `extractRootDomain` (TLDs compuestos), `validateMTASTSPolicy`— no tiene ninguna. Son funciones puras, fáciles de testear.
**Propuesta:** añadir tests unitarios de `analyzer.js` y `parsers.js`. Alto retorno por bajo esfuerzo.

### 7. Sin linting ni formateo
No hay ESLint ni Prettier. Con ~5.700 líneas de JS conviene fijar un estándar.
**Propuesta:** añadir ESLint (config recomendada) + Prettier y un script `lint`.

### 8. Duplicación masiva de strings es/en en `export.js`
`export.js` genera el informe con decenas de `lang === 'es' ? '...' : '...'` inline en vez de usar las claves de `i18n.js`. Duplica el sistema de traducción y es difícil de mantener.
**Propuesta:** mover esas descripciones a `i18n.js` y consumirlas por clave, como el resto de la app.

### 9. Ejecución secuencial innecesaria en `runAnalysis`
MX → SPF → DMARC → DKIM → BIMI se ejecutan en serie con `await` encadenados (más dos `setTimeout` artificiales de 400/300 ms). Solo el bloque "advanced" usa `Promise.all`.
**Propuesta:** paralelizar las consultas independientes. Si se quiere conservar el feedback por pasos, marcar varios pasos como activos a la vez o actualizar el estado al resolverse cada promesa (`Promise.allSettled` + handlers).

### 10. Auditoría de XSS en los 37 usos de `innerHTML`
Existe `escapeHtml` (bien), pero hay 37 inserciones vía `innerHTML` que mezclan datos DNS no confiables. Basta una que olvide escapar para introducir XSS (los registros TXT/SPF/DKIM son atacante-controlables por el dueño del dominio consultado).
**Propuesta:** auditar cada `innerHTML` y garantizar que todo dato externo pasa por `escapeHtml`; considerar una CSP en `index.html`.

---

## 🟡 Prioridad baja (higiene / privacidad)

### 11. Proxies de terceros para fetch
MTA-STS usa `api.allorigins.win` como fallback CORS y la detección de awareness consulta `crt.sh`. Ambos envían el dominio analizado a terceros (privacidad) y son puntos de fallo externos.
**Propuesta:** documentarlo claramente en el README y/o ofrecer un pequeño proxy propio opcional.

### 12. Artefactos en el repo / `.gitignore`
`git status` muestra sin trackear toda la carpeta `graphify-out/` (caché generada), además de `package-lock.json`. Hay un `.DS_Store` en el árbol de trabajo.
**Propuesta:** añadir `graphify-out/` al `.gitignore` (si es salida generada) y decidir si `package-lock.json` debe versionarse (recomendado: sí).

### 13. Sin CI
No hay workflow de CI.
**Propuesta:** un GitHub Action mínimo que corra `lint` + `test` en cada push/PR.

### 14. Detalles menores
- `parseSPF` no soporta el mecanismo `all` con modificadores ni valida sintaxis; `ptr` está deprecado por RFC 7208 (se podría marcar como warning).
- `getSPFLookupTree` cuenta lookups de forma aproximada; conviene un test que verifique el límite de 10.
- Comentarios mezclados es/en; unificar idioma de comentarios ayudaría a la consistencia.
- Accesibilidad: revisar gestión de foco al abrir/cerrar modales (DKIM info, KB) y navegación por teclado.

---

## Resumen ejecutivo
La arquitectura modular es sólida y el dominio (análisis de seguridad de email) está bien cubierto. Las mejoras de mayor impacto y menor coste son: **acotar el score (1)**, **sacar el español hardcodeado de la lógica (2, 8)**, **wirear vitest + tests de scoring/parsers (5, 6)** y **deduplicar la normalización de dominio (4)**. Lo demás es robustez (IPv6/RBL), rendimiento (paralelizar) e higiene de repo.
