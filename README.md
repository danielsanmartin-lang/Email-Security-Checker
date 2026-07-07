# 🛡️ Email-Security-Checker
Auditoría de Seguridad de Correo

Una herramienta web de ciberseguridad diseñada para auditar la infraestructura de correo electrónico, analizar registros DNS y detectar pasarelas de seguridad (SEGs), soluciones ICES y **plataformas de Security Awareness / Phishing Simulation**.

🚀 **[PROBAR LA APLICACIÓN](https://danielsanmartin-lang.github.io/Email-Security-Checker/)**

---

## 💡 Características principales

* **Análisis DNS en tiempo real:** Consulta registros MX, SPF, DMARC, DKIM, BIMI, MTA-STS, TLS-RPT, NS y **DNSSEC** directamente desde el navegador vía DNS-over-HTTPS.
* **Identificación de Proveedores (SEGs/ICES):** Base de conocimiento local con más de 50 firmas de servicios de correo (Microsoft 365, Google Workspace, Proofpoint, Mimecast, etc.).
* **Awareness-Vendor Detector:** Módulo dedicado que detecta plataformas de concienciación de seguridad y simulación de phishing (KnowBe4, Proofpoint SAT, Cofense, Hoxhunt, Barracuda PhishLine, etc.) a partir de señales DNS, con score de confianza y evidencia estructurada. Distingue **"tiene el gateway del vendor"** de **"usa el módulo de awareness"** (confirmación de producto), y se enriquece con dos fuentes de Certificate Transparency (crt.sh + Certspotter).
* **Análisis por cabeceras de correo:** Pega las cabeceras de un correo de simulación recibido y la herramienta detecta el vendor con **alta confianza** por dominios de envío y X-headers propietarias (`X-PHISHTEST`, `X-Gophish-*`, `simulator.office.com`…). Cubre **Microsoft Attack Simulation Training**, que no deja rastro en DNS. 100% local.
* **Evaluación de Seguridad:** Diagnóstico visual del estado de las políticas de autenticación (A+ a F, 0–100 puntos).
* **Análisis profundo de autenticación:**
  - **DMARC**: política de subdominios (`sp`), porcentaje (`pct`), modo de alineación (`adkim`/`aspf`) y **autorización de destinos de informe externos** (`_report._dmarc`, RFC 7489).
  - **DKIM**: validación de la **fuerza de la clave** (bits del módulo RSA), detección de claves **revocadas** (`p=` vacío) y **modo de prueba** (`t=y`). La ausencia de DKIM ya no penaliza (detección *best-effort* por selectores comunes).
  - **SPF**: aviso de ausencia de mecanismo `all` (neutral por defecto) y de uso del mecanismo `ptr` (desaconsejado por RFC 7208).
  - **MTA-STS**: validación de `max_age` (presencia y valor recomendado, RFC 8461).
  - **DNSSEC**: detección de zona firmada (DNSKEY + flag `AD`) que protege la integridad de SPF/DMARC/DKIM.
* **Reputación y Listas Negras (RBL):** Verificación en tiempo real de IPs de servidores MX contra listas globales, con interpretación de los códigos de respuesta (`listado` / `limpio` / `no concluyente`) y aviso *best-effort* — muchas DNSBL rechazan consultas vía resolvers DoH públicos.
* **Exportaciones Premium:** Informes en Google Docs, Word (.doc) y PDF con score, hallazgos, SPF tree y DMARC detallado.
* **Validación de entrada y errores claros:** Normalización de dominios **IDN → punycode**, validación de formato y mensajes de error diferenciados (dominio inexistente / sin conexión / formato inválido).
* **Multilingüe:** Interfaz completa en Español e Inglés con persistencia por `localStorage`.

## 🏗️ Arquitectura del Sistema

Este proyecto está construido bajo una arquitectura **Pure Frontend (Serverless)**:

* **Sin Backend:** Todo el procesamiento y parseo de registros ocurre en el cliente.
* **DNS-over-HTTPS (DoH):** Utiliza las APIs públicas de Google DNS y Cloudflare DNS con fallback automático.
* **Certificate Transparency (crt.sh):** El módulo de Awareness enriquece la detección consultando CT logs para buscar subdominios asociados a infra de vendors.
* **Módulos ES6:** Separación estricta de responsabilidades en `/js/`.

```
js/
├── app.js               # Orquestador principal — runAnalysis()
├── api.js               # Motor DoH (getMX, getSPF, getDMARC, getDKIM…)
├── analyzer.js          # Lógica de identificación de proveedores/SEGs
├── ui.js                # Renderizado de resultados y paneles
├── awarenessDetector.js # 🆕 Detector de plataformas de Awareness/PhishSim (DNS)
├── headerAnalyzer.js    # 🆕 Detección por cabeceras de correo (cubre el punto ciego DNS)
├── knowledge.js         # Base de conocimiento de vendors (>50 firmas)
├── i18n.js              # Traducciones ES/EN
├── lang.js              # Selector de idioma con persistencia
├── export.js            # Motor de exportación (Google Docs / Word / PDF)
└── parsers.js           # Parsers de registros DNS
```

## 🛠️ Tecnologías utilizadas

* HTML5 / CSS3 (Vanilla — sin frameworks)
* JavaScript Vanilla (ES6+ Modules)
* API de DNS-over-HTTPS (Google / Cloudflare)
* Certificate Transparency API (crt.sh)

---

## 🔐 Privacidad y servicios de terceros

La herramienta es 100% cliente y no usa backend propio, pero ciertas comprobaciones
delegan en servicios externos. Al usarlas, **el dominio analizado se envía a esos terceros**:

* **DNS-over-HTTPS (Google `dns.google` y Cloudflare `cloudflare-dns.com`):** todas las
  consultas DNS. Cloudflare actúa como _fallback_ si Google falla.
* **Proxy CORS `api.allorigins.win`:** solo como _fallback_ para descargar el fichero de
  política MTA-STS (`https://mta-sts.<dominio>/.well-known/mta-sts.txt`) cuando el navegador
  bloquea la petición directa por CORS. El dominio objetivo viaja en la URL del proxy.
* **Certificate Transparency (`crt.sh` y `api.certspotter.com`):** el módulo de Awareness
  consulta los CT logs para enriquecer la detección; el dominio se envía como parámetro de
  búsqueda. Certspotter actúa como _fallback_ si crt.sh falla o no devuelve datos.

El **análisis por cabeceras de correo** es 100% local (no envía nada a terceros): las
cabeceras pegadas se procesan en el navegador.

Si la privacidad es crítica (p. ej. auditorías confidenciales), se recomienda alojar un
proxy CORS propio y/o un resolver DoH interno y sustituir estas URLs en `js/api.js` y
`js/awarenessDetector.js`.

---

## 💻 Instalación y Uso Local

Si prefieres ejecutar este proyecto de forma local en tu máquina:

1. Clona este repositorio:
   ```bash
   git clone https://github.com/danielsanmartin-lang/Email-Security-Checker.git
   ```
2. Accede al directorio:
   ```bash
   cd Email-Security-Checker
   ```
3. Dado que la aplicación utiliza **Módulos ES6**, el navegador bloqueará la carga de archivos locales por políticas de seguridad (CORS). Es necesario servir el proyecto mediante un servidor HTTP local. Puedes levantarlo fácilmente:
   * **Con Python (Recomendado):**
     ```bash
     python3 -m http.server 8080
     ```
   * **Con Node/NPM:**
     ```bash
     npx http-server -p 8080
     ```
4. Abre tu navegador y accede a **`http://localhost:8080`**.

### Desarrollo: Tests, Lint y Formato

El proyecto incluye `package.json` con scripts y dependencias de desarrollo (Vitest, ESLint, Prettier):

```bash
npm install        # instala devDependencies

npm test           # ejecuta toda la suite de tests (Vitest)
npm run test:watch # modo watch
npm run coverage   # tests + informe de cobertura (v8)
npm run lint       # ESLint sobre js/
npm run format     # Prettier (formatea js/)
```

La suite (**128 tests**) cubre el módulo de Awareness (fixtures DNS mockeados), el análisis
por cabeceras (`headerAnalyzer`), los parsers
(`parseSPF`, `parseDMARC`, `parseMTASTSPolicy`, `validateMTASTSPolicy`, `analyzeDKIMRecord`,
`extractTxtValue`), el analizador (`extractRootDomain`, `calculateScoreAndFindings` y los
nuevos findings de DMARC/DKIM/SPF/DNSSEC/MTA-STS), la capa DNS (`checkRBL`, `getDNSSEC`,
`checkDomainExists`, `checkDMARCExternalAuth` con `fetch` mockeado), las utilidades
(`normalizeDomain` IDN, `isValidDomain`, helper `html``) y pruebas de integración con
**jsdom** que ejecutan `renderResults` y la generación del informe verificando el escapado
anti-XSS de extremo a extremo.

Cada push/PR ejecuta en CI mediante GitHub Actions:
* **`ci.yml`** — lint + tests con cobertura + `npm audit` (informativo). El informe de
  cobertura se publica como artefacto.
* **`codeql.yml`** — análisis estático de seguridad (CodeQL, `security-extended`) en cada
  push/PR y de forma programada semanalmente.

---

## 📅 Historial de Cambios

### v2.5.1 — Precisión SEG/ICES: cross-check con el MX y deduplicación de vendors (Actual)

Correcciones de exactitud en la detección de capas de seguridad (`detectSecurityLayers`), a raíz de un falso positivo del tipo *"amazon.com usa Cisco Email Security — 70%"*.

* **Fin del 70% falso por token de verificación:** un SEG cuya **única** evidencia era un token TXT de propiedad de dominio alcanzaba "media" (0.7) en solitario. Ahora se **cruza con el MX**: si ningún registro MX pertenece a ese vendor (p. ej. el dominio tiene MX propio), la afirmación se degrada a **"baja"** y se marca *"sin confirmar en el MX"* en la UI y el informe. Un gateway que no está en el flujo de correo no está filtrando nada. Mismo patrón que el 70% falso de Microsoft AST ya corregido en v2.4.0.
* **`cisco-ci-domain-verification` recategorizado:** deja de reportarse como SEG "Cisco Email Security". Es un token del **Cisco Security Cloud** (transversal a Umbrella/XDR/Threat Defense…), no prueba del gateway IronPort. Pasa a **ICES de baja confianza** (peso propio `0.35`), ya que Threat Defense es API-based y su único rastro DNS suele ser ese TXT.
* **Peso por token TXT:** cada token del diccionario puede fijar su propio peso (`weight`) en lugar del `0.7` global, para calibrar la confianza señal a señal.
* **Identidad canónica de vendor:** la confirmación por MX reconoce al mismo vendor aunque los diccionarios usen nombres distintos (*"Sophos"* en el token vs *"Sophos Email"* en el MX), evitando marcar como "sin confirmar" a un cliente cuyo MX **sí** es de ese vendor.
* **Deduplicación de entradas:** nombres unificados en el KB (Sophos, Trend Micro, Forcepoint, Avanan/Check Point) para que un vendor detectado por varias señales (MX + SPF + TXT) se muestre como **una sola** tarjeta con toda la evidencia agregada, en vez de duplicarse. Se preservan los productos genuinamente distintos (Proofpoint vs Proofpoint Essentials, Symantec cloud vs gateway).

> **+6 tests** (total **134**): caso Amazon (token Cisco → ICES baja, no SEG), cross-check de MX, identidad canónica, fusión de entradas y renderizado del aviso en UI y export.

### v2.5.0 — Detección de Awareness más precisa y por cabeceras

Seis mejoras al detector de plataformas de Awareness / Phishing Simulation, centradas en exactitud y en romper el techo del análisis solo-DNS.

* **Análisis por cabeceras de correo (`js/headerAnalyzer.js`):** nuevo módulo + panel en el detector de Awareness para **pegar las cabeceras** de un correo de simulación y detectar el vendor con **alta confianza** por dominios de envío y X-headers propietarias (`X-PHISHTEST` de KnowBe4, `X-Gophish-Contact`/`X-Gophish-Signature`, `X-PhishMe` de Cofense, `simulator.office.com`/`phishingsimulations.microsoft.com` de Microsoft AST…). Cubre **Microsoft Attack Simulation Training**, indetectable por DNS. Trabajo 100% local.
* **Gateway vs. módulo de awareness (`productConfirmed`):** se distingue la evidencia *directa* del producto de concienciación de la evidencia *indirecta* (su gateway de correo / co-ubicación). Si solo hay señal de gateway (p. ej. MX de Proofpoint/Mimecast), la tarjeta lo indica: *"proveedor compatible — módulo no confirmado"*.
* **Sondeo CNAME ampliado y con verificación de destino:** lista de subdominios de campaña mucho mayor; ahora **cualquier** subdominio del cliente cuyo CNAME apunte a infra del vendor cuenta (se verifica el destino, no solo que el subdominio exista).
* **Correlación DKIM más estricta:** un selector de vendor recibe peso fuerte solo si el registro **referencia/está CNAME-ado** al dominio firmante del vendor; un selector con clave genérica que no lo referencia pasa a indicio débil (evita falsos positivos por selectores comunes como `s1`).
* **Doble fuente de Certificate Transparency:** `crt.sh` como primaria y **Certspotter** como _fallback_ (fusiona resultados, degrada con elegancia si CORS/red falla).
* **Diccionario versionado y actualizable:** versión exportada (`AWARENESS_DICT_VERSION`) y funciones para cargar/persistir fingerprints personalizados (`loadCustomFingerprints`/`saveCustomFingerprints`/`loadFingerprintsFromUrl` + auto-carga desde `localStorage`), para mantener las firmas al día sin tocar código.

> **Nota:** también se corrigió un *bug* de pesos del MX hint heredado (cualquier dominio M365 mostraba 70% de usar AST con la única señal "usa Microsoft"); ahora Microsoft AST queda en **15% ("baja")** y los gateways reales (Proofpoint/Mimecast 0.3) pesan más. **+12 tests** (total **128**).

### v2.4.0 — Precisión del Análisis, DNSSEC y Endurecimiento de Calidad

Esta versión profundiza la **exactitud** de los resultados que la herramienta presenta como verdad, además de reforzar la validación de entrada y el tooling de calidad.

* **RBL más fiable (interpretación de códigos):** `checkRBL` ya no trata cualquier respuesta como "listado". Distingue **`listado`** (`127.0.0.x`), **`limpio`** (NXDOMAIN) y **`no concluyente`** (`127.255.255.x` = consulta rechazada por resolver público o fallo de red). La UI y el informe muestran el estado real y un aviso *best-effort*, porque muchas DNSBL (Spamhaus, SpamCop…) rechazan las consultas que llegan vía DoH público (Google/Cloudflare).
* **Análisis DMARC profundo:** nuevos hallazgos para política de subdominios más débil (`sp` < `p`), aplicación parcial (`pct` < 100), alineación estricta (`adkim`/`aspf`) y, sobre todo, **autorización de destinos de informe externos** (`<dominio>._report._dmarc.<destino>`, RFC 7489 §7.1) — un fallo de configuración real que provoca que los informes se descarten. Se muestra por destino en el panel de reporting.
* **DKIM: fuerza de clave y estado, sin falsos castigos:** `analyzeDKIMRecord` parsea el `SubjectPublicKeyInfo` (DER) y calcula los **bits del módulo RSA**, marcando claves **débiles (< 1024)**, **1024 (mínimo, recomienda 2048)**, **revocadas** (`p=` vacío) y en **modo prueba** (`t=y`). La **ausencia** de DKIM pasa a ser informativa (detección *best-effort* por selectores comunes): un selector personalizado válido ya no baja la nota.
* **SPF: cobertura de huecos comunes:** aviso cuando **no hay mecanismo `all`** (la política por defecto es neutral `?all`) y cuando se usa el mecanismo **`ptr`** (desaconsejado por RFC 7208).
* **MTA-STS `max_age`:** validación de presencia y valor recomendado (≥ 604800 s, RFC 8461) sin invalidar la política, expuesto como aviso.
* **DNSSEC:** nuevo `getDNSSEC` (registros `DNSKEY` + flag `AD`), con bonificación de score, hallazgo y panel propio en DNS avanzado. La firma de la zona protege la integridad de SPF/DMARC/DKIM frente a envenenamiento de caché.
* **Validación de entrada y errores diferenciados:** `normalizeDomain` convierte **IDN → punycode** (vía API `URL`) y quita puerto; `isValidDomain` valida el formato antes de consultar. Los errores se distinguen entre **dominio inexistente (NXDOMAIN)**, **error de red** y **formato inválido**, cada uno con su mensaje (ES/EN).
* **Awareness — peso del MX hint corregido (representatividad):** se arregló un *bug* por el que el motor de scoring leía claves de peso (`mxExact`/`mxSubstring`) que los fingerprints no definían, cayendo a un valor por defecto de **0.7**. Esto inflaba la detección: cualquier dominio M365 aparecía con **70% (MEDIA)** de usar *Microsoft Attack Simulation Training* con la única señal de "usa Microsoft". Ahora se honra el peso de cada fingerprint (`w.mxHint`): Microsoft AST baja a **15% ("baja")** y los gateways de seguridad reales (Proofpoint/Mimecast `0.3`, Sophos/Barracuda `0.25`) pesan más que el simple uso de M365, reflejando que suelen venderse o complementarse con concienciación.
* **Calidad y DevEx:** `playwright` movido a `devDependencies`; añadido **`@vitest/coverage-v8`** y script `npm run coverage`. CI ampliado con cobertura (artefacto) + `npm audit`, y nuevo workflow **CodeQL** (`security-extended`, también semanal). **+36 tests** nuevos (total **116**), incluyendo `js/api.test.js` con `fetch` mockeado, la validación del parser DKIM contra claves RSA reales y los tests del peso del MX hint en Awareness.

> ⚠️ Las comprobaciones RBL son **orientativas** (best-effort): para resultados fiables se recomienda un resolver/proxy propio. Las listas de selectores/tokens por vendor siguen siendo heurísticas.

### v2.3.0 — Detección de Capas de Seguridad Multi-Señal

* **Detección SEG/ICES ponderada y multi-señal**: La identificación de capas de seguridad dejó de ser binaria. Ahora `detectSecurityLayers` agrega evidencia de varias fuentes y calcula una **confianza por vendor** (noisy-OR → nivel Alta/Media/Baja), mostrada en la UI y en el informe junto a las evidencias concretas.
* **Nuevas fuentes de señal aprovechando datos que ya se obtenían**:
  - **SPF aplanado**: se inspecciona toda la cadena de includes (no solo el primer nivel), detectando gateways escondidos en includes anidados (`collectSpfDomains` sobre el árbol SPF).
  - **Lista `mx:` de la política MTA-STS**: los hostnames MX autorizados en el fichero de política se cruzan contra la base de conocimiento, revelando el gateway aunque el MX activo no lo muestre.
  - **Selectores DKIM → vendor** (`KB.dkim_security_selectors`): permite detectar la capa de seguridad por la firma DKIM incluso cuando el MX es el del proveedor (Microsoft/Google) y el gateway opera en modo API o re-firmando.
* **ICES basados en API**: ampliada la base de conocimiento de tokens de verificación TXT (Material, Sublime, Avanan/Check Point, Tessian, Egress, Vade, Darktrace, Cyren…) y la UI deja claro que estos ICES (Graph/Google API) **no dejan rastro DNS**: "no detectado" ≠ "no hay capa de seguridad".
* **Awareness**: el matching de IPs SPF ahora soporta **IPv6** (CIDR con BigInt), y **crt.sh** nunca puede ser señal única (requiere al menos otra evidencia) con caché ampliada para reducir su fragilidad.
* **Pesos centralizados** en `KB.seg_signal_weights` y **20 tests** nuevos (detección multi-señal, SPF aplanado, IPv6 CIDR). Total: 80 tests.

> ⚠️ Las listas de selectores/tokens por vendor son heurísticas y deben validarse contra la documentación oficial; pueden cambiar con el tiempo.

### v2.2.0 — Refactorización Arquitectónica

* **Helper de plantillas `html`` ` con auto-escapado**: Nuevo tagged template (`js/utils.js`) que escapa cada interpolación por defecto (XSS-safe), con marcador `raw()` para HTML ya seguro y soporte de anidación/arrays. `escapeHtml` se reimplementó sin DOM (funciona en Node y escapa también comillas). Adoptado en `renderSPFTree` y en el renderizado de findings/postura.
* **Capa view-model compartida (`js/viewmodel.js`)**: Centraliza la lógica de presentación que antes duplicaban `ui.js` y `export.js` (texto de findings, política DMARC, postura, descripción de servicios, fuente del proveedor, conteo RBL, etiquetas de categoría).
* **Scoring declarativo**: `calculateScoreAndFindings` se reescribió como una tabla de evaluadores por sección con pesos centralizados (`SCORE_WEIGHTS`, `MAX_POSITIVE_SCORE`), preservando el comportamiento y facilitando los tests.
* **Eliminado el patrón "sentinel" de proveedor/fuente**: El analyzer emite estructura neutral de idioma (`providerIdentified`, `providerSource = { key, arg }`) y la traducción ocurre en la capa de presentación, en lugar de revertir cadenas en español por coincidencia de texto.
* **Etiquetas de categoría movidas a i18n**: Los mapas de traducción de categorías viven ahora en `i18n.js` (`category_labels`, `category_defaults`).
* **Capa DNS unificada**: `awarenessDetector.js` reutiliza `queryDNS` de `api.js` (caché y fallback compartidos) en vez de su propio cliente DoH duplicado.
* **`extractTxtValue`**: Extraído el parsing repetido de registros TXT entrecomillados (usado por SPF, DMARC, MTA-STS, TLS-RPT y getAllTXT).
* **Tests**: 68 en total, incluyendo pruebas de integración con jsdom que ejecutan `renderResults` y el informe de exportación verificando el escapado anti-XSS de extremo a extremo.

### v2.1.0 — Robustez, i18n completa, IPv6 y Tooling

* **Puntuación acotada (0–100)**: El cálculo del score ahora se limita correctamente al rango 0–100 antes de derivar el grado, evitando valores incoherentes (>100) frente al umbral A+.
* **Internacionalización completa de la lógica**: Se eliminaron las cadenas en español incrustadas en el código. Los errores del árbol SPF, la postura de seguridad y los paneles SRV/DANE ahora usan claves i18n y se traducen correctamente en ambos idiomas. El informe exportado (`export.js`) consume claves de `i18n.js` en lugar de duplicar el sistema de traducción con ternarios `es/en`.
* **Soporte IPv6 y multi-IP en RBL**: La resolución de IPs ahora incluye registros `AAAA` y todas las IPs del host; `checkRBL` soporta el formato de consulta inverso IPv6. Las listas RBL se externalizaron a `knowledge.js` (se retiró SORBS, cerrada en 2024).
* **Análisis en paralelo**: `runAnalysis` ejecuta las consultas DNS independientes concurrentemente (MX, SPF, DMARC, BIMI, avanzadas), reduciendo significativamente el tiempo total, manteniendo el feedback por pasos.
* **Refuerzo anti-XSS**: Auditoría y escapado (`escapeHtml`) de todos los valores derivados de DNS insertados vía `innerHTML`, tanto en la UI como en el informe exportado.
* **Utilidad compartida `normalizeDomain`**: Deduplicada la lógica de normalización de dominio (email, esquema, `www`, ruta) en `js/utils.js`.
* **Tooling de desarrollo**: `package.json` completo (`type: module`, scripts), Vitest configurado, ESLint (flat config) + Prettier, y CI con GitHub Actions. Nueva cobertura de tests para parsers y analizador (49 tests).
* **Privacidad documentada**: Nueva sección del README sobre los servicios de terceros (DoH de Google/Cloudflare, proxy CORS `allorigins.win`, `crt.sh`).

### v2.0.0 — Detección Avanzada de DNS (SRV/DANE), Postura de Seguridad y Mejoras en Awareness

* **Protocolo DANE (TLSA) y Registros SRV**: Añadido soporte para consultas DNS en paralelo de registros de autenticación DANE/TLSA (`_25._tcp`) para verificar la seguridad del cifrado en los servidores MX, además de sondeos de autodescubrimiento SRV (`_autodiscover`, `_imaps`, `_submission`).
* **Indicador de Postura de Seguridad**: Cálculo automático y visualización de la postura general del dominio (`Fuerte` 🟢, `Moderada` 🟡, `Débil` 🔴) en la tarjeta de puntuación, evaluando SPF, DMARC, DKIM, SEG/ICES y MTA-STS.
* **Mejoras de Detección de Awareness**:
  - *Sondeo CNAME*: Búsqueda de subdominios populares de landings/tracking (`click`, `track`, `phish`, etc.) delegados a infraestructuras de proveedores.
  - *Sondeo DKIM Genérico*: Prueba automática de selectores estándar (`s1`, `s2`, `k1`, etc.) para verificar firmas criptográficas de vendors.
  - *Detección Cruzada*: Impulso por correlación de seguridad perimetral (SEG) para proveedores co-localizados (Proofpoint, Barracuda, Mimecast, Sophos).
  - *Tokens TXT*: Detección de tokens de verificación específicos en el dominio raíz.
* **Ampliación de Base de Conocimiento**: Añadidas firmas de SEG/ICES para *Egress Defend*, *Libraesva*, *VIPRE*, *Graphus* y *Armorblox*.

### v1.9.0 — Awareness-Vendor Detector: Detección de Plataformas de Phishing Simulation

El módulo más ambicioso hasta la fecha: detecta automáticamente si una empresa usa una plataforma de **Security Awareness Training / Phishing Simulation** a partir de su huella DNS, sin necesidad de acceso privilegiado.

#### 🔍 Pipeline de detección (por dominio de entrada)

1. **SPF Flattening (RFC 7208):** Resolución recursiva de la cadena `v=spf1` respetando el límite de 10 lookups. Se aplana a la lista final de `include:`, dominios e IPs/CIDRs.
2. **MX:** Inferencia de gateway (Mimecast bundlea awareness, Proofpoint pphosted, etc.).
3. **DMARC:** Registro `_dmarc.<dominio>` — se registra `rua`/`ruf` por si apuntan a infra de vendor.
4. **DKIM selectivo:** Sondeo SOLO de los selectores conocidos del diccionario (`<selector>._domainkey.<dominio>`). Si resuelven hacia el dominio firmante del vendor → señal fuerte.
5. **Certificate Transparency (crt.sh):** Búsqueda de subdominios del dominio auditado cuyo CN/SAN apunte a infra de vendor.
6. **Scoring probabilístico:** Score combinado `1 − Π(1 − peso_i)` por tipo de señal, nunca supera 1. Niveles: **Alta ≥ 75%**, **Media ≥ 45%**, **Baja**.

#### 📚 Diccionario de fingerprints (v2026-06-05)

| Vendor | SPF Include | SPF IPs/CIDRs | DKIM Selector | MX Hint | crt.sh |
|--------|:-----------:|:-------------:|:-------------:|:-------:|:------:|
| **KnowBe4 (KSAT)** | `_spf.psm.knowbe4.com` | `23.21.109.197`, `147.160.167.0/26`… | — | — | ✓ |
| **Proofpoint SAT** | — | — | — | `pphosted` | ✓ |
| **Cofense PhishMe** | — | — | — | — | ✓ |
| **Mimecast Awareness** | — | — | — | `mimecast` | ✓ |
| **Sophos Phish Threat** | — | — | — | `sophos.com` | ✓ |
| **Hoxhunt** | `_spf.hoxhunt.com` | — | `hoxhunt` | — | ✓ |
| **Infosec IQ** | — | — | — | — | ✓ |
| **Barracuda / PhishLine** | `_spf.phishline.com` | — | `phishline` | `barracudanetworks.com` | ✓ |
| **Proofpoint ThreatSim** | — | — | — | — | ✓ |

> **⚠️ Punto ciego documentado:** Microsoft Attack Simulation Training (Defender for O365) — todo el tráfico es interno al tenant M365. Los allowlists se configuran en "Advanced Delivery" (Exchange Online Protection) a nivel de tenant sin dejar rastro DNS externo. **No es detectable por este módulo.**

#### Nuevos componentes

* **`js/awarenessDetector.js`** — Motor completo con diccionario recargable en caliente (`mergeFingerprints()`), caché interno con TTL de 5 min y fallback Cloudflare DoH.
* **`js/awarenessDetector.test.js`** — Suite Vitest con fixtures DNS mockeados para todos los vendors, scoring, CIDR matching y SPF PermError.
* **Panel UI** — Tarjetas de vendor con barra de confianza animada, nivel (Alta/Media/Baja), evidence pills con tipo de señal + valor, nota de vendor y alerta de punto ciego Microsoft siempre visible.
* **Paso de carga** — Nuevo `step-awareness` visible en la secuencia de loading tras el análisis principal.
* **Soporte multilingüe** — 25 claves nuevas en ES + EN en `i18n.js`.

---

### v1.8.0 — Informes de Exportación Enriquecidos y Detección SEG Mejorada
* **Puntuación de Seguridad en Exportaciones:** La sección de Resumen Ejecutivo de los informes exportados (Google Docs, Word, PDF) ahora incluye la nota de seguridad (A+ a F) junto con la puntuación sobre 100 puntos.
* **Tabla de Configuración DMARC Detallada:** Los informes exportados muestran una tabla de parámetros DMARC parseados (`p`, `sp`, `pct`, `adkim`, `aspf`) para una lectura más clara de la política activa.
* **Columna de Resultado en Tabla SPF:** Cada entrada de la tabla SPF en el informe exportado incluye ahora una columna de resultado (`Pass`, `Fail`, `SoftFail`, `Neutral`) según el calificador del mecanismo.
* **Identificación de Proveedores de Reporte DMARC (RUA/RUF):** Los informes exportados detectan e identifican automáticamente el nombre del proveedor de reporting (Valimail, Dmarcian, Postmark, etc.) a partir de las direcciones `rua`/`ruf`.
* **Fuente de Evidencia del Proveedor:** La tarjeta de resultado ahora muestra en qué registro DNS (MX, SPF, TXT, NS) se detectó cada proveedor o SEG identificado.
* **Corrección: Sin Falsos Positivos de SEG en Auto-hospedaje:** Cuando los registros MX apuntan al mismo dominio raíz que se analiza, la herramienta ya no clasifica incorrectamente la infraestructura propia como una pasarela de seguridad (SEG).
* **Detección de SEG Desconocido por Dominio MX Externo:** Si los registros MX apuntan a un dominio raíz diferente al analizado y no coinciden con ninguna firma conocida, la herramienta ahora lo reporta como pasarela de seguridad de proveedor desconocido.

### v1.7.4 — Validaciones de Seguridad Robustas para SPF y DMARC
* **Detección de Múltiples Registros DNS:** Alertas críticas y penalización en la puntuación si se configuran múltiples registros SPF o DMARC (infracciones de RFC 7208 y RFC 7489 que rompen la autenticación de correos).
* **Análisis del Calificador `all` en SPF:** Penalización y alertas específicas para directivas SPF inseguras o excesivamente permisivas como `+all` (pase libre para cualquier remitente) y `?all` (neutral/sin protección).
* **Validación de Sintaxis DMARC:** Validación estricta para garantizar que la etiqueta de versión (`v=DMARC1`) y la directiva de política (`p=none|quarantine|reject`) cumplan con los estándares y no contengan valores inválidos.
* **Interfaz de Registros Múltiples:** La interfaz ahora detecta, resalta y renderiza de forma independiente cada uno de los registros en conflicto detectados en el DNS.

### v1.7.3 — Seguridad contra XSS, Bypass de CORS en MTA-STS y Caché DNS
* **Sanitización contra vulnerabilidades XSS en registros DNS:** Sanitización automática de caracteres HTML conflictivos en cualquier registro recuperado de DNS antes de renderizarlo con `innerHTML`.
* **Bypass de CORS en MTA-STS:** Fallback inteligente a un proxy CORS (allorigins.win) cuando la recuperación directa del archivo de políticas MTA-STS es bloqueada por restricciones CORS del navegador.
* **Caché DNS en memoria:** Implementación de caché local con TTL de 5 minutos para evitar consultas DNS redundantes y optimizar la velocidad general de la auditoría.

### v1.7.2 — Corrección en Detección de Hornetsecurity y Extracción de Dominio
* **Soporte Mejorado para Hornetsecurity:** Añadidas firmas de detección para Hornetsecurity en registros MX (patrón `antispameurope`) y registros SPF (patrones `hornetsecurity` y `antispameurope`).
* **Extracción de Dominio de Direcciones de Correo:** Al introducir o pegar una dirección de correo completa en el buscador, la herramienta limpia automáticamente la entrada ignorando el prefijo y el símbolo `@`.

### v1.7.1 — Explicación de Bucles SPF en Árbol de Consultas
* **Tooltip Explicativo de Bucles (Loops) SPF:** Visualización interactiva y tooltip didáctico al pasar el cursor sobre la alerta `[Error: Loop detectado]`, explicando en detalle la causa raíz del error por referencias circulares en registros DNS SPF en español e inglés.

### v1.7.0 — Detección Avanzada de ICES y Consultas DNS Paralelas
* **Auditoría DNS Avanzada:** Incorporación de consultas DNS sobre registros TXT raíz, NS, MTA-STS y TLS-RPT para realizar un escrutinio de seguridad en tiempo real y sin servidor.
* **Detección de Soluciones ICES Ocultas:** Nuevo motor de cruce de datos que detecta pasarelas de seguridad cloud y soluciones ICES de próxima generación (Perception Point, xorlab, Material Security, Area 1, etc.) analizando registros de verificación (TXT) y enrutadores (NS).
* **Panel de Resultados Avanzado:** Nuevo módulo en la interfaz de resultados que expone de forma amigable la adopción de tecnologías MTA-STS y TLS-RPT.

### v1.6.1 — Mejoras en Exportación a Google Docs
* **Auto-titulado Inteligente:** Se ha optimizado la exportación a Google Docs añadiendo el nombre del dominio auditado al inicio del reporte.

### v1.6.0 — Tooltips Didácticos, Auto-descubrimiento DKIM y Reputación RBL
* **Auto-descubrimiento Inteligente de Selectores DKIM:** Búsqueda automática de hasta 10 selectores DKIM más comunes en paralelo.
* **Auditoría de Reputación de Dominio (Listas Negras/RBLs):** Resolución en tiempo real de IPs de servidores MX y verificación paralela contra listas de reputación globales (SORBS, Spamcop, DroneBL).
* **Exportaciones e Informes Premium:** Rediseño completo del motor de exportación a Google Docs, archivos Word (.doc) e impresión PDF.

### v1.5.0 — Tarjeta de Puntuación de Seguridad Interactiva
* **Puntuación de Seguridad (Security Score Card):** Integración de un panel dinámico que calcula una nota (A+ hasta F) sobre 100 puntos basada en la configuración DNS de la seguridad del correo.
* **Indicador Radial Animado:** Implementación visual de la puntuación a través de un anillo SVG interactivo animado.
* **Auditoría Dinámica Multilingüe:** Generación de una lista de hallazgos instantáneos (positivos y alertas) que se traduce en tiempo real al cambiar entre Inglés y Español.

### v1.4.0 — Soporte Multilingüe e Informes PDF Optimizados
* **Soporte Multilingüe (Español / Inglés):** Implementación multi-idioma (`js/lang.js` y `js/i18n.js`) traduciendo toda la interfaz web.
* **Selector de Idiomas:** Menú interactivo en la cabecera con indicadores visuales de banderas y persistencia del idioma seleccionado vía `localStorage`.
* **Reportes Localizados Dinámicos:** Generación de informes en Google Docs, archivos de Word (.doc) e impresión PDF completamente traducidos al idioma activo.

### v1.3.0 — Refactorización Arquitectónica y Experiencia DKIM
* **Arquitectura Modular ES6:** Migración completa del monolito `app.js` original hacia un sistema estructurado de módulos independientes en la carpeta `/js/`.
* **Resiliencia en Red DoH:** Implementación de un sistema de consultas híbridas con fallback tolerante a fallos de DNS-over-HTTPS (Google DoH ➡️ Cloudflare DoH).
* **Usabilidad Mejorada en DKIM:** Rediseño del campo de selector DKIM opcional con modal didáctico para perfiles no técnicos.

### v1.2.0 — Auditorías Avanzadas y Visualización SPF
* **Árbol Jerárquico de Consultas SPF:** Creación de un algoritmo recursivo que dibuja el árbol de consultas de DNS de SPF en pantalla, calculando el límite crítico de 10 búsquedas DNS.
* **Verificación BIMI:** Extracción de marcas e imágenes de logotipos directamente desde los registros DNS BIMI.
* **Exportación PDF Nativa:** Hojas de estilo `@media print` para exportar el informe como PDF.

### v1.1.0 — Clasificación de Servicios y Aprendizaje Dinámico
* **Clasificación SPF Dinámica:** Selector en caliente para clasificar y etiquetar firmas SPF no reconocidas en tiempo real.
* **Creación de Reglas de Base de Datos:** Pop-up para añadir nuevos servicios directamente a la Base de Conocimiento persistida localmente con `localStorage`.

### v1.0.0 — Lanzamiento Inicial
* **Auditoría DNS Básica:** Escaneo y renderizado de registros MX, SPF y DMARC vía DoH.
* **Identificación Automática:** Clasificación básica de los proveedores más comunes de email corporativo y seguridad perimetral.
* **Exportación Básica:** Funciones nativas para exportar informes al portapapeles o como archivo descargable `.doc`.
