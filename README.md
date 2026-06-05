# 🛡️ Email-Security-Checker
Auditoría de Seguridad de Correo

Una herramienta web de ciberseguridad diseñada para auditar la infraestructura de correo electrónico, analizar registros DNS y detectar pasarelas de seguridad (SEGs), soluciones ICES y **plataformas de Security Awareness / Phishing Simulation**.

🚀 **[PROBAR LA APLICACIÓN](https://danielsanmartin-lang.github.io/Email-Security-Checker/)**

---

## 💡 Características principales

* **Análisis DNS en tiempo real:** Consulta registros MX, SPF, DMARC, DKIM, BIMI, MTA-STS, TLS-RPT y NS directamente desde el navegador vía DNS-over-HTTPS.
* **Identificación de Proveedores (SEGs/ICES):** Base de conocimiento local con más de 50 firmas de servicios de correo (Microsoft 365, Google Workspace, Proofpoint, Mimecast, etc.).
* **Awareness-Vendor Detector:** Módulo dedicado que detecta plataformas de concienciación de seguridad y simulación de phishing (KnowBe4, Proofpoint SAT, Cofense, Hoxhunt, Barracuda PhishLine, etc.) a partir de señales DNS, con score de confianza y evidencia estructurada.
* **Evaluación de Seguridad:** Diagnóstico visual del estado de las políticas de autenticación (A+ a F, 0–100 puntos).
* **Reputación y Listas Negras (RBL):** Verificación en tiempo real de IPs de servidores MX contra listas globales.
* **Exportaciones Premium:** Informes en Google Docs, Word (.doc) y PDF con score, hallazgos, SPF tree y DMARC detallado.
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
├── awarenessDetector.js # 🆕 Detector de plataformas de Awareness/PhishSim
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

### Ejecutar Tests Unitarios

El módulo de Awareness incluye una suite completa de tests con fixtures DNS mockeados:

```bash
# Requiere Vitest (ESM-compatible)
npx vitest run js/awarenessDetector.test.js
```

---

## 📅 Historial de Cambios

### v1.9.0 — Awareness-Vendor Detector: Detección de Plataformas de Phishing Simulation (Actual)

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
