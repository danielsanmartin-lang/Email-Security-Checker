# 🛡️ Email-Security-Checker
Auditoría de Seguridad de Correo

Una herramienta web de ciberseguridad diseñada para auditar la infraestructura de correo electrónico, analizar registros DNS y detectar pasarelas de seguridad segura (SEGs) y soluciones ICES.

🚀 **[PROBAR LA APLICACIÓN](https://danielsanmartin-lang.github.io/Email-Security-Checker/)**

---

## 💡 Características principales

* **Análisis DNS en tiempo real:** Consulta registros SPF y DMARC directamente desde el navegador.
* **Identificación de Proveedores (SEGs/ICES):** Base de conocimiento local con más de 50 firmas de servicios de correo (Microsoft 365, Google Workspace, Proofpoint, Mimecast, etc.).
* **Evaluación de Seguridad:** Diagnóstico visual del estado de las políticas de autenticación de correo.

## 🏗️ Arquitectura del Sistema

Este proyecto está construido bajo una arquitectura **Pure Frontend (Serverless)**, lo que garantiza total privacidad y velocidad:

* **Sin Backend:** Todo el procesamiento y parseo de registros ocurre en el cliente.
* **DNS-over-HTTPS (DoH):** Utiliza la API pública de Google DNS para realizar consultas seguras directamente desde el navegador.
* **Estructura limpia:** Separación estricta de responsabilidades en HTML, CSS y JavaScript modular (`app.js` y `knowledge.js`).

## 🛠️ Tecnologías utilizadas

* HTML5 / CSS3 (Diseño responsivo y efectos avanzados)
* JavaScript Vanilla (ES6+)
* API de DNS-over-HTTPS (Google / Cloudflare)

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

---

## 📅 Historial de Cambios

### v1.4.0 — Soporte Multilingüe e Informes PDF Optimizados (Actual)
* **Soporte Multilingüe (Español / Inglés):** Implementación de un motor de internacionalización (`js/lang.js` y `js/i18n.js`) que traduce toda la interfaz web, formularios, descripciones y mensajes informativos en caliente.
* **Selector de Idiomas:** Menú interactivo en la cabecera con indicadores visuales de banderas y persistencia del idioma seleccionado vía `localStorage`.
* **Reportes Localizados Dinámicos:** Generación de informes en Google Docs, archivos de Word (.doc) e impresión PDF completamente traducidos al idioma activo en el selector.
* **Impresión PDF Premium con Renombrado Inteligente:**
  * Reestructuración de la hoja de estilos `@media print` para aplicar un tema claro corporativo con tipografía optimizada, fondos blancos y etiquetas de colores pastel de alto contraste.
  * Modificación del título del documento durante el ciclo de impresión para forzar al navegador a proponer un nombre de archivo descriptivo y localizado según el idioma (ej. `Auditoría de Seguridad de Correo: salesforce.com.pdf` o `Email Security Audit: salesforce.com.pdf`).

### v1.3.0 — Refactorización Arquitectónica y Experiencia DKIM
* **Arquitectura Modular ES6:** Migración completa del monolito `app.js` original hacia un sistema estructurado de módulos independientes en la carpeta `/js/` (`api.js`, `parsers.js`, `analyzer.js`, `ui.js`, `export.js` y `knowledge.js`).
* **Resiliencia en Red DoH:** Implementación de un sistema de consultas híbridas con fallback tolerante a fallos de DNS-over-HTTPS (Google DoH ➡️ Cloudflare DoH).
* **Usabilidad Mejorada en DKIM:** Rediseño del campo de selector DKIM opcional, transformándolo en un botón expandible con un color índigo sólido (`#5e6eeb`) para limpiar la interfaz de búsqueda principal.
* **Ayuda Didáctica para No-Técnicos:** Botón de asistencia que despliega un modal interactivo con explicaciones detalladas y métodos prácticos (como el *"Truco del correo de prueba"*) diseñados para que perfiles comerciales (ej. Account Managers) puedan encontrar fácilmente un selector DKIM.
* **Robustez en Entorno Local (`file:///`):** Control y captura de excepciones en `history.pushState` que evita bloqueos y crashes silenciosos cuando el usuario abre el proyecto haciendo doble clic sin levantar un servidor.

### v1.2.0 — Auditorías Avanzadas y Visualización SPF
* **Árbol Jerárquico de Consultas SPF:** Creación de un algoritmo recursivo que dibuja el árbol de consultas de DNS de SPF en pantalla, calculando de manera visual y exacta el límite crítico de 10 búsquedas DNS para evitar fallos de entrega.
* **Selector DKIM Manual:** Incorporación de un escáner de firmas DKIM personalizables mediante la introducción directa del selector.
* **Verificación BIMI:** Extracción de marcas e imágenes de logotipos directamente desde el tag de marca `l=` de los registros DNS de tipo BIMI.
* **Exportación PDF Nativa:** Incorporación de hojas de estilo `@media print` para limpiar la interfaz y permitir exportar el informe de manera perfecta como PDF usando el motor de impresión nativo del navegador.

### v1.1.0 — Clasificación de Servicios y Aprendizaje Dinámico
* **Sugerencias de Búsqueda:** Adición de accesos directos de análisis rápido, incluyendo `salesforce.com` en segunda posición.
* **Clasificación SPF Dinámica:** Implementación de un selector en caliente para que el auditor pueda clasificar y etiquetar firmas SPF no reconocidas en tiempo real.
* **Creación de Reglas de Base de Datos:** Pop-up para añadir nuevos servicios (Nombre, Categoría, Patrón de SPF) directamente a la Base de Conocimiento persistida localmente con `localStorage`.

### v1.0.0 — Lanzamiento Inicial
* **Auditoría DNS Básica:** Escaneo y renderizado de registros MX, SPF y DMARC vía DoH.
* **Identificación Automática:** Clasificación básica de los proveedores más comunes de email corporativo y seguridad perimetral.
* **Exportación Básica:** Funciones nativas para exportar informes al portapapeles o como archivo descargable `.doc`.
