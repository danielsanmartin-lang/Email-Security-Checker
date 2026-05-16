# 🛡️ Email-Security-Checker
Auditoría de Seguridad de Correo

Una herramienta web de ciberseguridad diseñada para auditar la infraestructura de correo electrónico, analizar registros DNS y detectar pasarelas de seguridad segura (SEGs) y soluciones ICES.

🚀 **[PROBAR LA APLICACIÓN](https://danielsanmartin-lang.github.io/Email-Security-Checker/)**

---

## 💡 Características principales

* **Análisis DNS en tiempo real:** Consulta registros SPF y DMARC directamente desde el navegador.
* **Identificación de Proveedores (SEGs/ICES):** Base de conocimiento local con más de 50 firmas de servicios de correo (Microsoft 365, Google Workspace, Proofpoint, Mimecast, etc.).
* **Evaluación de Seguridad:** Diagnóstico visual del estado de las políticas de autenticación de correo.
* **Interfaz:** Diseño moderno con tema oscuro y estética *glassmorphism*.

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
   git clone [https://github.com/TU_USUARIO/danielsanmartin-lang.git](https://github.com/danielsanmartin-lang/Email-Security-Checker.git)
