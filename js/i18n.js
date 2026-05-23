// Internationalization (i18n) dictionary for Spanish and English
export const translations = {
    es: {
        // App Header & Meta
        app_title: "Email Security Checker",
        app_subtitle: "Email Security Intelligence",
        live_dns_badge: "Live DNS Analysis",

        // Search Section
        search_title: "Auditoría de Seguridad de Correo",
        search_desc: "Introduce un dominio para analizar sus registros MX, SPF, DMARC e identificar su pila tecnológica de email.",
        search_btn: "Analizar",
        dkim_toggle_btn: "Selector DKIM (opcional)",
        dkim_input_placeholder: "Selector DKIM (Opcional, ej. google, s1, mail)",
        dkim_info_btn: "¿Qué es un Selector DKIM?",

        // Loading Section
        step_mx: "Consultando registros MX...",
        step_spf: "Consultando registros SPF...",
        step_dmarc: "Consultando DMARC...",
        step_dkim: "Verificando DKIM...",
        step_bimi: "Consultando BIMI...",
        step_advanced: "Comprobaciones avanzadas (MTA-STS, TLS-RPT, NS, TXT)...",
        step_analysis: "Analizando pila tecnológica...",

        // Error Section
        error_title: "Error en la consulta",
        error_default_message: "No se pudieron obtener los registros DNS.",
        error_retry: "Reintentar",

        // Results Actions
        export_google: "Exportar a Google Docs",
        export_file: "Exportar a .doc",
        export_pdf: "Exportar a PDF",
        new_scan: "Nuevo análisis",
        dns_tech_report: "🔍 Reporte Técnico de DNS",

        // Summary Labels
        summary_provider: "Proveedor de Correo",
        summary_security: "Capa de Seguridad",
        summary_dmarc: "Política DMARC",
        summary_services: "Servicios Terceros",

        // Panels
        panel_mx_title: "Registros MX",
        panel_provider_title: "Proveedor de Correo",
        panel_security_title: "Capas de Seguridad (SEG / ICES)",
        panel_spf_title: "Registro SPF — Análisis Detallado",
        panel_dmarc_title: "Estado DMARC",
        panel_dmarc_reporting_title: "Reportes DMARC (rua/ruf)",
        panel_dkim_title: "Verificación DKIM",
        panel_bimi_title: "Verificación BIMI",
        panel_spf_tree_title: "Árbol de Consultas SPF",
        panel_advanced_dns_title: "DNS Avanzado (ICES Detection)",

        // Score Card Findings (ES)
        score_title_panel: "Puntuación de Seguridad",
        score_desc_panel: "Análisis automatizado de las políticas y configuración de seguridad.",
        finding_spf_ok: "Registro SPF configurado correctamente.",
        finding_spf_err: "No se encontró registro SPF (alto riesgo de phishing).",
        finding_spf_lookups_ok: "Número de consultas SPF dentro del límite ({lookups}/10).",
        finding_spf_lookups_err: "Límite de consultas SPF superado ({lookups}/10) - puede causar fallos de entrega.",
        finding_dmarc_ok: "Registro DMARC configurado ({policy}).",
        finding_dmarc_err: "No se encontró registro DMARC (riesgo de suplantación de identidad).",
        finding_dmarc_policy_reject: "Política DMARC configurada como 'reject' (máxima protección).",
        finding_dmarc_policy_quarantine: "Política DMARC configurada como 'quarantine' (protección media).",
        finding_dmarc_policy_none: "Política DMARC configurada como 'none' (solo monitorización, no bloquea suplantaciones).",
        finding_dmarc_reporting_ok: "Informes de suplantación DMARC habilitados (rua/ruf).",
        finding_dmarc_reporting_err: "No se configuran informes DMARC (falta de visibilidad de abusos).",
        finding_dkim_ok: "Firma criptográfica DKIM detectada ({count} selector/es).",
        finding_dkim_err: "No se detectaron firmas DKIM en los selectores comunes.",
        finding_bimi_ok: "Registro BIMI configurado con logotipo corporativo.",
        finding_bimi_err: "Registro BIMI no configurado o incorrecto.",
        finding_mta_sts_ok: "MTA-STS configurado (TLS forzado para correo entrante).",
        finding_mta_sts_err: "MTA-STS no configurado (correo entrante sin TLS forzado).",
        finding_tls_rpt_ok: "TLS-RPT configurado (reportes de fallos TLS habilitados).",
        finding_tls_rpt_err: "TLS-RPT no configurado (sin visibilidad de fallos TLS).",

        spf_header_prefix: "Prefijo",
        spf_header_type: "Tipo",
        spf_header_value: "Valor",
        spf_header_result: "Resultado",
        spf_header_service: "Servicio Identificado",

        // Dynamic texts
        no_mx_records: "No se encontraron registros MX",
        no_spf_record: "No se encontró registro SPF",
        no_dmarc_record: "No se encontró registro DMARC. El dominio no tiene protección DMARC configurada.",
        no_dmarc_reporting: "No se encontraron direcciones de reporte (rua/ruf). El dominio no está recopilando informes DMARC.",
        no_dkim_records: "No se detectaron registros DKIM usando los selectores consultados.",
        no_bimi_record: "No se encontró registro BIMI (default._bimi).",
        no_third_party_spf: "No se identificaron servicios de terceros en el SPF",
        no_spf_tree: "No se pudo generar el árbol de consultas SPF.",
        
        provider_identified: "Proveedor Identificado",
        seg_detected: "SEG Detectado",
        ices_detected: "ICES Detectado",
        evidence: "Evidencia",
        no_evidence_dns: "Sin evidencia en DNS",
        no_seg_ices_detected: "No se detectó SEG ni ICES",
        no_seg_ices_detail: "El dominio podría usar seguridad nativa del proveedor o una solución integrada por API que no deja rastro en DNS.",
        
        spf_version: "Versión SPF",
        spf_default_policy: "Política por defecto",
        
        dmarc_policy_p: "Política (p)",
        dmarc_policy_sp: "Subdominios (sp)",
        dmarc_policy_pct: "Porcentaje (pct)",
        dmarc_alignment_dkim: "Alineación DKIM",
        dmarc_alignment_spf: "Alineación SPF",
        
        dmarc_policy_desc_reject: "Rechazar correos no autenticados — máxima protección",
        dmarc_policy_desc_quarantine: "Cuarentena — los correos sospechosos se envían a spam",
        dmarc_policy_desc_none: "Solo monitorización — no se bloquea nada",
        dmarc_policy_desc_unknown: "Política desconocida",

        bimi_record_found: "Registro BIMI Encontrado",
        bimi_error: "Error al consultar BIMI",
        dkim_network_error: "Errores de red en selectores",
        
        add_to_db: "➕ Añadir a DB",
        add_to_db_tooltip: "Añadir a Base de Datos",
        
        // Modal Add to KB
        modal_kb_title: "Añadir a Knowledge Base",
        modal_kb_domain: "Dominio (Pattern)",
        modal_kb_name: "Nombre del Servicio",
        modal_kb_category: "Categoría (Label)",
        modal_kb_save: "Guardar y Analizar de Nuevo",

        cat_marketing: "Marketing",
        cat_transactional: "Transaccional",
        cat_crm: "CRM / ERP",
        cat_support: "Soporte / Tickets",
        cat_signatures: "Firmas Email",
        cat_email: "Proveedor Email",
        cat_seg: "SEG (Filtro perimetral)",
        cat_ices: "ICES (Seguridad Integrada)",
        cat_other: "Otro / Varios",

        // Modal DKIM Info
        modal_dkim_title: "¿Para qué sirve el \"Selector DKIM Opcional\"?",
        modal_dkim_q1: "¿Qué es un Selector DKIM?",
        modal_dkim_p1: "<strong>DKIM (DomainKeys Identified Mail)</strong> es una firma digital que valida que un correo realmente salió de tu servidor y no fue falsificado. Para verificar esta firma, los servidores de destino buscan una clave pública en tu DNS. El <em>selector</em> es el nombre o \"etiqueta\" que identifica a esa clave. Por ejemplo:",
        modal_dkim_li1: "Si usas Google Workspace, tu selector suele ser <code>google</code>.",
        modal_dkim_li2: "Si usas Microsoft 365, suele ser <code>selector1</code>.",
        modal_dkim_p2: "La consulta DNS se realiza buscando <code>[selector]._domainkey.tudominio.com</code>.",
        
        modal_dkim_q2: "¿Por qué agregamos esta función?",
        modal_dkim_p3: "Si una empresa usa un selector personalizado (por ejemplo, <code>empresa-key</code> o <code>mkt2026</code>), no hay modo de saberlo y no mostrarán registros DKIM en el reporte.",
        
        modal_dkim_q3: "¿Qué debes poner ahí y qué vas a obtener?",
        modal_dkim_li3: "<strong>Qué poner:</strong> Si estás auditando una empresa y sabes (a través de las cabeceras de un correo de prueba o documentación técnica) que usan un selector específico, lo escribes ahí. Por ejemplo: <code>mandrill</code>, <code>salesforce</code>, <code>exclaimer</code>, etc.",
        modal_dkim_li4: "<strong>Qué vas a obtener:</strong> La herramienta irá a buscar directamente ese registro DNS específico (<code>[tu-selector]._domainkey.empresa.com</code>). Si existe, te mostrará la clave criptográfica pública estructurada en el panel de resultados.",
        modal_dkim_p4: "Esto te permite auditar y certificar cualquier configuración DKIM de terceros o personalizada, algo esencial en auditorías de seguridad avanzadas.",
        
        modal_dkim_q4: "Hay dos formas súper sencillas para conseguir el dato si fuera necesario:",
        modal_dkim_p5: "<strong>1. El truco del \"Email de Prueba\" (Súper fácil)</strong>",
        modal_dkim_p6: "Si estás hablando con un cliente o prospecto y quieres auditar su DKIM exacto, solo pídele: <em>\"Por favor, envíame un correo de prueba desde tu cuenta corporativa\"</em>. Cuando te llegue a tu bandeja:",
        modal_dkim_li5: "Abre el correo en Outlook o Gmail.",
        modal_dkim_li6: "Dale a los tres puntitos y selecciona <em>\"Ver original\"</em> o <em>\"Ver detalles del mensaje\"</em>.",
        modal_dkim_li7: "Busca con <strong>Ctrl + F</strong> (o <strong>Cmd + F</strong>) la palabra <code>dkim</code>.",
        modal_dkim_li8: "Verás una línea que dice algo como <code>s=selector1</code> o <code>s=google</code>. ¡Ese valor después de la <code>s=</code> es el selector! Lo copias, lo pegas en tu herramienta y listo.",
        
        modal_dkim_p7: "<strong>2. Preguntando a su departamento de TI</strong>",
        modal_dkim_p8: "Cuando estás en fase de preventa o soporte con un cliente y quieres asegurar que todo está bien configurado, puedes pedirle a su contacto técnico: <em>\"¿Me podrías indicar qué selectores DKIM tenéis activos para poder auditarlos en nuestro sistema?\"</em>. Ellos te darán una palabra corta (ej. <code>exclaimer</code> o <code>marketing</code>) que podrás ingresar en la herramienta.",
        
        modal_dkim_q5: "¿Y si lo dejas en blanco?",
        modal_dkim_p9: "<strong>¡No pasa nada!</strong> De hecho, el 90% de las veces lo vas a dejar vacío.",
        modal_dkim_p10: "Si lo dejas en blanco, la herramienta utiliza de forma invisible un \"escáner automático\" que prueba los selectores más comunes del mercado (como los de Microsoft 365, Google Workspace o Mailchimp).",
        modal_dkim_p11: "Piensa en esta casilla como un <strong>\"superpoder de emergencia\"</strong>: si un cliente te dice <em>\"Oye, nuestro equipo de sistemas acaba de configurar un DKIM especial con el selector 'envios2026' y no sabemos si se ha propagado bien en internet\"</em>, tú vas, escribes <code>envios2026</code> y en 3 segundos tendrás la respuesta.",

        // Footer disclaimer
        footer_text: "Email Security Checker — Consultas DNS en tiempo real vía DoH (DNS-over-HTTPS)",
        footer_disclaimer: "Los datos se obtienen de registros DNS públicos. No se almacena ninguna información.",

        // ===== Advanced DNS panel =====
        adv_mta_sts_title: "MTA-STS",
        adv_mta_sts_configured: "Configurado",
        adv_mta_sts_not_configured: "No configurado",
        adv_mta_sts_desc: "MTA-STS fuerza el uso de TLS para el correo entrante, evitando ataques de downgrade.",
        adv_mta_sts_id: "ID de política",
        adv_tls_rpt_title: "TLS-RPT",
        adv_tls_rpt_configured: "Configurado",
        adv_tls_rpt_not_configured: "No configurado",
        adv_tls_rpt_desc: "TLS-RPT envía reportes cuando hay fallos de conexión TLS al entregar correo al dominio.",
        adv_tls_rpt_dest: "Destino de reportes",
        adv_tls_rpt_reporter: "Herramienta",
        adv_ns_title: "Proveedor DNS (NS)",
        adv_ns_hint: "Pista de seguridad",
        adv_ns_servers: "Servidores NS",
        adv_txt_title: "Verificaciones TXT detectadas",
        adv_txt_none: "No se detectaron tokens de verificación de terceros relevantes.",
        adv_txt_security_label: "Seguridad",
        adv_txt_other_label: "Otros servicios",

        // Dynamic strings
        plural_records: "registros",
        singular_record: "registro",
        detected_plural: "detectados",
        detected_none: "Ninguno",
        unidentified_provider: "No identificado",
        unidentified_provider_detail: "No se encontraron indicadores claros en MX ni SPF",
        evidence_mx: "MX apunta a",
        evidence_spf: "SPF include:",

        // ===== Reputation / RBL panel =====
        panel_reputation_title: "Reputación y Listas Negras (RBL)",
        rbl_no_data: "No se encontraron servidores MX para comprobar.",
        rbl_listed: "Listado",
        rbl_clean: "Limpio",
        rbl_badge_listed: "⚠ Listado",
        rbl_badge_clean: "✓ Limpio",
        rbl_unresolved: "No resuelto",

        // ===== SPF qualifier tooltips =====
        "spf_qualifier_+": "Calificador PASS: El remitente está autorizado a enviar correo. Si pasa esta verificación, el correo supera SPF.",
        "spf_qualifier_-": "Calificador FAIL: El remitente NO está autorizado. Los correos que coincidan deben ser rechazados.",
        "spf_qualifier_~": "Calificador SOFTFAIL: El remitente probablemente no está autorizado. El correo puede entregarse pero marcado como sospechoso.",
        "spf_qualifier_?": "Calificador NEUTRAL: No se hace ninguna afirmación sobre si el remitente está autorizado o no.",

        // ===== SPF mechanism type tooltips =====
        spf_type_v: "Versión del registro SPF. Siempre debe ser 'spf1'.",
        spf_type_include: "Incluye la política SPF de otro dominio. Consume 1 de los 10 lookups DNS permitidos.",
        spf_type_ip4: "Autoriza una dirección IPv4 o un rango CIDR específico a enviar correo.",
        spf_type_ip6: "Autoriza una dirección IPv6 o un rango CIDR específico a enviar correo.",
        spf_type_a: "Autoriza la IP a la que resuelve el registro A del dominio. Consume 1 lookup DNS.",
        spf_type_mx: "Autoriza las IPs de los servidores MX del dominio. Consume 1 lookup DNS.",
        spf_type_ptr: "Comprueba el nombre de host inverso de la IP. Lento y desaconsejado por el RFC 7208.",
        spf_type_exists: "Realiza una consulta DNS personalizada. Se usa en casos avanzados. Consume 1 lookup.",
        spf_type_redirect: "Delega toda la política SPF a otro dominio. Solo puede haber uno en el registro.",
        spf_type_all: "Regla de fin de registro. Define qué ocurre con los remitentes no cubiertos por otras reglas.",

        // ===== DMARC tag tooltips =====
        dmarc_tooltip_p: "Política principal (p=): Define qué debe hacer el servidor de destino con los correos que no superen la validación DMARC. 'none' = solo monitorizar; 'quarantine' = mover a spam; 'reject' = rechazar el correo.",
        dmarc_tooltip_sp: "Política para subdominios (sp=): Si se define, aplica una política diferente a los correos enviados desde subdominios del dominio principal.",
        dmarc_tooltip_pct: "Porcentaje (pct=): Solo aplica la política a este porcentaje del tráfico de correo. Útil para despliegues graduales. El valor recomendado en producción es 100.",
        dmarc_tooltip_adkim: "Alineación DKIM (adkim=): 'r' (Relaxed) permite que el dominio DKIM sea un subdominio del dominio 'From'. 's' (Strict) exige que coincidan exactamente.",
        dmarc_tooltip_aspf: "Alineación SPF (aspf=): 'r' (Relaxed) permite que el dominio SMTP sea un subdominio del dominio 'From'. 's' (Strict) exige coincidencia exacta."
    },
    en: {
        // App Header & Meta
        app_title: "Email Security Checker",
        app_subtitle: "Email Security Intelligence",
        live_dns_badge: "Live DNS Analysis",

        // Search Section
        search_title: "Email Security Audit",
        search_desc: "Enter a domain to analyze its MX, SPF, and DMARC records, and identify its email technology stack.",
        search_btn: "Analyze",
        dkim_toggle_btn: "DKIM Selector (optional)",
        dkim_input_placeholder: "DKIM Selector (Optional, e.g. google, s1, mail)",
        dkim_info_btn: "What is a DKIM Selector?",

        // Loading Section
        step_mx: "Querying MX records...",
        step_spf: "Querying SPF records...",
        step_dmarc: "Querying DMARC...",
        step_dkim: "Verifying DKIM...",
        step_bimi: "Querying BIMI...",
        step_advanced: "Advanced checks (MTA-STS, TLS-RPT, NS, TXT)...",
        step_analysis: "Analyzing technology stack...",

        // Error Section
        error_title: "Query Error",
        error_default_message: "Failed to fetch DNS records.",
        error_retry: "Retry",

        // Results Actions
        export_google: "Export to Google Docs",
        export_file: "Export to .doc",
        export_pdf: "Export to PDF",
        new_scan: "New Analysis",
        dns_tech_report: "🔍 Technical DNS Report",

        // Summary Labels
        summary_provider: "Email Provider",
        summary_security: "Security Layer",
        summary_dmarc: "DMARC Policy",
        summary_services: "Third-Party Services",

        // Panels
        panel_mx_title: "MX Records",
        panel_provider_title: "Email Provider",
        panel_security_title: "Security Layers (SEG / ICES)",
        panel_spf_title: "SPF Record — Detailed Analysis",
        panel_dmarc_title: "DMARC Status",
        panel_dmarc_reporting_title: "DMARC Reports (rua/ruf)",
        panel_dkim_title: "DKIM Verification",
        panel_bimi_title: "BIMI Verification",
        panel_spf_tree_title: "SPF Lookup Tree",
        panel_advanced_dns_title: "Advanced DNS (ICES Detection)",

        // Score Card Findings (EN)
        score_title_panel: "Security Score",
        score_desc_panel: "Automated analysis of domain authentication policies and settings.",
        finding_spf_ok: "SPF record configured correctly.",
        finding_spf_err: "No SPF record found (high phishing risk).",
        finding_spf_lookups_ok: "SPF DNS lookups within limits ({lookups}/10).",
        finding_spf_lookups_err: "SPF DNS lookups limit exceeded ({lookups}/10) - may cause email delivery issues.",
        finding_dmarc_ok: "DMARC record configured ({policy}).",
        finding_dmarc_err: "No DMARC record found (domain spoofing risk).",
        finding_dmarc_policy_reject: "DMARC policy set to 'reject' (maximum protection).",
        finding_dmarc_policy_quarantine: "DMARC policy set to 'quarantine' (medium protection).",
        finding_dmarc_policy_none: "DMARC policy set to 'none' (monitoring only, doesn't block spoofing).",
        finding_dmarc_reporting_ok: "DMARC spoofing reports enabled (rua/ruf).",
        finding_dmarc_reporting_err: "No DMARC reporting configured (lack of visibility into abuse).",
        finding_dkim_ok: "DKIM cryptographic signatures detected ({count} selector/s).",
        finding_dkim_err: "No DKIM signatures detected using common selectors.",
        finding_bimi_ok: "BIMI record configured with corporate logo.",
        finding_bimi_err: "BIMI record not configured or incorrect.",
        finding_mta_sts_ok: "MTA-STS configured (forced TLS for inbound email).",
        finding_mta_sts_err: "MTA-STS not configured (inbound email without forced TLS).",
        finding_tls_rpt_ok: "TLS-RPT configured (TLS failure reports enabled).",
        finding_tls_rpt_err: "TLS-RPT not configured (no visibility into TLS failures).",

        spf_header_prefix: "Prefix",
        spf_header_type: "Type",
        spf_header_value: "Value",
        spf_header_result: "Result",
        spf_header_service: "Identified Service",

        // Dynamic texts
        no_mx_records: "No MX records found",
        no_spf_record: "No SPF record found",
        no_dmarc_record: "No DMARC record found. The domain has no DMARC protection configured.",
        no_dmarc_reporting: "No reporting addresses (rua/ruf) were found. The domain is not collecting DMARC reports.",
        no_dkim_records: "No DKIM records detected using the queried selectors.",
        no_bimi_record: "No BIMI record found (default._bimi).",
        no_third_party_spf: "No third-party services identified in SPF",
        no_spf_tree: "Failed to generate SPF lookup tree.",
        
        provider_identified: "Identified Provider",
        seg_detected: "SEG Detected",
        ices_detected: "ICES Detected",
        evidence: "Evidence",
        no_evidence_dns: "No DNS evidence",
        no_seg_ices_detected: "No SEG or ICES detected",
        no_seg_ices_detail: "The domain might use native provider security or an API-integrated solution that leaves no trace in DNS.",
        
        spf_version: "SPF Version",
        spf_default_policy: "Default policy",
        
        dmarc_policy_p: "Policy (p)",
        dmarc_policy_sp: "Subdomains (sp)",
        dmarc_policy_pct: "Percentage (pct)",
        dmarc_alignment_dkim: "DKIM Alignment",
        dmarc_alignment_spf: "SPF Alignment",
        
        dmarc_policy_desc_reject: "Reject unauthenticated emails — maximum protection",
        dmarc_policy_desc_quarantine: "Quarantine — suspicious emails are sent to spam",
        dmarc_policy_desc_none: "Monitoring only — nothing is blocked",
        dmarc_policy_desc_unknown: "Unknown policy",

        bimi_record_found: "BIMI Record Found",
        bimi_error: "Error querying BIMI",
        dkim_network_error: "Network errors on selectors",
        
        add_to_db: "➕ Add to DB",
        add_to_db_tooltip: "Add to Knowledge Base",
        
        // Modal Add to KB
        modal_kb_title: "Add to Knowledge Base",
        modal_kb_domain: "Domain (Pattern)",
        modal_kb_name: "Service Name",
        modal_kb_category: "Category (Label)",
        modal_kb_save: "Save and Analyze Again",

        cat_marketing: "Marketing",
        cat_transactional: "Transactional",
        cat_crm: "CRM / ERP",
        cat_support: "Support / Tickets",
        cat_signatures: "Email Signatures",
        cat_email: "Email Provider",
        cat_seg: "SEG (Email Gateway)",
        cat_ices: "ICES (Integrated Security)",
        cat_other: "Other / Misc",

        // Modal DKIM Info
        modal_dkim_title: "What is the \"Optional DKIM Selector\" for?",
        modal_dkim_q1: "What is a DKIM Selector?",
        modal_dkim_p1: "<strong>DKIM (DomainKeys Identified Mail)</strong> is a digital signature that validates that an email actually originated from your server and was not forged. To verify this signature, destination servers look for a public key in your DNS. The <em>selector</em> is the name or \"label\" that identifies that key. For example:",
        modal_dkim_li1: "If you use Google Workspace, your selector is usually <code>google</code>.",
        modal_dkim_li2: "If you use Microsoft 365, it is usually <code>selector1</code>.",
        modal_dkim_p2: "The DNS query is performed by looking for <code>[selector]._domainkey.yourdomain.com</code>.",
        
        modal_dkim_q2: "Why did we add this feature?",
        modal_dkim_p3: "If a company uses a custom selector (for example, <code>company-key</code> or <code>mkt2026</code>), there is no way to know it automatically, and DKIM records won't show in the report.",
        
        modal_dkim_q3: "What should you enter and what will you get?",
        modal_dkim_li3: "<strong>What to enter:</strong> If you are auditing a company and know (via test email headers or technical documentation) that they use a specific selector, write it there. For example: <code>mandrill</code>, <code>salesforce</code>, <code>exclaimer</code>, etc.",
        modal_dkim_li4: "<strong>What you will get:</strong> The tool will query that specific DNS record directly (<code>[your-selector]._domainkey.company.com</code>). If it exists, it will display the structured public cryptographic key in the results panel.",
        modal_dkim_p4: "This allows you to audit and certify any third-party or custom DKIM configuration, which is essential in advanced security audits.",
        
        modal_dkim_q4: "There are two very simple ways to get this data if needed:",
        modal_dkim_p5: "<strong>1. The \"Test Email\" trick (Super easy)</strong>",
        modal_dkim_p6: "If you are speaking with a client or prospect and want to audit their exact DKIM, just ask: <em>\"Please send me a test email from your corporate account\"</em>. When it arrives in your inbox:",
        modal_dkim_li5: "Open the email in Outlook or Gmail.",
        modal_dkim_li6: "Click the three dots and select <em>\"Show original\"</em> or <em>\"View message details\"</em>.",
        modal_dkim_li7: "Search using <strong>Ctrl + F</strong> (or <strong>Cmd + F</strong>) for the word <code>dkim</code>.",
        modal_dkim_li8: "You will see a line that says something like <code>s=selector1</code> or <code>s=google</code>. That value after <code>s=</code> is the selector! Copy it, paste it into your tool and you're set.",
        
        modal_dkim_p7: "<strong>2. Asking their IT department</strong>",
        modal_dkim_p8: "When you are in a pre-sales or support phase with a client and want to ensure everything is properly configured, you can ask their technical contact: <em>\"Could you tell me which DKIM selectors you have active so we can audit them in our system?\"</em>. They will give you a short word (e.g., `exclaimer` or `marketing`) that you can enter in the tool.",
        
        modal_dkim_q5: "And if you leave it blank?",
        modal_dkim_p9: "<strong>Nothing happens!</strong> In fact, 90% of the time you will leave it empty.",
        modal_dkim_p10: "If you leave it blank, the tool silently uses an \"auto scanner\" that tests the most common selectors in the market (such as Microsoft 365, Google Workspace, or Mailchimp).",
        modal_dkim_p11: "Think of this input as an <strong>\"emergency superpower\"</strong>: if a client tells you *\"Hey, our systems team just set up a special DKIM with the selector 'envios2026' and we don't know if it propagated correctly on the internet\"*, you go, type <code>envios2026</code>, and in 3 seconds you'll have the answer.",

        // Footer disclaimer
        footer_text: "Email Security Checker — Real-time DNS queries via DoH (DNS-over-HTTPS)",
        footer_disclaimer: "Data is retrieved from public DNS records. No information is stored.",

        // ===== Advanced DNS panel =====
        adv_mta_sts_title: "MTA-STS",
        adv_mta_sts_configured: "Configured",
        adv_mta_sts_not_configured: "Not configured",
        adv_mta_sts_desc: "MTA-STS enforces TLS for inbound email, preventing downgrade attacks.",
        adv_mta_sts_id: "Policy ID",
        adv_tls_rpt_title: "TLS-RPT",
        adv_tls_rpt_configured: "Configured",
        adv_tls_rpt_not_configured: "Not configured",
        adv_tls_rpt_desc: "TLS-RPT sends reports when TLS connection failures occur while delivering email to the domain.",
        adv_tls_rpt_dest: "Report destination",
        adv_tls_rpt_reporter: "Tool",
        adv_ns_title: "DNS Provider (NS)",
        adv_ns_hint: "Security hint",
        adv_ns_servers: "NS servers",
        adv_txt_title: "Detected TXT Verifications",
        adv_txt_none: "No relevant third-party verification tokens detected.",
        adv_txt_security_label: "Security",
        adv_txt_other_label: "Other services",

        // Dynamic strings
        plural_records: "records",
        singular_record: "record",
        detected_plural: "detected",
        detected_none: "None",
        unidentified_provider: "Unidentified",
        unidentified_provider_detail: "No clear indicators found in MX or SPF",
        evidence_mx: "MX points to",
        evidence_spf: "SPF include:",

        // ===== Reputation / RBL panel =====
        panel_reputation_title: "Domain Reputation & Blacklists (RBL)",
        rbl_no_data: "No MX servers found to check.",
        rbl_listed: "Listed",
        rbl_clean: "Clean",
        rbl_badge_listed: "⚠ Listed",
        rbl_badge_clean: "✓ Clean",
        rbl_unresolved: "Unresolved",

        // ===== SPF qualifier tooltips =====
        "spf_qualifier_+": "Qualifier PASS: The sender is authorized to send mail. If this check passes, the email passes SPF.",
        "spf_qualifier_-": "Qualifier FAIL: The sender is NOT authorized. Emails matching this should be rejected.",
        "spf_qualifier_~": "Qualifier SOFTFAIL: The sender is probably not authorized. The email may be delivered but flagged as suspicious.",
        "spf_qualifier_?": "Qualifier NEUTRAL: No assertion is made about whether the sender is authorized or not.",

        // ===== SPF mechanism type tooltips =====
        spf_type_v: "SPF record version. Must always be 'spf1'.",
        spf_type_include: "Includes the SPF policy from another domain. Consumes 1 of the 10 allowed DNS lookups.",
        spf_type_ip4: "Authorizes a specific IPv4 address or CIDR range to send email.",
        spf_type_ip6: "Authorizes a specific IPv6 address or CIDR range to send email.",
        spf_type_a: "Authorizes the IP the domain's A record resolves to. Consumes 1 DNS lookup.",
        spf_type_mx: "Authorizes the IPs of the domain's MX servers. Consumes 1 DNS lookup.",
        spf_type_ptr: "Checks the reverse hostname of the IP. Slow and discouraged by RFC 7208.",
        spf_type_exists: "Performs a custom DNS query. Used in advanced cases. Consumes 1 lookup.",
        spf_type_redirect: "Delegates the entire SPF policy to another domain. Only one is allowed per record.",
        spf_type_all: "End-of-record rule. Defines what happens to senders not covered by other rules.",

        // ===== DMARC tag tooltips =====
        dmarc_tooltip_p: "Main policy (p=): Defines what the receiving server should do with emails that fail DMARC validation. 'none' = monitor only; 'quarantine' = move to spam; 'reject' = reject the email.",
        dmarc_tooltip_sp: "Subdomain policy (sp=): If defined, applies a different policy to emails sent from subdomains of the main domain.",
        dmarc_tooltip_pct: "Percentage (pct=): Only applies the policy to this percentage of email traffic. Useful for gradual rollouts. Recommended production value is 100.",
        dmarc_tooltip_adkim: "DKIM alignment (adkim=): 'r' (Relaxed) allows the DKIM domain to be a subdomain of the From domain. 's' (Strict) requires an exact match.",
        dmarc_tooltip_aspf: "SPF alignment (aspf=): 'r' (Relaxed) allows the SMTP domain to be a subdomain of the From domain. 's' (Strict) requires an exact match."
    }
};
