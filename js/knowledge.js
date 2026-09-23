// Knowledge base for identifying email services from DNS records.
// `version` / `updatedAt` permiten saber con qué diccionario se hizo un análisis
// (aparece en los informes) y detectar firmas obsoletas sin leer el diff.
// Súbelos al añadir o corregir firmas. El test de esquema (knowledge.test.js)
// valida la forma de cada entrada y la ausencia de duplicados.
export const KB_VERSION = '3.2.0';
export const KB_UPDATED_AT = '2026-09-23';

export const KB = {
    version: KB_VERSION,
    updatedAt: KB_UPDATED_AT,
    mx: [
        // MX de Exchange Online con DNSSEC y DANE de entrada (<dominio>.<x>-v1.mx.microsoft).
        // Es el formato de los dominios nuevos; mail.protection.outlook.com sigue vivo pero
        // ya no recibe mejoras. Sufijo exacto: no debe casar con mx.microsoft.com.
        { pattern: '.mx.microsoft', name: 'Microsoft 365', type: 'provider', matchType: 'suffix' },
        { pattern: 'protection.outlook.com', name: 'Microsoft 365', type: 'provider' },
        { pattern: 'mail.protection.outlook.com', name: 'Microsoft 365', type: 'provider' },
        { pattern: 'google.com', name: 'Google Workspace', type: 'provider' },
        { pattern: 'googlemail.com', name: 'Google Workspace', type: 'provider' },
        { pattern: 'pphosted.com', name: 'Proofpoint', type: 'seg' },
        { pattern: 'ppe-hosted.com', name: 'Proofpoint', type: 'seg' },
        { pattern: 'mimecast.com', name: 'Mimecast', type: 'seg' },
        { pattern: 'barracudanetworks.com', name: 'Barracuda', type: 'seg' },
        { pattern: 'barracuda.com', name: 'Barracuda', type: 'seg' },
        { pattern: 'fortimailcloud.com', name: 'FortiMail (Fortinet)', type: 'seg' },
        { pattern: 'fortimail.com', name: 'FortiMail (Fortinet)', type: 'seg' },
        { pattern: 'iphmx.com', name: 'Cisco Email Security (IronPort)', type: 'seg' },
        { pattern: 'ess.cisco.com', name: 'Cisco Email Security (IronPort)', type: 'seg' },
        // Cisco ESA on-premise: hostname prefix detection (e.g. esa01.company.com, ironport.company.com)
        { pattern: 'esa', name: 'Cisco Email Security (IronPort)', type: 'seg', matchType: 'hostname_prefix' },
        { pattern: 'ironport', name: 'Cisco Email Security (IronPort)', type: 'seg', matchType: 'hostname_prefix' },
        { pattern: 'trendmicro.com', name: 'Trend Micro Email Security', type: 'seg' },
        { pattern: 'in.trendmicro.com', name: 'Trend Micro Email Security', type: 'seg' },
        { pattern: 'sophos.com', name: 'Sophos Email', type: 'seg' },
        { pattern: 'fireeye.com', name: 'FireEye Email Security', type: 'seg' },
        { pattern: 'messagelabs.com', name: 'Symantec Email Security', type: 'seg' },
        { pattern: 'symanteccloud.com', name: 'Symantec Email Security', type: 'seg' },
        { pattern: 'securence.com', name: 'Securence', type: 'seg' },
        { pattern: 'spamexperts.com', name: 'SpamExperts', type: 'seg' },
        { pattern: 'hornetsecurity.com', name: 'Hornetsecurity', type: 'seg' },
        { pattern: 'antispameurope', name: 'Hornetsecurity', type: 'seg' },
        // On-premise appliance hostname prefixes
        { pattern: 'smg', name: 'Symantec Messaging Gateway (Broadcom)', type: 'seg', matchType: 'hostname_prefix' },
        { pattern: 'gwia', name: 'GroupWise Internet Agent (Micro Focus)', type: 'seg', matchType: 'hostname_prefix' },
        // Additional cloud SEG MX domains
        { pattern: 'reflexion.net', name: 'Sophos Email (Reflexion)', type: 'seg' },
        { pattern: 'proofpointessentials.com', name: 'Proofpoint Essentials', type: 'seg' },
        { pattern: 'mailcontrol.com', name: 'Forcepoint Email Security', type: 'seg' },
        { pattern: 'forcepoint.com', name: 'Forcepoint Email Security', type: 'seg' },
        { pattern: 'spamtitan.com', name: 'SpamTitan (TitanHQ)', type: 'seg' },
        { pattern: 'mailroute.net', name: 'MailRoute', type: 'seg' },
        { pattern: 'mailchannels.net', name: 'MailChannels', type: 'seg' },
        { pattern: 'zixmail.net', name: 'Zix (OpenText)', type: 'seg' },
        { pattern: 'zixmessagecenter.com', name: 'Zix (OpenText)', type: 'seg' },
        { pattern: 'libraesva.com', name: 'Libraesva', type: 'seg' },
        { pattern: 'cellopoint.com', name: 'Cellopoint', type: 'seg' },
        { pattern: 'spamhero.com', name: 'SpamHero', type: 'seg' },
        { pattern: 'cleandns.com', name: 'Cleandns (N-able)', type: 'seg' },
        // ICES inline MX patterns
        { pattern: 'perception-point.io', name: 'Perception Point', type: 'ices' },
        { pattern: 'xorlab.com', name: 'xorlab', type: 'ices' },
        { pattern: 'mailprotection.checkpoint.com', name: 'Avanan (Check Point Harmony Email)', type: 'ices' },
        { pattern: 'material.security', name: 'Material Security', type: 'ices' },
        { pattern: 'defend.egress.com', name: 'Egress Defend', type: 'ices' },
        // Providers
        { pattern: 'zoho.com', name: 'Zoho Mail', type: 'provider' },
        { pattern: 'yahoodns.net', name: 'Yahoo Mail', type: 'provider' },
        { pattern: 'amazonaws.com', name: 'Amazon SES/WorkMail', type: 'provider' },
        { pattern: 'secureserver.net', name: 'GoDaddy Email', type: 'provider' },
        { pattern: 'emailsrvr.com', name: 'Rackspace Email', type: 'provider' },
        { pattern: 'ovh.net', name: 'OVH Mail', type: 'provider' },
        { pattern: 'ionos.com', name: 'IONOS Mail', type: 'provider' },
        { pattern: 'proton.ch', name: 'ProtonMail', type: 'provider' },
        { pattern: 'protonmail.ch', name: 'ProtonMail', type: 'provider' },
        { pattern: 'tutanota.de', name: 'Tuta (Tutanota)', type: 'provider' },
        { pattern: 'tuta.io', name: 'Tuta (Tutanota)', type: 'provider' },
        { pattern: 'fastmail.com', name: 'FastMail', type: 'provider' },
        { pattern: 'fastmail.fm', name: 'FastMail', type: 'provider' },
        { pattern: 'mailbox.org', name: 'Mailbox.org', type: 'provider' },
        { pattern: 'mail.office365.us', name: 'Microsoft 365 GCC High', type: 'provider' },
    ],
    spf: [
        { pattern: 'spf.protection.outlook.com', name: 'Microsoft 365', category: 'email', cat_label: 'Proveedor Email' },
        { pattern: '_spf.google.com', name: 'Google Workspace', category: 'email', cat_label: 'Proveedor Email' },
        { pattern: 'amazonses.com', name: 'Amazon SES', category: 'email', cat_label: 'Proveedor Email / Transaccional' },
        { pattern: 'awsapps.com', name: 'Amazon WorkMail', category: 'email', cat_label: 'Proveedor Email' },
        { pattern: 'hornetsecurity', name: 'Hornetsecurity', category: 'seg', cat_label: 'SEG' },
        { pattern: 'antispameurope', name: 'Hornetsecurity', category: 'seg', cat_label: 'SEG' },
        { pattern: 'sendgrid.net', name: 'SendGrid (Twilio)', category: 'transactional', cat_label: 'Transaccional' },
        { pattern: 'mailgun.org', name: 'Mailgun', category: 'transactional', cat_label: 'Transaccional' },
        { pattern: 'mandrillapp.com', name: 'Mandrill (Mailchimp)', category: 'transactional', cat_label: 'Transaccional' },
        { pattern: 'postmarkapp.com', name: 'Postmark', category: 'transactional', cat_label: 'Transaccional' },
        { pattern: 'sparkpostmail.com', name: 'SparkPost', category: 'transactional', cat_label: 'Transaccional' },
        { pattern: 'mailjet.com', name: 'Mailjet', category: 'transactional', cat_label: 'Transaccional' },
        { pattern: 'sendinblue.com', name: 'Brevo (Sendinblue)', category: 'transactional', cat_label: 'Transaccional' },
        { pattern: 'brevosend.com', name: 'Brevo', category: 'transactional', cat_label: 'Transaccional' },
        { pattern: 'exclaimer.net', name: 'Exclaimer', category: 'signatures', cat_label: 'Firmas Email' },
        { pattern: 'exclaimer.com', name: 'Exclaimer', category: 'signatures', cat_label: 'Firmas Email' },
        { pattern: 'codetwo.com', name: 'CodeTwo', category: 'signatures', cat_label: 'Firmas Email' },
        { pattern: 'salesforce.com', name: 'Salesforce', category: 'crm', cat_label: 'CRM' },
        { pattern: 'hubspot.com', name: 'HubSpot', category: 'crm', cat_label: 'CRM/Marketing' },
        { pattern: 'mktomail.com', name: 'Marketo (Adobe)', category: 'marketing', cat_label: 'Marketing' },
        { pattern: 'mktoweb.com', name: 'Marketo (Adobe)', category: 'marketing', cat_label: 'Marketing' },
        { pattern: 'servers.mcsv.net', name: 'Mailchimp', category: 'marketing', cat_label: 'Marketing' },
        { pattern: 'mailchimp.com', name: 'Mailchimp', category: 'marketing', cat_label: 'Marketing' },
        { pattern: 'constantcontact.com', name: 'Constant Contact', category: 'marketing', cat_label: 'Marketing' },
        { pattern: 'campaignmonitor.com', name: 'Campaign Monitor', category: 'marketing', cat_label: 'Marketing' },
        { pattern: 'activecampaign.com', name: 'ActiveCampaign', category: 'marketing', cat_label: 'Marketing' },
        { pattern: 'klaviyo.com', name: 'Klaviyo', category: 'marketing', cat_label: 'Marketing' },
        { pattern: 'mlsend.com', name: 'MailerLite', category: 'marketing', cat_label: 'Marketing' },
        { pattern: 'mailerlite.com', name: 'MailerLite', category: 'marketing', cat_label: 'Marketing' },
        { pattern: 'zendesk.com', name: 'Zendesk', category: 'support', cat_label: 'Soporte' },
        { pattern: 'freshdesk.com', name: 'Freshdesk', category: 'support', cat_label: 'Soporte' },
        { pattern: 'intercom.io', name: 'Intercom', category: 'support', cat_label: 'Soporte' },
        { pattern: 'helpscout.net', name: 'Help Scout', category: 'support', cat_label: 'Soporte' },
        { pattern: 'zoho.com', name: 'Zoho', category: 'email', cat_label: 'Proveedor Email' },
        { pattern: 'zoho.eu', name: 'Zoho', category: 'email', cat_label: 'Proveedor Email' },
        { pattern: 'fortimailcloud.com', name: 'FortiMail (Fortinet)', category: 'seg', cat_label: 'SEG' },
        { pattern: 'fortimail.com', name: 'FortiMail (Fortinet)', category: 'seg', cat_label: 'SEG' },
        { pattern: 'pphosted.com', name: 'Proofpoint', category: 'seg', cat_label: 'SEG' },
        { pattern: 'proofpoint.com', name: 'Proofpoint', category: 'seg', cat_label: 'SEG' },
        { pattern: 'mimecast.com', name: 'Mimecast', category: 'seg', cat_label: 'SEG' },
        { pattern: 'barracuda', name: 'Barracuda', category: 'seg', cat_label: 'SEG' },
        { pattern: 'sophos.com', name: 'Sophos Email', category: 'seg', cat_label: 'SEG' },
        { pattern: 'trendmicro.com', name: 'Trend Micro Email Security', category: 'seg', cat_label: 'SEG' },
        { pattern: 'cisco.com', name: 'Cisco Email Security (IronPort)', category: 'seg', cat_label: 'SEG' },
        { pattern: 'iphmx.com', name: 'Cisco Email Security (IronPort)', category: 'seg', cat_label: 'SEG' },
        { pattern: 'mcafee.com', name: 'McAfee / Trellix', category: 'seg', cat_label: 'SEG' },
        { pattern: 'trellix.com', name: 'Trellix (McAfee)', category: 'seg', cat_label: 'SEG' },
        { pattern: 'spf.proofpoint.com', name: 'Proofpoint', category: 'seg', cat_label: 'SEG' },
        { pattern: 'spf.pphosted.com', name: 'Proofpoint', category: 'seg', cat_label: 'SEG' },
        { pattern: 'ppe-hosted.com', name: 'Proofpoint Essentials', category: 'seg', cat_label: 'SEG' },
        { pattern: 'spf.proofpointessentials.com', name: 'Proofpoint Essentials', category: 'seg', cat_label: 'SEG' },
        { pattern: 'proofpointessentials.com', name: 'Proofpoint Essentials', category: 'seg', cat_label: 'SEG' },
        { pattern: '_spf.mimecast.com', name: 'Mimecast', category: 'seg', cat_label: 'SEG' },
        { pattern: 'forcepoint.com', name: 'Forcepoint Email Security', category: 'seg', cat_label: 'SEG' },
        { pattern: 'mailcontrol.com', name: 'Forcepoint Email Security', category: 'seg', cat_label: 'SEG' },
        { pattern: 'trustwave.com', name: 'Trustwave SEG', category: 'seg', cat_label: 'SEG' },
        { pattern: 'spamtitan.com', name: 'SpamTitan (TitanHQ)', category: 'seg', cat_label: 'SEG' },
        { pattern: 'zixmail.net', name: 'Zix (OpenText)', category: 'seg', cat_label: 'SEG' },
        { pattern: 'zixmessagecenter.com', name: 'Zix (OpenText)', category: 'seg', cat_label: 'SEG' },
        { pattern: 'mailroute.net', name: 'MailRoute', category: 'seg', cat_label: 'SEG' },
        { pattern: 'libraesva.com', name: 'Libraesva', category: 'seg', cat_label: 'SEG' },
        { pattern: 'vipre.com', name: 'VIPRE Email Security', category: 'seg', cat_label: 'SEG' },
        { pattern: 'avanan.net', name: 'Avanan (Check Point Harmony Email)', category: 'ices', cat_label: 'ICES' },
        { pattern: 'abnormalsecurity.com', name: 'Abnormal Security', category: 'ices', cat_label: 'ICES' },
        { pattern: 'ironscales.com', name: 'Ironscales', category: 'ices', cat_label: 'ICES' },
        { pattern: 'darktrace.com', name: 'Darktrace', category: 'ices', cat_label: 'ICES' },
        { pattern: 'tessian.com', name: 'Tessian', category: 'ices', cat_label: 'ICES' },
        // New ICES providers
        { pattern: 'perception-point.io', name: 'Perception Point', category: 'ices', cat_label: 'ICES' },
        { pattern: 'material.security', name: 'Material Security', category: 'ices', cat_label: 'ICES' },
        { pattern: 'greathorn.com', name: 'GreatHorn', category: 'ices', cat_label: 'ICES' },
        { pattern: 'xorlab.com', name: 'xorlab', category: 'ices', cat_label: 'ICES' },
        { pattern: 'inky.com', name: 'INKY', category: 'ices', cat_label: 'ICES' },
        { pattern: 'agari.com', name: 'Agari (Fortra)', category: 'ices', cat_label: 'ICES' },
        { pattern: 'area1security.com', name: 'Cloudflare Email Security (Area 1)', category: 'ices', cat_label: 'ICES' },
        { pattern: 'cofense.com', name: 'Cofense', category: 'ices', cat_label: 'ICES' },
        { pattern: 'sublime.security', name: 'Sublime Security', category: 'ices', cat_label: 'ICES' },
        { pattern: 'valimail.com', name: 'Valimail', category: 'ices', cat_label: 'ICES' },
        { pattern: 'guardiandigital.com', name: 'Guardian Digital', category: 'ices', cat_label: 'ICES' },
        { pattern: 'graphus.ai', name: 'Graphus (Kaseya)', category: 'ices', cat_label: 'ICES' },
        { pattern: 'armorblox.com', name: 'Armorblox (Cisco)', category: 'ices', cat_label: 'ICES' },
        { pattern: 'spf.us1.defend.egress.com', name: 'Egress Defend', category: 'ices', cat_label: 'ICES' },
        // Existing non-ICES
        { pattern: 'knowbe4.com', name: 'KnowBe4', category: 'other', cat_label: 'Concienciación' },
        { pattern: 'docusign.com', name: 'DocuSign', category: 'other', cat_label: 'Firmas Digitales' },
        { pattern: 'netsuite.com', name: 'NetSuite (Oracle)', category: 'crm', cat_label: 'ERP/CRM' },
        { pattern: 'workday.com', name: 'Workday', category: 'other', cat_label: 'RRHH' },
        { pattern: 'servicenow.com', name: 'ServiceNow', category: 'other', cat_label: 'ITSM' },
        { pattern: 'fideltour.com', name: 'Fideltour', category: 'other', cat_label: 'Turismo/CRM' },
        { pattern: 'managed-otrs.com', name: 'OTRS', category: 'support', cat_label: 'Soporte/ITSM' },
    ],
    // Tokens TXT de verificación de dominio.
    //
    // REGLA: un token solo lleva categoría `seg` o `ices` si el producto que verifica es
    // de seguridad de CORREO. Los tokens de identidad, colaboración o SSO van a `other`
    // aunque los publique un fabricante de seguridad: prueban que alguien dio de alta el
    // dominio en una plataforma, no por dónde pasa el correo. Saltarse esta regla es lo
    // que hacía que google.com apareciera con "Cisco Secure Email" como capa de seguridad.
    txt_verification: [
        { pattern: 'proofpoint-verification', name: 'Proofpoint', category: 'seg' },
        { pattern: 'mimecast', name: 'Mimecast', category: 'seg' },
        // Verificación de dominio de Webex Control Hub ("CI" = Common Identity, la
        // plataforma de identidad de Cisco tras Webex, Duo y Control Hub). Sirve para
        // reclamar el dominio y sus usuarios dentro de una organización de Webex, y la
        // documentación de Cisco dice que se puede BORRAR del DNS una vez verificado.
        // No dice nada del correo: google.com lo publica y su MX es suyo (smtp.google.com).
        // Un SEG de Cisco lo probaría el MX (*.iphmx.com / *.ess.cisco.com), no este token.
        { pattern: 'cisco-ci-domain-verification', name: 'Cisco Webex / Control Hub (verificación de dominio)', category: 'other', verificationOnly: true },
        { pattern: 'sophos-domain-verification', name: 'Sophos Email', category: 'seg' },
        { pattern: 'ironscales-domain-verification', name: 'Ironscales', category: 'ices' },
        { pattern: 'abnormal-security', name: 'Abnormal Security', category: 'ices' },
        { pattern: 'knowbe4-site-verification', name: 'KnowBe4', category: 'other' },
        { pattern: 'knowbe4-domain-verification', name: 'KnowBe4', category: 'other' },
        { pattern: 'wombat-verification', name: 'Proofpoint Security Awareness', category: 'other' },
        { pattern: 'cofense-domain-verification', name: 'Cofense PhishMe', category: 'other' },
        { pattern: 'hoxhunt-domain-verification', name: 'Hoxhunt', category: 'other' },
        { pattern: 'phishline-verification', name: 'Barracuda Security Awareness', category: 'other' },
        { pattern: 'barracuda-phishline', name: 'Barracuda Security Awareness', category: 'other' },
        { pattern: 'atlassian-domain-verification', name: 'Atlassian', category: 'other' },
        { pattern: 'facebook-domain-verification', name: 'Meta (Facebook)', category: 'other' },
        { pattern: 'apple-domain-verification', name: 'Apple', category: 'other' },
        { pattern: 'google-site-verification', name: 'Google', category: 'other' },
        { pattern: 'MS=ms', name: 'Microsoft 365', category: 'email' },
        { pattern: 'docusign', name: 'DocuSign', category: 'other' },
        { pattern: 'stripe-verification', name: 'Stripe', category: 'other' },
        { pattern: 'hubspot-developer-verification', name: 'HubSpot', category: 'crm' },
        { pattern: 'pardot', name: 'Pardot (Salesforce)', category: 'marketing' },
        // SpyCloud es monitorización de credenciales expuestas (darknet/ATO), no un
        // filtro de correo: no es un ICES.
        { pattern: 'spycloud-domain-verification', name: 'SpyCloud (exposición de credenciales)', category: 'other' },
        { pattern: 'canva-site-verification', name: 'Canva', category: 'other' },
        { pattern: 'duo_sso_verification', name: 'Duo Security (Cisco)', category: 'other' },
        { pattern: 'cloudflare-verify', name: 'Cloudflare', category: 'other' },
        // Additional vendor TXT verifications
        { pattern: 'barracuda-domain-verification', name: 'Barracuda', category: 'seg' },
        { pattern: 'trendmicro-domain-verification', name: 'Trend Micro Email Security', category: 'seg' },
        { pattern: 'hornetsecurity-domain-verification', name: 'Hornetsecurity', category: 'seg' },
        { pattern: 'forcepoint-domain-verification', name: 'Forcepoint Email Security', category: 'seg' },
        { pattern: 'zix-domain-verification', name: 'Zix (OpenText)', category: 'seg' },
        { pattern: 'proofpointessentials', name: 'Proofpoint Essentials', category: 'seg' },
        { pattern: 'cisco-ironport-av', name: 'Cisco Email Security (IronPort)', category: 'seg' },
        { pattern: 'spamtitan', name: 'SpamTitan (TitanHQ)', category: 'seg' },
        { pattern: 'perception-point-domain-verify', name: 'Perception Point', category: 'ices' },
        { pattern: 'abnormalsecurity-domain-verification', name: 'Abnormal Security', category: 'ices' },
        // ICES basados en API (Microsoft Graph / Google API): NO tocan MX/SPF/DKIM,
        // su único rastro DNS suele ser un token de verificación TXT. Patrones
        // heurísticos — VALIDAR contra documentación oficial del vendor.
        { pattern: 'material-domain-verification', name: 'Material Security', category: 'ices' },
        { pattern: 'sublime-domain-verification', name: 'Sublime Security', category: 'ices' },
        { pattern: 'avanan-domain-verification', name: 'Avanan (Check Point Harmony Email)', category: 'ices' },
        { pattern: 'checkpoint-domain-verification', name: 'Check Point Harmony Email', category: 'ices' },
        { pattern: 'tessian-verification', name: 'Tessian (Proofpoint)', category: 'ices' },
        { pattern: 'egress-domain-verification', name: 'Egress Defend', category: 'ices' },
        { pattern: 'vade-domain-verification', name: 'Vade', category: 'ices' },
        { pattern: 'darktrace-domain-verification', name: 'Darktrace / Email', category: 'ices' },
        { pattern: 'cyren-domain-verification', name: 'Cyren (Data443)', category: 'ices' },
    ],
    // NS patterns to identify DNS providers (some imply email security services)
    ns_providers: [
        { pattern: 'cloudflare.com', name: 'Cloudflare', hint: 'Cloudflare Email Security (Area 1)' },
        { pattern: 'awsdns', name: 'Amazon Route 53', hint: null },
        { pattern: 'google.com', name: 'Google Cloud DNS', hint: null },
        { pattern: 'azure-dns.com', name: 'Azure DNS', hint: null },
        { pattern: 'domaincontrol.com', name: 'GoDaddy DNS', hint: null },
    ],
    // Additional DKIM selectors specific to ICES/SEG vendors
    ices_dkim_selectors: [
        'pp1', 'pphosted',           // Proofpoint
        'mimecast20190707',           // Mimecast (typical year-based)
        'mimecast20210101',
        'mimecast20230101',
        'mimecast-key1',               // Mimecast alternative
        'avanan',                      // Avanan
        'proofpoint',                  // Proofpoint re-signing
        'everbridge',                  // Everbridge
        'barracuda',                   // Barracuda
        'esa01', 'esa02', 'esa03',    // Cisco ESA on-premise
        'ironport',                    // Cisco IronPort
        'selector1', 'selector2',      // Microsoft 365
        'google', '20161025',          // Google Workspace
        'smg1', 'smg2',               // Symantec Messaging Gateway
        'cofense',                    // Cofense
        'hoxhunt',                    // Hoxhunt
        'phishline',                  // Barracuda Phishline
        'kb4', 'ksat', 'psm', 'psm2', // KnowBe4
    ],
    // Mapa selector DKIM -> vendor de seguridad (SEG/ICES). Permite detectar la capa
    // de seguridad por la firma DKIM incluso cuando el MX es el del proveedor
    // (Microsoft/Google) y el gateway opera en modo API o re-firmando saliente.
    // NOTA: selectores genéricos (selector1, google, s1...) se excluyen a propósito
    // para evitar falsos positivos; solo selectores razonablemente específicos.
    // Revisar contra documentación oficial del vendor (pueden cambiar).
    dkim_security_selectors: [
        { selector: 'pphosted', name: 'Proofpoint', category: 'seg' },
        { selector: 'pps', name: 'Proofpoint', category: 'seg' },
        { selector: 'pp1', name: 'Proofpoint', category: 'seg' },
        { selector: 'mimecast', name: 'Mimecast', category: 'seg' },
        { selector: 'mimecast20190707', name: 'Mimecast', category: 'seg' },
        { selector: 'mimecast20210101', name: 'Mimecast', category: 'seg' },
        { selector: 'mimecast20230101', name: 'Mimecast', category: 'seg' },
        { selector: 'barracuda', name: 'Barracuda', category: 'seg' },
        { selector: 'fortimail', name: 'FortiMail (Fortinet)', category: 'seg' },
        { selector: 'ironport', name: 'Cisco Email Security (IronPort)', category: 'seg' },
        { selector: 'hornetsecurity', name: 'Hornetsecurity', category: 'seg' },
        { selector: 'avanan', name: 'Avanan (Check Point Harmony Email)', category: 'ices' },
        { selector: 'checkpoint', name: 'Check Point Harmony Email', category: 'ices' },
        { selector: 'abnormal', name: 'Abnormal Security', category: 'ices' },
        { selector: 'sublime', name: 'Sublime Security', category: 'ices' },
        { selector: 'material', name: 'Material Security', category: 'ices' },
    ],
    // Pesos por tipo de señal para la detección ponderada de capas de seguridad.
    // Score combinado por vendor = 1 - Π(1 - peso_i) (noisy-OR).
    seg_signal_weights: {
        mx: 0.9,          // el correo entrante pasa por el gateway: señal fuerte
        mta_sts: 0.8,     // hostname listado en la política MTA-STS
        txt: 0.7,         // token de verificación TXT del vendor
        spf: 0.6,         // include de primer nivel en SPF
        spf_nested: 0.5,  // include anidado en la cadena SPF
        dkim: 0.6         // selector DKIM del vendor presente
    },
    // TLS-RPT reporter identification
    tlsrpt_reporters: [
        { pattern: 'google.com', name: 'Google' },
        { pattern: 'microsoft.com', name: 'Microsoft' },
        { pattern: 'proofpoint.com', name: 'Proofpoint' },
        { pattern: 'mimecast.com', name: 'Mimecast' },
        { pattern: 'agari.com', name: 'Agari' },
        { pattern: 'cloudflare.com', name: 'Cloudflare' },
        { pattern: 'valimail.com', name: 'Valimail' },
        { pattern: 'mailhardener.com', name: 'Mail Hardener' },
    ],
    dmarc_reporters: [
        { pattern: 'agari.com', name: 'Agari' },
        { pattern: 'dmarcian.com', name: 'Dmarcian' },
        { pattern: 'valimail.com', name: 'Valimail' },
        { pattern: 'easydmarc.com', name: 'EasyDMARC' },
        { pattern: 'postmarkapp.com', name: 'Postmark' },
        { pattern: 'ondmarc.com', name: 'Red Sift OnDMARC' },
        { pattern: 'dmarc.microsoft.com', name: 'Microsoft' },
        { pattern: 'google.com', name: 'Google' },
        { pattern: 'proofpoint.com', name: 'Proofpoint' },
        { pattern: 'mimecast.com', name: 'Mimecast' },
        { pattern: 'powerdmarc.com', name: 'PowerDMARC' },
        { pattern: 'uriports.com', name: 'URIports' },
    ],
    // ---------------------------------------------------------------------
    // Hospedaje del correo: ¿los buzones están en la nube o en un servidor propio?
    //
    // El MX responde a "quién FILTRA el correo entrante", que es una pregunta
    // distinta de "dónde VIVEN los buzones". Cuando un SEG va delante (Proofpoint,
    // Mimecast, Hornetsecurity…), el MX tapa por completo lo que hay detrás. Estas
    // listas alimentan el segundo eje, el de la plataforma de buzón.
    // ---------------------------------------------------------------------

    // ASN de hiperescalares y proveedores de correo en la nube. Una IP aquí NO es
    // infraestructura propia del dominio auditado.
    cloud_asns: [
        { asn: '8075', name: 'Microsoft', kind: 'cloud' },
        { asn: '8068', name: 'Microsoft', kind: 'cloud' },
        { asn: '8069', name: 'Microsoft', kind: 'cloud' },
        { asn: '12076', name: 'Microsoft (Azure)', kind: 'cloud' },
        { asn: '15169', name: 'Google', kind: 'cloud' },
        { asn: '19527', name: 'Google', kind: 'cloud' },
        { asn: '396982', name: 'Google Cloud', kind: 'cloud' },
        { asn: '16509', name: 'Amazon AWS', kind: 'cloud' },
        { asn: '14618', name: 'Amazon AWS', kind: 'cloud' },
        { asn: '7224', name: 'Amazon AWS', kind: 'cloud' },
        { asn: '2635', name: 'Automattic', kind: 'cloud' },
        { asn: '6185', name: 'Apple', kind: 'cloud' },
        { asn: '714', name: 'Apple', kind: 'cloud' },
        { asn: '2818', name: 'Zoho', kind: 'cloud' },
        { asn: '58182', name: 'Zoho', kind: 'cloud' },
    ],
    // CDN y proxies inversos. Una IP aquí NO dice NADA sobre dónde está el servidor
    // real: la señal se descarta como no concluyente, nunca se lee como on-premise.
    cdn_asns: [
        { asn: '13335', name: 'Cloudflare', kind: 'cdn' },
        { asn: '209242', name: 'Cloudflare', kind: 'cdn' },
        { asn: '20940', name: 'Akamai', kind: 'cdn' },
        { asn: '16625', name: 'Akamai', kind: 'cdn' },
        { asn: '32787', name: 'Akamai', kind: 'cdn' },
        { asn: '54113', name: 'Fastly', kind: 'cdn' },
        { asn: '22822', name: 'Edgio (Limelight)', kind: 'cdn' },
        { asn: '15133', name: 'Edgecast', kind: 'cdn' },
    ],
    // Hosters y proveedores de alojamiento compartido. Correo gestionado por un
    // tercero que no es hiperescalar: ni nube propiamente dicha, ni servidor propio.
    hoster_asns: [
        { asn: '16276', name: 'OVH', kind: 'hoster' },
        { asn: '35540', name: 'OVH', kind: 'hoster' },
        { asn: '8560', name: 'IONOS (1&1)', kind: 'hoster' },
        { asn: '8972', name: 'IONOS (1&1)', kind: 'hoster' },
        { asn: '24940', name: 'Hetzner', kind: 'hoster' },
        { asn: '20773', name: 'Hostcentric (Host Europe)', kind: 'hoster' },
        { asn: '26496', name: 'GoDaddy', kind: 'hoster' },
        { asn: '398101', name: 'GoDaddy', kind: 'hoster' },
        { asn: '30083', name: 'Newfold (Web.com)', kind: 'hoster' },
        { asn: '32475', name: 'SingleHop', kind: 'hoster' },
        { asn: '12772', name: 'Arsys', kind: 'hoster' },
        { asn: '15879', name: 'Nerim / Dinahosting', kind: 'hoster' },
        { asn: '197595', name: 'Dinahosting', kind: 'hoster' },
        { asn: '14061', name: 'DigitalOcean', kind: 'hoster' },
        { asn: '63949', name: 'Akamai (Linode)', kind: 'hoster' },
        { asn: '20473', name: 'Vultr (Choopa)', kind: 'hoster' },
    ],
    // Destinos de CNAME que identifican la PLATAFORMA DE BUZÓN.
    //   source 'autodiscover' → el CNAME de autodiscover.<dominio>
    //   source 'dkim'         → el CNAME de selectorN._domainkey.<dominio>, que en
    //                           M365 apunta al tenant (…onmicrosoft.com) y por tanto
    //                           demuestra que existe un tenant, no dónde está el buzón.
    mailbox_platform_cnames: [
        { pattern: 'autodiscover.outlook.com', platform: 'm365', source: 'autodiscover' },
        { pattern: 'autodiscover.office365.us', platform: 'm365', source: 'autodiscover' },
        { pattern: 'onmicrosoft.com', platform: 'm365', source: 'dkim' },
        { pattern: 'dkim.mail.microsoft', platform: 'm365', source: 'dkim' },
    ],
    // Primeras etiquetas de hostname que delatan un servidor de correo propio cuando
    // aparecen en Certificate Transparency. Señal DÉBIL y nunca única: un certificado
    // solo prueba que el nombre existió, no que el servicio esté activo hoy.
    onprem_ct_hostnames: [
        'owa', 'exchange', 'webmail', 'correo', 'zimbra', 'mdaemon', 'kerio', 'axigen', 'zarafa'
    ],
    // Patrones de PTR típicos de una línea de cliente de ISP (fibra/ADSL con IP fija).
    // Un MX detrás de uno de estos casi siempre es un servidor en las oficinas.
    isp_ptr_patterns: [
        'customer.static', 'static.customer', 'dynamic', 'dsl.', 'adsl', 'pool.',
        'cable.', 'fibertel', 'dyn.', '.rev.', 'business.static'
    ],
    // Pesos de las señales de hospedaje. Mismo esquema noisy-OR que seg_signal_weights.
    // Los pesos por DEBAJO del umbral de afirmación (0.55) están así a propósito: son
    // señales que nunca deben decidir solas. Ver mailHosting.js para el porqué de cada una.
    mail_hosting_weights: {
        autodiscover_cloud: 0.9,     // autodiscover → autodiscover.outlook.com
        autodiscover_own_asn: 0.9,   // la IP de autodiscover está en un ASN de la propia empresa
        autodiscover_own_domain: 0.85, // el CNAME de autodiscover apunta al propio dominio
        dkim_tenant_m365: 0.85,      // selectorN._domainkey → tenant .onmicrosoft.com
        mx_cloud: 0.8,               // el MX es de un proveedor cloud conocido
        autodiscover_own_ptr: 0.75,  // el PTR de la IP de autodiscover cae en el propio dominio
        mx_self_own_asn: 0.7,        // MX del propio dominio Y en un ASN que no es de nadie conocido
        autodiscover_cloud_asn: 0.5, // la IP de autodiscover está en un ASN de hiperescalar
        dane: 0.5,                   // TLSA en un MX propio: MTA autogestionado (M365 publica TLSA en *.mx.microsoft)
        mx_self: 0.45,               // la raíz del MX coincide con la del dominio auditado
        ptr_isp_static: 0.4,         // el PTR parece una línea de cliente de ISP
        ct_onprem_host: 0.35         // owa./webmail./zimbra. en Certificate Transparency
    },
    categoryColors: {
        email: '#6366f1', seg: '#a855f7', ices: '#8b5cf6',
        marketing: '#f59e0b', transactional: '#06b6d4', crm: '#10b981',
        signatures: '#f43f5e', support: '#fb923c', other: '#64748b',
        unknown: '#9ca3af'
    },
    // Listas RBL/DNSBL consultadas vía DoH. Revisar vigencia periódicamente.
    // NOTA: dnsbl.sorbs.net se retiró (SORBS cerró en 2024).
    rbl_lists: [
        'bl.spamcop.net',
        'dnsbl.dronebl.org',
        'b.barracudacentral.org'
    ]
};

// Cargar entradas personalizadas guardadas por el usuario
// (localStorage no existe fuera del navegador, p. ej. en tests con Node)
if (typeof localStorage !== 'undefined') {
    // Las entradas propias van DELANTE de las de serie en KB.mx: el diccionario se
    // recorre en orden y gana la primera coincidencia, así que una firma añadida por
    // el usuario debe poder afinar (no quedar tapada por) un patrón genérico.
    for (const list of ['spf', 'mx']) {
        try {
            const customKB = localStorage.getItem(`custom_kb_${list}`);
            if (!customKB) continue;
            const entries = JSON.parse(customKB);
            if (!Array.isArray(entries)) continue;
            if (list === 'mx') KB.mx.unshift(...entries);
            else KB.spf.push(...entries);
        } catch (e) {
            console.error('Error loading custom KB (%s) from localStorage', list, e);
        }
    }
}
