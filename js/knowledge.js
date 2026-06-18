// Knowledge base for identifying email services from DNS records
export const KB = {
    mx: [
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
        { pattern: 'mailprotection.checkpoint.com', name: 'Avanan (Check Point)', type: 'ices' },
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
        { pattern: 'sophos.com', name: 'Sophos', category: 'seg', cat_label: 'SEG' },
        { pattern: 'trendmicro.com', name: 'Trend Micro', category: 'seg', cat_label: 'SEG' },
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
        { pattern: 'avanan.net', name: 'Avanan (Check Point)', category: 'ices', cat_label: 'ICES' },
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
    // TXT domain verification patterns that reveal security vendors
    txt_verification: [
        { pattern: 'proofpoint-verification', name: 'Proofpoint', category: 'seg' },
        { pattern: 'mimecast', name: 'Mimecast', category: 'seg' },
        { pattern: 'cisco-ci-domain-verification', name: 'Cisco Email Security', category: 'seg' },
        { pattern: 'sophos-domain-verification', name: 'Sophos', category: 'seg' },
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
        { pattern: 'spycloud-domain-verification', name: 'SpyCloud', category: 'ices' },
        { pattern: 'canva-site-verification', name: 'Canva', category: 'other' },
        { pattern: 'duo_sso_verification', name: 'Duo Security (Cisco)', category: 'other' },
        { pattern: 'cloudflare-verify', name: 'Cloudflare', category: 'other' },
        // Additional vendor TXT verifications
        { pattern: 'barracuda-domain-verification', name: 'Barracuda', category: 'seg' },
        { pattern: 'trendmicro-domain-verification', name: 'Trend Micro', category: 'seg' },
        { pattern: 'hornetsecurity-domain-verification', name: 'Hornetsecurity', category: 'seg' },
        { pattern: 'forcepoint-domain-verification', name: 'Forcepoint', category: 'seg' },
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
    try {
        const customKB = localStorage.getItem('custom_kb_spf');
        if (customKB) {
            const entries = JSON.parse(customKB);
            if (Array.isArray(entries)) {
                KB.spf.push(...entries);
            }
        }
    } catch (e) {
        console.error('Error loading custom KB from localStorage', e);
    }
}
