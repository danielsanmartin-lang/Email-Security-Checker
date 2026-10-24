# 🛡️ Email-Security-Checker

**English** · [Español](README.es.md)

Email Security Audit

A browser-based tool that audits an organisation's email security from its public DNS alone. Enter a domain and it identifies the email provider, the secure email gateway (SEG) or Integrated Cloud Email Security (ICES) solution in front of it and any **security awareness / phishing simulation platform** in use, scores how well the domain is protected against spoofing, and flags lookalike domains. It is for anyone who needs a quick, discreet read of a third party's email set-up, such as a security consultant or a sales team researching a prospect: no backend, no sign-up, exportable reports, and an interface in English, Spanish and German.

🚀 **[TRY THE APP](https://danielsanmartin-lang.github.io/Email-Security-Checker/)**

---

## 💡 Key features

* **Real-time DNS analysis:** Queries MX, SPF, DMARC, DKIM, BIMI, MTA-STS, TLS-RPT, NS and **DNSSEC** records directly from the browser via DNS-over-HTTPS.
* **Provider identification (SEGs/ICES):** Local knowledge base with more than 50 email service signatures (Microsoft 365, Google Workspace, Proofpoint, Mimecast, etc.).
* **Mail hosting — cloud, hybrid or on-premises:** The MX shows who **filters** inbound mail, not where the mailboxes **live**: with a gateway in front (Proofpoint, Mimecast, Hornetsecurity…) the two answers differ. A separate axis answers the second question using `autodiscover`, the DKIM CNAME (which reveals the Microsoft 365 tenant), Team Cymru's IP→ASN mapping (when a company announces its own IP ranges, the ASN literally carries its name), the **Microsoft Entra tenant** (public OIDC discovery: ID and region, even with a gateway in front; it only corroborates, never decides) and the company's own mail host names (`owa.`, `webmail.`…) that appear in **public certificates**. Each verdict comes with its evidence and its confidence level, and **"not determinable" is a first-class result**: the tool says so when public DNS gives nothing more, rather than guessing. It does not affect the score: on-premises is not insecure per se.
* **Awareness-Vendor Detector:** A dedicated module that detects security awareness and phishing simulation platforms (KnowBe4, Proofpoint SAT, Cofense, Hoxhunt, Barracuda PhishLine, etc.) from DNS signals, with a confidence score and structured evidence. It distinguishes **"has the vendor's gateway"** from **"uses the awareness module"** (product confirmation), and is enriched with two Certificate Transparency sources (crt.sh + Certspotter).
* **Email header analysis:** Paste the headers of a simulated phishing email you have received and the tool identifies the vendor with **high confidence** from sending domains and proprietary X-headers (`X-PHISHTEST`, `X-Gophish-*`, `simulator.office.com`…). It covers **Microsoft Attack Simulation Training**, which leaves no trace in DNS. 100% local.
* **Security assessment:** a **spoofing protection** grade (A+ to F, 0–100) with a level — Protected, Partial or Spoofable — and, separately, a **transport security** grade (or "Not applicable" if the domain does not receive email).
* **In-depth authentication analysis:**
  - **DMARC (RFC 9989/9990, DMARCbis)**: the **effective** policy (the one each generation of receivers applies during the transition), **test mode (`t=y`)**, `pct` (removed in RFC 9989, but still honoured by RFC 7489 receivers), subdomains (`sp`) and **non-existent subdomains (`np`)**, `psd`, **enforcement** in the sense of RFC 9989 §3.2.9, invalid values (which turn the record into `p=none`), `rua` destinations without `mailto:`, alignment (`adkim`/`aspf`) and **authorisation of external report destinations** (`_report._dmarc`, RFC 9990 §4).
  - **DKIM**: validates **key strength** (RSA and **Ed25519**, RFC 8463), **revoked** keys (empty `p=`) and **test mode** (`t=y`). Accepts several comma-separated selectors. A missing DKIM record is not penalised (detection is *best-effort*, using common selectors).
  - **SPF**: **PermError caused by an `include`/`redirect` whose target publishes no SPF** (the most common silent failure), counting of **void lookups** (RFC 7208 §4.6.4), mechanisms that are unreachable after `all`, multiple `all` mechanisms, length >255 characters, missing `all` and use of `ptr`.
  - **MTA-STS**: **coverage of the real MX hosts by the policy's `mx:` list** (RFC 8461 §4.1, the failure that breaks delivery after a change of provider), `max_age` validation, `testing` mode (valid, but not enforced) and a **DNS-only** check that `mta-sts.<domain>` exists.
  - **TLS-RPT**: checks that `rua` destinations are `mailto:` or `https:` (RFC 8460).
  - **BIMI**: **VMC/CMC** certificate (`a=`), explicit opt-out (empty `l=`), a warning if the URL is not HTTPS, and **inheritance from the organisational domain** when the subdomain does not publish its own. Informational only: it does not count towards the score.
  - **MTA-STS**: `max_age` validation (presence and recommended value, RFC 8461).
  - **DNSSEC**: detects a signed zone (DNSKEY + `AD` flag), which protects the integrity of SPF/DMARC/DKIM.
* **Reputation and blocklists (RBL):** Real-time check of the MX servers' IPs against global lists, interpreting the response codes (`listed` / `clean` / `inconclusive`), with a *best-effort* warning — many DNSBLs reject queries that arrive through public DoH resolvers.
* **Exports:** Reports in Google Docs, Word (.doc) and PDF with the score, findings, SPF tree, detailed DMARC, **DNSSEC, DANE, SRV and external DMARC authorisation**. All three formats share a single content source (the PDF is generated from the same report as Word/Docs).
* **Remediation records appendix:** the exported report ends with the DNS records that would leave the domain properly configured, ready to copy: the DMARC ladder up to `reject` (keeping the report destinations), the authorisation record an external report destination must publish, the corrected SPF (records merged, broken `include`s removed, `~all`, and the most expensive `include`s flattened if it goes over 10 lookups), MTA-STS (the TXT record and a policy file with the real MX hosts) and TLS-RPT. Anything that is only an example is marked as such.
* **Fast, resilient DNS engine:** each query waits only for what it needs (there are no stages), with a **priority queue, a per-zone cap and cancellation** (starting a new domain cancels whatever the previous one still had queued) and a cut-off after two SERVFAILs. Queries **degrade gracefully** (a transient failure does not bring down the whole analysis), **the DoH `Status` is validated** (SERVFAIL/REFUSED are told apart from "no records"), the **RFC 9989 §4.10 DNS Tree Walk** discovers the policy and the organisational domain (no Public Suffix List and no backend), **Null MX** (RFC 7505) is recognised, SPF lookups with a CIDR mask are counted correctly and in-flight queries are deduplicated.
* **Input validation and clear errors:** **IDN → punycode** domain normalisation, tolerance of FQDNs with a trailing dot, format validation and distinct error messages (non-existent domain / no connection / **DNS resolution problem** / invalid format).
* **Multilingual and accessible:** Full interface in Spanish, English and German, remembered via `localStorage`, with `<html lang>` and `aria-label` kept in sync, `aria-live` regions, form labels for screen readers, **keyboard-accessible tooltips** (focus, Escape, `aria-describedby`), modals with a focus trap and WCAG AA contrast.
* **Progressive rendering:** The main results appear straight away; awareness, lookalike domains, subdomains with mail and the hosting refinement (which depend on CT logs or on many queries) fill in when they finish, without blocking the view.

* **Email security posture (v5):** the ring measures what can be seen of the domain's email from the outside, on three weighted axes: **spoofing 60** (effective DMARC 50 / SPF 20 / DKIM 20 / reporting 10), **inbound filtering 25** (SEG on the MX or ICES: 100; ICES seen only through a TXT token: 85; gateway with an MX that bypasses it: 75; native filtering only, or an unidentified MX: 65) and **transport 15** (MTA-STS 40 / TLS-RPT 15 / DNSSEC 25 / DANE 20). Each axis has its own pill on the card ("Filtering: Reinforced · Proofpoint"). An axis that does not apply (no MX) drops out of the average and the others share its weight. Without DMARC at enforcement the score cannot go above 45 (D), and A+ requires fully verified spoofing protection. The grades are **calibrated against 61 large-company domains** (`scripts/calibrate.mjs`), and the card shows where the grade sits against that sample ("Better than 20% of a sample of 61 large companies"). The **"How is the grade calculated?"** button shows the working for the analysed domain, the points for each rule and why, the caps, what each grade means and what is reported without being scored, in all three languages. It does not measure how well the filtering actually works, or the human factor, and it says so.
* **Lookalike domains (typosquatting):** in the background, up to 80 variants of the domain are generated (another TLD, a country in the name, homoglyphs, letters left out, swapped or repeated, a hyphen) and the tool checks which ones are registered and which ones **receive email**, the usual vector for payment fraud. Those that share MX or NS with the audited domain, or delegate SPF or DMARC reports to it, are marked as probably its own. The first 3 that receive email are looked up in the certificate logs, and for those that receive email the registration date is requested via RDAP. Not scored.
  * **Risk verdict for each lookalike**, with fixed rules and the reasons on show (`assessLookalikeRisk`):
    * **High:** receives email and was registered less than 90 days ago, or is a homoglyph that can send authenticated email.
    * **Medium:** can send authenticated email, because it has mailboxes with a provider (Google, Microsoft, Zoho…) or an SPF record that authorises sending servers or services. It is also medium if, with no registration date available, its first certificate is less than 30 days old, or if it is parked and new.
    * **Low:** does not receive email, or only forwards it (Namecheap, Porkbun, Cloudflare Email Routing, ImprovMX, Forward Email) or parks it.
    * **Own:** linked to the audited domain.

    The panel and the report sort by risk, and the badge counts the high-risk lookalikes or, if there are none, the medium-risk ones. If any are high risk, a warning above the table (and in the report) explains that this profile often comes before payment fraud (BEC) or a phishing campaign, without claiming that an attack is under way. No signal proves intent: a lookalike may belong to a legitimate company with a similar name.
* **Subdomains with mail:** of the names seen in public certificates, the tool queries those that look as if they send email (news., marketing., mail.…): their SPF, their MX and the DMARC policy that applies to them, either their own or the one inherited through `sp`. A `p=reject` with `sp=none` leaves precisely the newsletter subdomain open to spoofing. Not scored.
* **Sending surface:** how many services authorised in the SPF record can send as the domain. Reported, not scored.
* **DMARC aggregate report (RUA) viewer:** drop in a `.xml`, `.xml.gz` or `.zip` file and see who sends on behalf of the domain, in what volume and what percentage authenticates. Decompression and parsing happen **in the browser**, without uploading the file anywhere.
* **Privacy settings:** choice of DoH resolver (Google / Cloudflare / Quad9 / your own), **opt-in** public CORS proxy, Microsoft tenant lookup (on, with a toggle) and a force-refresh button that bypasses the 5-minute cache.
* **Installable (PWA), lightweight and with no third parties needed to render:** published bundled and minified (89 KB compressed on first load; languages, the report and the awareness detector are downloaded only when used), with a service worker that serves hashed assets from cache, self-hosted fonts and a declared CSP.

## 🏗️ System architecture

This project is built on a **Pure Frontend (Serverless)** architecture:

* **No backend:** All processing and record parsing happens on the client.
* **DNS-over-HTTPS (DoH):** Uses the public Google DNS and Cloudflare DNS APIs with automatic fallback.
* **Certificate Transparency (crt.sh, Certspotter):** the names on the domain's public certificates feed the awareness detector, mail hosting, subdomains with mail and the lookalike domains' certificates.
* **RDAP (each TLD's registry):** the registration date of lookalike domains that receive email shows whether a recent certificate is a campaign being prepared (new domain) or a renewal (old domain).
* **ES6 modules:** Strict separation of concerns in `/js/`. It is developed and tested without a build step; the published version comes out of `scripts/build.mjs` (esbuild).

```
js/
├── bootstrap.js         # Punto de entrada: cablea el DOM (formulario, idioma, modales, PWA)
├── app.js               # runAnalysis(): lanza el análisis y pinta el resultado
├── analysis.js          # performAnalysis(): el análisis completo, sin interfaz (también en Node)
├── lookalike.js         # Dominios parecidos: variantes, clasificación y veredicto de riesgo (puro)
├── state.js             # Estado global compartido (rompe el ciclo app ↔ export)
├── settings.js          # Preferencias: resolver DoH, proxy CORS opt-in, tenant, firmas externas
├── api.js               # Motor DoH (getMX, getSPF, getDMARC, getDKIM…): caché, dedup y cola por zona
├── ct.js                # Certificate Transparency (crt.sh + Certspotter), compartido
├── rdap.js              # Fecha de registro de los dominios parecidos (RDAP + bootstrap de IANA)
├── mailSubdomains.js    # Subdominios con correo vistos en CT: selección y clasificación (puro)
├── remediation.js       # Registros de corrección del anexo del informe (puro)
├── analyzer.js          # Identificación de proveedores/SEGs + scoring por categorías
├── viewmodel.js         # Derivaciones de presentación compartidas por ui.js y export.js
├── ui.js                # Fachada de presentación: tooltips, i18n del DOM y orquestación
├── ui/                  # Un módulo por panel
│   ├── scorePanel.js        # Nota, hallazgos y desglose por categoría
│   ├── summaryPanel.js      # Cabecera y tarjetas resumen
│   ├── mxPanel.js           # MX, proveedor y capas de seguridad (SEG/ICES)
│   ├── spfPanel.js          # Registro, tabla de mecanismos y árbol de lookups
│   ├── dmarcPanel.js        # Política y destinos de informe
│   ├── dkimBimiPanel.js     # DKIM y BIMI (incluido el VMC)
│   ├── reputationPanel.js   # Reputación RBL
│   ├── advancedDnsPanel.js  # MTA-STS, TLS-RPT, DNSSEC, DANE, SRV, NS
│   ├── awarenessPanel.js    # Detector de awareness + analizador de cabeceras
│   ├── lookalikePanel.js    # Dominios parecidos (typosquatting) y sus certificados
│   ├── mailSubdomainsPanel.js # Subdominios con correo
│   ├── scoreMethod.js       # "¿Cómo se calcula la nota?", generado de las constantes del motor
│   └── dmarcReportPanel.js  # Visor de informes agregados (RUA)
├── dmarc.js             # Semántica RFC 9989: Tree Walk, t/pct, enforcement (módulo puro)
├── dmarcReport.js       # Descompresión (.gz/.zip) y agregación de informes RUA — 100% local
├── awarenessDetector.js # Detector de plataformas de Awareness/PhishSim (DNS + CT logs)
├── headerAnalyzer.js    # Detección por cabeceras de correo (cubre el punto ciego DNS)
├── knowledge.js         # Base de conocimiento de vendors (versionada, >50 firmas)
├── i18n.js              # Carga de idiomas (el español va con la app; inglés y alemán, bajo demanda)
├── i18n/                # Un diccionario por idioma: es.js, en.js, de.js (paridad verificada por tests)
├── lang.js              # Idioma activo, idiomas soportados y locale de fechas
├── export.js            # Motor de exportación (Word / PDF / Google Docs), cargado bajo demanda
├── docsExport.js        # Portapapeles de Google Docs (dentro del clic, como exige Safari)
├── parsers.js           # Parsers y validadores de registros DNS
└── utils.js             # Helpers, incluido el tagged template html`` (XSS-safe)

scripts/build.mjs        # Versión publicable en dist/: empaquetada, minificada y con hash (esbuild)
scripts/calibrate.mjs    # Calibración de las letras contra una lista de dominios (Node 22)
sw.js                    # Service worker: cachea la app (lo que lleva hash, de caché), nunca el tráfico externo
manifest.webmanifest     # PWA instalable
css/fonts/               # Tipografías autoalojadas (sin Google Fonts)
```

## 🛠️ Technologies used

* HTML5 / CSS3 (vanilla — no frameworks)
* Vanilla JavaScript (ES6+ modules)
* DNS-over-HTTPS API (Google / Cloudflare / Quad9 or your own resolver, configurable)
* Certificate Transparency API (crt.sh + Certspotter)
* RDAP (RFC 9083), with IANA bootstrap (RFC 9224)
* Vitest + jsdom (tests), ESLint + Prettier (quality), GitHub Actions (CI/CD)
* PWA (service worker + manifest) and self-hosted fonts: zero third-party dependencies to render

---

## 🔐 Privacy and third-party services

The tool is 100% client-side and has no backend of its own. **Everything that goes out to a
third party is configurable or switched off by default**, because the tool is also used in
confidential audits.

* **DNS-over-HTTPS:** all DNS queries. Google (`dns.google`) by default, with Cloudflare and
  Quad9 as fallbacks. In **Settings** you can choose the resolver or enter your own; with your
  own resolver **no public fallback resolver is used**, so the audited domain never leaves your
  infrastructure. Google is sent `edns_client_subnet=0.0.0.0/0`: without it, Google would
  forward an approximation of your network to the audited domain's authoritative DNS servers.
* **The audited domain's servers.** Fetching the MTA-STS policy directly is a CORS request:
  it would leave your IP address and the app's `Origin` in the prospect's logs. It is **off**
  by default (setting *Download the MTA-STS policy directly from the audited domain*): MTA-STS
  is checked via DNS only and credited as "published, not verified". The **BIMI logo does load
  by default** (setting *Load the BIMI logo automatically*): an image carries no `Origin` and
  the page sends no `Referer`, so the logo's server — almost always a CDN — sees only your IP.
  With the setting off, the logo loads with one click. No request carries a `Referer`.
* **CORS proxy `api.allorigins.win`** (fetches the MTA-STS policy when the browser blocks it
  because of CORS): **off by default**. Without it, a policy that cannot be downloaded counts
  as *published, not verified*. It can be switched on in Settings.
* **Certificate Transparency (`crt.sh` and `api.certspotter.com`):** the audited domain and,
  at most, the 3 lookalike domains that receive email are sent as search parameters. They feed
  awareness, hosting, subdomains with mail and the lookalikes' certificates. The audited
  domain is never contacted.
* **RDAP (`data.iana.org` and each TLD's registry):** IANA's list says which registry serves
  each TLD, and that registry (Verisign for `.com`, Google for `.app`…) is asked for the
  registration date of, at most, 10 lookalike domains that receive email. Only the
  lookalike's name is sent; neither the audited domain nor its servers receive anything. Many
  ccTLDs (`.es`, `.de`, `.io`, `.eu`…) do not publish RDAP: in those cases the date stays
  unknown, and for the lookalikes looked up in CT, crt.sh's certificate history acts as a
  fallback.
* **Microsoft (`login.microsoftonline.com`):** the public OIDC document says whether the
  domain is in a Microsoft Entra tenant. It receives the audited domain; **on by default**
  because it goes to Microsoft rather than to the audited domain's servers, and it can be
  switched off in Settings (*Look up the Microsoft tenant*). No credentials and no `Referer`.
* **Fonts:** self-hosted in `css/fonts/`. The app **makes no requests to Google Fonts**.
* **Content-Security-Policy** declared in `index.html`: `default-src 'self'`,
  `script-src 'self'`, `base-uri 'none'` and `form-action 'none'`. `connect-src` lists the
  services above and also allows `https:` in general, because the MTA-STS check requests the
  policy from `mta-sts.<audited-domain>`, a host that is only known at runtime and for which
  CSP has no wildcard.

These run 100% locally, with no network requests at all: **email header analysis** and the
**DMARC aggregate report viewer** (the RUA file is not uploaded anywhere; not even PTR
lookups are run on the IPs, because a DMARC report is a map of an organisation's senders).

---

## 💻 Installation and local use

If you prefer to run this project locally on your machine:

1. Clone this repository:
   ```bash
   git clone https://github.com/danielsanmartin-lang/Email-Security-Checker.git
   ```
2. Go into the directory:
   ```bash
   cd Email-Security-Checker
   ```
3. Because the app uses **ES6 modules**, the browser will block loading local files for security reasons (CORS). You need to serve the project through a local HTTP server, which is easy to start:
   * **With Python (recommended):**
     ```bash
     python3 -m http.server 8080
     ```
   * **With Node/npm:**
     ```bash
     npx http-server -p 8080
     ```
4. Open your browser and go to **`http://localhost:8080`**.

### Development: tests, lint and formatting

The project includes a `package.json` with scripts and development dependencies (Vitest, ESLint, Prettier):

```bash
npm ci             # instala devDependencies desde package-lock (reproducible)

npm test           # ejecuta toda la suite de tests (Vitest)
npm run test:watch # modo watch
npm run coverage   # tests + informe de cobertura (v8) con umbrales bloqueantes
npm run lint       # ESLint sobre js/, sw.js y scripts/ (recommended, --max-warnings=0)
npm run build      # versión publicable en dist/ (esbuild: empaquetada, minificada, con hash)
npm run format     # Prettier (formatea js/)
```

The app works without a build step (that is how it is developed and how the tests run). To
try what gets published: `npm run build` and serve `dist/` (for example,
`npx http-server dist -p 8100`).

The suite (**687 tests**, ~93% coverage) covers the Awareness module (mocked DNS fixtures),
header analysis (`headerAnalyzer`), the parsers and validators (`parseSPF` with indices,
`parseDMARC`, `parseMTASTSPolicy`, `validateMTASTSPolicy`, `analyzeDKIMRecord` with RSA and
Ed25519, `validateTlsRptRua`, `checkMtaStsMxCoverage`), the analyser (`extractRootDomain`,
`collectSpfTreeIssues`, `calculateScoreAndFindings`, the **weighted categories** model and
all the findings), the **DNS layer** (`queryDNS` with a configurable resolver and `Status`
validation, TTL cache, in-flight deduplication, **queue with a per-zone cap, priority and
cancellation** — with *deadlock* regression tests — and **retry on SERVFAIL**,
`getSPFLookupTree` with CIDR, loops, PermError and void lookups, `fetchMTASTSPolicyFile`,
`checkRBL`, `getDNSSEC`, `checkDMARCExternalAuth`), the **RUA report viewer** (parsing,
aggregation, `.gz`, `.zip` and corrupt files), the **knowledge base schema** (valid patterns,
no duplicates), the utilities (`normalizeDomain` IDN/FQDN, `isValidDomain`,
`parseDkimSelectors`, the `` html`` `` helper), **i18n dictionary parity** (same keys, no
empty strings and the same placeholders in all three languages), the **CT logs** (`ct.js`:
race between sources, cache, crt.sh outage), the **remediation appendix** (`remediation.js`)
and the **build** (`scripts/build.test.js`: everything the site references exists, and the
minified analysis engine gives the same score as the unbuilt one).

There are also two levels of tests with **jsdom**:
* `render.dom.test.js` — `renderResults`/`generateReportHTML`, anti-XSS escaping and report
  completeness.
* `integration.dom.test.js` — mounts the real `index.html` with a simulated DoH layer and
  runs through the complete flow (submit → analysis → render), language switching, NXDOMAIN,
  input validation and discarding stale analyses. Each case wires up the page with `init()`
  from `bootstrap.js` and tears it down with the `dispose()` it returns, rather than
  dispatching `DOMContentLoaded`: that way it inherits no listeners or URL from earlier cases.

Every push/PR runs in CI through GitHub Actions:
* **`ci.yml`** — lint (**blocking**) + tests with coverage (**blocking thresholds**) +
  build + `npm audit` (informational), on Node 22 and 24. The coverage report is published as an artefact.
* **`pages.yml`** — deploys to GitHub Pages **only if lint and tests pass**, publishing
  only `dist/` (`npm run build`): no tests and no unbuilt code. Requires
  Settings → Pages → Source to be set to "GitHub Actions".
* **`codeql.yml`** — static security analysis (CodeQL, `security-extended`) on every
  push/PR and on a weekly schedule.

---

## 📅 Version history

> Details of recent versions now live in **[CHANGELOG.md](CHANGELOG.md)** (Keep a Changelog format, written in Spanish). The long history is kept below for compatibility.

### v5.2.0 — Faster and with more context (current)

See **[CHANGELOG.md](CHANGELOG.md)** for details. In short: results arrive two to four times
sooner (each query waits only for what it needs, with a per-zone DNS queue with priority and
cancellation) and the app is published as a bundle (from 215 KB to 89 KB on first load).
Added: the Microsoft Entra tenant, subdomains with mail and the lookalike domains'
certificates (from CT logs), an appendix with remediation records in the report, and a
comparison of the grade against the calibration sample. The score does not change.

### v5.1.0 — A fairer, better-explained score

See **[CHANGELOG.md](CHANGELOG.md)** for details. In short: native Microsoft 365 or Google
filtering goes from 50 to 65, an unidentified MX no longer drops out of the average (being
opaque used to score better than being transparent) and an ICES seen only through a TXT
token is worth 85. The grades are calibrated against 61 large-company domains, the card is
renamed "Email security posture", and the "How is the grade calculated?" section, the
lookalike domain search and the sending surface are added.

### v5.0.0 — The score measures the email ecosystem, with inbound filtering as an axis

See **[CHANGELOG.md](CHANGELOG.md)** for details. In short: the ring no longer measures
spoofing alone but the protection of the whole email ecosystem, with spoofing (60), inbound
filtering (25) and transport (15). An extra security layer on the MX (Proofpoint,
Mimecast…) or an ICES counts in full, native Microsoft 365 or Google filtering counts for
half, and an unidentified MX is not assessed. salesforce.com (Proofpoint) scores 87 (A); a
domain with perfect authentication and its MX pointing straight at Microsoft 365 scores 73 (B).
**v5 scores are not comparable with v4 scores.**

### v4.0.0 — DMARCbis, two-axis scoring and auditor privacy

See **[CHANGELOG.md](CHANGELOG.md)** for details. In short: the score stops adding
transport and brand on top of authentication and instead answers whether the domain can be
spoofed, counting the DMARC policy that is **actually** applied under RFC 9989 (`t=y`, `pct`,
inheritance through `sp`, invalid values, duplicate records) with the RFC's Tree Walk.
Transport gets a separate score. support.apple.com goes from F to A, iberdrola.es from D to
A and posteo.de, which publishes `p=none`, from C to F. An HTML injection in the exported
report is also closed, and the MTA-STS policy is no longer downloaded by default. **v4
scores are not comparable with v3 scores.**

### v3.3.0 — Mail hosting: cloud, hybrid or on-premises

See **[CHANGELOG.md](CHANGELOG.md)** for details. In short: the tool used to infer the
provider from the MX record, but the MX is the **inbound filter**, not the **mailbox
platform** — telefonica.es and mercadona.es both have a gateway in front, yet one keeps its
mailboxes in Microsoft 365 and the other in its own data centre. The two axes are now told
apart, and the `type: 'self'` that `identifyMX` had always calculated — and that nothing
ever read — finally serves a purpose.

### v3.1.0 — Resilient DNS and auditing third-party domains

See **[CHANGELOG.md](CHANGELOG.md)** for details. In short: the DNS layer no longer loses
queries to its own bursts (a cap of 6 concurrent queries and a retry on SERVFAIL — which
also turned out **faster**: 3095 ms → 782 ms on a domain with fragile DNS), a DNS failure no
longer passes itself off as "this domain uses nothing", and the Awareness panel states the
real limit of what DNS can show instead of asking for a sample email that, when you are
auditing a third party, you will never have.

### v3.0.0 — Analysis engine, category scoring, RUA viewer, privacy and PWA

See **[CHANGELOG.md](CHANGELOG.md)** for details. In short: new checks for problems that
used to go unnoticed (SPF PermError, MTA-STS↔MX coverage, BIMI VMC, Ed25519, DMARCbis
`np`), a score that discriminates again, a local aggregate report viewer, privacy settings
and an installable app. **The score calculation changes from v2.x.**

### v2.5.2 → v2.7.1 — Security hardening, DNS engine resilience, accessibility and quality

Internal audit series. See [CHANGELOG.md](CHANGELOG.md) for details. Summary:

* **Security (v2.5.2):** fixed a **click-triggered XSS** in the SPF table (inline onclick → `data-` attribute + delegated listener); `queryDNS` validates the DoH `Status` (SERVFAIL/REFUSED are no longer reported as "no records" or cached); an inconclusive RBL result is no longer shown as "Clean"; new deployment workflow with a **lint+tests gate**, and `graphify-out/` is no longer published.
* **DNS robustness (v2.5.3–v2.6.0):** organisational DMARC inheritance, Null MX (RFC 7505), FQDNs with a trailing dot, stable scan time; **resilient degradation** (`Promise.allSettled`), SPF tree resolved in parallel with CIDR counting, MTA-STS without following redirects (RFC 8461), query deduplication and unified multi-string TXT parsing.
* **Accessibility and UX (v2.6.2):** `aria-live`/roles, keyboard hints, dynamic `<html lang>`, AA contrast, modals with Escape and a focus trap, and **progressive rendering** of the Awareness panel.
* **Export and architecture (v2.6.1–v2.7.1):** report with DNSSEC/DANE/SRV/SPF tree/external DMARC authorisation, unified PDF, i18n of the report, state extracted to `state.js` and presentation logic deduplicated in `viewmodel.js`.
* **Testing/CI (v2.6.2–v2.7.0):** `performAnalysis` extracted and testable (app.js 0%→36%, api.js 26%→76%, overall ~78%), ESLint `recommended`, CI with `npm ci` + cache + Node 20/22 + coverage with blocking thresholds, `LICENSE` (MIT) and `CHANGELOG.md`.

> **159 tests** passing. Lint and coverage are now **blocking** in CI.

### v2.5.1 — SEG/ICES accuracy: MX cross-check and vendor deduplication

Accuracy fixes in security layer detection (`detectSecurityLayers`), prompted by a false positive along the lines of *"amazon.com uses Cisco Email Security — 70%"*.

* **No more false 70% from a verification token:** a SEG whose **only** evidence was a domain-ownership TXT token reached "medium" (0.7) on its own. It is now **cross-checked against the MX**: if no MX record belongs to that vendor (e.g. the domain has its own MX), the claim is downgraded to **"low"** and marked *"not confirmed on the MX"* in the UI and the report. A gateway that is not in the mail flow is not filtering anything. Same pattern as the false 70% for Microsoft AST already fixed in v2.4.0.
* **`cisco-ci-domain-verification` recategorised:** it is no longer reported as the SEG "Cisco Email Security". It is a **Cisco Security Cloud** token (shared across Umbrella/XDR/Threat Defense…), not proof of the IronPort gateway. It becomes a **low-confidence ICES** (with its own weight, `0.35`), since Threat Defense is API-based and its only DNS trace is usually that TXT record.
* **Per-token TXT weight:** each token in the dictionary can set its own weight (`weight`) instead of the global `0.7`, so that confidence can be calibrated signal by signal.
* **Canonical vendor identity:** MX confirmation recognises the same vendor even when the dictionaries use different names (*"Sophos"* in the token vs *"Sophos Email"* in the MX), so a customer whose MX **does** belong to that vendor is not marked as "not confirmed".
* **Entry deduplication:** names unified in the KB (Sophos, Trend Micro, Forcepoint, Avanan/Check Point) so that a vendor detected through several signals (MX + SPF + TXT) is shown as **a single** card with all the evidence combined, rather than being duplicated. Genuinely different products are kept apart (Proofpoint vs Proofpoint Essentials, Symantec cloud vs gateway).

> **+6 tests** (total **134**): the Amazon case (Cisco token → low-confidence ICES, not SEG), MX cross-check, canonical identity, entry merging and rendering of the warning in the UI and the export.

### v2.5.0 — More accurate Awareness detection, including from email headers

Six improvements to the Awareness / Phishing Simulation platform detector, focused on accuracy and on breaking through the limits of DNS-only analysis.

* **Email header analysis (`js/headerAnalyzer.js`):** new module + panel in the Awareness detector where you can **paste the headers** of a simulated phishing email and identify the vendor with **high confidence** from sending domains and proprietary X-headers (`X-PHISHTEST` from KnowBe4, `X-Gophish-Contact`/`X-Gophish-Signature`, `X-PhishMe` from Cofense, `simulator.office.com`/`phishingsimulations.microsoft.com` from Microsoft AST…). It covers **Microsoft Attack Simulation Training**, which cannot be detected through DNS. Runs 100% locally.
* **Gateway vs awareness module (`productConfirmed`):** *direct* evidence of the awareness product is distinguished from *indirect* evidence (its email gateway / co-location). If there is only a gateway signal (e.g. a Proofpoint/Mimecast MX), the card says so: *"awareness-capable provider — module not confirmed"*.
* **Wider CNAME probing with target verification:** a much larger list of campaign subdomains; **any** customer subdomain whose CNAME points to vendor infrastructure now counts (the target is verified, not just the fact that the subdomain exists).
* **Stricter DKIM correlation:** a vendor selector is given a strong weight only if the record **references / is CNAMEd to** the vendor's signing domain; a selector with a generic key that does not reference it becomes a weak hint (this avoids false positives from common selectors such as `s1`).
* **Two Certificate Transparency sources:** `crt.sh` as the primary source and **Certspotter** as _fallback_ (results are merged, and it degrades gracefully if CORS or the network fails).
* **Versioned, updatable dictionary:** an exported version (`AWARENESS_DICT_VERSION`) and functions to load/persist custom fingerprints (`loadCustomFingerprints`/`saveCustomFingerprints`/`loadFingerprintsFromUrl` + automatic loading from `localStorage`), to keep the signatures up to date without touching the code.

> **Note:** an inherited MX-hint weighting *bug* was also fixed (any M365 domain showed a 70% likelihood of using AST based solely on the signal "uses Microsoft"); Microsoft AST now sits at **15% ("low")** and real gateways (Proofpoint/Mimecast 0.3) carry more weight. **+12 tests** (total **128**).

### v2.4.0 — Analysis accuracy, DNSSEC and quality hardening

This version improves the **accuracy** of the results the tool presents as fact, and strengthens input validation and quality tooling.

* **More reliable RBL checks (response code interpretation):** `checkRBL` no longer treats every response as "listed". It distinguishes **`listed`** (`127.0.0.x`), **`clean`** (NXDOMAIN) and **`inconclusive`** (`127.255.255.x` = query refused because it came from a public resolver, or a network failure). The UI and the report show the real status and a *best-effort* warning, because many DNSBLs (Spamhaus, SpamCop…) reject queries that arrive through public DoH (Google/Cloudflare).
* **In-depth DMARC analysis:** new findings for a weaker subdomain policy (`sp` < `p`), partial enforcement (`pct` < 100), strict alignment (`adkim`/`aspf`) and, above all, **authorisation of external report destinations** (`<domain>._report._dmarc.<destination>`, RFC 7489 §7.1) — a real misconfiguration that causes reports to be discarded. Shown per destination in the reporting panel.
* **DKIM: key strength and status, without unfair penalties:** `analyzeDKIMRecord` parses the `SubjectPublicKeyInfo` (DER) and calculates the **RSA modulus size in bits**, flagging **weak (< 1024)**, **1024 (the minimum; 2048 recommended)**, **revoked** (empty `p=`) and **test mode** (`t=y`) keys. A **missing** DKIM record becomes informational (*best-effort* detection using common selectors): a valid custom selector no longer lowers the score.
* **SPF: common gaps covered:** a warning when there is **no `all` mechanism** (the default policy is a neutral `?all`) and when the **`ptr`** mechanism is used (discouraged by RFC 7208).
* **MTA-STS `max_age`:** checks its presence and recommended value (≥ 604800 s, RFC 8461) without invalidating the policy, shown as a warning.
* **DNSSEC:** new `getDNSSEC` (`DNSKEY` records + `AD` flag), with a score bonus, a finding and its own panel under advanced DNS. Signing the zone protects the integrity of SPF/DMARC/DKIM against cache poisoning.
* **Input validation and distinct errors:** `normalizeDomain` converts **IDN → punycode** (via the `URL` API) and strips the port; `isValidDomain` validates the format before querying. Errors are split into **non-existent domain (NXDOMAIN)**, **network error** and **invalid format**, each with its own message (ES/EN).
* **Awareness — MX hint weight fixed (representativeness):** fixed a *bug* where the scoring engine read weight keys (`mxExact`/`mxSubstring`) that the fingerprints did not define, falling back to a default of **0.7**. This inflated detection: any M365 domain showed a **70% (MEDIUM)** likelihood of using *Microsoft Attack Simulation Training* based solely on the signal "uses Microsoft". Each fingerprint's own weight (`w.mxHint`) is now honoured: Microsoft AST drops to **15% ("low")** and real security gateways (Proofpoint/Mimecast `0.3`, Sophos/Barracuda `0.25`) carry more weight than simply using M365, reflecting that they are often sold with, or complemented by, awareness training.
* **Quality and DevEx:** `playwright` moved to `devDependencies`; added **`@vitest/coverage-v8`** and the `npm run coverage` script. CI extended with coverage (artefact) + `npm audit`, and a new **CodeQL** workflow (`security-extended`, also weekly). **+36 new tests** (total **116**), including `js/api.test.js` with a mocked `fetch`, validation of the DKIM parser against real RSA keys and tests for the Awareness MX-hint weight.

> ⚠️ RBL checks are **indicative** (best-effort): for reliable results, your own resolver/proxy is recommended. The per-vendor selector/token lists are still heuristics.

### v2.3.0 — Multi-signal security layer detection

* **Weighted, multi-signal SEG/ICES detection**: Security layer identification is no longer binary. `detectSecurityLayers` now combines evidence from several sources and calculates a **per-vendor confidence** (noisy-OR → High/Medium/Low level), shown in the UI and in the report alongside the specific evidence.
* **New signal sources, using data that was already being fetched**:
  - **Flattened SPF**: the whole chain of includes is inspected (not just the first level), detecting gateways hidden in nested includes (`collectSpfDomains` over the SPF tree).
  - **The MTA-STS policy's `mx:` list**: the MX hostnames authorised in the policy file are matched against the knowledge base, revealing the gateway even when the active MX does not show it.
  - **DKIM selectors → vendor** (`KB.dkim_security_selectors`): makes it possible to detect the security layer from the DKIM signature even when the MX belongs to the provider (Microsoft/Google) and the gateway works in API mode or re-signs messages.
* **API-based ICES**: expanded knowledge base of TXT verification tokens (Material, Sublime, Avanan/Check Point, Tessian, Egress, Vade, Darktrace, Cyren…), and the UI makes it clear that these ICES (Graph/Google API) **leave no DNS trace**: "not detected" ≠ "no security layer".
* **Awareness**: SPF IP matching now supports **IPv6** (CIDR with BigInt), and **crt.sh** can never be the only signal (at least one other piece of evidence is required), with a longer cache to make it less fragile.
* **Centralised weights** in `KB.seg_signal_weights` and **20 new tests** (multi-signal detection, flattened SPF, IPv6 CIDR). Total: 80 tests.

> ⚠️ The per-vendor selector/token lists are heuristics and should be checked against the official documentation; they may change over time.

### v2.2.0 — Architectural refactoring

* **`` html`` `` template helper with auto-escaping**: A new tagged template (`js/utils.js`) that escapes every interpolation by default (XSS-safe), with a `raw()` marker for HTML that is already safe and support for nesting/arrays. `escapeHtml` was reimplemented without the DOM (it works in Node and also escapes quotes). Adopted in `renderSPFTree` and in the rendering of findings/posture.
* **Shared view-model layer (`js/viewmodel.js`)**: Centralises the presentation logic that `ui.js` and `export.js` used to duplicate (finding text, DMARC policy, posture, service description, provider source, RBL count, category labels).
* **Declarative scoring**: `calculateScoreAndFindings` was rewritten as a table of per-section evaluators with centralised weights (`SCORE_WEIGHTS`, `MAX_POSITIVE_SCORE`), preserving its behaviour and making it easier to test.
* **Provider/source "sentinel" pattern removed**: The analyser emits a language-neutral structure (`providerIdentified`, `providerSource = { key, arg }`) and translation happens in the presentation layer, instead of reverting Spanish strings by text matching.
* **Category labels moved to i18n**: The category translation maps now live in `i18n.js` (`category_labels`, `category_defaults`).
* **Unified DNS layer**: `awarenessDetector.js` reuses `queryDNS` from `api.js` (shared cache and fallback) instead of its own duplicate DoH client.
* **`extractTxtValue`**: Extracted the repeated parsing of quoted TXT records (used by SPF, DMARC, MTA-STS, TLS-RPT and getAllTXT).
* **Tests**: 68 in total, including jsdom integration tests that run `renderResults` and the export report, checking anti-XSS escaping end to end.

### v2.1.0 — Robustness, full i18n, IPv6 and tooling

* **Bounded score (0–100)**: The score is now correctly clamped to the 0–100 range before the grade is derived, avoiding inconsistent values (>100) against the A+ threshold.
* **Full internationalisation of the logic**: Hard-coded Spanish strings were removed from the code. SPF tree errors, security posture and the SRV/DANE panels now use i18n keys and are translated correctly in both languages. The exported report (`export.js`) takes its keys from `i18n.js` instead of duplicating the translation system with `es/en` ternaries.
* **IPv6 and multi-IP support in RBL**: IP resolution now includes `AAAA` records and all of the host's IPs; `checkRBL` supports the reverse query format for IPv6. The RBL lists were moved out to `knowledge.js` (SORBS, which closed in 2024, was removed).
* **Parallel analysis**: `runAnalysis` runs the independent DNS queries concurrently (MX, SPF, DMARC, BIMI, advanced), cutting total time significantly while keeping the step-by-step feedback.
* **Anti-XSS hardening**: Audit and escaping (`escapeHtml`) of every DNS-derived value inserted via `innerHTML`, in both the UI and the exported report.
* **Shared `normalizeDomain` utility**: Deduplicated the domain normalisation logic (email, scheme, `www`, path) in `js/utils.js`.
* **Development tooling**: Complete `package.json` (`type: module`, scripts), Vitest configured, ESLint (flat config) + Prettier, and CI with GitHub Actions. New test coverage for the parsers and the analyser (49 tests).
* **Documented privacy**: New README section on third-party services (Google/Cloudflare DoH, the `allorigins.win` CORS proxy, `crt.sh`).

### v2.0.0 — Advanced DNS detection (SRV/DANE), security posture and Awareness improvements

* **DANE (TLSA) protocol and SRV records**: Added support for parallel DNS queries of DANE/TLSA authentication records (`_25._tcp`) to verify encryption security on the MX servers, plus SRV autodiscovery probes (`_autodiscover`, `_imaps`, `_submission`).
* **Security posture indicator**: Automatic calculation and display of the domain's overall posture (`Strong` 🟢, `Moderate` 🟡, `Weak` 🔴) on the score card, assessing SPF, DMARC, DKIM, SEG/ICES and MTA-STS.
* **Awareness detection improvements**:
  - *CNAME probing*: Searches for popular landing-page/tracking subdomains (`click`, `track`, `phish`, etc.) delegated to vendor infrastructure.
  - *Generic DKIM probing*: Automatically tries standard selectors (`s1`, `s2`, `k1`, etc.) to verify vendors' cryptographic signatures.
  - *Cross-detection*: A boost from perimeter security (SEG) correlation for co-located providers (Proofpoint, Barracuda, Mimecast, Sophos).
  - *TXT tokens*: Detection of specific verification tokens on the root domain.
* **Expanded knowledge base**: Added SEG/ICES signatures for *Egress Defend*, *Libraesva*, *VIPRE*, *Graphus* and *Armorblox*.

### v1.9.0 — Awareness-Vendor Detector: detecting phishing simulation platforms

The most ambitious module so far: it automatically detects whether a company uses a **Security Awareness Training / Phishing Simulation** platform from its DNS footprint, with no privileged access needed.

#### 🔍 Detection pipeline (per input domain)

1. **SPF flattening (RFC 7208):** Recursive resolution of the `v=spf1` chain, respecting the 10-lookup limit. It is flattened into the final list of `include:`s, domains and IPs/CIDRs.
2. **MX:** Gateway inference (Mimecast bundles awareness, Proofpoint pphosted, etc.).
3. **DMARC:** The `_dmarc.<domain>` record — `rua`/`ruf` are recorded in case they point to vendor infrastructure.
4. **Selective DKIM:** Probes ONLY the selectors known to the dictionary (`<selector>._domainkey.<domain>`). If they resolve to the vendor's signing domain → strong signal.
5. **Certificate Transparency (crt.sh):** Searches for subdomains of the audited domain whose CN/SAN points to vendor infrastructure.
6. **Probabilistic scoring:** Combined score `1 − Π(1 − weight_i)` per signal type, never above 1. Levels: **High ≥ 75%**, **Medium ≥ 45%**, **Low**.

#### 📚 Fingerprint dictionary (v2026-06-05)

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

> **⚠️ Documented blind spot:** Microsoft Attack Simulation Training (Defender for O365) — all its traffic is internal to the M365 tenant. Allowlists are configured under "Advanced Delivery" (Exchange Online Protection) at tenant level and leave no external DNS trace. **This module cannot detect it.**

#### New components

* **`js/awarenessDetector.js`** — Complete engine with a hot-reloadable dictionary (`mergeFingerprints()`), an internal cache with a 5-minute TTL and Cloudflare DoH fallback.
* **`js/awarenessDetector.test.js`** — Vitest suite with mocked DNS fixtures for every vendor, scoring, CIDR matching and SPF PermError.
* **UI panel** — Vendor cards with an animated confidence bar, level (High/Medium/Low), evidence pills with the signal type + value, a vendor note and an always-visible alert about the Microsoft blind spot.
* **Loading step** — New `step-awareness` shown in the loading sequence after the main analysis.
* **Multilingual support** — 25 new keys in ES + EN in `i18n.js`.

---

### v1.8.0 — Richer export reports and improved SEG detection
* **Security score in exports:** The Executive Summary section of exported reports (Google Docs, Word, PDF) now includes the security grade (A+ to F) alongside the score out of 100.
* **Detailed DMARC configuration table:** Exported reports show a table of the parsed DMARC parameters (`p`, `sp`, `pct`, `adkim`, `aspf`) for a clearer reading of the active policy.
* **Result column in the SPF table:** Each entry in the exported report's SPF table now includes a result column (`Pass`, `Fail`, `SoftFail`, `Neutral`) based on the mechanism's qualifier.
* **DMARC reporting provider identification (RUA/RUF):** Exported reports automatically detect and name the reporting provider (Valimail, Dmarcian, Postmark, etc.) from the `rua`/`ruf` addresses.
* **Provider evidence source:** The result card now shows in which DNS record (MX, SPF, TXT, NS) each identified provider or SEG was detected.
* **Fix: no false SEG positives for self-hosting:** When the MX records point to the same root domain that is being analysed, the tool no longer misclassifies the organisation's own infrastructure as a secure email gateway (SEG).
* **Unknown SEG detection via an external MX domain:** If the MX records point to a root domain other than the one being analysed and do not match any known signature, the tool now reports it as a security gateway from an unknown provider.

### v1.7.4 — Robust security validation for SPF and DMARC
* **Multiple DNS record detection:** Critical alerts and a score penalty if multiple SPF or DMARC records are configured (violations of RFC 7208 and RFC 7489 that break email authentication).
* **SPF `all` qualifier analysis:** Specific penalties and alerts for insecure or overly permissive SPF directives such as `+all` (a free pass for any sender) and `?all` (neutral / no protection).
* **DMARC syntax validation:** Strict validation to ensure that the version tag (`v=DMARC1`) and the policy directive (`p=none|quarantine|reject`) comply with the standards and contain no invalid values.
* **Multiple-record interface:** The interface now detects, highlights and renders separately each of the conflicting records found in DNS.

### v1.7.3 — XSS protection, CORS bypass for MTA-STS and DNS cache
* **Sanitisation against XSS in DNS records:** Automatic sanitisation of problematic HTML characters in any record retrieved from DNS before it is rendered with `innerHTML`.
* **CORS bypass for MTA-STS:** Smart fallback to a CORS proxy (allorigins.win) when direct retrieval of the MTA-STS policy file is blocked by the browser's CORS restrictions.
* **In-memory DNS cache:** A local cache with a 5-minute TTL to avoid redundant DNS queries and speed up the audit as a whole.

### v1.7.2 — Fixes to Hornetsecurity detection and domain extraction
* **Improved Hornetsecurity support:** Added detection signatures for Hornetsecurity in MX records (`antispameurope` pattern) and SPF records (`hornetsecurity` and `antispameurope` patterns).
* **Domain extraction from email addresses:** When a full email address is typed or pasted into the search box, the tool automatically cleans up the input, ignoring the local part and the `@` sign.

### v1.7.1 — Explaining SPF loops in the lookup tree
* **Explanatory tooltip for SPF loops:** Interactive display and an explanatory tooltip when hovering over the `[Error: Loop detectado]` alert, explaining in detail the root cause of the error — circular references in SPF DNS records — in Spanish and English.

### v1.7.0 — Advanced ICES detection and parallel DNS queries
* **Advanced DNS audit:** Added DNS queries on root TXT, NS, MTA-STS and TLS-RPT records for real-time, serverless security scrutiny.
* **Detection of hidden ICES solutions:** A new cross-referencing engine that detects cloud security gateways and next-generation ICES solutions (Perception Point, xorlab, Material Security, Area 1, etc.) by analysing verification (TXT) and routing (NS) records.
* **Advanced results panel:** A new module in the results interface that presents MTA-STS and TLS-RPT adoption in a user-friendly way.

### v1.6.1 — Google Docs export improvements
* **Smart auto-titling:** The Google Docs export now adds the audited domain's name at the top of the report.

### v1.6.0 — Explanatory tooltips, DKIM auto-discovery and RBL reputation
* **Smart DKIM selector auto-discovery:** Automatic parallel search for up to 10 of the most common DKIM selectors.
* **Domain reputation audit (blocklists/RBLs):** Real-time resolution of the MX servers' IPs and parallel checks against global reputation lists (SORBS, Spamcop, DroneBL).
* **Premium exports and reports:** Complete redesign of the export engine for Google Docs, Word (.doc) files and PDF printing.

### v1.5.0 — Interactive security score card
* **Security Score Card:** A dynamic panel that calculates a grade (A+ to F) out of 100 points based on the DNS configuration of the domain's email security.
* **Animated radial indicator:** The score is displayed through an interactive, animated SVG ring.
* **Dynamic multilingual audit:** An instant list of findings (positives and alerts) that is translated in real time when switching between English and Spanish.

### v1.4.0 — Multilingual support and optimised PDF reports
* **Multilingual support (Spanish / English):** Multi-language implementation (`js/lang.js` and `js/i18n.js`) that translates the whole web interface.
* **Language selector:** Interactive menu in the header with flag icons and the selected language remembered via `localStorage`.
* **Dynamic localised reports:** Reports in Google Docs, Word (.doc) files and PDF printing, fully translated into the active language.

### v1.3.0 — Architectural refactoring and DKIM experience
* **Modular ES6 architecture:** Complete migration of the original monolithic `app.js` to a structured system of independent modules in the `/js/` folder.
* **DoH network resilience:** A hybrid query system with fault-tolerant DNS-over-HTTPS fallback (Google DoH ➡️ Cloudflare DoH).
* **Improved DKIM usability:** Redesigned optional DKIM selector field with an explanatory modal for non-technical users.

### v1.2.0 — Advanced audits and SPF visualisation
* **Hierarchical SPF lookup tree:** A recursive algorithm that draws the SPF DNS lookup tree on screen, keeping track of the critical limit of 10 DNS lookups.
* **BIMI verification:** Extraction of brand marks and logo images directly from BIMI DNS records.
* **Native PDF export:** `@media print` stylesheets to export the report as a PDF.

### v1.1.0 — Service classification and dynamic learning
* **Dynamic SPF classification:** An on-the-fly selector to classify and tag unrecognised SPF signatures in real time.
* **Database rule creation:** A pop-up to add new services directly to the Knowledge Base, persisted locally with `localStorage`.

### v1.0.0 — Initial release
* **Basic DNS audit:** Scanning and rendering of MX, SPF and DMARC records via DoH.
* **Automatic identification:** Basic classification of the most common corporate email and perimeter security providers.
* **Basic export:** Native functions to export reports to the clipboard or as a downloadable `.doc` file.
