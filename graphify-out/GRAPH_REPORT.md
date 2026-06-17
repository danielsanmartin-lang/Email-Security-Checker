# Graph Report - Email Security Checker  (2026-06-17)

## Corpus Check
- 13 files · ~30,858 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 126 nodes · 277 edges · 7 communities (5 shown, 2 thin omitted)
- Extraction: 97% EXTRACTED · 3% INFERRED · 0% AMBIGUOUS · INFERRED: 7 edges (avg confidence: 0.89)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `1138b5b1`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- [[_COMMUNITY_DNS Analysis & Scoring|DNS Analysis & Scoring]]
- [[_COMMUNITY_UI Result Views|UI Result Views]]
- [[_COMMUNITY_DNS Query Client|DNS Query Client]]
- [[_COMMUNITY_App Setup & KB|App Setup & KB]]
- [[_COMMUNITY_DKIM & DMARC Detection|DKIM & DMARC Detection]]
- [[_COMMUNITY_Report Exporters|Report Exporters]]
- [[_COMMUNITY_Arch & Tech Specs|Arch & Tech Specs]]

## God Nodes (most connected - your core abstractions)
1. `runAnalysis()` - 25 edges
2. `📅 Historial de Cambios` - 17 edges
3. `queryDNS()` - 14 edges
4. `getLanguage()` - 13 edges
5. `renderResults()` - 13 edges
6. `detectAwarenessVendors()` - 8 edges
7. `analyze()` - 7 edges
8. `escapeHtml()` - 7 edges
9. `identifySPFService()` - 6 edges
10. `_doh()` - 6 edges

## Surprising Connections (you probably didn't know these)
- `queryDNS()` --implements--> `DNS-over-HTTPS (DoH)`  [INFERRED]
  js/api.js → README.md
- `checkRBL()` --implements--> `RBL Blacklist Reputation Lookup`  [INFERRED]
  js/api.js → README.md
- `calculateScoreAndFindings()` --implements--> `Security Score Card`  [INFERRED]
  js/analyzer.js → README.md
- `renderResults()` --calls--> `identifySPFService()`  [EXTRACTED]
  js/ui.js → js/analyzer.js
- `runAnalysis()` --calls--> `identifyTXTVerifications()`  [EXTRACTED]
  js/app.js → js/analyzer.js

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **DNS Checking Pipeline** — js_api_getmx, js_api_getspf, js_api_getdmarc [INFERRED 0.85]

## Communities (7 total, 2 thin omitted)

### Community 0 - "DNS Analysis & Scoring"
Cohesion: 0.27
Nodes (11): Security Score Card, analyze(), analyzeTLSRPT(), calculateScoreAndFindings(), extractRootDomain(), identifyMX(), identifyNSProvider(), identifySPFService() (+3 more)

### Community 1 - "UI Result Views"
Cohesion: 0.18
Nodes (22): identifyDMARCReporter(), state, exportToFile(), exportToGoogle(), exportToPDF(), generateReportHTML(), translations, KB (+14 more)

### Community 2 - "DNS Query Client"
Cohesion: 0.16
Nodes (25): RBL Blacklist Reputation Lookup, checkRBL(), COMMON_DKIM_SELECTORS, discoverDKIMSelectors(), _dnsCache, fetchMTASTSPolicyFile(), getAllTXT(), getBIMI() (+17 more)

### Community 3 - "App Setup & KB"
Cohesion: 0.07
Nodes (26): 🏗️ Arquitectura del Sistema, 💡 Características principales, 📚 Diccionario de fingerprints (v2026-06-05), Ejecutar Tests Unitarios, 🛡️ Email-Security-Checker, 📅 Historial de Cambios, 💻 Instalación y Uso Local, Nuevos componentes (+18 more)

### Community 4 - "DKIM & DMARC Detection"
Cohesion: 0.16
Nodes (17): AWARENESS_FINGERPRINTS, _cache, _cached(), _crtCache, detectAwarenessVendors(), _doh(), DOH_ENDPOINTS, flattenSpf() (+9 more)

## Knowledge Gaps
- **32 isolated node(s):** `_dnsCache`, `COMMON_DKIM_SELECTORS`, `_cache`, `DOH_ENDPOINTS`, `_crtCache` (+27 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **2 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `detectAwarenessVendors()` connect `DKIM & DMARC Detection` to `UI Result Views`, `DNS Query Client`?**
  _High betweenness centrality (0.047) - this node is a cross-community bridge._
- **Why does `runAnalysis()` connect `DNS Query Client` to `DNS Analysis & Scoring`, `UI Result Views`, `DKIM & DMARC Detection`?**
  _High betweenness centrality (0.043) - this node is a cross-community bridge._
- **Why does `queryDNS()` connect `DNS Query Client` to `Arch & Tech Specs`?**
  _High betweenness centrality (0.039) - this node is a cross-community bridge._
- **What connects `_dnsCache`, `COMMON_DKIM_SELECTORS`, `_cache` to the rest of the system?**
  _32 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `App Setup & KB` be split into smaller, more focused modules?**
  _Cohesion score 0.07407407407407407 - nodes in this community are weakly interconnected._