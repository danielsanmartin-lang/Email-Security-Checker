# Graph Report - .  (2026-06-01)

## Corpus Check
- Corpus is ~18,958 words - fits in a single context window. You may not need a graph.

## Summary
- 63 nodes · 174 edges · 10 communities (6 shown, 4 thin omitted)
- Extraction: 96% EXTRACTED · 4% INFERRED · 0% AMBIGUOUS · INFERRED: 7 edges (avg confidence: 0.89)
- Token cost: 18,958 input · 1,500 output

## Community Hubs (Navigation)
- [[_COMMUNITY_DNS Analysis & Scoring|DNS Analysis & Scoring]]
- [[_COMMUNITY_UI Result Views|UI Result Views]]
- [[_COMMUNITY_DNS Query Client|DNS Query Client]]
- [[_COMMUNITY_App Setup & KB|App Setup & KB]]
- [[_COMMUNITY_DKIM & DMARC Detection|DKIM & DMARC Detection]]
- [[_COMMUNITY_Report Exporters|Report Exporters]]
- [[_COMMUNITY_Translation & Core State|Translation & Core State]]
- [[_COMMUNITY_Arch & Tech Specs|Arch & Tech Specs]]
- [[_COMMUNITY_RBL Blacklist Lookup|RBL Blacklist Lookup]]
- [[_COMMUNITY_SPF Resolver|SPF Resolver]]

## God Nodes (most connected - your core abstractions)
1. `runAnalysis()` - 22 edges
2. `getLanguage()` - 13 edges
3. `queryDNS()` - 12 edges
4. `renderResults()` - 11 edges
5. `analyze()` - 7 edges
6. `identifySPFService()` - 6 edges
7. `exportToGoogle()` - 6 edges
8. `getSPF()` - 5 edges
9. `checkRBL()` - 5 edges
10. `generateReportHTML()` - 5 edges

## Surprising Connections (you probably didn't know these)
- `queryDNS()` --implements--> `DNS-over-HTTPS (DoH)`  [INFERRED]
  js/api.js → README.md
- `checkRBL()` --implements--> `RBL Blacklist Reputation Lookup`  [INFERRED]
  js/api.js → README.md
- `calculateScoreAndFindings()` --implements--> `Security Score Card`  [INFERRED]
  js/analyzer.js → README.md
- `getLanguage()` --conceptually_related_to--> `translations`  [INFERRED]
  js/lang.js → js/i18n.js
- `renderResults()` --calls--> `identifySPFService()`  [EXTRACTED]
  js/ui.js → js/analyzer.js

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **DNS Checking Pipeline** — js_api_getmx, js_api_getspf, js_api_getdmarc [INFERRED 0.85]

## Communities (10 total, 4 thin omitted)

### Community 0 - "DNS Analysis & Scoring"
Cohesion: 0.27
Nodes (11): Security Score Card, analyze(), analyzeTLSRPT(), calculateScoreAndFindings(), extractRootDomain(), identifyMX(), identifyNSProvider(), identifySPFService() (+3 more)

### Community 1 - "UI Result Views"
Cohesion: 0.26
Nodes (9): identifyDMARCReporter(), getCategoryLabel(), renderAdvancedDNS(), renderReputation(), renderResults(), renderSPFTree(), setStep(), translateDOM() (+1 more)

### Community 2 - "DNS Query Client"
Cohesion: 0.39
Nodes (9): getAllTXT(), getBIMI(), getIPAddress(), getMTASTS(), getMX(), getNS(), getTLSRPT(), queryDNS() (+1 more)

### Community 3 - "App Setup & KB"
Cohesion: 0.32
Nodes (4): KB, setLanguage(), closeKbModal(), showSection()

### Community 4 - "DKIM & DMARC Detection"
Cohesion: 0.50
Nodes (4): COMMON_DKIM_SELECTORS, discoverDKIMSelectors(), getDKIM(), getDMARC()

### Community 5 - "Report Exporters"
Cohesion: 0.80
Nodes (5): exportToFile(), exportToGoogle(), exportToPDF(), generateReportHTML(), getLanguage()

## Knowledge Gaps
- **4 isolated node(s):** `COMMON_DKIM_SELECTORS`, `Pure Frontend Architecture`, `Security Score Card`, `RBL Blacklist Reputation Lookup`
  These have ≤1 connection - possible missing edges or undocumented components.
- **4 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `runAnalysis()` connect `DNS Query Client` to `DNS Analysis & Scoring`, `UI Result Views`, `App Setup & KB`, `DKIM & DMARC Detection`, `Report Exporters`, `RBL Blacklist Lookup`, `SPF Resolver`?**
  _High betweenness centrality (0.102) - this node is a cross-community bridge._
- **Why does `queryDNS()` connect `DNS Query Client` to `RBL Blacklist Lookup`, `SPF Resolver`, `DKIM & DMARC Detection`, `Arch & Tech Specs`?**
  _High betweenness centrality (0.101) - this node is a cross-community bridge._
- **Why does `DNS-over-HTTPS (DoH)` connect `Arch & Tech Specs` to `DNS Query Client`?**
  _High betweenness centrality (0.063) - this node is a cross-community bridge._
- **What connects `COMMON_DKIM_SELECTORS`, `Pure Frontend Architecture`, `Security Score Card` to the rest of the system?**
  _4 weakly-connected nodes found - possible documentation gaps or missing edges._