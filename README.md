<div align="center">

<img src="https://img.shields.io/badge/BurpMax-1.0.0-FF6B35?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0id2hpdGUiIGQ9Ik0xMiAyTDIgN2wxMCA1IDEwLTV6TTIgMTdsOCA0IDgtNFYxMkwyIDE3eiIvPjwvc3ZnPg==" alt="BurpMax"/>

# BurpMax

### Professional-Grade Vulnerability Scanner for Burp Suite

**Bringing Burp Suite Professional scanning capabilities to every security tester, including Community Edition users.**

<br/>

[![Java](https://img.shields.io/badge/Java-17%2B-ED8B00?style=flat-square&logo=openjdk&logoColor=white)](https://adoptium.net/)
[![Burp Suite](https://img.shields.io/badge/Burp_Suite-2022.8%2B-FF6633?style=flat-square&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PC9zdmc+&logoColor=white)](https://portswigger.net/burp)
[![Version](https://img.shields.io/badge/Version-1.0.0-28A745?style=flat-square)](https://github.com/omkar-mirkute/burpmax/releases)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)
[![Active Probes](https://img.shields.io/badge/Active_Probes-24-DC3545?style=flat-square)](#active-scanner--24-probes)
[![Passive Checks](https://img.shields.io/badge/Passive_Checks-13-6F42C1?style=flat-square)](#passive-scanner--13-checkers)
[![Author](https://img.shields.io/badge/Author-Omkar_Mirkute-0D6EFD?style=flat-square)](https://github.com/omkar-mirkute)

<br/>

[**Installation**](#installation) • [**Features**](#features) • [**Usage**](#usage) • [**Build from Source**](#building-from-source) • [**Disclaimer**](#disclaimer)

</div>

---

## What is BurpMax?

BurpMax is a feature-rich Burp Suite extension that levels the playing field for security professionals. It delivers **automated active and passive vulnerability scanning, OOB (out-of-band) detection, WAF evasion, CVSS 4.0 scoring, and professional report generation** , capabilities that are either locked behind Burp Professional or require multiple separate tools.

> 🔓 **BurpMax gives Burp Community Edition users access to Pro-grade scanning features** including automated active scanning, out-of-band interaction tracking (via Interactsh), scan checkpointing, professional PDF/DOCX reports with CVSS 4.0, and more, at no extra cost.

---

## Installation

### Requirements

| Requirement | Minimum |
|---|---|
| Burp Suite | Community or Professional 2022.8+ |
| Java Runtime | 17+ (JRE is sufficient for running the pre-built JAR) |

### Option A - Pre-built JAR (Recommended)

1. Download `burpmax-1.0.0.jar` from the [**Releases**](../../releases) page
2. Open Burp Suite → **Extensions** → **Add**
3. Set **Extension Type** to `Java`
4. Select the downloaded JAR and click **Next**
5. The **BurpMax** tab appears in Burp's top navigation bar ✅

### Option B - Build from Source

```bash
git clone https://github.com/omkar-mirkute/burpmax
cd burpmax
./build.sh
# Output: build/burpmax-1.0.0.jar
```

> The build uses local Burp API stubs for compilation. Stubs are **not** bundled in the output JAR. Burp Suite provides the real API classes at runtime.

---

## Usage

### Passive Scanning

Passive scanning starts **automatically** when the extension loads. Browse your target with Burp proxy active and findings appear in the BurpMax tab in real time. No configuration required.

### Active Scanning

```
1. Browse target to populate Burp's site map
2. Set target scope → Target → Scope
3. Click ⚡ Active Scan in the BurpMax toolbar
4. Confirm the warning dialog
5. Monitor progress bar (done / total endpoints)
6. Cancel anytime with ⏹ Cancel Scan
```

> ⚠️ **Only run active scans against targets you have explicit written permission to test.**

### OOB Configuration (Community Edition)

1. Deploy or use a public [Interactsh](https://github.com/projectdiscovery/interactsh) server
2. In BurpMax settings, set the **OOB Server URL** to your Interactsh endpoint
3. BurpMax will automatically use it for OOB-capable probes (SQLi, CMDi, XXE, SSRF, Log4Shell)

### Report Export

1. Click **Export PDF**, **Export DOCX**, or **Export CSV** in the toolbar
2. For PDF/DOCX: fill in the report metadata dialog (client name, scope, date, version, analyst name)
3. Choose a save location. The file is created immediately.

### Finding Management

| Action | How |
|---|---|
| Filter by severity | Click **Critical / High / Medium / Low / Info** badge buttons |
| Override severity | Right-click a finding → **Override Severity** |
| Suppress false positive | Right-click → **Mark as FP** |
| Open in Repeater | Right-click → **Send to Repeater** |
| Save/load session | **File → Save Session** / **Load Session** |

---

## Features

### 🔴 Active Scanner - 24 Probes

Triggered manually via **⚡ Active Scan**. All probes support **30+ WAF evasion encoding variants** per payload.

| Category | Probe | Detection Method |
|---|---|---|
| **Injection** | SQL Injection | Error-based, Boolean-based, Time-based (sleep/benchmark), OOB (DNS) |
| | Command Injection | Output-based, Time-based, OOB (DNS/HTTP) |
| | Blind Command Injection | Time-delay confirmation |
| | SSTI | 8 engine payloads (Jinja2, Twig, Freemarker, etc.) with baseline diff |
| | Blind SSTI | Timing-based math evaluation |
| | XXE | In-band (file read) + OOB (external entity DNS callback) |
| | LDAP Injection | Operator injection, response analysis |
| | NoSQL Injection | Operator injection, regex injection, parameter pollution |
| | Path Traversal | `../` traversal, `etc/passwd` content confirmation |
| **Client-Side** | XSS | Unique canary injection, unescaped reflection check |
| | Prototype Pollution | `__proto__` / `constructor.prototype` injection |
| | Blind Prototype Pollution | OOB callback variant |
| **Auth & Session** | JWT Attacks | `alg=none`, weak secret brute-force, RS256 to HS256 confusion, `kid` injection, `x5u` injection |
| | CSRF | Missing token detection on state-changing endpoints |
| | Auth Bypass | Strip auth headers, dual response similarity check |
| | IDOR | Numeric ID increment, response diff analysis |
| **Infrastructure** | SSRF | Parameter injection + header injection, OOB callback |
| | Host Header Injection | Canary hostname, reflection in body/redirect |
| | HTTP Request Smuggling | CL.TE, TE.CL, TE-obfuscation variants |
| | Log4Shell | JNDI LDAP/DNS callback via OOB |
| | Open Redirect | Canary URL injection into redirect params |
| **Modern Apps** | GraphQL | Introspection, batch queries, alias abuse, depth limit bypass |
| | CORS Misconfiguration | Evil-origin probe, ACAO/ACAC header analysis |

---

### 🟣 Passive Scanner - 13 Checkers

Analyses every HTTP request/response through the Burp proxy. **Zero extra requests sent.** Runs automatically from the moment the extension loads.

| Checker | What It Finds |
|---|---|
| **HeaderChecker** | Missing HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy, CORS misconfigs |
| **CookieChecker** | Missing HttpOnly / Secure / SameSite flags, JWT/JSON stored in cookies |
| **BodyChecker** | Secrets and sensitive data in response bodies |
| **HtmlChecker** | HTML comments with sensitive data, debug markers, directory listings, backup file references |
| **RequestChecker** | Dangerous HTTP method usage, overly permissive access |
| **VersionChecker** | 46 patterns across servers, libraries, CMS, and frameworks (Apache, Nginx, PHP, Spring, WordPress, etc.) |
| **SecretChecker** | AWS keys, GitHub/GitLab tokens, Google API keys, Stripe, Slack, HashiCorp Vault, private keys, DB connection strings (19+ patterns) |
| **ApiResponseChecker** | PII fields, credential exposure, credit cards (Luhn-validated), SSN, stack traces, debug mode leaks |
| **CacheControlChecker** | Insecure `Cache-Control` on authenticated responses |
| **RateLimitChecker** | Missing rate limiting on auth endpoints (passive detection + optional active verification) |
| **CloudMetadataChecker** | IMDS/`169.254.169.254` references in responses |
| **CleartextCredentialChecker** | Username/password in plaintext in request bodies or URLs |
| **MethodChecker** | Dangerous HTTP methods enabled (TRACE, PUT, DELETE) |

---

### 📡 Out-of-Band (OOB) Detection

BurpMax supports two OOB backends, automatically selected based on what is available:

| Backend | Availability | Use Case |
|---|---|---|
| **Burp Collaborator** | Burp Suite Professional | Full integration via Burp's internal API |
| **Interactsh** | Community Edition ✅ | Free, open-source OOB platform. Enables OOB scanning on Community. |

> Community Edition users can configure an [Interactsh](https://github.com/projectdiscovery/interactsh) server URL in the BurpMax settings to unlock OOB detection for SQLi, CMDi, XXE, SSRF, Log4Shell, and more.

---

### 📄 Report Generation

Export findings in multiple formats with full context and evidence:

| Format | Description |
|---|---|
| **PDF** | Cover page, executive summary, severity breakdown, per-finding detail with PoC screenshots, CVSS 4.0 score, logo |
| **DOCX** | Client-ready Word document with cover page, TOC, executive summary with severity chart, findings (each on a new page), and appendix |
| **CSV** | JIRA / Dradis ready, sorted by severity, formula-injection safe |
| **Scan Diff** | Compare two scan sessions to highlight new or resolved findings |

**PoC Screenshots** are automatically generated as side-by-side request/response views with red highlights on key evidence lines, matching Burp's UI style.

**CVSS 4.0** scores are computed automatically per finding and embedded in PDF/DOCX exports.

---

### 🕷️ Crawler

BurpMax's built-in crawler discovers endpoints before active scanning:

- `robots.txt` and `sitemap.xml` parsing
- HTML form extraction (GET + POST)
- JavaScript `fetch` / `axios` / router path discovery
- JSON HAL link traversal
- HTML and JS comment mining
- Path parameter normalisation (avoids duplicate scans of `/user/1` vs `/user/2`)

---

### 💾 Session Management

- **Autosave** - findings saved every 2 seconds (debounced) with atomic file writes (`ATOMIC_MOVE`) for crash safety
- **Scan Checkpoints** - resume an interrupted active scan without re-testing already-completed endpoints
- **Session Load** - reload previous sessions on Burp restart

---

## Project Structure

```
burpmax/
├── src/main/java/com/autovuln/
│   ├── BurpExtender.java              # Extension entry point (IBurpExtender)
│   ├── model/
│   │   ├── Finding.java               # Finding data model + JSON serialisation
│   │   └── Cvss4Calculator.java       # CVSS 4.0 score computation
│   ├── store/
│   │   └── FindingStore.java          # Thread-safe store, dedup, session I/O
│   ├── scanner/                       # Passive checkers (13 modules)
│   │   ├── Dispatcher.java            # Routes traffic to all passive checkers
│   │   ├── HeaderChecker.java
│   │   ├── CookieChecker.java
│   │   ├── BodyChecker.java
│   │   ├── HtmlChecker.java
│   │   ├── RequestChecker.java
│   │   ├── VersionChecker.java        # 46 version fingerprints
│   │   ├── SecretChecker.java         # 19+ secret patterns
│   │   ├── ApiResponseChecker.java
│   │   ├── CacheControlChecker.java
│   │   ├── RateLimitChecker.java
│   │   ├── CloudMetadataChecker.java
│   │   ├── CleartextCredentialChecker.java
│   │   └── MethodChecker.java
│   ├── active/                        # Active probes (24 modules)
│   │   ├── ActiveScanner.java         # Probe orchestrator
│   │   ├── HttpSender.java            # Probe-isolated HTTP client
│   │   ├── RequestBuilder.java        # Payload injection engine
│   │   ├── WafEvasionEncoder.java     # 30+ encoding variants
│   │   ├── OobClient.java             # OOB abstraction interface
│   │   ├── CollaboratorOobClient.java # Burp Collaborator backend
│   │   ├── InteractshOobClient.java   # Interactsh backend (Community)
│   │   ├── LinkExtractor.java         # Crawler / endpoint discovery
│   │   ├── ScanCheckpoint.java        # Scan state persistence
│   │   ├── ConfirmationEngine.java    # Probe result confirmation logic
│   │   ├── JsonWalker.java            # Recursive JSON param injection
│   │   ├── XmlBodyParser.java         # XML/XXE body handling
│   │   ├── SqliProbe.java             # + OobSqliProbe.java
│   │   ├── XssProbe.java
│   │   ├── CommandInjectionProbe.java # + BlindCmdiProbe.java
│   │   ├── SstiProbe.java             # + BlindSstiProbe.java
│   │   ├── PathTraversalProbe.java
│   │   ├── SsrfProbe.java
│   │   ├── XxeProbe.java
│   │   ├── JwtProbe.java
│   │   ├── GraphQlProbe.java
│   │   ├── HttpRequestSmugglingProbe.java
│   │   ├── NoSqlInjectionProbe.java
│   │   ├── PrototypePollutionProbe.java # + BlindPrototypePollutionProbe.java
│   │   ├── LdapInjectionProbe.java
│   │   ├── CorsMisconfigProbe.java
│   │   ├── HostHeaderProbe.java
│   │   ├── CsrfProbe.java
│   │   ├── IdorProbe.java
│   │   ├── AuthBypassProbe.java
│   │   ├── OpenRedirectProbe.java
│   │   └── Log4ShellProbe.java
│   ├── export/
│   │   ├── PdfExporter.java           # PDF with PoC screenshots + CVSS 4.0
│   │   ├── DocxExporter.java          # DOCX (pure ZIP/XML, no external lib)
│   │   ├── CsvExporter.java           # JIRA/Dradis-ready CSV
│   │   ├── ScanDiff.java              # Session comparison / diff export
│   │   └── ReportMeta.java            # Cover page metadata model
│   ├── session/
│   │   └── SessionManager.java        # Debounced autosave, atomic writes
│   └── ui/
│       ├── UIBuilder.java             # Main Swing UI
│       ├── FindingTableModel.java     # JTable model
│       └── Theme.java                 # Colour / font constants
├── burp-stub/                         # Compile-time Burp API stubs only
├── build/
│   └── MANIFEST.MF
├── build.sh                           # Build script (no Maven install required)
├── pom.xml
└── README.md
```

---

## Security Design

BurpMax is built to be safe to run in live engagements:

- **No passive-to-active bleed** - Active scanner uses `makeHttpRequest()` which does not fire `IHttpListener`, preventing probe payloads from triggering passive findings on probe-generated traffic. All probe URLs are registered and filtered.
- **Thread-safe finding store** - `FindingStore.add()` is synchronised; listener notifications fire outside the lock to prevent deadlock.
- **Secret masking** - Matched secrets are partially redacted in evidence before storage or export.
- **XML injection prevention** - All user and finding data passes through `esc()` before DOCX XML embedding.
- **Path canonicalisation** - All export file paths are canonicalised to prevent directory traversal.
- **Atomic session writes** - Autosave uses `Files.move(ATOMIC_MOVE)`. Partial writes on crash are impossible.
- **Active scan cap** - Hard limit of 500 targets per scan session to prevent runaway scans on large sites.
- **No network calls from passive scanner** - `IHttpListener` observes proxy traffic only; the passive scanner never initiates a request.

---

## Building Against the Real Burp API

For CI pipelines or production builds, swap the local stubs with the official Burp Extender API:

```xml
<!-- pom.xml -->
<dependency>
    <groupId>net.portswigger.burp.extender</groupId>
    <artifactId>burp-extender-api</artifactId>
    <version>2.3</version>
    <scope>provided</scope>
</dependency>
```

Or fetch it directly:

```bash
mvn dependency:get -Dartifact=net.portswigger.burp.extender:burp-extender-api:2.3:jar
```

---

## Community vs Professional

| Feature | Community Edition | Professional |
|---|:---:|:---:|
| Passive scanning (all 13 checkers) | ✅ | ✅ |
| Active scanning (all 24 probes) | ✅ | ✅ |
| WAF evasion (30+ variants) | ✅ | ✅ |
| OOB detection via Interactsh | ✅ | ✅ |
| OOB detection via Burp Collaborator | ❌ | ✅ |
| PDF / DOCX / CSV export | ✅ | ✅ |
| CVSS 4.0 scoring | ✅ | ✅ |
| Scan checkpoints + resume | ✅ | ✅ |
| Autosave sessions | ✅ | ✅ |
| Scan Diff export | ✅ | ✅ |
| Crawler (JS paths, HAL links, forms) | ✅ | ✅ |

> BurpMax is designed to close the gap between Community and Professional. The only capability that remains Pro-exclusive is Burp Collaborator integration. Interactsh covers the same OOB use cases for free.

---

## Disclaimer

BurpMax is intended exclusively for use by security professionals on systems they are **explicitly authorised to test**. Unauthorised scanning or exploitation of systems you do not own, or for which you do not have written permission, is illegal under the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act (CMA), and equivalent laws worldwide.

The author and contributors accept no liability for misuse, damage, or legal consequences arising from the use of this tool.

---

## License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for the full text.

---

<div align="center">

Developed by **Omkar Mirkute**

*If BurpMax saved you time on an engagement, consider leaving a ⭐. It helps others find the tool.*

</div>
