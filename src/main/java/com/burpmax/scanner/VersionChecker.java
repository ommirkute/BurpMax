package com.burpmax.scanner;

import java.util.*;
import java.util.regex.*;

import static com.burpmax.model.Finding.*;

/**
 * Detects outdated, vulnerable, or version-disclosing libraries, frameworks,
 * and server software from both response headers and body content.
 *
 * Detection domains:
 *
 *   1. Frontend JavaScript libraries    — jQuery, jQuery UI, Bootstrap, Lodash,
 *                                         Vue 2.x/3.x, AngularJS, Moment.js,
 *                                         Handlebars, Underscore, React, Axios,
 *                                         Alpine.js, Knockout.js
 *
 *   2. Server-side frameworks           — Spring Boot (actuator), Django (error page),
 *                                         Laravel (Whoops page), Ruby on Rails (error page),
 *                                         Apache Struts
 *
 *   3. Web servers (headers)            — nginx, Apache httpd, Microsoft IIS,
 *                                         Apache Tomcat, Jetty
 *
 *   4. Runtime environments (headers)   — PHP (X-Powered-By), ASP.NET (X-AspNet-Version),
 *                                         ASP.NET MVC (X-AspNetMvc-Version)
 *
 *   5. Framework disclosure (headers)   — Express.js, Next.js
 *
 *   6. CMS platforms                    — WordPress (asset query params + meta tag),
 *                                         Joomla (meta tag + X-Content-Encoded-By),
 *                                         Drupal (X-Drupal-Cache header + body),
 *                                         Magento
 *
 *   7. Database error pages (body)      — MySQL, PostgreSQL, MongoDB
 *
 *   8. Package manifests (body)         — Exposed package.json, composer.json
 *
 * Severity model:
 *   HIGH    — package manifest exposed (full dependency map to attackers)
 *   MEDIUM  — known CVE in detected version, or EoL framework
 *   LOW     — version disclosure only (no specific CVE tied to version)
 *
 * False-positive controls:
 *   - Header checks use exact lowercased header names — no body scanning for header values
 *   - Body library checks require a loading-context signal (src=, href=, import, require())
 *   - SRI integrity= attribute on the same tag suppresses JS library findings
 *   - Documentation context (<code>, <pre>, changelog, <!--) suppresses body matches
 *   - Version strings must match digit.digit format — bare keyword matches are rejected
 *   - Per-name deduplication: only the first match per library name fires
 */
public class VersionChecker {

    // ─────────────────────────────────────────────────────────────────────────
    // RECORD TYPES
    // ─────────────────────────────────────────────────────────────────────────

    /** Describes a library detected from the response body. */
    private record LibDef(
        String  name,
        Pattern pattern,
        int[]   safeMin,            // first SAFE version - anything strictly below is flagged
                                    // null → flag any detected version (disclosure only)
        String  cwe,
        String  severity,
        String  finding,            // {VERSION} substituted with detected string
        boolean requireLoadingCtx   // true → body match only fires inside a loading context
    ) {}

    /** Describes a version pattern expected in a specific response header. */
    private record HeaderDef(
        String  headerName,         // exact lowercased header name
        Pattern versionPattern,     // regex with at least one capture group = version string
        int[]   safeMin,            // null → any detected value is a disclosure finding
        String  name,               // display name for dedup and title
        String  cwe,
        String  severity,
        String  findingTemplate,    // {VERSION} substituted
        String  remediation
    ) {}

    /** Describes a version/error pattern expected anywhere in the response body. */
    private record BodyPattern(
        String  name,
        Pattern pattern,
        String  cwe,
        String  severity,
        String  finding,            // {VERSION} substituted
        String  remediation
    ) {}

    // ─────────────────────────────────────────────────────────────────────────
    // BODY LIBRARY DEFINITIONS
    // ─────────────────────────────────────────────────────────────────────────

    private static final List<LibDef> BODY_LIBS = List.of(

        // ── jQuery ────────────────────────────────────────────────────────────
        new LibDef("jQuery",
            Pattern.compile("jquery[.\\-/](\\d+\\.\\d+\\.\\d+)", Pattern.CASE_INSENSITIVE),
            new int[]{3, 7, 0}, "CWE-1035", SEV_MEDIUM,
            "jQuery {VERSION} is outdated. Versions below 3.5.0 contain DOM-based XSS via " +
            ".html(), .append(), and related methods when they receive attacker-controlled " +
            "input (CVE-2020-11022, CVE-2020-11023). Versions 3.5.x–3.6.x patch the XSS " +
            "but have prototype pollution exposure. Update to jQuery 3.7.x.",
            true),

        // ── jQuery UI ─────────────────────────────────────────────────────────
        new LibDef("jQuery UI",
            Pattern.compile("jquery[\\-.]ui[.\\-/](\\d+\\.\\d+\\.\\d+)", Pattern.CASE_INSENSITIVE),
            new int[]{1, 13, 3}, "CWE-1035", SEV_MEDIUM,
            "jQuery UI {VERSION} is outdated. Versions below 1.13.0 contain XSS in the " +
            "checkboxradio and tooltip widgets (CVE-2021-41182, CVE-2021-41183, CVE-2021-41184). " +
            "Versions below 1.13.3 have additional XSS via the dialog widget. Update to 1.13.3.",
            true),

        // ── Bootstrap ─────────────────────────────────────────────────────────
        new LibDef("Bootstrap",
            Pattern.compile("bootstrap[.\\-/](\\d+\\.\\d+\\.\\d+)", Pattern.CASE_INSENSITIVE),
            new int[]{5, 3, 3}, "CWE-1035", SEV_MEDIUM,
            "Bootstrap {VERSION} is outdated. Bootstrap 3.x and 4.x are End-of-Life and have " +
            "received no security patches since 2022. Versions below 4.3.1 contain XSS in " +
            "data-template, data-content, and data-title attributes (CVE-2019-8331). " +
            "Bootstrap 4.x also has prototype pollution vectors. Update to Bootstrap 5.3.3.",
            true),

        // ── Lodash ────────────────────────────────────────────────────────────
        new LibDef("Lodash",
            Pattern.compile("lodash[.\\-/](\\d+\\.\\d+\\.\\d+)", Pattern.CASE_INSENSITIVE),
            new int[]{4, 17, 21}, "CWE-1035", SEV_MEDIUM,
            "Lodash {VERSION} is outdated. Versions below 4.17.21 contain prototype pollution " +
            "via _.merge(), _.mergeWith(), _.defaultsDeep(), and _.template() " +
            "(CVE-2021-23337, CVE-2020-8203). In Node.js server contexts this can escalate " +
            "to Remote Code Execution. Update to 4.17.21.",
            true),

        // ── Moment.js ─────────────────────────────────────────────────────────
        new LibDef("Moment.js",
            Pattern.compile("moment[.\\-/](\\d+\\.\\d+\\.\\d+)", Pattern.CASE_INSENSITIVE),
            new int[]{2, 29, 4}, "CWE-1035", SEV_MEDIUM,
            "Moment.js {VERSION} is outdated. Versions below 2.29.4 contain a Regular Expression " +
            "Denial of Service (ReDoS) vulnerability exploitable via crafted date strings " +
            "(CVE-2022-24785). Moment.js is also in maintenance mode - no new features will be " +
            "added. Migrate to date-fns (≥2.30) or Luxon (≥3.x) for new projects.",
            true),

        // ── Handlebars ────────────────────────────────────────────────────────
        new LibDef("Handlebars",
            Pattern.compile("handlebars[.\\-/](\\d+\\.\\d+\\.\\d+)", Pattern.CASE_INSENSITIVE),
            new int[]{4, 7, 7}, "CWE-1035", SEV_MEDIUM,
            "Handlebars.js {VERSION} is outdated. Versions below 4.7.7 contain prototype pollution " +
            "leading to Remote Code Execution when user-supplied template strings are compiled " +
            "server-side (CVE-2021-23369, CVE-2021-23383). Update to 4.7.7 and never compile " +
            "user-controlled templates.",
            true),

        // ── Underscore.js ─────────────────────────────────────────────────────
        new LibDef("Underscore.js",
            Pattern.compile("underscore[.\\-/](\\d+\\.\\d+\\.\\d+)", Pattern.CASE_INSENSITIVE),
            new int[]{1, 13, 2}, "CWE-1035", SEV_MEDIUM,
            "Underscore.js {VERSION} is outdated. Versions below 1.13.0 contain prototype " +
            "pollution via _.extend(), _.extendOwn(), and _.defaults() (CVE-2021-23358). " +
            "Update to 1.13.2 or later.",
            true),

        // ── Vue.js 2.x (EOL) ──────────────────────────────────────────────────
        new LibDef("Vue.js 2.x",
            Pattern.compile("vue[.\\-/](2\\.\\d+\\.\\d+)", Pattern.CASE_INSENSITIVE),
            new int[]{3, 0, 0}, "CWE-1035", SEV_MEDIUM,
            "Vue.js 2.x ({VERSION}) reached End-of-Life in December 2023. No further security " +
            "patches will be provided. Vue 2's v-html directive is a persistent XSS risk if any " +
            "user-controlled content is ever passed to it. Migrate to Vue 3.4.x. While migrating: " +
            "deploy a strict CSP (script-src with nonces) and audit all v-html, $createElement, " +
            "and $compile() usages for user-controlled input.",
            true),

        // ── Vue.js 3.x (outdated) ─────────────────────────────────────────────
        new LibDef("Vue.js 3.x",
            Pattern.compile("vue[.\\-/](3\\.\\d+\\.\\d+)", Pattern.CASE_INSENSITIVE),
            new int[]{3, 4, 0}, "CWE-1035", SEV_MEDIUM,
            "Vue.js 3.x ({VERSION}) is outdated. Versions below 3.4.0 contain XSS via the " +
            "v-html directive under Server-Side Rendering (CVE-2023-49083). Update to 3.4.x.",
            true),

        // ── AngularJS 1.x (EOL) ───────────────────────────────────────────────
        new LibDef("AngularJS 1.x",
            Pattern.compile("angular(?:js)?[.\\-/](1\\.\\d+\\.\\d+)", Pattern.CASE_INSENSITIVE),
            new int[]{2, 0, 0}, "CWE-1035", SEV_MEDIUM,
            "AngularJS 1.x ({VERSION}) reached End-of-Life in December 2021. No security patches " +
            "are provided. Multiple sandbox escapes enabling XSS are known (CVE-2019-14863, " +
            "CVE-2023-26116, CVE-2023-26117, CVE-2023-26118). Migrate to Angular 17+. While " +
            "migrating: enable strict CSP with nonces; audit all $sce.trustAsHtml(), $compile(), " +
            "and ng-bind-html usages for user-controlled input.",
            true),

        // ── React ─────────────────────────────────────────────────────────────
        new LibDef("React",
            Pattern.compile("react[.\\-/](\\d+\\.\\d+\\.\\d+)\\.(?:min\\.)?js", Pattern.CASE_INSENSITIVE),
            new int[]{18, 3, 0}, "CWE-200", SEV_LOW,
            "React {VERSION} version is disclosed via static asset filenames. React 16.x and " +
            "17.x are no longer receiving feature updates. Versions below 16.9.0 contain a timing " +
            "attack vulnerability (CVE-2019-11299). Embedding version numbers in filenames assists " +
            "attackers in identifying CVE-specific targets. Configure your bundler to use " +
            "content-addressed hashes ([contenthash]) and update to React 18.3.x.",
            true),

        // ── Axios ─────────────────────────────────────────────────────────────
        new LibDef("Axios",
            Pattern.compile("axios[.\\-/](\\d+\\.\\d+\\.\\d+)", Pattern.CASE_INSENSITIVE),
            new int[]{1, 6, 0}, "CWE-1035", SEV_MEDIUM,
            "Axios {VERSION} is outdated. Versions below 1.6.0 contain an SSRF vulnerability " +
            "where crafted URLs bypass origin protections (CVE-2023-45857) and a prototype " +
            "pollution issue. Update to Axios 1.6.0 or later.",
            true),

        // ── Alpine.js ─────────────────────────────────────────────────────────
        new LibDef("Alpine.js",
            Pattern.compile("alpinejs[.\\-/](\\d+\\.\\d+\\.\\d+)", Pattern.CASE_INSENSITIVE),
            new int[]{3, 13, 0}, "CWE-1035", SEV_MEDIUM,
            "Alpine.js {VERSION} is outdated. Versions below 3.13.0 contain an XSS vulnerability " +
            "when x-html receives user-controlled content without sanitisation. Update to 3.13.x " +
            "and treat x-html with the same caution as setting innerHTML directly.",
            true),

        // ── Knockout.js ───────────────────────────────────────────────────────
        new LibDef("Knockout.js",
            Pattern.compile("knockout[.\\-/](\\d+\\.\\d+\\.\\d+)", Pattern.CASE_INSENSITIVE),
            new int[]{3, 5, 1}, "CWE-1035", SEV_MEDIUM,
            "Knockout.js {VERSION} is outdated. Versions below 3.5.1 contain prototype pollution. " +
            "Knockout.js is also in low-maintenance mode. Update to 3.5.1 and consider migrating " +
            "to an actively maintained framework for new development.",
            true),

        // ── WordPress (asset query parameter) ────────────────────────────────
        new LibDef("WordPress",
            Pattern.compile("wp-(?:includes|content)/[^\"'\\s]*\\?ver=([\\d.]+)", Pattern.CASE_INSENSITIVE),
            new int[]{6, 7, 0}, "CWE-1035", SEV_MEDIUM,
            "WordPress {VERSION} is detected (outdated). WordPress releases frequent security " +
            "patches; versions below 6.7 lack fixes for authenticated XSS, SQL injection, and " +
            "path traversal vulnerabilities. Automated exploit campaigns actively target outdated " +
            "WordPress installations. Enable automatic background updates " +
            "(define('WP_AUTO_UPDATE_CORE', true)), keep all plugins and themes updated, and " +
            "remove version disclosure from asset URLs: remove_action('wp_head', 'wp_generator').",
            false),

        // ── WordPress generator meta tag ──────────────────────────────────────
        new LibDef("WordPress (meta tag)",
            Pattern.compile("<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']WordPress ([\\d.]+)[\"']",
                Pattern.CASE_INSENSITIVE),
            new int[]{6, 7, 0}, "CWE-200", SEV_LOW,
            "WordPress {VERSION} version is disclosed via the HTML generator meta tag. This " +
            "assists targeted exploitation. Remove with: remove_action('wp_head', 'wp_generator') " +
            "in functions.php. Update to WordPress 6.7+.",
            false),

        // ── Apache Struts ─────────────────────────────────────────────────────
        new LibDef("Apache Struts",
            Pattern.compile("Apache Struts[/ ](\\d+\\.\\d+\\.\\d+)", Pattern.CASE_INSENSITIVE),
            new int[]{2, 5, 33}, "CWE-1035", SEV_MEDIUM,
            "Apache Struts {VERSION} is outdated. Versions below 2.5.33 contain a critical " +
            "Remote Code Execution vulnerability via file upload path traversal (CVE-2023-50164). " +
            "Struts 2 has an extensive CVE history - the Equifax breach (CVE-2017-5638) exploited " +
            "a Struts RCE. Update to the latest Struts 6.x release immediately.",
            false),

        // ── Spring Boot actuator info ─────────────────────────────────────────
        new LibDef("Spring Boot",
            Pattern.compile("\"spring-boot\"\\s*:\\s*\\{[^}]*\"version\"\\s*:\\s*\"([\\d.]+)\"",
                Pattern.CASE_INSENSITIVE),
            new int[]{3, 3, 0}, "CWE-200", SEV_MEDIUM,
            "Spring Boot {VERSION} version is exposed via the /actuator/info endpoint. " +
            "Version exposure enables targeted exploitation of known CVEs. Restrict actuator " +
            "endpoints: management.endpoints.web.exposure.include=health. Require authentication: " +
            "management.endpoint.health.show-details=when-authorized. Update to Spring Boot 3.3.x.",
            false),

        // ── Django debug error page ───────────────────────────────────────────
        new LibDef("Django",
            Pattern.compile("Django Version:\\s*([\\d.]+)", Pattern.CASE_INSENSITIVE),
            new int[]{4, 2, 0}, "CWE-200", SEV_MEDIUM,
            "Django {VERSION} is exposed via a debug error page (DEBUG=True). This is a critical " +
            "misconfiguration: the Django technical error page reveals full stack traces, SQL " +
            "queries, local variable values, and settings (including SECRET_KEY). Set DEBUG=False " +
            "in production. Django versions below 4.2 are End-of-Life. Update to Django 5.0+.",
            false),

        // ── Laravel Whoops error page ─────────────────────────────────────────
        new LibDef("Laravel",
            Pattern.compile("(?:Whoops!|Illuminate\\\\)[\\s\\S]{0,100}?Laravel[\\s\\S]{0,50}?([\\d]+\\.[\\d]+)",
                Pattern.CASE_INSENSITIVE),
            new int[]{10, 0, 0}, "CWE-200", SEV_MEDIUM,
            "Laravel {VERSION} debug error page (Whoops) is exposed. Whoops reveals full stack " +
            "traces, file paths, environment variables (.env contents), and application code. " +
            "Set APP_DEBUG=false and APP_ENV=production in .env. Update to Laravel 11.x.",
            false),

        // ── Ruby on Rails error page ──────────────────────────────────────────
        new LibDef("Ruby on Rails",
            Pattern.compile("(?:Action(?:Controller|Dispatch|View)|ActiveRecord)[^<]{0,60}Exception",
                Pattern.CASE_INSENSITIVE),
            null, "CWE-200", SEV_MEDIUM,
            "A Ruby on Rails debug error page was detected. Rails development-mode error pages " +
            "expose full stack traces, request parameters, session data, and environment variables " +
            "including credentials. Set config.consider_all_requests_local = false in " +
            "config/environments/production.rb and ensure RAILS_ENV=production.",
            false),

        // ── Joomla generator meta tag ─────────────────────────────────────────
        new LibDef("Joomla",
            Pattern.compile("<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']Joomla[!]?\\s*([\\d.]*)[\"']",
                Pattern.CASE_INSENSITIVE),
            new int[]{5, 1, 0}, "CWE-1035", SEV_MEDIUM,
            "Joomla {VERSION} is detected via the HTML generator meta tag. Versions below 5.x " +
            "contain SQL injection and authentication bypass vulnerabilities. Remove the tag: " +
            "System → Global Configuration → Metadata Settings → Show Joomla Version → No. " +
            "Update to Joomla 5.1+.",
            false),

        // ── Magento ───────────────────────────────────────────────────────────
        new LibDef("Magento",
            Pattern.compile("(?:Magento[/ ]|mage/|Mage\\.Cookies)[^\"'\\s>]{0,30}?([\\d]+\\.[\\d]+)",
                Pattern.CASE_INSENSITIVE),
            new int[]{2, 4, 7}, "CWE-1035", SEV_MEDIUM,
            "Magento/Adobe Commerce {VERSION} is detected. Versions below 2.4.7 contain critical " +
            "vulnerabilities including unauthenticated RCE (CVE-2024-34102 - CosmicSting XXE), " +
            "SQL injection, and path traversal. Only the latest two 2.4.x patch releases are " +
            "supported. Update to 2.4.7-p2+ and apply all Adobe Security Bulletins immediately.",
            false),

        // ── Exposed package.json ──────────────────────────────────────────────
        new LibDef("Exposed package.json",
            Pattern.compile("\"name\"\\s*:\\s*\"[^\"]+\"[\\s\\S]{0,200}\"version\"\\s*:\\s*\"[\\d.]+\"[\\s\\S]{0,200}\"dependencies\"\\s*:",
                Pattern.CASE_INSENSITIVE),
            null, "CWE-538", SEV_HIGH,
            "A package.json file is publicly accessible. It exposes the full npm dependency tree " +
            "with exact version numbers, allowing attackers to enumerate vulnerable dependencies " +
            "without active probing. Remove from the web root: deny all; for package\\.json in " +
            "web server config. This file should never be served by a production web server.",
            false),

        // ── Exposed composer.json ─────────────────────────────────────────────
        new LibDef("Exposed composer.json",
            Pattern.compile("\"require\"\\s*:\\s*\\{[^}]{20,}\"php\"\\s*:", Pattern.CASE_INSENSITIVE),
            null, "CWE-538", SEV_HIGH,
            "A composer.json file is publicly accessible. It exposes the PHP dependency tree " +
            "with exact package versions and PHP version constraints. Remove from web root and " +
            "deny access: location ~* composer\\.json { deny all; } in nginx, or " +
            "<Files composer.json> Deny from all </Files> in Apache.",
            false)
    );

    // ─────────────────────────────────────────────────────────────────────────
    // HEADER DEFINITIONS
    // ─────────────────────────────────────────────────────────────────────────

    private static final List<HeaderDef> HEADER_DEFS = List.of(

        // ── nginx ─────────────────────────────────────────────────────────────
        new HeaderDef("server",
            Pattern.compile("nginx/(\\d+\\.\\d+\\.\\d+)", Pattern.CASE_INSENSITIVE),
            new int[]{1, 26, 0},
            "nginx", "CWE-200", SEV_MEDIUM,
            "nginx {VERSION} is outdated. Versions below 1.24.0 are vulnerable to HTTP/2 Rapid " +
            "Reset DoS (CVE-2023-44487). Versions below 1.26.0 lack the fix for CVE-2024-7347 " +
            "(mp4 module OOB read). Update to nginx 1.26.x (stable) or 1.27.x (mainline). " +
            "Suppress version disclosure with server_tokens off; in nginx.conf.",
            "- Update nginx to 1.26.x stable or 1.27.x mainline\n" +
            "- Set server_tokens off; in http {} block in nginx.conf\n" +
            "- Subscribe to nginx security advisories: nginx.org/en/security_advisories.html"),

        // ── Apache httpd ──────────────────────────────────────────────────────
        new HeaderDef("server",
            Pattern.compile("Apache/(\\d+\\.\\d+\\.\\d+)", Pattern.CASE_INSENSITIVE),
            new int[]{2, 4, 62},
            "Apache httpd", "CWE-200", SEV_MEDIUM,
            "Apache httpd {VERSION} is outdated. Apache 2.4 below 2.4.62 contains source code " +
            "disclosure via mod_rewrite (CVE-2024-38475), HTTP/2 DoS (CVE-2024-27316), and SSRF " +
            "via mod_proxy. Apache 2.2.x is End-of-Life since 2018. Update to Apache 2.4.62+.",
            "- Update to Apache httpd 2.4.62 or later\n" +
            "- Set ServerTokens Prod and ServerSignature Off in httpd.conf\n" +
            "- Subscribe to advisories: httpd.apache.org/security/vulnerabilities_24.html"),

        // ── Microsoft IIS ─────────────────────────────────────────────────────
        new HeaderDef("server",
            Pattern.compile("Microsoft-IIS/(\\d+\\.\\d+)", Pattern.CASE_INSENSITIVE),
            new int[]{10, 0},
            "Microsoft IIS", "CWE-200", SEV_LOW,
            "Microsoft IIS {VERSION} version is disclosed. IIS versions below 10.0 are " +
            "End-of-Life. IIS 10.0 (Windows Server 2016/2019/2022) is the current supported " +
            "release. Remove the Server header to prevent version disclosure.",
            "- Remove Server header: URL Rewrite outbound rule to remove Server header\n" +
            "- Upgrade to Windows Server 2022 and IIS 10.0 if on older versions\n" +
            "- Apply all Windows cumulative updates via Windows Update"),

        // ── Apache Tomcat ─────────────────────────────────────────────────────
        new HeaderDef("server",
            Pattern.compile("Apache-Coyote/(\\d+\\.\\d+)|Apache Tomcat/(\\d+\\.\\d+\\.\\d+)",
                Pattern.CASE_INSENSITIVE),
            new int[]{10, 1, 24},
            "Apache Tomcat", "CWE-200", SEV_MEDIUM,
            "Apache Tomcat {VERSION} is outdated or disclosed. Tomcat versions below 9.0.89 and " +
            "10.1.24 contain partial PUT request handling vulnerabilities enabling remote code " +
            "execution (CVE-2024-50379 - partial PUT RCE) and HTTP request smuggling. Tomcat 8.x " +
            "is End-of-Life. Update to Tomcat 10.1.24+ or 11.0.x. Remove Server header in " +
            "server.xml: <Connector server=\"\" xpoweredBy=\"false\" />",
            "- Update to Apache Tomcat 10.1.24+ (or 11.0.x for Jakarta EE 11)\n" +
            "- Set server=\"\" and xpoweredBy=\"false\" on Connector elements in server.xml\n" +
            "- Subscribe to advisories: tomcat.apache.org/security.html"),

        // ── Jetty ─────────────────────────────────────────────────────────────
        new HeaderDef("server",
            Pattern.compile("Jetty/(\\d+\\.\\d+\\.\\d+)", Pattern.CASE_INSENSITIVE),
            new int[]{12, 0, 9},
            "Jetty", "CWE-200", SEV_MEDIUM,
            "Jetty {VERSION} is disclosed. Jetty versions below 12.0.9 and 11.0.21 contain " +
            "an HTTP/2 DoS vulnerability (CVE-2024-22201) and null pointer dereference issues. " +
            "Update to Jetty 12.0.9+ and remove the Server header via SecuredResponseCustomizer " +
            "in jetty.xml.",
            "- Update to Jetty 12.0.9 or latest supported branch\n" +
            "- Remove Server header: add SecuredResponseCustomizer to jetty.xml\n" +
            "- See eclipse.org/jetty/documentation for configuration reference"),

        // ── PHP via X-Powered-By ──────────────────────────────────────────────
        new HeaderDef("x-powered-by",
            Pattern.compile("PHP/(\\d+\\.\\d+\\.\\d+)", Pattern.CASE_INSENSITIVE),
            new int[]{8, 3, 0},
            "PHP (X-Powered-By)", "CWE-200", SEV_MEDIUM,
            "PHP {VERSION} is disclosed via X-Powered-By. PHP 8.1.x reached End-of-Life in " +
            "December 2024 and receives no further security patches. PHP 8.2 below 8.2.22 and " +
            "PHP 8.3 below 8.3.10 contain memory corruption vulnerabilities. Update to PHP 8.3.x " +
            "and set expose_php = Off in php.ini to suppress the header.",
            "- Update PHP to 8.3.x (8.1.x is End-of-Life)\n" +
            "- Set expose_php = Off in php.ini\n" +
            "- Subscribe to PHP security releases: php.net/security"),

        // ── PHP via Server header ─────────────────────────────────────────────
        new HeaderDef("server",
            Pattern.compile("PHP/(\\d+\\.\\d+\\.\\d+)", Pattern.CASE_INSENSITIVE),
            new int[]{8, 3, 0},
            "PHP (Server header)", "CWE-200", SEV_MEDIUM,
            "PHP {VERSION} version appears in the Server header - an unusual configuration that " +
            "indicates non-standard server setup. PHP 8.1.x is End-of-Life (December 2024). " +
            "Update to PHP 8.3.x and set expose_php = Off in php.ini.",
            "- Set expose_php = Off in php.ini\n" +
            "- Update PHP to 8.3.x\n" +
            "- Investigate why PHP version appears in Server header (non-standard setup)"),

        // ── ASP.NET version ───────────────────────────────────────────────────
        new HeaderDef("x-aspnet-version",
            Pattern.compile("([\\d.]+)", Pattern.CASE_INSENSITIVE),
            null,
            "ASP.NET", "CWE-200", SEV_LOW,
            "ASP.NET version {VERSION} is disclosed via X-AspNet-Version. Version disclosure " +
            "enables targeted exploitation of .NET runtime CVEs.",
            "- Add <httpRuntime enableVersionHeader=\"false\" /> to web.config\n" +
            "- Or remove via IIS HTTP Response Headers module\n" +
            "- Ensure .NET is updated to the latest LTS (dotnet.microsoft.com/download)"),

        // ── ASP.NET MVC version ───────────────────────────────────────────────
        new HeaderDef("x-aspnetmvc-version",
            Pattern.compile("([\\d.]+)", Pattern.CASE_INSENSITIVE),
            null,
            "ASP.NET MVC", "CWE-200", SEV_LOW,
            "ASP.NET MVC version {VERSION} is disclosed via X-AspNetMvc-Version.",
            "- Add to Global.asax Application_Start: MvcHandler.DisableMvcResponseHeader = true;\n" +
            "- Or suppress via web.config outbound rule to remove the header"),

        // ── Express.js ────────────────────────────────────────────────────────
        new HeaderDef("x-powered-by",
            Pattern.compile("(Express)", Pattern.CASE_INSENSITIVE),
            null,
            "Express.js", "CWE-200", SEV_LOW,
            "Express.js framework is disclosed via X-Powered-By. Framework disclosure assists " +
            "in targeted exploitation of Express-specific CVEs.",
            "- Disable: app.disable('x-powered-by'); in your app entry point\n" +
            "- Or use Helmet: app.use(require('helmet')()) - disables X-Powered-By among others\n" +
            "- Check expressjs.com/en/advanced/security-updates.html for current CVEs"),

        // ── Next.js ───────────────────────────────────────────────────────────
        new HeaderDef("x-powered-by",
            Pattern.compile("(Next\\.js)", Pattern.CASE_INSENSITIVE),
            null,
            "Next.js", "CWE-200", SEV_LOW,
            "Next.js framework is disclosed via X-Powered-By. Next.js versions below 13.5.x " +
            "contain SSRF (CVE-2024-34351) and path traversal vulnerabilities. Ensure Next.js " +
            "is updated to 14.x+ and disable the header in next.config.js: poweredByHeader: false.",
            "- Disable in next.config.js: module.exports = { poweredByHeader: false }\n" +
            "- Update Next.js to 14.x - CVE-2024-34351 SSRF affects 13.x\n" +
            "- Subscribe: github.com/vercel/next.js/security/advisories"),

        // ── WordPress via X-Generator ─────────────────────────────────────────
        new HeaderDef("x-generator",
            Pattern.compile("WordPress ([\\d.]+)", Pattern.CASE_INSENSITIVE),
            new int[]{6, 7, 0},
            "WordPress (X-Generator header)", "CWE-200", SEV_LOW,
            "WordPress {VERSION} is disclosed via X-Generator response header. Update to 6.7+ " +
            "and suppress the header: remove_action('wp_head', 'wp_generator') in functions.php.",
            "- Add to functions.php: remove_action('wp_head', 'wp_generator');\n" +
            "- Update WordPress to 6.7 or later\n" +
            "- Enable automatic background security updates"),

        // ── Drupal via X-Drupal-Cache ─────────────────────────────────────────
        new HeaderDef("x-drupal-cache",
            Pattern.compile("(.+)", Pattern.CASE_INSENSITIVE),
            null,
            "Drupal (X-Drupal-Cache)", "CWE-200", SEV_LOW,
            "Drupal CMS is detected via X-Drupal-Cache. CMS disclosure enables targeted " +
            "exploitation. Drupal has critical CVE history: Drupalgeddon (CVE-2018-7600, " +
            "CVE-2018-7602). Suppress this header and keep Drupal updated to the latest 10.x.",
            "- Use the HTTP Response Headers module to suppress Drupal-specific headers\n" +
            "- Update to the latest Drupal 10.x release\n" +
            "- Remove CHANGELOG.txt from web root (discloses version)\n" +
            "- Subscribe: drupal.org/security"),

        // ── Drupal via X-Drupal-Dynamic-Cache ────────────────────────────────
        new HeaderDef("x-drupal-dynamic-cache",
            Pattern.compile("(.+)", Pattern.CASE_INSENSITIVE),
            null,
            "Drupal (X-Drupal-Dynamic-Cache)", "CWE-200", SEV_LOW,
            "Drupal CMS is detected via X-Drupal-Dynamic-Cache header. See X-Drupal-Cache finding.",
            "- Suppress Drupal headers with the HTTP Response Headers module\n" +
            "- Update to the latest Drupal 10.x release"),

        // ── Joomla via X-Content-Encoded-By ──────────────────────────────────
        new HeaderDef("x-content-encoded-by",
            Pattern.compile("Joomla[!]?\\s*([\\d.]*)", Pattern.CASE_INSENSITIVE),
            new int[]{5, 1, 0},
            "Joomla (X-Content-Encoded-By)", "CWE-1035", SEV_MEDIUM,
            "Joomla {VERSION} is detected via X-Content-Encoded-By. Joomla versions below 5.x " +
            "contain SQL injection and authentication bypass vulnerabilities. Remove header via " +
            "System → Global Configuration → Server → Response Headers. Update to 5.1+.",
            "- Remove header: System → Global Config → Server → Response Headers\n" +
            "- Update Joomla to 5.1 or later\n" +
            "- Subscribe: developer.joomla.org/security-centre.html")
    );

    // ─────────────────────────────────────────────────────────────────────────
    // BODY PATTERNS (database/runtime error disclosures)
    // ─────────────────────────────────────────────────────────────────────────

    private static final List<BodyPattern> BODY_PATTERNS = List.of(

        new BodyPattern("MySQL version disclosure",
            Pattern.compile("mysql\\s+(\\d+\\.\\d+\\.\\d+)", Pattern.CASE_INSENSITIVE),
            "CWE-200", SEV_LOW,
            "MySQL version {VERSION} is disclosed in a database error response. Attackers use " +
            "version data to identify applicable CVEs and plan targeted database attacks.",
            "- Catch all database exceptions at the ORM/service layer before they reach HTTP responses\n" +
            "- Implement a global exception handler returning only generic error codes\n" +
            "- Disable client-visible MySQL error output; write to server-side log only\n" +
            "- Java/Spring: use @ControllerAdvice to intercept and suppress all SQLException messages"),

        new BodyPattern("PostgreSQL version disclosure",
            Pattern.compile("PostgreSQL\\s+(\\d+\\.\\d+)", Pattern.CASE_INSENSITIVE),
            "CWE-200", SEV_LOW,
            "PostgreSQL version {VERSION} is disclosed in a database error response.",
            "- Catch all database exceptions before they propagate to HTTP responses\n" +
            "- Return only generic 500 status codes to clients on database errors\n" +
            "- Configure log_destination to write to server-side files only"),

        new BodyPattern("MongoDB error disclosure",
            Pattern.compile("(?:MongoError|MongoServerError)[^<\\n]{0,80}?([\\d]+\\.[\\d]+\\.[\\d]+)",
                Pattern.CASE_INSENSITIVE),
            "CWE-200", SEV_LOW,
            "MongoDB error output with version {VERSION} is visible in the response. MongoDB " +
            "errors often include collection names, query structure, and internal paths.",
            "- Never propagate MongoDB driver errors to HTTP responses\n" +
            "- Catch MongoError/MongoServerError at the service layer; return generic 500\n" +
            "- Use NODE_ENV=production to suppress verbose error output in Express/Node.js apps"),

        new BodyPattern("PHP version disclosure (body)",
            Pattern.compile("PHP/(\\d+\\.\\d+\\.\\d+)", Pattern.CASE_INSENSITIVE),
            "CWE-200", SEV_LOW,
            "PHP version {VERSION} is disclosed in the response body (from an error page or " +
            "reflected header value). PHP 8.1.x is End-of-Life (December 2024).",
            "- Set expose_php = Off in php.ini\n" +
            "- Set display_errors = Off and log_errors = On\n" +
            "- Update PHP to 8.3.x"),

        new BodyPattern("ASP.NET version disclosure (body)",
            Pattern.compile("ASP\\.NET(?:\\s+Version:?)?[/ ](\\d+\\.\\d+\\.\\d+)", Pattern.CASE_INSENSITIVE),
            "CWE-200", SEV_LOW,
            "ASP.NET version {VERSION} is disclosed in the response body from an error page. " +
            "ASP.NET error pages in development mode expose version, stack traces, and source.",
            "- Set <customErrors mode=\"On\" /> in web.config for all error codes\n" +
            "- Set ASPNETCORE_ENVIRONMENT=Production in deployment environment\n" +
            "- Add <httpRuntime enableVersionHeader=\"false\" /> to web.config"),

        new BodyPattern("Drupal version disclosure (body)",
            Pattern.compile("Drupal\\s+(\\d+\\.\\d+(?:\\.\\d+)?)", Pattern.CASE_INSENSITIVE),
            "CWE-1035", SEV_MEDIUM,
            "Drupal version {VERSION} is disclosed in the response body. Outdated Drupal " +
            "installations are targeted by automated Drupalgeddon exploit campaigns " +
            "(CVE-2018-7600). Update to the latest Drupal 10.x release.",
            "- Update Drupal core to latest 10.x immediately\n" +
            "- Remove CHANGELOG.txt, README.txt, and INSTALL.txt from web root\n" +
            "- Subscribe to Drupal security advisories: drupal.org/security")
    );

    // ─────────────────────────────────────────────────────────────────────────
    // PUBLIC CHECK METHOD
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Check both response headers and body for version disclosures and
     * outdated/vulnerable library/framework/server detections.
     *
     * @param body        response body string (may be null or empty)
     * @param respHeaders lowercased response header map (may be null or empty)
     * @return            list of CheckResult findings (never null)
     */
    public static List<CheckResult> check(String body, Map<String, String> respHeaders) {
        List<CheckResult> results = new ArrayList<>();
        Set<String>       fired   = new HashSet<>();   // dedup by name

        if (respHeaders == null) respHeaders = Collections.emptyMap();

        // ── 1. Header-based detection ─────────────────────────────────────────
        for (HeaderDef hd : HEADER_DEFS) {
            if (fired.contains(hd.name())) continue;
            String hVal = respHeaders.getOrDefault(hd.headerName(), "");
            if (hVal.isEmpty()) continue;

            Matcher m = hd.versionPattern().matcher(hVal);
            if (!m.find()) continue;

            // Extract version from first non-null capture group
            String verStr = extractGroup(m);

            // If safeMin defined, only flag if below safe threshold
            if (hd.safeMin() != null && verStr != null && !verStr.isEmpty()) {
                int[] ver = parseVersion(verStr);
                if (ver == null || !isBelow(ver, hd.safeMin())) continue;
            }

            fired.add(hd.name());
            String displayVer = (verStr != null && !verStr.isEmpty()) ? verStr : hVal.trim();
            String finding = hd.findingTemplate().replace("{VERSION}", displayVer);
            results.add(new CheckResult(
                buildTitle(hd.name(), displayVer, hd.safeMin()),
                hd.severity(), finding,
                hd.headerName() + ": " + truncate(hVal, 120),
                hd.remediation(),
                hd.cwe()));
        }

        // ── 2. Body library detection ─────────────────────────────────────────
        if (body != null && !body.isEmpty()) {
            for (LibDef lib : BODY_LIBS) {
                if (fired.contains(lib.name())) continue;
                Matcher m = lib.pattern().matcher(body);
                if (!m.find()) continue;

                String verStr = extractGroup(m);
                if (verStr == null) verStr = "";

                // Version threshold check
                if (lib.safeMin() != null && !verStr.isEmpty()) {
                    int[] ver = parseVersion(verStr);
                    if (ver == null || !isBelow(ver, lib.safeMin())) continue;
                }

                // Loading context check (for JS library patterns)
                if (lib.requireLoadingCtx()) {
                    int matchStart = m.start();
                    String before = body.substring(Math.max(0, matchStart - 200), matchStart).toLowerCase();
                    String after  = body.substring(matchStart,
                                    Math.min(body.length(), matchStart + 300)).toLowerCase();

                    boolean inLoad = before.contains("<script") || before.contains("src=")
                            || before.contains("href=") || before.contains("require(")
                            || before.contains("import ") || before.contains("\"version\":")
                            || before.contains(".min.js") || before.contains(".bundle.")
                            || before.contains("dependencies") || after.contains(".min.js")
                            || after.contains(".bundle.");

                    boolean inDoc = before.contains("<code") || before.contains("<pre")
                            || before.contains("<!--") || before.contains("changelog")
                            || before.contains("release note") || before.contains("history");

                    if (!inLoad || inDoc) continue;

                    // SRI suppression: integrity= on same tag means version is pinned and verified
                    int closeTag = after.indexOf('>');
                    String withinTag = closeTag > 0 ? after.substring(0, closeTag) : after;
                    if (withinTag.contains("integrity=")) continue;
                }

                fired.add(lib.name());
                String finding = lib.finding().replace("{VERSION}", verStr.isEmpty() ? "detected" : verStr);
                String remediation = lib.safeMin() != null
                    ? "- Update " + lib.name() + " to the latest stable release immediately\n" +
                      "- Run: npm audit / pip-audit / OWASP Dependency-Check\n" +
                      "- Enable automated dependency PRs: Dependabot or Renovate Bot\n" +
                      "- Use content-addressed filenames ([contenthash]) to obscure versions in URLs"
                    : "- Remove this file from the web root - it should never be served publicly\n" +
                      "- Deny access in web server config: deny all; for this file pattern\n" +
                      "- Audit deployment scripts to prevent configuration files reaching web root";

                results.add(new CheckResult(
                    buildTitle(lib.name(), verStr, lib.safeMin()),
                    lib.severity(), finding,
                    lib.name() + (verStr.isEmpty() ? "" : " " + verStr) + " detected in response.",
                    remediation,
                    lib.cwe()));
            }

            // ── 3. Database / runtime error page patterns ─────────────────────
            for (BodyPattern bp : BODY_PATTERNS) {
                if (fired.contains(bp.name())) continue;
                Matcher m = bp.pattern().matcher(body);
                if (!m.find()) continue;

                String verStr = extractGroup(m);
                fired.add(bp.name());

                String finding = bp.finding().replace("{VERSION}", verStr != null && !verStr.isEmpty()
                        ? verStr : "unknown");
                String title = (verStr != null && !verStr.isEmpty())
                        ? bp.name().replace(" (body)", "") + " (" + verStr + ")"
                        : bp.name();

                results.add(new CheckResult(
                    title, bp.severity(), finding,
                    bp.name() + (verStr != null ? " " + verStr : "") + " detected in response body.",
                    bp.remediation(),
                    bp.cwe()));
            }
        }

        return results;
    }

    /**
     * Legacy single-argument overload. Header-based checks will not run.
     * Retained for any caller that only has the body available.
     */
    public static List<CheckResult> check(String body) {
        return check(body, Collections.emptyMap());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PRIVATE HELPERS
    // ─────────────────────────────────────────────────────────────────────────

    /** Extract version string from first non-null capture group, or null. */
    private static String extractGroup(Matcher m) {
        for (int g = 1; g <= m.groupCount(); g++) {
            if (m.group(g) != null) return m.group(g);
        }
        return m.group();
    }

    /**
     * Parse a version string into an int[3] (major, minor, patch).
     * Handles 2-part ("1.18") and 3-part ("1.18.0") strings.
     */
    private static int[] parseVersion(String s) {
        if (s == null || s.isEmpty()) return null;
        try {
            String[] parts = s.split("\\.");
            return new int[]{
                Integer.parseInt(parts[0]),
                parts.length > 1 ? Integer.parseInt(parts[1]) : 0,
                parts.length > 2 ? Integer.parseInt(parts[2]) : 0
            };
        } catch (NumberFormatException e) { return null; }
    }

    /**
     * Returns true if {@code ver} is strictly below {@code safe}.
     * {@code safe} is the first version that is NOT vulnerable.
     */
    private static boolean isBelow(int[] ver, int[] safe) {
        int len = Math.min(ver.length, safe.length);
        for (int i = 0; i < len; i++) {
            if (ver[i] < safe[i]) return true;
            if (ver[i] > safe[i]) return false;
        }
        return false;   // equal - not below - not vulnerable
    }

    /** Build a display title for a finding. */
    private static String buildTitle(String name, String verStr, int[] safeMin) {
        if (safeMin == null || verStr == null || verStr.isEmpty()) {
            return name + " Detected (Version Disclosure)";
        }
        return "Outdated " + name + " Detected: " + verStr;
    }

    private static String truncate(String s, int n) {
        if (s == null) return "";
        return s.length() > n ? s.substring(0, n) + "…" : s;
    }
}
