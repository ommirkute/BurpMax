package com.burpmax.active;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.*;
import static com.burpmax.model.Finding.*;

/**
 * Smart Crawler probe. discovers sensitive endpoints by first fingerprinting
 * the server's technology stack from passive signals, then requesting paths
 * known to be sensitive ON THAT STACK. If no stack can be identified the
 * probe falls back to a small generic wordlist of paths exposed across most
 * web servers.
 *
 * Design goals (in order):
 *   1. PRECISION over recall. False positives are a maintenance burden for
 *      anyone running the tool. Every candidate path carries a content
 *      signature that the response body MUST match; signature is confirmed
 *      on a second request; soft-404/SPA catch-all bodies are filtered out.
 *   2. POLITENESS. One sweep per host per scan (host guard), capped at
 *      MAX_REQUESTS total HTTP calls per host. The standard inter-request
 *      delay configured on HttpSender already applies.
 *   3. ZERO OVERLAP with SensitiveFileProbe. That probe handles paths that
 *      are sensitive ON ANY web server (.git/config, .env, .DS_Store etc).
 *      This probe handles paths that are sensitive ONLY on specific stacks
 *      (Tomcat /manager/html, Jenkins /script, Actuator /env, etc.). When in
 *      doubt the path belongs in the more specific bucket here.
 *   4. NO SHARED STATE WITH PASSIVE SCANNER. We register every URL we hit
 *      via ActiveScanner.registerProbeUrl(...) so passive findings never
 *      fire on our probe-generated traffic.
 *
 * Fingerprinting rules apply in this priority:
 *   - Response headers (Server, X-Powered-By, X-AspNet-Version, Via, etc.)
 *   - Cookies (PHPSESSID, JSESSIONID, ASP.NET_SessionId, ci_session, ...)
 *   - Body markers (Generator meta tags, framework error pages, library URLs)
 * If two or more stacks fingerprint at once (common. e.g. Apache + PHP +
 * WordPress on the same host) ALL matching wordlists are merged.
 */
public class SmartCrawlerProbe {

    // Run-once-per-host guard. sibling to SensitiveFileProbe.SWEPT_HOSTS.
    // Thread-safe set: a host that is currently being swept by one target
    // thread must not be swept again by a parallel thread.
    private static final Set<String> SWEPT_HOSTS =
            java.util.concurrent.ConcurrentHashMap.newKeySet();

    /** Reset between scans. called by ActiveScanner.clearProbeUrls(). */
    public static void resetSweptHosts() { SWEPT_HOSTS.clear(); }

    // Hard cap on probe-generated requests per host. The candidate list may be
    // hundreds of paths long; the cap ensures any single host never spends more
    // than a bounded budget. Candidates are sorted by severity-priority before
    // probing so the most impactful paths are always exercised first within the
    // budget regardless of list size.
    private static final int MAX_REQUESTS = 120;

    // ── Candidate definition ──────────────────────────────────────────────────
    /**
     * @param path        absolute path to GET (always starts with '/')
     * @param signature   regex that MUST match the response body to confirm
     * @param name        short finding label
     * @param severity    finding severity
     * @param cwe         CWE id (538 = file/resource disclosure, 200 = info disclosure)
     * @param description detail text
     */
    private record Candidate(String path, Pattern signature, String name,
                             String severity, String cwe, String description) {}

    private static Pattern ci(String regex) {
        return Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
    }

    // ── Wordlists ─────────────────────────────────────────────────────────────
    // Each wordlist below is keyed by a technology tag. The fingerprinter
    // returns a set of tags, and the union of those wordlists is probed.

    /** Stack tag enum. Mirror these strings exactly in fingerprint() and lists. */
    private static final String T_GENERIC   = "generic";
    private static final String T_APACHE    = "apache";
    private static final String T_NGINX     = "nginx";
    private static final String T_IIS       = "iis";
    private static final String T_TOMCAT    = "tomcat";
    private static final String T_PHP       = "php";
    private static final String T_WORDPRESS = "wordpress";
    private static final String T_DRUPAL    = "drupal";
    private static final String T_JOOMLA    = "joomla";
    private static final String T_LARAVEL   = "laravel";
    private static final String T_DJANGO    = "django";
    private static final String T_RAILS     = "rails";
    private static final String T_SPRING    = "spring";
    private static final String T_NODEJS    = "nodejs";
    private static final String T_JENKINS   = "jenkins";
    private static final String T_GITLAB    = "gitlab";

    private static final Map<String, List<Candidate>> WORDLISTS = new LinkedHashMap<>();

    static {
        // ── Generic (used as fallback AND merged into every targeted sweep) ──
        // 500+ paths sourced from real-world disclosure patterns. Built via
        // signature-group expansion (see buildGenericWordlist) so the entries
        // share a small set of well-tested content-signature regexes. The
        // probe is capped at MAX_REQUESTS requests per host, with candidates
        // sorted Critical -> High -> Medium -> Low -> Info before sweeping,
        // so the highest-impact paths are always tested within budget.
        WORDLISTS.put(T_GENERIC, buildGenericWordlist());

        // ── Apache HTTP Server ──
        WORDLISTS.put(T_APACHE, List.of(
            new Candidate("/server-info",
                ci("(?i)Apache Server Information|<title>Server Information"),
                "Apache mod_info (server-info) exposed", SEV_HIGH, "CWE-200",
                "Apache mod_info is enabled and publicly reachable. It exposes the full server "
                + "configuration, loaded modules, and module-specific data."),
            new Candidate("/icons/",
                ci("(?i)Index of /icons|<title>Index of"),
                "Apache /icons/ directory listing enabled", SEV_LOW, "CWE-548",
                "Apache's default /icons/ directory has directory listing enabled. Restrict with "
                + "'Options -Indexes'."),
            new Candidate("/manual/",
                ci("(?i)Apache HTTP Server[^<]{0,80}Documentation"),
                "Apache documentation (/manual/) exposed", SEV_LOW, "CWE-200",
                "Apache's bundled documentation is exposed, confirming server version and revealing the "
                + "default install layout to attackers.")
        ));

        // ── nginx ──
        WORDLISTS.put(T_NGINX, List.of(
            new Candidate("/nginx_status",
                ci("(?i)Active connections|server accepts handled requests"),
                "nginx stub_status exposed", SEV_MEDIUM, "CWE-200",
                "nginx's stub_status module is publicly reachable, leaking connection counts, request "
                + "rates, and internal traffic patterns. Restrict to localhost or trusted IPs.")
        ));

        // ── IIS / ASP.NET ──
        WORDLISTS.put(T_IIS, List.of(
            new Candidate("/trace.axd",
                ci("(?i)Application Trace|<title>Application Trace|Trace.axd"),
                "ASP.NET trace.axd exposed", SEV_HIGH, "CWE-200",
                "The ASP.NET trace handler is enabled in production. It logs every request, including "
                + "POST bodies and session contents, and is reachable by any unauthenticated visitor."),
            new Candidate("/elmah.axd",
                ci("(?i)Error Log for|<title>Error log for|ELMAH"),
                "ELMAH error log exposed", SEV_CRITICAL, "CWE-200",
                "ELMAH (Error Logging Modules and Handlers) is publicly accessible, exposing exception "
                + "details, stack traces, source paths, and often request payloads containing credentials."),
            new Candidate("/_vti_pvt/",
                ci("(?i)access denied|forbidden|<title>"),
                "FrontPage Server Extensions directory present", SEV_MEDIUM, "CWE-200",
                "_vti_pvt/ is a FrontPage/SharePoint metadata directory that should not be reachable.")
        ));

        // ── Tomcat / Java app server ──
        WORDLISTS.put(T_TOMCAT, List.of(
            new Candidate("/manager/html",
                ci("(?i)Tomcat Web Application Manager|<title>/manager"),
                "Tomcat Manager exposed", SEV_CRITICAL, "CWE-284",
                "The Tomcat Manager application is reachable. If credentials are weak or default it "
                + "permits arbitrary WAR upload. a direct path to remote code execution."),
            new Candidate("/host-manager/html",
                ci("(?i)Tomcat Virtual Host Manager|host-manager"),
                "Tomcat Host Manager exposed", SEV_CRITICAL, "CWE-284",
                "The Tomcat Host Manager is reachable. It can deploy new virtual hosts and is a "
                + "frequent target for credential brute-force leading to full server takeover."),
            new Candidate("/manager/status",
                ci("(?i)Tomcat Manager Status|JVM Version|server info"),
                "Tomcat manager status page exposed", SEV_MEDIUM, "CWE-200",
                "The Tomcat status page leaks JVM info, deployed apps, memory, and connector "
                + "configuration."),
            new Candidate("/examples/servlets/",
                ci("(?i)Apache Tomcat[^<]{0,40}Examples|Servlet Examples"),
                "Tomcat servlet examples exposed", SEV_MEDIUM, "CWE-200",
                "The Tomcat servlet examples are deployed. The SessionExample servlet allows arbitrary "
                + "session-cookie manipulation."),
            new Candidate("/examples/jsp/",
                ci("(?i)Apache Tomcat[^<]{0,40}Examples|JSP Examples"),
                "Tomcat JSP examples exposed", SEV_MEDIUM, "CWE-200",
                "The Tomcat JSP examples are deployed and have been a source of XSS and SSRF "
                + "vulnerabilities historically.")
        ));

        // ── PHP runtime (independent of CMS) ──
        WORDLISTS.put(T_PHP, List.of(
            new Candidate("/info.php",
                ci("(?i)phpinfo\\(\\)|<title>phpinfo"),
                "info.php (phpinfo) exposed", SEV_HIGH, "CWE-200",
                "A phpinfo() page is reachable, dumping the full PHP configuration, loaded modules, "
                + "and server environment."),
            new Candidate("/test.php",
                ci("(?i)phpinfo\\(\\)|<title>phpinfo|<title>test"),
                "test.php exposed", SEV_MEDIUM, "CWE-200",
                "A test.php page is reachable. Frequently contains phpinfo() output or other "
                + "diagnostic data left over from development."),
            new Candidate("/phpmyadmin/",
                ci("(?i)phpMyAdmin|pma_username|<title>[^<]{0,40}phpMyAdmin"),
                "phpMyAdmin exposed", SEV_HIGH, "CWE-200",
                "phpMyAdmin is publicly reachable. Confirm it is up-to-date and restricted to "
                + "trusted networks; outdated phpMyAdmin has had multiple RCE CVEs."),
            new Candidate("/adminer.php",
                ci("(?i)Adminer|<title>Login - Adminer"),
                "Adminer database admin exposed", SEV_HIGH, "CWE-200",
                "Adminer (database web admin) is reachable. If credentials are weak or default this "
                + "is direct database access.")
        ));

        // ── WordPress ──
        WORDLISTS.put(T_WORDPRESS, List.of(
            new Candidate("/wp-admin/",
                ci("(?i)<title>[^<]{0,40}Log In[^<]{0,40}|wp-login.php|wordpress"),
                "WordPress admin exposed (informational)", SEV_INFO, "CWE-200",
                "WordPress admin endpoint is reachable. Audit for brute-force protection and 2FA."),
            new Candidate("/wp-login.php",
                ci("(?i)wp-submit|<title>[^<]{0,40}Log In|user_login"),
                "WordPress login exposed (informational)", SEV_INFO, "CWE-200",
                "WordPress login is reachable. Ensure rate limiting and 2FA are configured."),
            new Candidate("/wp-config.php.bak",
                ci("DB_PASSWORD|DB_USER|AUTH_KEY"),
                "WordPress wp-config.php backup exposed", SEV_CRITICAL, "CWE-538",
                "A backup of wp-config.php is readable, exposing the WordPress database credentials "
                + "and auth keys in plaintext."),
            new Candidate("/wp-config.php~",
                ci("DB_PASSWORD|DB_USER|AUTH_KEY"),
                "WordPress wp-config.php~ backup exposed", SEV_CRITICAL, "CWE-538",
                "An editor-backup of wp-config.php is readable, exposing the WordPress credentials."),
            new Candidate("/wp-content/debug.log",
                ci("(?i)PHP (Fatal|Warning|Notice)|stack trace|wp-includes"),
                "WordPress debug.log exposed", SEV_HIGH, "CWE-200",
                "WordPress debug.log is publicly readable, exposing PHP errors, file paths, and "
                + "potentially user data captured in error contexts."),
            new Candidate("/xmlrpc.php",
                ci("(?i)XML-RPC server accepts POST requests|<title>XML-RPC"),
                "WordPress xmlrpc.php exposed", SEV_MEDIUM, "CWE-200",
                "xmlrpc.php is enabled. It enables pingback abuse, user enumeration via system."
                + "multicall, and brute-force amplification."),
            new Candidate("/wp-json/wp/v2/users",
                ci("\"id\"\\s*:\\s*\\d+[\\s\\S]{0,60}\"slug\"|\"name\""),
                "WordPress REST API user enumeration", SEV_MEDIUM, "CWE-200",
                "/wp-json/wp/v2/users returns the list of WordPress users without authentication. "
                + "User enumeration enables targeted brute-force.")
        ));

        // ── Drupal ──
        WORDLISTS.put(T_DRUPAL, List.of(
            new Candidate("/user/login",
                ci("(?i)<form[^>]+user-login|name=[\"']?form_id[\"']?[^>]+user_login_form"),
                "Drupal login exposed (informational)", SEV_INFO, "CWE-200",
                "Drupal user login form is reachable. Confirm rate limiting and account-lock "
                + "policies."),
            new Candidate("/CHANGELOG.txt",
                ci("(?i)Drupal [\\d.]+,|SA-CORE-|Security advisor"),
                "Drupal CHANGELOG.txt exposed", SEV_MEDIUM, "CWE-200",
                "Drupal's CHANGELOG.txt is readable, disclosing the exact Drupal version and applied "
                + "security advisories."),
            new Candidate("/sites/default/files/",
                ci("(?i)Index of /sites|<title>Index of"),
                "Drupal sites/default/files directory listing", SEV_LOW, "CWE-548",
                "Drupal's files directory has directory listing enabled, exposing uploaded content.")
        ));

        // ── Joomla ──
        WORDLISTS.put(T_JOOMLA, List.of(
            new Candidate("/administrator/",
                ci("(?i)<title>[^<]{0,30}Administration[^<]{0,30}Login|Joomla[^<]{0,40}Administration"),
                "Joomla administrator panel exposed (informational)", SEV_INFO, "CWE-200",
                "Joomla administrator login is reachable."),
            new Candidate("/configuration.php~",
                ci("\\$jconfig|public \\$db|public \\$password"),
                "Joomla configuration.php backup exposed", SEV_CRITICAL, "CWE-538",
                "A backup of Joomla's configuration.php is readable, exposing database credentials.")
        ));

        // ── Laravel ──
        WORDLISTS.put(T_LARAVEL, List.of(
            new Candidate("/telescope",
                ci("(?i)Laravel Telescope|<title>Telescope"),
                "Laravel Telescope exposed", SEV_CRITICAL, "CWE-200",
                "Laravel Telescope is reachable in production. It records every request, query, "
                + "exception, and queued job. a comprehensive sensitive-data leak source."),
            new Candidate("/horizon",
                ci("(?i)Laravel Horizon|<title>Horizon"),
                "Laravel Horizon dashboard exposed", SEV_HIGH, "CWE-200",
                "Laravel Horizon (queue dashboard) is reachable. It exposes job payloads, failures, "
                + "and worker status."),
            new Candidate("/_ignition/execute-solution",
                ci("(?i)ignition|solution|namespace[^<]{0,20}execute"),
                "Laravel Ignition debug endpoint exposed", SEV_CRITICAL, "CWE-200",
                "Laravel Ignition's execute-solution endpoint is reachable. Historic CVE-2021-3129 "
                + "allowed RCE through this route on Laravel <8.4.2; even on patched versions it "
                + "remains a dangerous debug surface to expose.")
        ));

        // ── Django ──
        WORDLISTS.put(T_DJANGO, List.of(
            new Candidate("/admin/",
                ci("(?i)<title>[^<]{0,30}Django site admin|<title>Log in[^<]{0,30}Django"),
                "Django admin reachable (informational)", SEV_INFO, "CWE-200",
                "Django admin is reachable. Confirm it is restricted to trusted IPs and uses MFA."),
            new Candidate("/__debug__/",
                ci("(?i)Django Debug Toolbar|debug_toolbar"),
                "Django Debug Toolbar exposed", SEV_HIGH, "CWE-200",
                "Django Debug Toolbar is enabled in production. It exposes SQL queries, settings, "
                + "template context, and request data."),
            new Candidate("/static/admin/",
                ci("(?i)<title>Index of|admin/css|admin/js"),
                "Django admin static assets directory listing", SEV_LOW, "CWE-548",
                "Django admin static directory is browseable.")
        ));

        // ── Rails ──
        WORDLISTS.put(T_RAILS, List.of(
            new Candidate("/rails/info/routes",
                ci("(?i)Routing Error|Listing routes|Helper.*HTTP Verb.*Path"),
                "Rails routes exposed", SEV_HIGH, "CWE-200",
                "Rails' route listing is reachable. It exposes every defined route, parameter, and "
                + "controller in the application."),
            new Candidate("/rails/info/properties",
                ci("(?i)Rails version|Ruby version|Action(?:Pack|View|Mailer)"),
                "Rails properties exposed", SEV_MEDIUM, "CWE-200",
                "Rails' /rails/info/properties endpoint reveals Rails and Ruby versions plus loaded "
                + "components."),
            new Candidate("/sidekiq",
                ci("(?i)Sidekiq|<title>Sidekiq"),
                "Sidekiq dashboard exposed", SEV_HIGH, "CWE-200",
                "Sidekiq's web dashboard is reachable, exposing background job payloads which often "
                + "contain PII or auth tokens.")
        ));

        // ── Spring Boot / Actuator ──
        WORDLISTS.put(T_SPRING, List.of(
            new Candidate("/actuator",
                ci("\\{[\\s\\S]{0,60}\"_links\"|\"href\"\\s*:\\s*\"[^\"]+/actuator"),
                "Spring Boot Actuator root exposed", SEV_HIGH, "CWE-200",
                "Spring Boot Actuator root is reachable, listing the enabled management endpoints. "
                + "Any endpoint listed here is a candidate for further inspection."),
            new Candidate("/actuator/env",
                ci("\"propertySources\"|\"systemEnvironment\"|\"applicationConfig\""),
                "Spring Boot Actuator /env exposed", SEV_CRITICAL, "CWE-200",
                "Actuator /env dumps every property source including environment variables, often "
                + "containing database URLs, API keys, and secrets in plaintext."),
            new Candidate("/actuator/heapdump",
                ci("\\AHPROF|\\Aheapdump|\\A.{0,16}JAVA PROFILE"),
                "Spring Boot Actuator /heapdump exposed", SEV_CRITICAL, "CWE-200",
                "Actuator /heapdump returns a full JVM heap dump. The heap contains in-memory "
                + "secrets: connection strings, JWT signing keys, session tokens, decrypted PII."),
            new Candidate("/actuator/configprops",
                ci("\"contexts\"|\"configurationProperties\"|\"prefix\""),
                "Spring Boot Actuator /configprops exposed", SEV_HIGH, "CWE-200",
                "Actuator /configprops exposes the full configuration property tree of the running "
                + "application, including non-obvious internal settings."),
            new Candidate("/actuator/mappings",
                ci("\"mappings\"|\"handler\"|\"requestMappingConditions\""),
                "Spring Boot Actuator /mappings exposed", SEV_MEDIUM, "CWE-200",
                "Actuator /mappings lists every request mapping in the application. a full route "
                + "inventory for an attacker."),
            new Candidate("/actuator/loggers",
                ci("\"loggers\"|\"configuredLevel\""),
                "Spring Boot Actuator /loggers exposed", SEV_MEDIUM, "CWE-200",
                "Actuator /loggers lets an unauthenticated attacker change log levels at runtime; "
                + "the resulting verbose logs may leak sensitive data into log sinks."),
            new Candidate("/actuator/threaddump",
                ci("\"threadName\"|\"stackTrace\"|\"lockOwnerName\""),
                "Spring Boot Actuator /threaddump exposed", SEV_HIGH, "CWE-200",
                "Actuator /threaddump exposes every JVM thread's stack trace. useful for finding "
                + "internal class layouts and reconstructing application logic.")
        ));

        // ── Node.js / Express ──
        WORDLISTS.put(T_NODEJS, List.of(
            new Candidate("/.npmrc",
                ci("(?i)registry\\s*=|_authToken\\s*=|_password\\s*="),
                "Node.js .npmrc exposed", SEV_CRITICAL, "CWE-538",
                ".npmrc is readable and may contain npm authentication tokens granting publish access "
                + "to private packages."),
            new Candidate("/yarn.lock",
                ci("(?i)# yarn lockfile|integrity sha\\d+"),
                "Node.js yarn.lock exposed", SEV_LOW, "CWE-200",
                "yarn.lock is publicly readable, disclosing the exact dependency tree and versions."),
            new Candidate("/.next/",
                ci("(?i)Index of /\\.next|build-manifest|<title>Index of"),
                "Next.js .next/ directory exposed", SEV_HIGH, "CWE-538",
                ".next/ build directory is reachable. It may contain server-side code, source maps, "
                + "and build artefacts that should never be web-accessible.")
        ));

        // ── Jenkins ──
        WORDLISTS.put(T_JENKINS, List.of(
            new Candidate("/manage",
                ci("(?i)Jenkins[^<]{0,30}Manage|<title>Manage Jenkins"),
                "Jenkins management page exposed", SEV_HIGH, "CWE-200",
                "Jenkins /manage is reachable. Confirm authentication and matrix-based authorisation "
                + "are configured; this surface enables plugin installation and config changes."),
            new Candidate("/script",
                ci("(?i)Script Console|Groovy script|<title>Script Console"),
                "Jenkins Script Console exposed", SEV_CRITICAL, "CWE-77",
                "The Jenkins Script Console accepts arbitrary Groovy and executes it on the master "
                + "with full JVM privileges. Unauthenticated access is immediate RCE; even "
                + "authenticated access should be restricted to administrators only."),
            new Candidate("/asynchPeople/",
                ci("(?i)People|<title>People|Jenkins users"),
                "Jenkins user list exposed", SEV_MEDIUM, "CWE-200",
                "Jenkins user list is reachable without authentication, enabling targeted "
                + "credential attacks against valid usernames.")
        ));

        // ── GitLab ──
        WORDLISTS.put(T_GITLAB, List.of(
            new Candidate("/explore",
                ci("(?i)GitLab|<title>[^<]{0,40}Explore[^<]{0,40}GitLab"),
                "GitLab /explore exposed (informational)", SEV_INFO, "CWE-200",
                "GitLab Explore is reachable. likely intentional for public instances. Confirm "
                + "private projects are not enumerable via this surface."),
            new Candidate("/users/sign_up",
                ci("(?i)New User|<title>[^<]{0,30}Sign up"),
                "GitLab open user registration", SEV_MEDIUM, "CWE-284",
                "GitLab allows new user sign-ups. If this is internal-only, disable open sign-up.")
        ));
    }

    // ── Generic wordlist builder ───────────────────────────────────────────────
    //
    // 500+ high-value paths organised by signature group. Each group bundles:
    //   - a battle-tested regex that distinguishes a real hit from a 200-OK
    //     catch-all SPA shell (signature is the single most important field;
    //     a loose signature here means false positives in user reports), and
    //   - a path list. Paths are expanded against the group's signature into
    //     individual Candidate entries.
    //
    // Sources for path selection:
    //   - SecLists Discovery/Web-Content/common.txt and quickhits.txt
    //   - SVNDigger, RobotsDisallowed top-1000
    //   - HackerOne disclosed-report path frequency analysis
    //   - Burp Pro "discover content" default content paths
    //   - Real engagement findings (admin panel locations, backup naming
    //     conventions, framework-default debug endpoints).
    //
    // Signature design discipline:
    //   - Regex MUST match content unique to the real resource at that path
    //     (a magic byte sequence, a structural keyword, a framework marker).
    //   - Regex MUST NOT match a typical SPA index.html (no "<html>", no
    //     "<!doctype html>", no plain "<title>App</title>" by themselves).
    //   - The soft-404 catch-all rejection in the main loop is a backstop;
    //     don't rely on it as the primary defence against false positives.

    private static List<Candidate> buildGenericWordlist() {
        List<Candidate> out = new ArrayList<>(600);

        // Reused signature regexes (compiled once at class init).
        Pattern SIG_ZIP      = Pattern.compile("PK\\x03\\x04");
        Pattern SIG_GZIP     = Pattern.compile("\\x1f\\x8b\\x08");
        Pattern SIG_TAR      = Pattern.compile("(?s)\\A[\\w\\.\\-_/]{1,100}\\x00{50,}");
        Pattern SIG_7Z       = Pattern.compile("\\A7z\\xbc\\xaf\\x27\\x1c");
        Pattern SIG_RAR      = Pattern.compile("\\ARar!\\x1a\\x07");
        Pattern SIG_BZIP2    = Pattern.compile("\\ABZh");
        Pattern SIG_SQL_DUMP = Pattern.compile(
            "(?i)(INSERT INTO|CREATE TABLE|DROP TABLE|-- (?:MySQL|MariaDB) dump|" +
            "PostgreSQL database dump|sqlite_master|BEGIN TRANSACTION)");
        Pattern SIG_ENV_LIKE = Pattern.compile(
            "(?m)^\\s*(?:[A-Z][A-Z0-9_]{2,}|DB_PASSWORD|DB_USER|AUTH_KEY|SECRET_KEY_BASE|" +
            "APP_KEY|JWT_SECRET|API_KEY|AWS_(?:ACCESS|SECRET))\\s*=\\s*\\S");
        Pattern SIG_PRIVKEY  = Pattern.compile(
            "-----BEGIN\\s+(?:RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED|PRIVATE)\\s+PRIVATE KEY-----");
        Pattern SIG_CERT     = Pattern.compile("-----BEGIN CERTIFICATE-----");
        Pattern SIG_PKCS12   = Pattern.compile("\\A\\x30\\x82");   // ASN.1 SEQUENCE
        Pattern SIG_GIT_CFG  = Pattern.compile(
            "(?i)\\[core\\][\\s\\S]{0,200}repositoryformatversion|\\[remote\\b");
        Pattern SIG_SVN      = Pattern.compile("(?i)\\bsvn\\b|svn://|<wc-entries");
        Pattern SIG_HG       = Pattern.compile(
            "(?m)^\\[(?:paths|ui|extensions|web)\\]|default\\s*=\\s*\\S");
        Pattern SIG_DS_STORE = Pattern.compile("\\ABud1|\\A.{0,8}Bud1.{0,4}\\x00", Pattern.DOTALL);
        Pattern SIG_DOCKERFILE = Pattern.compile(
            "(?m)^\\s*(?:FROM|RUN|COPY|ADD|ENV|EXPOSE|ENTRYPOINT|CMD|ARG|LABEL|WORKDIR|USER)\\s+\\S");
        Pattern SIG_DOCKER_COMPOSE = Pattern.compile(
            "(?m)^\\s*(?:version|services|image|environment|volumes|networks|ports|depends_on)\\s*:");
        Pattern SIG_K8S_YAML = Pattern.compile(
            "(?m)^\\s*(?:apiVersion|kind|metadata|spec|namespace)\\s*:\\s*\\S");
        Pattern SIG_GITHUB_ACTIONS = Pattern.compile(
            "(?m)^\\s*(?:name|on|jobs|runs-on|steps|uses|run|env|with)\\s*:");
        Pattern SIG_GITLAB_CI = Pattern.compile(
            "(?m)^(?:stages|variables|before_script|script|image|services|cache|" +
            "[a-zA-Z_][\\w-]*)\\s*:");
        Pattern SIG_AWS_CRED = Pattern.compile(
            "(?i)aws_access_key_id|aws_secret_access_key|AKIA[0-9A-Z]{16}|\\[default\\]");
        Pattern SIG_GCP_CRED = Pattern.compile(
            "(?i)\"type\"\\s*:\\s*\"service_account\"|\"private_key_id\"\\s*:|\"client_email\"\\s*:");
        Pattern SIG_TF_STATE = Pattern.compile(
            "(?i)\"terraform_version\"\\s*:|\"resources\"\\s*:[\\s\\S]{0,40}\"mode\"\\s*:");
        Pattern SIG_NPMRC    = Pattern.compile(
            "(?im)^\\s*(?:registry\\s*=|_authToken\\s*=|_password\\s*=|//.*:\\s*_authToken)");
        Pattern SIG_PACKAGE_LOCK = Pattern.compile(
            "(?s)\"lockfileVersion\"\\s*:|\"requires\"\\s*:\\s*true|\"dependencies\"\\s*:\\s*\\{");
        Pattern SIG_YARN_LOCK = Pattern.compile("(?i)# yarn lockfile|integrity sha\\d+");
        Pattern SIG_COMPOSER = Pattern.compile(
            "\"(require|require-dev|autoload|name)\"\\s*:");
        Pattern SIG_GEMFILE  = Pattern.compile(
            "(?m)^(?:source|gem|gemspec|group|ruby)\\s+");
        Pattern SIG_DIRLIST  = Pattern.compile(
            "(?i)<title>\\s*Index of\\s+/|<h1>\\s*Index of\\s+/|Parent Directory</a>");
        Pattern SIG_PHPINFO  = Pattern.compile(
            "(?i)phpinfo\\(\\)|<title>phpinfo|PHP Version[^<]{0,30}<");
        Pattern SIG_HEAPDUMP = Pattern.compile(
            "\\AJAVA PROFILE|\\AHPROF|\\A.{0,32}JAVA PROFILE");
        Pattern SIG_DUMP_RDB = Pattern.compile("\\AREDIS\\d{4}");
        Pattern SIG_PCAP     = Pattern.compile("\\A(?:\\xd4\\xc3\\xb2\\xa1|\\xa1\\xb2\\xc3\\xd4)");
        Pattern SIG_KEYSTORE = Pattern.compile("\\A\\xfe\\xed\\xfe\\xed");   // JKS magic
        Pattern SIG_PKCS8    = Pattern.compile("-----BEGIN ENCRYPTED PRIVATE KEY-----");
        Pattern SIG_HTACCESS = Pattern.compile(
            "(?im)^(?:RewriteRule|RewriteEngine|AuthType|Require\\s+|Order\\s+(?:allow|deny)|" +
            "<Directory|<Files|AllowOverride|Options\\s+(?:Indexes|FollowSymLinks))");
        Pattern SIG_HTPASSWD = Pattern.compile(
            "(?m)^[A-Za-z0-9_.\\-]{1,32}:\\$(?:1|2[aby]?|5|6|apr1|y)\\$");
        Pattern SIG_LOG_HTTP = Pattern.compile(
            "(?im)(?:^|\\n)\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\s+-\\s+(?:-|\\w+)\\s+\\[" +
            "|HTTP/1\\.[01]\"\\s+\\d{3}\\s+\\d+");
        Pattern SIG_LOG_PHP_ERR = Pattern.compile(
            "(?im)^\\[\\d{2}-[A-Za-z]{3}-\\d{4}[^]]*\\]\\s+PHP\\s+(?:Fatal|Warning|Notice|Parse error)");
        Pattern SIG_STACK_TRACE = Pattern.compile(
            "(?i)(?:at\\s+\\S+\\([^)]*:\\d+\\)|Traceback \\(most recent|Stack trace:|in [^\\s]+ on line \\d+)");
        Pattern SIG_SWAGGER  = Pattern.compile(
            "\"swagger\"\\s*:|\"openapi\"\\s*:|\\\"swagger\\\":|<title>[^<]{0,40}Swagger UI");
        Pattern SIG_POSTMAN  = Pattern.compile(
            "\"info\"\\s*:\\s*\\{[\\s\\S]{0,80}\"schema\"\\s*:\\s*\"https?://schema\\.getpostman");
        Pattern SIG_ASYNCAPI = Pattern.compile("\"asyncapi\"\\s*:");
        Pattern SIG_GRAPHQL  = Pattern.compile(
            "\"data\"\\s*:[\\s\\S]{0,80}\\{|\"__schema\"|\"errors\"\\s*:\\s*\\[\\s*\\{[\\s\\S]{0,80}\"message\"");
        Pattern SIG_PROM     = Pattern.compile(
            "(?m)^# (?:HELP|TYPE)\\s+\\S|^[a-zA-Z_][\\w]*(?:\\{[^}]*\\})?\\s+\\d+\\.?\\d*\\s*$");
        Pattern SIG_HEALTH   = Pattern.compile(
            "\"status\"\\s*:\\s*\"(?:UP|OK|HEALTHY|RUNNING)\"|\"healthy\"\\s*:\\s*true");
        Pattern SIG_ROBOTS   = Pattern.compile("(?im)^(?:User-agent|Disallow|Allow|Sitemap):");
        Pattern SIG_SITEMAP  = Pattern.compile(
            "(?i)<urlset\\b[\\s\\S]{0,200}xmlns=|<sitemapindex");
        Pattern SIG_CROSSDOM = Pattern.compile(
            "(?i)<\\?xml[\\s\\S]{0,100}<cross-domain-policy");
        Pattern SIG_WEBCONF  = Pattern.compile(
            "(?i)<configuration[\\s>]|<connectionStrings\\b|<system\\.web\\b|<appSettings\\b");
        Pattern SIG_WEBXML   = Pattern.compile(
            "(?i)<web-app\\b|<servlet\\b|<filter-mapping\\b|<security-constraint\\b");
        Pattern SIG_WEBLOGIC = Pattern.compile(
            "(?i)<weblogic-web-app\\b|<weblogic-application\\b");
        Pattern SIG_AXIS2    = Pattern.compile("(?i)<title>[^<]{0,30}Axis2|Hi, this is an AXIS2");
        Pattern SIG_SOAP_WSDL= Pattern.compile(
            "(?i)<(?:wsdl:)?definitions\\b|<\\?xml[\\s\\S]{0,80}<wsdl");
        Pattern SIG_LOGIN_FORM = Pattern.compile(
            "(?i)<form[^>]+(?:login|signin|authenticate|/login|/signin)" +
            "|<input[^>]+name\\s*=\\s*[\"']?(?:username|userid|user|email|login|pass(?:word)?)[\"']?" +
            "|<title>[^<]{0,60}(?:Log\\s*[Ii]n|Sign\\s*[Ii]n|Login|Authentication)");
        Pattern SIG_ADMIN_UI = Pattern.compile(
            "(?i)<title>[^<]{0,60}(?:admin|administration|control panel|dashboard|console|cpanel)" +
            "|<form[^>]+action\\s*=\\s*[\"']?(?:/admin|/manage|/dashboard)");
        Pattern SIG_DEBUG_PAGE = Pattern.compile(
            "(?i)(?:stack trace|exception|debug=true|werkzeug|debugger pin|" +
            "<title>[^<]{0,40}debug|<title>[^<]{0,40}error|Traceback \\(most recent)");
        Pattern SIG_INSTALL  = Pattern.compile(
            "(?i)<title>[^<]{0,40}(?:install|setup|installation|configure)|" +
            "<form[^>]+action\\s*=\\s*[\"']?(?:install|setup)|installer|installation wizard");
        Pattern SIG_ADMINER  = Pattern.compile("(?i)Adminer\\b|<title>[^<]{0,30}Adminer");
        Pattern SIG_PHPMYADM = Pattern.compile(
            "(?i)phpMyAdmin|pma_username|<title>[^<]{0,40}phpMyAdmin");
        Pattern SIG_KIBANA   = Pattern.compile(
            "(?i)<title>Kibana|window\\.__kbnInjectedMetadata|kbnInjectedMetadata");
        Pattern SIG_GRAFANA  = Pattern.compile(
            "(?i)<title>Grafana|window\\.grafanaBootData|grafana_bootdata");
        Pattern SIG_ELASTIC  = Pattern.compile(
            "\"cluster_name\"\\s*:|\"tagline\"\\s*:\\s*\"You Know, for Search\"");
        Pattern SIG_PROM_UI  = Pattern.compile("(?i)<title>\\s*Prometheus|prometheus_build_info");
        Pattern SIG_VAULT    = Pattern.compile(
            "(?i)<title>Vault|/v1/sys/health|\"sealed\"\\s*:\\s*(?:true|false)");

        // ── 1. Backup archives (root + common prefixes × extensions) ──────────
        // ZIP-shaped backups (PK magic confirms genuine archive)
        String[] archiveBases = {
            "backup", "backups", "bak", "old", "site", "www", "web", "html",
            "public_html", "wwwroot", "htdocs", "site-backup", "archive",
            "release", "deploy", "dump", "data", "database", "db", "files",
            "source", "src", "code", "app", "application", "project", "build",
            "dist", "export", "snapshot", "wordpress", "drupal", "joomla",
            "magento", "shop", "store", "prod", "production", "staging", "dev"
        };
        for (String base : archiveBases) {
            out.add(c("/" + base + ".zip", SIG_ZIP,
                "Archive (" + base + ".zip) exposed", SEV_CRITICAL, "CWE-538",
                "A ZIP archive at /" + base + ".zip is publicly downloadable. Backup archives "
                + "typically contain the full application source, configuration, and credentials."));
            out.add(c("/" + base + ".tar.gz", SIG_GZIP,
                "Archive (" + base + ".tar.gz) exposed", SEV_CRITICAL, "CWE-538",
                "A gzip-compressed tarball at /" + base + ".tar.gz is publicly downloadable."));
            out.add(c("/" + base + ".tar", SIG_TAR,
                "Archive (" + base + ".tar) exposed", SEV_CRITICAL, "CWE-538",
                "A tar archive at /" + base + ".tar is publicly downloadable."));
            out.add(c("/" + base + ".tgz", SIG_GZIP,
                "Archive (" + base + ".tgz) exposed", SEV_CRITICAL, "CWE-538",
                "A gzip-compressed tarball at /" + base + ".tgz is publicly downloadable."));
        }
        // 7z / rar / bz2 sample on the most common bases only
        for (String base : new String[]{"backup", "site", "www", "data"}) {
            out.add(c("/" + base + ".7z", SIG_7Z,
                "Archive (" + base + ".7z) exposed", SEV_CRITICAL, "CWE-538",
                "A 7-Zip archive at /" + base + ".7z is publicly downloadable."));
            out.add(c("/" + base + ".rar", SIG_RAR,
                "Archive (" + base + ".rar) exposed", SEV_CRITICAL, "CWE-538",
                "A RAR archive at /" + base + ".rar is publicly downloadable."));
            out.add(c("/" + base + ".tar.bz2", SIG_BZIP2,
                "Archive (" + base + ".tar.bz2) exposed", SEV_CRITICAL, "CWE-538",
                "A bzip2-compressed tarball at /" + base + ".tar.bz2 is publicly downloadable."));
        }

        // ── 2. SQL database dumps ─────────────────────────────────────────────
        String[] sqlBases = {
            "backup", "dump", "database", "db", "data", "mysql", "postgres",
            "pgsql", "sql", "schema", "init", "seed", "users", "customers",
            "orders", "production", "prod", "staging", "test", "old", "site"
        };
        for (String base : sqlBases) {
            out.add(c("/" + base + ".sql", SIG_SQL_DUMP,
                "SQL dump (" + base + ".sql) exposed", SEV_CRITICAL, "CWE-538",
                "A SQL database dump is publicly downloadable from /" + base + ".sql. Dumps "
                + "typically contain every row in the database including credentials and PII."));
            out.add(c("/" + base + ".sql.gz", SIG_GZIP,
                "Compressed SQL dump (" + base + ".sql.gz) exposed", SEV_CRITICAL, "CWE-538",
                "A gzip-compressed SQL dump is publicly readable at /" + base + ".sql.gz."));
        }

        // ── 3. Env / config files (the broadest single class of disclosure) ──
        String[] envPaths = {
            "/.env", "/.env.bak", "/.env.old", "/.env.backup", "/.env.save",
            "/.env.production", "/.env.prod", "/.env.staging", "/.env.dev",
            "/.env.development", "/.env.local", "/.env.test", "/.env~",
            "/.env.example.bak",
            "/env", "/env.json", "/env.txt",
            "/config/.env", "/app/.env", "/api/.env", "/src/.env", "/laravel/.env",
            "/web/.env", "/backend/.env", "/server/.env"
        };
        for (String p : envPaths) {
            out.add(c(p, SIG_ENV_LIKE,
                "Environment file (" + p + ") exposed", SEV_CRITICAL, "CWE-538",
                "An environment file is publicly readable at " + p + ". These files contain "
                + "database credentials, API keys, signing secrets, and third-party tokens. "
                + "Treat every value present as compromised and rotate immediately."));
        }

        // ── 4. Source control directories ────────────────────────────────────
        out.add(c("/.git/config", SIG_GIT_CFG,
            "Git repository (.git/config) exposed", SEV_HIGH, "CWE-538",
            "The .git/config file is publicly accessible, indicating the entire .git directory "
            + "is served. An attacker can reconstruct the full source code history including "
            + "removed credentials in old commits."));
        out.add(c("/.git/HEAD", Pattern.compile("(?m)^ref:\\s+refs/"),
            "Git repository (.git/HEAD) exposed", SEV_HIGH, "CWE-538",
            "The .git/HEAD reference is publicly readable, indicating .git/ is served. Run "
            + "git-dumper to reconstruct the working tree."));
        out.add(c("/.git/index", Pattern.compile("\\ADIRC"),
            "Git index (.git/index) exposed", SEV_HIGH, "CWE-538",
            "The .git/index binary file is publicly readable, exposing the tracked file tree."));
        out.add(c("/.git/logs/HEAD", Pattern.compile("(?m)^[0-9a-f]{40}\\s+[0-9a-f]{40}\\s+"),
            "Git reflog (.git/logs/HEAD) exposed", SEV_HIGH, "CWE-538",
            "The Git reflog is publicly readable, disclosing commit history with author emails."));
        out.add(c("/.git/COMMIT_EDITMSG",
            Pattern.compile("(?m)^[^<\\s][^\\n]{0,200}(?:\\n# Please enter the commit message|\\n# On branch|\\Z)"),
            "Git COMMIT_EDITMSG exposed", SEV_MEDIUM, "CWE-538",
            "The Git COMMIT_EDITMSG is readable, exposing recent commit messages. The file "
            + "either contains the prepared message followed by Git's '# Please enter' helper "
            + "comments, or a previously-committed message at the start of the file."));
        out.add(c("/.svn/entries", SIG_SVN,
            "Subversion (.svn/entries) exposed", SEV_MEDIUM, "CWE-538",
            "Subversion metadata is publicly readable."));
        out.add(c("/.svn/wc.db", Pattern.compile("\\ASQLite format 3"),
            "Subversion working copy DB exposed", SEV_HIGH, "CWE-538",
            "The Subversion working-copy SQLite database is publicly downloadable."));
        out.add(c("/.hg/hgrc", SIG_HG,
            "Mercurial (.hg/hgrc) exposed", SEV_MEDIUM, "CWE-538",
            "Mercurial repository configuration is publicly readable."));
        out.add(c("/.bzr/branch/branch.conf", Pattern.compile("\\[branch\\]|parent_location"),
            "Bazaar (.bzr) exposed", SEV_MEDIUM, "CWE-538",
            "A Bazaar repository configuration is publicly readable."));
        out.add(c("/CVS/Entries", Pattern.compile("(?m)^/.+/.+/.+/"),
            "CVS metadata exposed", SEV_MEDIUM, "CWE-538",
            "CVS repository metadata is publicly readable."));
        out.add(c("/.DS_Store", SIG_DS_STORE,
            "macOS .DS_Store exposed", SEV_LOW, "CWE-538",
            "A .DS_Store file is publicly accessible, revealing directory entries to aid "
            + "discovery of hidden or backup files."));

        // ── 5. CI/CD configuration ───────────────────────────────────────────
        out.add(c("/.github/workflows/main.yml", SIG_GITHUB_ACTIONS,
            "GitHub Actions workflow exposed", SEV_MEDIUM, "CWE-538",
            "A GitHub Actions workflow is publicly readable, revealing the build pipeline, "
            + "secret names referenced, and sometimes inline credentials."));
        out.add(c("/.github/workflows/ci.yml", SIG_GITHUB_ACTIONS,
            "GitHub Actions CI workflow exposed", SEV_MEDIUM, "CWE-538",
            "A GitHub Actions CI workflow is publicly readable."));
        out.add(c("/.github/workflows/deploy.yml", SIG_GITHUB_ACTIONS,
            "GitHub Actions deploy workflow exposed", SEV_HIGH, "CWE-538",
            "A GitHub Actions deploy workflow is publicly readable, often referencing deploy "
            + "secrets, target environments, and infrastructure."));
        out.add(c("/.gitlab-ci.yml", SIG_GITLAB_CI,
            "GitLab CI configuration exposed", SEV_MEDIUM, "CWE-538",
            "A GitLab CI configuration is publicly readable, revealing the build/deploy pipeline."));
        out.add(c("/.travis.yml", Pattern.compile("(?m)^(?:language|sudo|script|deploy|env):"),
            "Travis CI configuration exposed", SEV_LOW, "CWE-538",
            "Travis CI configuration is publicly readable."));
        out.add(c("/.circleci/config.yml", Pattern.compile("(?m)^(?:version|jobs|workflows):"),
            "CircleCI configuration exposed", SEV_MEDIUM, "CWE-538",
            "CircleCI configuration is publicly readable."));
        out.add(c("/Jenkinsfile", Pattern.compile("(?i)pipeline\\s*\\{|node\\s*\\{|stage\\s*\\("),
            "Jenkinsfile exposed", SEV_MEDIUM, "CWE-538",
            "A Jenkinsfile is publicly readable, exposing build steps, credentials helper IDs, "
            + "and deployment targets."));
        out.add(c("/bitbucket-pipelines.yml", Pattern.compile("(?m)^(?:pipelines|image|step|definitions):"),
            "Bitbucket Pipelines configuration exposed", SEV_MEDIUM, "CWE-538",
            "Bitbucket Pipelines configuration is publicly readable."));
        out.add(c("/azure-pipelines.yml", Pattern.compile("(?m)^(?:trigger|pool|stages|jobs|steps|variables):"),
            "Azure DevOps Pipelines configuration exposed", SEV_MEDIUM, "CWE-538",
            "Azure DevOps Pipelines configuration is publicly readable."));
        out.add(c("/buildspec.yml", Pattern.compile("(?m)^(?:version|phases|artifacts|env):"),
            "AWS CodeBuild buildspec exposed", SEV_MEDIUM, "CWE-538",
            "An AWS CodeBuild buildspec.yml is publicly readable."));
        out.add(c("/cloudbuild.yaml", Pattern.compile("(?m)^(?:steps|images|options|substitutions):"),
            "Google Cloud Build configuration exposed", SEV_MEDIUM, "CWE-538",
            "A Google Cloud Build configuration is publicly readable."));

        // ── 6. Container / orchestration manifests ───────────────────────────
        out.add(c("/Dockerfile", SIG_DOCKERFILE,
            "Dockerfile exposed", SEV_MEDIUM, "CWE-538",
            "The Dockerfile is publicly readable, disclosing base image, build steps, exposed "
            + "ports, and sometimes embedded credentials or build arguments."));
        out.add(c("/docker-compose.yml", SIG_DOCKER_COMPOSE,
            "docker-compose.yml exposed", SEV_HIGH, "CWE-538",
            "docker-compose.yml is publicly readable, disclosing service topology, environment "
            + "variables (often including database credentials), and inter-service auth."));
        out.add(c("/docker-compose.yaml", SIG_DOCKER_COMPOSE,
            "docker-compose.yaml exposed", SEV_HIGH, "CWE-538",
            "docker-compose.yaml is publicly readable."));
        out.add(c("/docker-compose.prod.yml", SIG_DOCKER_COMPOSE,
            "Production docker-compose.prod.yml exposed", SEV_HIGH, "CWE-538",
            "A production docker-compose file is publicly readable, exposing production service "
            + "configuration including credentials."));
        out.add(c("/docker-compose.override.yml", SIG_DOCKER_COMPOSE,
            "docker-compose.override.yml exposed", SEV_HIGH, "CWE-538",
            "A docker-compose override file is publicly readable."));
        out.add(c("/k8s/deployment.yaml", SIG_K8S_YAML,
            "Kubernetes deployment manifest exposed", SEV_MEDIUM, "CWE-538",
            "A Kubernetes deployment manifest is publicly readable, exposing image, replicas, "
            + "env vars, and resource limits."));
        out.add(c("/kubernetes/deployment.yaml", SIG_K8S_YAML,
            "Kubernetes deployment manifest exposed", SEV_MEDIUM, "CWE-538",
            "A Kubernetes deployment manifest is publicly readable."));
        out.add(c("/helm/values.yaml", Pattern.compile("(?m)^(?:replicaCount|image|service|ingress|resources):"),
            "Helm values.yaml exposed", SEV_MEDIUM, "CWE-538",
            "A Helm values.yaml is publicly readable, exposing chart configuration including "
            + "secret-reference paths."));

        // ── 7. Cloud / IaC credential files ──────────────────────────────────
        out.add(c("/.aws/credentials", SIG_AWS_CRED,
            "AWS credentials file exposed", SEV_CRITICAL, "CWE-538",
            "An AWS credentials file is publicly readable, exposing access keys that grant "
            + "programmatic access to AWS resources."));
        out.add(c("/.aws/config", Pattern.compile("(?im)^\\s*\\[(?:default|profile\\b)|region\\s*="),
            "AWS config file exposed", SEV_HIGH, "CWE-538",
            "An AWS config file is publicly readable, disclosing profile names, regions, and "
            + "role-assumption configuration."));
        out.add(c("/credentials", SIG_AWS_CRED,
            "Generic credentials file exposed", SEV_CRITICAL, "CWE-538",
            "A file named /credentials contains AWS-style credentials and is publicly readable."));
        out.add(c("/gcp-key.json", SIG_GCP_CRED,
            "GCP service account key exposed", SEV_CRITICAL, "CWE-538",
            "A GCP service account JSON key is publicly downloadable, granting impersonation "
            + "of the service account and access to every resource it has permission for."));
        out.add(c("/serviceAccount.json", SIG_GCP_CRED,
            "GCP service account key exposed", SEV_CRITICAL, "CWE-538",
            "A GCP service account JSON key is publicly downloadable."));
        out.add(c("/service-account.json", SIG_GCP_CRED,
            "GCP service account key exposed", SEV_CRITICAL, "CWE-538",
            "A GCP service account JSON key is publicly downloadable."));
        out.add(c("/terraform.tfstate", SIG_TF_STATE,
            "Terraform state file exposed", SEV_CRITICAL, "CWE-538",
            "The terraform.tfstate is publicly downloadable. It contains the full resource "
            + "inventory with credentials, secret-manager paths, and provider configuration "
            + "in plaintext."));
        out.add(c("/terraform.tfstate.backup", SIG_TF_STATE,
            "Terraform state backup exposed", SEV_CRITICAL, "CWE-538",
            "A Terraform state backup is publicly downloadable."));
        out.add(c("/.terraform/terraform.tfstate", SIG_TF_STATE,
            "Terraform state in .terraform/ exposed", SEV_CRITICAL, "CWE-538",
            "The terraform state in .terraform/ is publicly readable."));
        out.add(c("/ansible.cfg", Pattern.compile("(?m)^\\[(?:defaults|inventory|ssh_connection|privilege_escalation)\\]"),
            "Ansible configuration exposed", SEV_MEDIUM, "CWE-538",
            "An Ansible configuration file is publicly readable."));
        out.add(c("/inventory", Pattern.compile("(?m)^\\[[\\w-]+\\]\\s*$"),
            "Ansible inventory exposed", SEV_MEDIUM, "CWE-538",
            "An Ansible inventory file is publicly readable, disclosing target host groups."));
        out.add(c("/playbook.yml", Pattern.compile("(?m)^-\\s+(?:hosts|name|tasks):"),
            "Ansible playbook exposed", SEV_MEDIUM, "CWE-538",
            "An Ansible playbook is publicly readable, exposing automation logic and secrets."));

        // ── 8. Editor / IDE artefacts ────────────────────────────────────────
        out.add(c("/.idea/workspace.xml", Pattern.compile("(?i)<\\?xml[\\s\\S]{0,80}<project\\b"),
            "JetBrains workspace.xml exposed", SEV_MEDIUM, "CWE-538",
            "A JetBrains IDE workspace.xml is publicly readable, exposing project paths, "
            + "open files, and sometimes credentials in run configurations."));
        out.add(c("/.idea/dataSources.xml", Pattern.compile("(?i)<dataSource\\b|<jdbc-url"),
            "JetBrains dataSources.xml exposed", SEV_CRITICAL, "CWE-538",
            "A JetBrains dataSources.xml is publicly readable, frequently containing JDBC URLs "
            + "with embedded credentials."));
        out.add(c("/.vscode/settings.json", Pattern.compile("\\{[\\s\\S]{0,200}\"[a-zA-Z\\.]+\"\\s*:"),
            "VS Code settings.json exposed", SEV_LOW, "CWE-538",
            "A VS Code settings.json is publicly readable."));
        out.add(c("/.vscode/launch.json", Pattern.compile("\"configurations\"\\s*:|\"type\"\\s*:\\s*\"(?:node|python|chrome|java)"),
            "VS Code launch.json exposed", SEV_MEDIUM, "CWE-538",
            "A VS Code launch.json is publicly readable, sometimes containing debug environment "
            + "variables with secrets."));
        out.add(c("/.project", Pattern.compile("(?i)<projectDescription\\b|<name>[^<]+</name>"),
            "Eclipse .project file exposed", SEV_LOW, "CWE-538",
            "An Eclipse .project descriptor is publicly readable."));
        out.add(c("/.settings/", SIG_DIRLIST,
            "Eclipse .settings/ directory listing", SEV_MEDIUM, "CWE-548",
            "The Eclipse .settings/ directory has listing enabled and is publicly browsable."));
        out.add(c("/nbproject/private/private.properties",
            Pattern.compile("(?m)^[a-zA-Z\\.]+\\s*="),
            "NetBeans private.properties exposed", SEV_MEDIUM, "CWE-538",
            "A NetBeans IDE private.properties is publicly readable, may contain credentials."));

        // ── 9. Dependency manifests and lockfiles ────────────────────────────
        out.add(c("/package.json", SIG_COMPOSER,
            "package.json exposed", SEV_LOW, "CWE-200",
            "A Node.js package.json is publicly readable, disclosing dependencies and scripts."));
        out.add(c("/package-lock.json", SIG_PACKAGE_LOCK,
            "package-lock.json exposed", SEV_LOW, "CWE-200",
            "A Node.js package-lock.json is publicly readable, disclosing exact transitive "
            + "dependency versions for targeted CVE lookup."));
        out.add(c("/yarn.lock", SIG_YARN_LOCK,
            "yarn.lock exposed", SEV_LOW, "CWE-200",
            "A yarn.lock is publicly readable, disclosing exact dependency versions."));
        out.add(c("/composer.json", SIG_COMPOSER,
            "composer.json exposed", SEV_LOW, "CWE-200",
            "A PHP composer.json is publicly readable."));
        out.add(c("/composer.lock", Pattern.compile("\"_readme\"|\"content-hash\"\\s*:|\"packages\"\\s*:"),
            "composer.lock exposed", SEV_LOW, "CWE-200",
            "A PHP composer.lock is publicly readable, disclosing exact package versions."));
        out.add(c("/Gemfile", SIG_GEMFILE,
            "Ruby Gemfile exposed", SEV_LOW, "CWE-200",
            "A Ruby Gemfile is publicly readable, disclosing dependencies."));
        out.add(c("/Gemfile.lock", Pattern.compile("(?m)^GEM\\s*$|^\\s+remote:\\s+https?://"),
            "Ruby Gemfile.lock exposed", SEV_LOW, "CWE-200",
            "A Ruby Gemfile.lock is publicly readable, disclosing exact gem versions."));
        out.add(c("/requirements.txt", Pattern.compile("(?m)^\\s*[\\w\\.\\-]+\\s*(?:==|>=|<=|~=|!=)\\s*[\\d\\.\\w]+"),
            "Python requirements.txt exposed", SEV_LOW, "CWE-200",
            "A Python requirements.txt is publicly readable, disclosing dependencies."));
        out.add(c("/Pipfile", Pattern.compile("(?m)^\\[(?:source|packages|dev-packages|requires)\\]"),
            "Python Pipfile exposed", SEV_LOW, "CWE-200",
            "A Python Pipfile is publicly readable."));
        out.add(c("/Pipfile.lock", Pattern.compile("\"_meta\"\\s*:|\"sha256\"\\s*:|\"version\"\\s*:\\s*\"=="),
            "Python Pipfile.lock exposed", SEV_LOW, "CWE-200",
            "A Python Pipfile.lock is publicly readable."));
        out.add(c("/pyproject.toml", Pattern.compile("(?m)^\\[(?:tool|build-system|project)\\."),
            "Python pyproject.toml exposed", SEV_LOW, "CWE-200",
            "A Python pyproject.toml is publicly readable."));
        out.add(c("/poetry.lock", Pattern.compile("(?m)^\\[\\[package\\]\\]|^name = \""),
            "Python poetry.lock exposed", SEV_LOW, "CWE-200",
            "A Python poetry.lock is publicly readable."));
        out.add(c("/go.mod", Pattern.compile("(?m)^module\\s+\\S|^go\\s+\\d+\\.\\d+|^require\\b"),
            "Go module file (go.mod) exposed", SEV_LOW, "CWE-200",
            "A Go go.mod is publicly readable."));
        out.add(c("/go.sum", Pattern.compile("(?m)^\\S+\\s+v\\d+\\.\\d+\\.\\d+(?:-\\S+)?\\s+h1:"),
            "Go module checksums (go.sum) exposed", SEV_LOW, "CWE-200",
            "A Go go.sum is publicly readable, disclosing exact module versions."));
        out.add(c("/Cargo.toml", Pattern.compile("(?m)^\\[(?:package|dependencies)\\]"),
            "Rust Cargo.toml exposed", SEV_LOW, "CWE-200",
            "A Rust Cargo.toml is publicly readable."));
        out.add(c("/pom.xml", Pattern.compile("(?i)<project\\b[\\s\\S]{0,200}xmlns=\"http://maven\\.apache\\.org"),
            "Maven pom.xml exposed", SEV_LOW, "CWE-200",
            "A Maven pom.xml is publicly readable, disclosing dependencies and group/artifact IDs."));
        out.add(c("/build.gradle", Pattern.compile("(?m)^(?:plugins|dependencies|repositories|sourceSets)\\s*\\{|apply plugin:"),
            "Gradle build.gradle exposed", SEV_LOW, "CWE-200",
            "A Gradle build.gradle is publicly readable."));
        out.add(c("/.npmrc", SIG_NPMRC,
            "npm .npmrc exposed", SEV_CRITICAL, "CWE-538",
            "A .npmrc is publicly readable. If it contains _authToken or _password, the npm "
            + "account is compromised for any package publish."));

        // ── 10. Secret / credential files (highest impact) ───────────────────
        for (String p : new String[]{
            "/.htpasswd", "/htpasswd", "/.passwd", "/passwd",
            "/auth.htpasswd", "/admin.htpasswd"
        }) {
            out.add(c(p, SIG_HTPASSWD,
                "Password file (" + p + ") exposed", SEV_CRITICAL, "CWE-522",
                "An htpasswd-style password file is publicly readable at " + p + ". The bcrypt/"
                + "MD5/SHA hashes within can be brute-forced offline."));
        }
        out.add(c("/.htaccess", SIG_HTACCESS,
            "Apache .htaccess exposed", SEV_MEDIUM, "CWE-538",
            "An Apache .htaccess is publicly readable, disclosing rewrite rules and access "
            + "control configuration."));
        for (String p : new String[]{
            "/id_rsa", "/id_dsa", "/id_ecdsa", "/id_ed25519",
            "/.ssh/id_rsa", "/.ssh/id_dsa", "/.ssh/id_ecdsa", "/.ssh/id_ed25519",
            "/server.key", "/private.key", "/privkey.pem", "/key.pem"
        }) {
            out.add(c(p, SIG_PRIVKEY,
                "Private key (" + p + ") exposed", SEV_CRITICAL, "CWE-538",
                "A private cryptographic key is publicly downloadable at " + p + ". Treat any "
                + "service that trusted this key as compromised; rotate immediately."));
        }
        for (String p : new String[]{
            "/server.crt", "/cert.pem", "/certificate.crt", "/ca.crt", "/chain.pem"
        }) {
            out.add(c(p, SIG_CERT,
                "Certificate (" + p + ") exposed", SEV_INFO, "CWE-200",
                "A certificate is publicly downloadable at " + p + ". Certificates themselves "
                + "are not secret, but their exposure can aid reconnaissance."));
        }
        for (String p : new String[]{
            "/keystore.jks", "/server.jks", "/cacerts.jks", "/identity.jks"
        }) {
            out.add(c(p, SIG_KEYSTORE,
                "Java keystore (" + p + ") exposed", SEV_HIGH, "CWE-538",
                "A Java keystore is publicly downloadable. Keystores typically protect signing "
                + "keys and TLS private keys; the file can be brute-forced offline."));
        }
        for (String p : new String[]{
            "/keystore.p12", "/server.p12", "/cert.pfx", "/identity.pfx"
        }) {
            out.add(c(p, SIG_PKCS12,
                "PKCS#12 keystore (" + p + ") exposed", SEV_HIGH, "CWE-538",
                "A PKCS#12/PFX keystore is publicly downloadable."));
        }
        out.add(c("/.netrc", Pattern.compile("(?m)^machine\\s+\\S|login\\s+\\S|password\\s+\\S"),
            "netrc credentials file exposed", SEV_CRITICAL, "CWE-522",
            "A .netrc file is publicly readable, containing cleartext machine/login/password "
            + "credentials for remote services."));

        // ── 11. Application config files ─────────────────────────────────────
        String[] cfgBases = {
            "config", "configuration", "settings", "app", "application",
            "database", "db", "secrets", "credentials", "keys"
            // Note: "auth" intentionally excluded - /auth is already in the
            // login-pages list and would dup. Same for /web.config (dedicated
            // entry below) and /secrets.yml / /database.yml (known-name list).
        };
        String[] cfgExts = {".json", ".yml", ".yaml", ".xml", ".ini", ".toml", ".conf", ".cfg", ".properties"};
        Pattern SIG_CFG_GENERIC = Pattern.compile(
            "(?i)\\b(?:password|secret|api[_-]?key|token|connection[_-]?string|" +
            "db[_-]?(?:host|user|pass)|aws_(?:access|secret))\\b\\s*[:=]\\s*[\"']?\\S{4,}");
        // Paths covered by the known-name list below (don't dup them from cross-product).
        Set<String> knownCfgPaths = Set.of(
            "/secrets.yml", "/secrets.yaml", "/database.yml", "/database.yaml",
            "/web.config", "/web.xml"
        );
        for (String base : cfgBases) {
            for (String ext : cfgExts) {
                String p = "/" + base + ext;
                if (knownCfgPaths.contains(p)) continue;
                out.add(c(p, SIG_CFG_GENERIC,
                    "Config (" + base + ext + ") with secret-like content exposed",
                    SEV_HIGH, "CWE-538",
                    "A configuration file at " + p + " is publicly readable and "
                    + "contains content matching credential/secret patterns."));
            }
        }
        // Known-name config files
        for (String p : new String[]{
            "/web.xml.bak",
            "/wp-config.php", "/wp-config.php.bak", "/wp-config.php~",
            "/wp-config.php.old", "/wp-config.txt", "/wp-config.inc",
            "/configuration.php", "/configuration.php~", "/sites/default/settings.php",
            "/local_settings.py", "/settings.py", "/secrets.yml", "/secrets.yaml",
            "/parameters.yml", "/security.yml", "/database.yml", "/database.yaml"
            // /web.config and /web.xml handled by dedicated SIG_WEBCONF and SIG_WEBXML entries below
        }) {
            out.add(c(p, SIG_CFG_GENERIC,
                "Application config (" + p + ") exposed", SEV_CRITICAL, "CWE-538",
                "A framework-specific configuration file at " + p + " is publicly readable and "
                + "contains credential-like content."));
        }
        out.add(c("/web.config", SIG_WEBCONF,
            ".NET web.config exposed", SEV_HIGH, "CWE-538",
            "A .NET web.config is publicly readable, commonly containing connection strings and "
            + "machine keys."));
        out.add(c("/WEB-INF/web.xml", SIG_WEBXML,
            "Java WEB-INF/web.xml exposed", SEV_HIGH, "CWE-538",
            "Java WEB-INF/web.xml is publicly readable. WEB-INF should never be web-accessible; "
            + "this exposes servlet mappings, filters, and security constraints."));
        out.add(c("/WEB-INF/weblogic.xml", SIG_WEBLOGIC,
            "WebLogic deployment descriptor exposed", SEV_HIGH, "CWE-538",
            "A WebLogic deployment descriptor is publicly readable from WEB-INF/."));

        // ── 12. Debug / diagnostic / profiling endpoints ─────────────────────
        for (String p : new String[]{
            "/debug", "/debug/", "/debug.php", "/debug.jsp", "/debug.aspx", "/debug.action",
            "/__debug__/", "/__debug__/console", "/console", "/_debug_toolbar/",
            "/error", "/errors",
            "/trace", "/trace.axd", "/trace.action",
            "/test", "/test.php", "/test.jsp", "/test.aspx",
            "/info", "/info.php", "/info.jsp", "/info.action",
            "/phpinfo", "/phpinfo.php", "/_profiler/", "/_profiler",
            "/xhprof/", "/xhprof_html/", "/opcache.php", "/opcache-status.php"
        }) {
            // Use phpinfo signature for php-specific paths, generic debug-page signature otherwise.
            Pattern sig = p.contains("phpinfo") || p.contains("info.php") || p.equals("/info.php")
                       || p.equals("/opcache.php") || p.equals("/opcache-status.php")
                       ? SIG_PHPINFO : SIG_DEBUG_PAGE;
            out.add(c(p, sig,
                "Debug/diagnostic endpoint (" + p + ") exposed", SEV_HIGH, "CWE-200",
                "A debug or diagnostic endpoint at " + p + " is publicly reachable. These pages "
                + "frequently expose stack traces, environment variables, configuration, and "
                + "request data that aid further exploitation."));
        }

        // ── 13. Status / metrics / health endpoints (info disclosure) ────────
        for (String p : new String[]{
            "/status", "/server-status", "/nginx_status", "/haproxy?stats",
            "/manager/status", "/server-info"
        }) {
            out.add(c(p, Pattern.compile(
                "(?i)Apache (?:Server (?:Status|Information))|Active connections|server accepts|" +
                "Tomcat Manager Status|HAProxy Statistics|server-info|Scoreboard:"),
                "Server status page (" + p + ") exposed", SEV_HIGH, "CWE-200",
                "A server status page at " + p + " is publicly reachable, exposing internal "
                + "operational data (connection counts, request rates, server config)."));
        }
        out.add(c("/metrics", SIG_PROM,
            "Prometheus /metrics endpoint exposed", SEV_MEDIUM, "CWE-200",
            "The Prometheus /metrics endpoint is publicly reachable, exposing internal metrics "
            + "including request rates, queue depths, and sometimes user counts."));
        out.add(c("/actuator/metrics", SIG_PROM,
            "Actuator /metrics endpoint exposed", SEV_MEDIUM, "CWE-200",
            "Spring Actuator /metrics is publicly reachable."));
        out.add(c("/health", SIG_HEALTH,
            "Health check endpoint exposed", SEV_INFO, "CWE-200",
            "A /health endpoint responds (informational). Confirm it does not leak internal "
            + "dependency status."));
        out.add(c("/healthz", SIG_HEALTH,
            "Kubernetes /healthz endpoint exposed", SEV_INFO, "CWE-200",
            "A Kubernetes-style /healthz endpoint responds (informational)."));
        out.add(c("/ping", Pattern.compile("(?i)pong|alive|\\{\"ok\":true\\}|<title>[^<]{0,20}ping"),
            "/ping endpoint exposed", SEV_INFO, "CWE-200",
            "A /ping endpoint responds (informational)."));
        out.add(c("/version", Pattern.compile("(?i)\"version\"\\s*:|<version>[\\d.]+</version>|^v?\\d+\\.\\d+\\.\\d+"),
            "Version disclosure endpoint exposed", SEV_LOW, "CWE-200",
            "A /version endpoint discloses application version. Combined with public CVE data "
            + "this aids targeted exploitation."));

        // ── 14. API documentation & spec leaks ───────────────────────────────
        for (String p : new String[]{
            "/swagger.json", "/swagger.yaml", "/swagger.yml",
            "/openapi.json", "/openapi.yaml", "/openapi.yml",
            "/api/swagger.json", "/api/openapi.json", "/api/v1/swagger.json",
            "/api/v2/swagger.json", "/api/v3/swagger.json",
            "/api-docs", "/api-docs/", "/api/docs", "/api/docs/",
            "/api/swagger", "/api/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
            "/swagger-resources", "/swagger-resources/", "/swagger-ui",
            "/swagger-ui/", "/swagger-ui.html", "/swagger-ui/index.html",
            "/swagger/index.html", "/swagger/v1/swagger.json",
            "/redoc", "/redoc/", "/redoc.html",
            "/api-spec", "/api-spec.json", "/api-spec.yaml",
            "/spec", "/spec.json"
        }) {
            out.add(c(p, SIG_SWAGGER,
                "API spec (" + p + ") exposed", SEV_MEDIUM, "CWE-200",
                "An API specification at " + p + " is publicly downloadable, revealing the "
                + "full API surface (routes, parameters, request/response shapes)."));
        }
        out.add(c("/postman.json", SIG_POSTMAN,
            "Postman collection exposed", SEV_MEDIUM, "CWE-200",
            "A Postman collection is publicly downloadable, often containing example payloads "
            + "with embedded auth tokens."));
        out.add(c("/postman_collection.json", SIG_POSTMAN,
            "Postman collection exposed", SEV_MEDIUM, "CWE-200",
            "A Postman collection is publicly downloadable."));
        out.add(c("/asyncapi.json", SIG_ASYNCAPI,
            "AsyncAPI spec exposed", SEV_MEDIUM, "CWE-200",
            "An AsyncAPI specification is publicly downloadable."));
        out.add(c("/asyncapi.yaml", SIG_ASYNCAPI,
            "AsyncAPI spec exposed", SEV_MEDIUM, "CWE-200",
            "An AsyncAPI specification is publicly downloadable."));
        out.add(c("/graphql", SIG_GRAPHQL,
            "GraphQL endpoint discovered", SEV_LOW, "CWE-200",
            "A /graphql endpoint responded. The dedicated GraphQL probe assesses introspection, "
            + "batching, and depth limits."));
        out.add(c("/graphiql", Pattern.compile("(?i)<title>[^<]{0,30}GraphiQL|graphiql\\.css|graphiql/index"),
            "GraphiQL IDE exposed", SEV_MEDIUM, "CWE-200",
            "GraphiQL IDE is publicly reachable, providing a browseable GraphQL query interface."));
        out.add(c("/playground", Pattern.compile("(?i)graphql.*playground|<title>[^<]{0,30}playground"),
            "GraphQL Playground exposed", SEV_MEDIUM, "CWE-200",
            "GraphQL Playground is publicly reachable."));

        // ── 15. SOAP / WSDL / older API styles ──────────────────────────────
        for (String p : new String[]{
            "/services", "/services/", "/services/listServices", "/axis2/services/",
            "/axis2/services/listServices", "/axis/services/", "/soap", "/soap/",
            "/wsdl", "/api.wsdl", "/service.wsdl"
        }) {
            Pattern sig = p.contains("axis2") || p.contains("axis/")
                       ? SIG_AXIS2 : SIG_SOAP_WSDL;
            out.add(c(p, sig,
                "SOAP/WSDL endpoint (" + p + ") exposed", SEV_MEDIUM, "CWE-200",
                "A SOAP service descriptor at " + p + " is publicly reachable, disclosing the "
                + "full service operation list."));
        }

        // ── 16. Database admin tools ─────────────────────────────────────────
        for (String p : new String[]{
            "/phpmyadmin/", "/phpmyadmin/index.php", "/pma/", "/myadmin/",
            "/mysql/", "/dbadmin/", "/phpMyAdmin/", "/PMA/",
            "/sql/", "/sqlmanager/", "/mysql-admin/"
        }) {
            out.add(c(p, SIG_PHPMYADM,
                "phpMyAdmin (" + p + ") exposed", SEV_HIGH, "CWE-284",
                "phpMyAdmin is publicly reachable at " + p + ". If credentials are weak or the "
                + "version is outdated this is direct database access; phpMyAdmin has had "
                + "multiple RCE CVEs historically."));
        }
        for (String p : new String[]{
            "/adminer.php", "/adminer/", "/adminer", "/db/adminer.php"
        }) {
            out.add(c(p, SIG_ADMINER,
                "Adminer (" + p + ") exposed", SEV_HIGH, "CWE-284",
                "Adminer (database admin) is publicly reachable at " + p + "."));
        }
        out.add(c("/rockmongo/", Pattern.compile("(?i)RockMongo|<title>[^<]{0,30}RockMongo"),
            "RockMongo exposed", SEV_HIGH, "CWE-284",
            "RockMongo (MongoDB admin) is publicly reachable."));
        out.add(c("/mongo-express/", Pattern.compile("(?i)Mongo Express|mongo-express"),
            "Mongo Express exposed", SEV_HIGH, "CWE-284",
            "Mongo Express (MongoDB admin) is publicly reachable."));
        out.add(c("/redis-commander/", Pattern.compile("(?i)Redis Commander"),
            "Redis Commander exposed", SEV_HIGH, "CWE-284",
            "Redis Commander is publicly reachable."));
        out.add(c("/pgadmin/", Pattern.compile("(?i)pgAdmin|<title>[^<]{0,30}pgAdmin"),
            "pgAdmin exposed", SEV_HIGH, "CWE-284",
            "pgAdmin (PostgreSQL admin) is publicly reachable."));

        // ── 17. Admin / management consoles (login pages, broad coverage) ────
        String[] adminPaths = {
            "/admin", "/admin/", "/admin.php", "/admin/login", "/admin/login.php",
            "/admin/login.html", "/admin/index.php", "/admin/index.html",
            "/admin/admin.php", "/admin/admin-login.php",
            "/administrator", "/administrator/", "/administrator/index.php",
            "/admin1/", "/admin2/", "/admin3/", "/admin-panel/",
            "/admincp/", "/admincp.php", "/control/", "/controlpanel/",
            "/cp/", "/cpanel/", "/dashboard", "/dashboard/", "/dashboard.php",
            "/manage", "/manage/", "/manager/", "/management/", "/mgmt/",
            "/portal/", "/portal/index.php", "/staff/", "/staff/login.php",
            "/sysadmin/", "/system/", "/console/", "/console/login",
            "/backend", "/backend/", "/backoffice/", "/internal/",
            "/private/", "/restricted/", "/secure/", "/secret/",
            "/moderator/", "/moderator/login", "/operator/", "/superuser/"
        };
        for (String p : adminPaths) {
            out.add(c(p, SIG_ADMIN_UI,
                "Admin interface (" + p + ") exposed", SEV_MEDIUM, "CWE-200",
                "An administrative interface is publicly reachable at " + p + ". Confirm "
                + "brute-force protection, MFA, and IP allowlisting are in place."));
        }

        // ── 18. Login pages (broad coverage) ─────────────────────────────────
        for (String p : new String[]{
            "/login", "/login/", "/login.php", "/login.html", "/login.action",
            "/login.do", "/login.jsp", "/login.aspx",
            "/signin", "/signin/", "/sign-in", "/sign_in",
            "/auth", "/auth/", "/auth/login", "/authenticate", "/authentication",
            "/user/login", "/users/login", "/users/sign_in", "/account/login",
            "/customer/account/login", "/my-account/", "/myaccount/",
            "/access", "/oauth/authorize", "/sso", "/sso/login", "/saml/login"
        }) {
            out.add(c(p, SIG_LOGIN_FORM,
                "Login page (" + p + ") reachable", SEV_LOW, "CWE-200",
                "A login form is reachable at " + p + ". Confirm brute-force protection, MFA, "
                + "and rate limiting (separate probes assess these)."));
        }

        // ── 19. Installation / setup scripts ────────────────────────────────
        for (String p : new String[]{
            "/install", "/install/", "/install.php", "/install.html", "/installer/",
            "/setup", "/setup/", "/setup.php", "/setup.html", "/setup-config.php",
            "/upgrade", "/upgrade/", "/upgrade.php",
            "/wizard/", "/firstrun/", "/install/index.php",
            "/admin/install.php", "/admin/setup.php"
        }) {
            out.add(c(p, SIG_INSTALL,
                "Installation script (" + p + ") exposed", SEV_HIGH, "CWE-200",
                "An installation or setup script at " + p + " is publicly reachable. If the "
                + "application is already installed but the installer remains, an attacker may "
                + "be able to re-initialise the database or overwrite configuration."));
        }

        // ── 20. Common file upload / dangerous paths ─────────────────────────
        for (String p : new String[]{
            "/upload/", "/uploads/", "/files/", "/media/uploads/",
            "/wp-content/uploads/", "/assets/uploads/", "/public/uploads/",
            "/storage/", "/storage/app/", "/storage/logs/",
            "/tmp/", "/temp/", "/cache/"
        }) {
            out.add(c(p, SIG_DIRLIST,
                "Directory listing (" + p + ") enabled", SEV_LOW, "CWE-548",
                "The directory at " + p + " has directory listing enabled, exposing every "
                + "uploaded file. Disable with the web server's directory-listing-off directive."));
        }

        // ── 21. Log files ───────────────────────────────────────────────────
        for (String p : new String[]{
            "/access.log", "/access_log", "/logs/access.log",
            "/error.log", "/error_log", "/logs/error.log",
            "/log/access.log", "/log/error.log",
            "/storage/logs/laravel.log", "/laravel.log",
            "/server.log", "/app.log", "/application.log",
            "/var/log/access.log", "/var/log/error.log"
        }) {
            Pattern sig = p.contains("error") ? SIG_LOG_PHP_ERR : SIG_LOG_HTTP;
            out.add(c(p, sig,
                "Log file (" + p + ") exposed", SEV_HIGH, "CWE-538",
                "A log file at " + p + " is publicly downloadable. Logs commonly contain "
                + "sensitive request data (auth headers, session IDs, internal IPs)."));
        }
        // Generic PHP error pattern hits across many of those
        out.add(c("/wp-content/debug.log", SIG_LOG_PHP_ERR,
            "WordPress debug.log exposed", SEV_HIGH, "CWE-538",
            "WordPress debug.log is publicly readable, exposing PHP errors and stack traces."));

        // ── 22. Database dumps and binary data files ─────────────────────────
        out.add(c("/dump.rdb", SIG_DUMP_RDB,
            "Redis dump file (dump.rdb) exposed", SEV_CRITICAL, "CWE-538",
            "A Redis dump.rdb is publicly downloadable. The file contains the entire Redis "
            + "key/value state, frequently including session tokens and cached PII."));
        out.add(c("/dump.pcap", SIG_PCAP,
            "Packet capture (dump.pcap) exposed", SEV_HIGH, "CWE-538",
            "A packet capture file is publicly downloadable. Captures typically contain "
            + "plaintext requests with credentials, tokens, and PII."));
        out.add(c("/capture.pcap", SIG_PCAP,
            "Packet capture (capture.pcap) exposed", SEV_HIGH, "CWE-538",
            "A packet capture file is publicly downloadable."));
        out.add(c("/heapdump", SIG_HEAPDUMP,
            "JVM heap dump (/heapdump) exposed", SEV_CRITICAL, "CWE-538",
            "A JVM heap dump is publicly downloadable. Heap dumps contain in-memory secrets: "
            + "connection strings, signing keys, session tokens, decrypted PII."));

        // ── 23. Vulnerable monitoring/admin dashboards ───────────────────────
        out.add(c("/kibana/", SIG_KIBANA,
            "Kibana exposed", SEV_HIGH, "CWE-284",
            "Kibana is publicly reachable. Restrict to trusted IPs; Kibana grants read access "
            + "to every Elasticsearch index by default."));
        out.add(c("/_plugin/kibana/", SIG_KIBANA,
            "Kibana exposed", SEV_HIGH, "CWE-284",
            "Kibana is publicly reachable at /_plugin/kibana/ (AWS managed)."));
        out.add(c("/grafana/", SIG_GRAFANA,
            "Grafana exposed", SEV_MEDIUM, "CWE-200",
            "Grafana is publicly reachable. Confirm authentication is enabled and anonymous "
            + "viewing is disabled."));
        out.add(c("/grafana/login", SIG_GRAFANA,
            "Grafana login exposed", SEV_LOW, "CWE-200",
            "Grafana login is reachable."));
        out.add(c("/prometheus/", SIG_PROM_UI,
            "Prometheus UI exposed", SEV_MEDIUM, "CWE-200",
            "Prometheus UI is publicly reachable, exposing all metrics and target endpoints."));
        out.add(c("/_cluster/health", Pattern.compile("\"cluster_name\"\\s*:|\"status\"\\s*:\\s*\"(?:green|yellow|red)\""),
            "Elasticsearch cluster health exposed", SEV_HIGH, "CWE-200",
            "Elasticsearch _cluster/health is publicly reachable, exposing cluster status and "
            + "index counts. Other Elasticsearch endpoints may be reachable too."));
        out.add(c("/_cat/indices", Pattern.compile("(?m)^(?:green|yellow|red)\\s+\\S+\\s+\\S+"),
            "Elasticsearch _cat/indices exposed", SEV_HIGH, "CWE-200",
            "Elasticsearch _cat/indices is publicly reachable, listing every index."));
        out.add(c("/_search", Pattern.compile("\"hits\"\\s*:\\s*\\{|\"took\"\\s*:\\s*\\d+|_index"),
            "Elasticsearch _search endpoint exposed", SEV_CRITICAL, "CWE-284",
            "Elasticsearch _search is publicly reachable. Unauthenticated _search means full "
            + "read access to every index in the cluster."));
        out.add(c("/v1/sys/health", SIG_VAULT,
            "HashiCorp Vault /v1/sys/health exposed", SEV_HIGH, "CWE-200",
            "HashiCorp Vault is publicly reachable. Confirm authentication and that the seal "
            + "status endpoint does not leak cluster topology unnecessarily."));

        // ── 24. Cross-domain / mobile-app helper files ───────────────────────
        out.add(c("/crossdomain.xml", SIG_CROSSDOM,
            "crossdomain.xml exposed", SEV_LOW, "CWE-200",
            "A Flash crossdomain.xml is present (Flash is end-of-life). If it contains "
            + "<allow-access-from domain=\"*\"/> the policy is dangerously permissive."));
        out.add(c("/clientaccesspolicy.xml", SIG_CROSSDOM,
            "Silverlight clientaccesspolicy.xml exposed", SEV_LOW, "CWE-200",
            "A Silverlight clientaccesspolicy.xml is present."));
        out.add(c("/robots.txt", SIG_ROBOTS,
            "robots.txt present (informational)", SEV_INFO, "CWE-200",
            "robots.txt is present and may disclose hidden paths via Disallow directives."));
        out.add(c("/sitemap.xml", SIG_SITEMAP,
            "sitemap.xml present (informational)", SEV_INFO, "CWE-200",
            "sitemap.xml is present, listing site URLs."));
        out.add(c("/.well-known/security.txt", Pattern.compile("(?im)^(?:Contact|Expires|Policy|Encryption|Acknowledgments):"),
            "security.txt present (informational)", SEV_INFO, "CWE-200",
            "A security.txt is present (good practice; informational only)."));
        out.add(c("/.well-known/openid-configuration",
            Pattern.compile("\"issuer\"\\s*:|\"authorization_endpoint\"\\s*:|\"token_endpoint\"\\s*:"),
            "OpenID Connect discovery document exposed", SEV_LOW, "CWE-200",
            "An OpenID Connect discovery document is published (informational; expected for "
            + "public OIDC providers)."));

        // ── 25. Common stack-trace / error pages ─────────────────────────────
        for (String p : new String[]{
            "/error/", "/exception", "/stacktrace", "/whoops/", "/__index__",
            "/_errors/", "/error500", "/500.html"
        }) {
            out.add(c(p, SIG_STACK_TRACE,
                "Stack trace / error page (" + p + ") exposed", SEV_HIGH, "CWE-200",
                "A page at " + p + " responds with content matching stack-trace / error patterns."));
        }

        return out;
    }

    /** Compact helper to construct a Candidate without redundant typing in the wordlist. */
    private static Candidate c(String path, Pattern signature, String name,
                                String severity, String cwe, String description) {
        return new Candidate(path, signature, name, severity, cwe, description);
    }

    private static final String REMEDIATION =
        "PRIMARY FIX. Block sensitive admin/management paths at the perimeter:\n"
        + "- Restrict admin, manager, actuator, debug, and config endpoints to trusted source IPs\n"
        + "  (corporate VPN range, jump host) at the load balancer or reverse proxy layer.\n"
        + "- Where feasible, expose management endpoints on a separate non-public port that is\n"
        + "  not routable from the internet.\n"
        + "- Require MFA for all administrative interfaces.\n"
        + "\nSECONDARY CONTROLS:\n"
        + "- Disable framework debug toolbars, profilers, and trace endpoints in production builds\n"
        + "  via environment-specific configuration (APP_ENV=production / DEBUG=False / etc).\n"
        + "- For Spring Boot Actuator, set management.endpoints.web.exposure.include= to the\n"
        + "  minimum required (typically only 'health' for liveness probes) and require\n"
        + "  authentication on every exposed endpoint.\n"
        + "- Remove example applications, default test pages, and documentation bundles from\n"
        + "  production deployments. Tomcat: undeploy /examples, /docs, /manager unless required.\n"
        + "- Strip backup files (*.bak, *.old, *.zip, *.tar.gz, *~) from the document root and\n"
        + "  block these extensions at the proxy.\n"
        + "- Rotate any credential reachable through these endpoints. assume compromise.";

    // ── Main entry point ──────────────────────────────────────────────────────
    static List<ActiveScanResult> probe(ProbeContext ctx, RequestBuilder rb,
                                        HttpSender sender) {
        List<ActiveScanResult> results = new ArrayList<>();

        // Host-wide sweep: run at most once per host per scan.
        if (!SWEPT_HOSTS.add(ctx.host)) return results;

        String origin = extractOrigin(ctx.url);
        if (origin == null) return results;

        // ── Step 1: fingerprint the stack from the endpoint's own response ──
        Set<String> tags = fingerprint(ctx);

        // ── Step 2: build the candidate set ─────────────────────────────────
        // Always include the generic list (small, broadly applicable). When at
        // least one specific tag is identified, append those wordlists too.
        // When no specific tag is identified the generic list IS the fallback.
        LinkedHashSet<Candidate> candidateSet = new LinkedHashSet<>();
        candidateSet.addAll(WORDLISTS.get(T_GENERIC));
        for (String tag : tags) {
            List<Candidate> list = WORDLISTS.get(tag);
            if (list != null) candidateSet.addAll(list);
        }
        // Sort by severity descending so the highest-impact paths probe first
        // within the MAX_REQUESTS budget. Stable sort preserves declaration
        // order within each severity bucket (Critical paths probed in the order
        // they were declared, then High, then Medium, then Low, then Info).
        List<Candidate> candidates = new ArrayList<>(candidateSet);
        candidates.sort(Comparator.comparingInt(c -> sevPriority(c.severity())));

        // ── Step 3: establish soft-404 baseline ─────────────────────────────
        String randomPath = "/burpmax-crawl-" + Long.toHexString(
                System.nanoTime() ^ System.identityHashCode(ctx)) + ".nonexist";
        byte[] baseReq = buildGetRequest(ctx, randomPath);
        String soft404Body = "";
        int    soft404Status = -1;
        if (baseReq != null) {
            ActiveScanner.registerProbeUrl(origin + randomPath);
            HttpSender.Response baseResp = sender.send(ctx.service, baseReq);
            if (baseResp != null) {
                soft404Status = baseResp.statusCode();
                soft404Body   = baseResp.body() != null ? baseResp.body() : "";
            }
        }

        // ── Step 4: sweep candidates with full confirmation discipline ──────
        int sent = 1;   // already sent the soft-404 baseline
        for (Candidate c : candidates) {
            if (sent >= MAX_REQUESTS) break;

            byte[] req = buildGetRequest(ctx, c.path());
            if (req == null) continue;
            ActiveScanner.registerProbeUrl(origin + c.path());

            HttpSender.Response resp = sender.send(ctx.service, req);
            sent++;
            if (resp == null) continue;
            // Only 200 OK counts as a discovered resource.
            if (resp.statusCode() != 200) continue;

            String body = resp.body();
            if (body == null || body.isBlank()) continue;

            // Filter SPA / catch-all soft-404 responses that return 200 for any path.
            if (soft404Status == 200 && isSamePage(body, soft404Body)) continue;

            // Confirm by content signature unique to the resource.
            Matcher m = c.signature().matcher(body);
            if (!m.find()) continue;

            // Re-request confirmation: a real resource is stable, a coincidental
            // match on a dynamic page often isn't. sent++ for the confirmation
            // request keeps MAX_REQUESTS honest.
            HttpSender.Response reResp = sender.send(ctx.service, req);
            sent++;
            if (reResp == null || reResp.statusCode() != 200) continue;
            if (reResp.body() == null || !c.signature().matcher(reResp.body()).find()) continue;

            String matched = m.group();
            String tagStr = tags.isEmpty() ? "generic fallback" : String.join(", ", tags);
            results.add(new ActiveScanResult(
                "Sensitive Endpoint: " + c.name(), c.severity(),
                c.description() + " Discovered by the smart crawler probe "
                + "(stack fingerprint: " + tagStr + "). The resource returned HTTP 200 and its "
                + "content signature was confirmed on a second request, ruling out a soft-404 "
                + "match.",
                "URL: " + origin + c.path() + " | HTTP 200 | Signature matched: "
                + trunc(sanitise(matched), 80)
                + " | Stack: " + tagStr,
                REMEDIATION, c.cwe(),
                origin + c.path(), "(path)", c.path(),
                trunc(new String(req, StandardCharsets.ISO_8859_1), 300),
                trunc(body, 200),
                req, resp.raw(), -1L));
        }
        return results;
    }

    // ── Fingerprinting ─────────────────────────────────────────────────────────

    /**
     * Identify the server stack from passive signals on this endpoint's
     * original response. Inspects the Server / X-Powered-By headers, cookie
     * names (PHPSESSID, JSESSIONID, ...), and a small set of body markers
     * (generator meta tag, framework error pages). Returns the set of stack
     * tags detected (may be empty).
     *
     * Conservative: any signal contributes a tag; nothing is mutually
     * exclusive. WordPress on Apache + PHP produces three tags and three
     * wordlists, by design.
     */
    static Set<String> fingerprint(ProbeContext ctx) {
        Set<String> tags = new LinkedHashSet<>();
        if (ctx.originalResponse == null) return tags;

        String raw;
        try {
            raw = new String(ctx.originalResponse, StandardCharsets.ISO_8859_1);
        } catch (Exception e) { return tags; }

        // Split headers from body once.
        int sep = raw.indexOf("\r\n\r\n");
        String headers = sep >= 0 ? raw.substring(0, sep) : raw;
        String body    = sep >= 0 ? raw.substring(sep + 4) : "";
        String headersLower = headers.toLowerCase();

        // ── Server header ───────────────────────────────────────────────────
        if (headersLower.contains("\nserver: apache") || headersLower.startsWith("server: apache"))
            tags.add(T_APACHE);
        if (headersLower.contains("server: nginx") || headersLower.contains("server: openresty"))
            tags.add(T_NGINX);
        if (headersLower.contains("microsoft-iis") || headersLower.contains("server: microsoft"))
            tags.add(T_IIS);
        if (headersLower.contains("apache-coyote") || headersLower.contains("apache tomcat")
                || headersLower.contains("server: jetty"))
            tags.add(T_TOMCAT);

        // ── X-Powered-By ────────────────────────────────────────────────────
        if (headersLower.contains("x-powered-by: php") || headersLower.contains("x-powered-by:php"))
            tags.add(T_PHP);
        if (headersLower.contains("x-powered-by: asp.net") || headersLower.contains("x-aspnet-version:"))
            tags.add(T_IIS);
        if (headersLower.contains("x-powered-by: express"))
            tags.add(T_NODEJS);

        // ── Cookies ─────────────────────────────────────────────────────────
        if (headersLower.contains("phpsessid="))                                tags.add(T_PHP);
        if (headersLower.contains("jsessionid="))                               tags.add(T_TOMCAT);
        if (headersLower.contains("asp.net_sessionid=")
                || headersLower.contains("aspxauth="))                          tags.add(T_IIS);
        if (headersLower.contains("laravel_session=")
                || headersLower.contains("xsrf-token=") && headersLower.contains("laravel"))
            tags.add(T_LARAVEL);
        if (headersLower.contains("ci_session="))                               tags.add(T_PHP);
        if (headersLower.contains("csrftoken=")
                && (headersLower.contains("sessionid=") || body.contains("django")))
            tags.add(T_DJANGO);
        if (headersLower.contains("_rails_session=")
                || headersLower.contains("rack.session=")
                || headersLower.contains("_session_id="))                       tags.add(T_RAILS);
        if (headersLower.contains("connect.sid="))                              tags.add(T_NODEJS);

        // ── Body markers (only if response has a parseable body) ───────────
        if (!body.isEmpty()) {
            String bl = body.length() > 65_536 ? body.substring(0, 65_536) : body;
            String blLower = bl.toLowerCase();

            // WordPress
            if (blLower.contains("/wp-content/") || blLower.contains("/wp-includes/")
                    || blLower.contains("name=\"generator\" content=\"wordpress")) {
                tags.add(T_WORDPRESS); tags.add(T_PHP);
            }
            // Drupal
            if (blLower.contains("/sites/default/files/") || blLower.contains("drupal.settings")
                    || blLower.contains("name=\"generator\" content=\"drupal")) {
                tags.add(T_DRUPAL); tags.add(T_PHP);
            }
            // Joomla
            if (blLower.contains("name=\"generator\" content=\"joomla")
                    || blLower.contains("/templates/system/")) {
                tags.add(T_JOOMLA); tags.add(T_PHP);
            }
            // Laravel. error pages, csrf-token meta, ignition signature
            if (bl.contains("Laravel") && (blLower.contains("ignition")
                    || blLower.contains("illuminate\\\\") || blLower.contains("name=\"csrf-token\""))) {
                tags.add(T_LARAVEL); tags.add(T_PHP);
            }
            // Django. error page, csrfmiddlewaretoken
            if (bl.contains("DJANGO_SETTINGS_MODULE") || blLower.contains("csrfmiddlewaretoken")
                    || blLower.contains("django.contrib.")) {
                tags.add(T_DJANGO);
            }
            // Rails. Action* exception page, rails-info
            if (bl.contains("ActionController") || bl.contains("ActiveRecord")
                    || blLower.contains("data-turbolinks") || bl.contains("X-Runtime")) {
                tags.add(T_RAILS);
            }
            // Spring Boot. Whitelabel error, Whitelabel error page, Spring CSRF
            if (bl.contains("Whitelabel Error Page") || bl.contains("springframework")
                    || bl.contains("springboot") || bl.contains("_csrf")) {
                tags.add(T_SPRING);
            }
            // Next.js / Node. __NEXT_DATA__ inline JSON, _next/static
            if (bl.contains("__NEXT_DATA__") || blLower.contains("/_next/static/")) {
                tags.add(T_NODEJS);
            }
            // Jenkins. X-Jenkins header is on headers; body has "Jenkins" branding
            if (headersLower.contains("x-jenkins:") || bl.contains("Jenkins ver.")
                    || bl.contains("hudson.model")) {
                tags.add(T_JENKINS);
            }
            // GitLab
            if (headersLower.contains("x-gitlab-") || bl.contains("GitLab.com")
                    || bl.contains("gon.gitlab_url")) {
                tags.add(T_GITLAB);
            }
        }

        return tags;
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    /**
     * Build a GET request for {@code newPath} on the same host, reusing the
     * original request's headers (cookies, auth) but forcing GET with no body.
     * Identical in shape to SensitiveFileProbe.buildGetRequest. kept here as
     * a copy rather than refactored into a shared helper to avoid creating a
     * cross-class dependency where none existed before.
     */
    private static byte[] buildGetRequest(ProbeContext ctx, String newPath) {
        try {
            String reqStr = new String(ctx.originalRequest, StandardCharsets.ISO_8859_1);
            int firstSpace  = reqStr.indexOf(' ');
            int secondSpace = reqStr.indexOf(' ', firstSpace + 1);
            if (firstSpace < 0 || secondSpace < 0) return null;
            String rebuilt = "GET " + newPath + reqStr.substring(secondSpace);

            int hdrEnd = rebuilt.indexOf("\r\n\r\n");
            String headerBlock = hdrEnd >= 0 ? rebuilt.substring(0, hdrEnd) : rebuilt;

            StringBuilder clean = new StringBuilder();
            String[] lines = headerBlock.split("\r\n", -1);
            for (int i = 0; i < lines.length; i++) {
                String lower = lines[i].toLowerCase();
                if (lower.startsWith("content-length:")
                        || lower.startsWith("transfer-encoding:")) continue;
                if (clean.length() > 0) clean.append("\r\n");
                clean.append(lines[i]);
            }
            clean.append("\r\n\r\n");
            return clean.toString().getBytes(StandardCharsets.ISO_8859_1);
        } catch (Exception e) {
            return null;
        }
    }

    private static String extractOrigin(String url) {
        try {
            java.net.URL u = new java.net.URL(url);
            int port = u.getPort();
            String portPart = (port > 0
                    && !(port == 80  && "http".equalsIgnoreCase(u.getProtocol()))
                    && !(port == 443 && "https".equalsIgnoreCase(u.getProtocol())))
                    ? ":" + port : "";
            return u.getProtocol() + "://" + u.getHost() + portPart;
        } catch (Exception e) {
            return null;
        }
    }

    /** Severity sort key. Lower number = higher priority = probed first. */
    private static int sevPriority(String sev) {
        if (SEV_CRITICAL.equals(sev)) return 0;
        if (SEV_HIGH.equals(sev))     return 1;
        if (SEV_MEDIUM.equals(sev))   return 2;
        if (SEV_LOW.equals(sev))      return 3;
        return 4;   // Informational and anything unrecognised
    }

    private static boolean isSamePage(String a, String b) {
        if (a == null || b == null) return false;
        if (a.equals(b)) return true;
        int la = a.length(), lb = b.length();
        if (la == 0 || lb == 0) return false;
        double ratio = (double) Math.min(la, lb) / Math.max(la, lb);
        if (ratio < 0.95) return false;
        int n = Math.min(256, Math.min(la, lb));
        return a.regionMatches(0, b, 0, n);
    }

    private static String sanitise(String s) {
        if (s == null) return "";
        return s.replaceAll("[\\r\\n\\t]+", " ").trim();
    }

    private static String trunc(String s, int n) {
        return s == null ? "" : s.length() > n ? s.substring(0, n) + "..." : s;
    }
}
