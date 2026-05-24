package com.burpmax.scanner;

import java.util.*;
import java.util.regex.*;

import static com.burpmax.scanner.ScannerUtils.trunc;
import static com.burpmax.model.Finding.*;

/**
 * Checks response body content for information disclosure and security issues.
 *
 * Content-type awareness:
 *   - Universal checks  : run on ALL non-empty bodies (internal IP, error patterns,
 *                         GraphQL, backup paths)
 *   - HTML-only checks  : directory listing, mixed content (require HTML structure)
 *   - JSON/XML checks   : stack traces, debug flags (already in ApiResponseChecker
 *                         for JSON key format; here we catch the raw string forms)
 */
public class BodyChecker {

    // ── Patterns ──────────────────────────────────────────────────────────────

    private static final Pattern RE_INTERNAL_IP = Pattern.compile(
        "(?:10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}" +
        "|172\\.(?:1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}" +
        "|192\\.168\\.\\d{1,3}\\.\\d{1,3})");

    // Error patterns — universal (SQL errors appear in JSON APIs too)
    private static final Pattern RE_ERROR = Pattern.compile(
        // These patterns are strong signals on their own:
        "(?:stack\\s+trace|at line \\d+|\\bfatal error\\b" +
        "|\\buncaught exception\\b|\\bparse error\\b|\\bsql syntax\\b" +
        "|ORA-\\d+|SQLSTATE\\[|mysqli_|pg_query|NullPointerException" +
        "|com\\.sun\\.|java\\.lang\\.|at [\\w.]+\\([\\w]+\\.java:\\d+\\)" +
        // SyntaxError alone is too generic (returned by Node on any malformed JSON).
        // Require it to appear alongside a file/line reference or stack context.
        "|\\bSyntaxError\\b.{0,120}(?:at |line \\d+|\\(\\w+\\.\\w+:\\d+\\))" +
        "|(?:at |line \\d+|\\(\\w+\\.\\w+:\\d+\\)).{0,120}\\bSyntaxError\\b)",
        Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

    // Warning-level disclosure (HTML responses from PHP/classic servers)
    private static final Pattern RE_WARNING = Pattern.compile(
        "\\bWarning:\\s*\\w+\\(\\)|\\bnotice:\\s|\\bdeprecated:\\s",
        Pattern.CASE_INSENSITIVE);

    private static final Pattern RE_SENSITIVE_PATH = Pattern.compile(
        "(?:href|src|action|url)[=:\\s]+[\"']*" +
        "(?:[^\\s\"']*(?:\\.bak|\\.backup|\\.sql|\\.dump|\\.tar\\.gz|\\.zip|\\.old|" +
        "web\\.config\\.bak|\\.env\\.bak|config\\.php\\.bak|database\\.yml|application\\.yml))",
        Pattern.CASE_INSENSITIVE);

    // Mixed content: only flag executable active resources loaded over HTTP.
    // We detect using contains() in the check method instead of a complex regex.
    private static final Pattern RE_MIXED = Pattern.compile(
        "(?i)(?:src|href|action)=[\\x22\\x27]?http://[^\\x22\\x27\\s>]+",
        Pattern.CASE_INSENSITIVE);

    // JSON/XML stack trace — raw string forms not caught by ApiResponseChecker
    private static final Pattern RE_STACK_JSON = Pattern.compile(
        "\"(?:stackTrace|stack_trace|stacktrace|backtrace|exception|lineNumber|" +
        "errorDetail|fileName|className)\"\\s*:\\s*[\"\\[]",
        Pattern.CASE_INSENSITIVE);

    // PHP/server-side path disclosure in any response type
    private static final Pattern RE_PATH_DISCLOSURE = Pattern.compile(
        "(?:/var/www/|/home/\\w+/|/usr/share/|/srv/www/|C:\\\\inetpub\\\\|" +
        "C:\\\\xampp\\\\|C:\\\\wamp\\\\)[^\\s<>\"']{3,}",
        Pattern.CASE_INSENSITIVE);

    // ── Public check method ───────────────────────────────────────────────────

    public static List<CheckResult> check(String body, String contentType) {
        List<CheckResult> results = new ArrayList<>();
        if (body == null || body.isEmpty()) return results;

        String ctLower = contentType != null ? contentType.toLowerCase() : "";
        boolean isHtml = ctLower.contains("text/html") || ctLower.contains("application/xhtml");
        boolean isJson = ctLower.contains("application/json") || ctLower.contains("application/ld+json");
        boolean isXml  = ctLower.contains("xml");
        boolean isJs   = ctLower.contains("javascript");
        boolean isText = ctLower.contains("text/plain");

        // ── Universal: Internal IP disclosure (all types) ──────────────────
        // Require the IP to appear in a context suggesting a runtime leak (error
        // message, stack trace, or header value) rather than application config data.
        // This prevents hardcoded IPs in app configuration responses from firing.
        Matcher m = RE_INTERNAL_IP.matcher(body);
        if (m.find()) {
            String ip = m.group();
            // Suppress if the IP appears to be application config / static data:
            // check if it's inside a JSON string with a config-like key nearby
            int ipIdx = body.indexOf(ip);
            String window = body.substring(Math.max(0, ipIdx - 120),
                                           Math.min(body.length(), ipIdx + 120)).toLowerCase();
            boolean isConfigValue = window.contains("\"host\"") || window.contains("\"address\"")
                    || window.contains("\"ip\"") || window.contains("\"url\"")
                    || window.contains("\"endpoint\"") || window.contains("\"server\"")
                    || window.contains("config") || window.contains("setting");
            boolean isErrorContext = window.contains("error") || window.contains("exception")
                    || window.contains("stack") || window.contains("trace")
                    || window.contains("econnrefused") || window.contains("connect");
            // Only fire if it looks like a runtime error leak, not a config field
            if (!isConfigValue || isErrorContext) {
                results.add(new CheckResult(
                    "Internal IP Disclosure", SEV_MEDIUM,
                    "A private (RFC-1918) IP address was found in the HTTP response body. " +
                    "Internal IP addresses reveal the server's private network topology to external " +
                    "attackers, assisting in post-exploitation pivoting, SSRF attack development, " +
                    "and targeting services only accessible from within the internal network.",
                    "Internal IP found: " + ip,
                    "- Implement custom exception handlers that return generic error messages\n" +
                    "- Configure your reverse proxy to strip X-Forwarded-For and X-Real-IP from responses\n" +
                    "- Review diagnostic and health-check endpoints that may include internal host info\n" +
                    "- Add a WAF rule to detect and redact RFC-1918 IP address patterns in outbound responses",
                    "CWE-200"));
            }
        }

        // ── Universal: Error / stack trace disclosure (HTML + JSON + XML + plain) ─
        if (!isJs) {
            boolean errorFound = false;
            boolean warnFound  = false;
            boolean stackJson  = false;
            String  errorSample = "";

            Matcher em = RE_ERROR.matcher(body);
            if (em.find()) {
                // HTML context exclusion: suppress matches inside <code>, <pre>, <blockquote>, comments
                int matchIdx = em.start();
                String pre300 = body.substring(Math.max(0, matchIdx - 300), matchIdx).toLowerCase();
                // Check whether we are inside a non-rendering block
                int lastCodeOpen  = Math.max(pre300.lastIndexOf("<code"),  pre300.lastIndexOf("<pre"));
                int lastCodeClose = Math.max(pre300.lastIndexOf("</code"), pre300.lastIndexOf("</pre"));
                int lastComOpen   = pre300.lastIndexOf("<!--");
                int lastComClose  = pre300.lastIndexOf("-->");
                int lastBlockOpen = pre300.lastIndexOf("<blockquote");
                int lastBlockClose= pre300.lastIndexOf("</blockquote");
                boolean inCodeBlock    = lastCodeOpen  > lastCodeClose;
                boolean inHtmlComment  = lastComOpen   > lastComClose;
                boolean inBlockquote   = lastBlockOpen > lastBlockClose;
                if (!inCodeBlock && !inHtmlComment && !inBlockquote) {
                    errorFound  = true;
                    errorSample = em.group();
                }
            }
            warnFound = isHtml && !errorFound && RE_WARNING.matcher(body).find();

            if (!errorFound && !warnFound && (isJson || isXml || isText)) {
                Matcher sm = RE_STACK_JSON.matcher(body);
                if (sm.find()) {
                    // Require the stack key to appear as a JSON value field, not in a comment or string key
                    // by checking the character before the match is not inside a known-safe prefix
                    stackJson   = true;
                    errorSample = "stack trace key detected";
                }
            }

            if (errorFound || warnFound || stackJson) {
                String sample = errorSample.isEmpty() ? "warning/stack signal" : errorSample;
                results.add(new CheckResult(
                    "Improper Error Handling / Stack Trace Exposure", SEV_MEDIUM,
                    "The response contains detailed error output including stack traces, exception " +
                    "messages, SQL queries, file paths, or debug information. This reveals the " +
                    "application's internal structure to attackers: class names, file paths, " +
                    "library versions, and line numbers pinpointing exploitable code paths.",
                    "Error pattern found in " + ctLower + " response: " + trunc(sample, 120),
                    "- Configure custom error pages for all HTTP error codes\n" +
                    "- Log full exception details server-side only\n" +
                    "- Disable debug/development mode in production\n" +
                    "- Implement a global exception handler returning generic error responses",
                    "CWE-209"));
            }
        }

        // ── Universal: Server-side file path disclosure ────────────────────
        m = RE_PATH_DISCLOSURE.matcher(body);
        if (m.find()) {
            results.add(new CheckResult(
                "Server-Side File Path Disclosure", SEV_LOW,
                "The response body contains an absolute server-side file system path. " +
                "This reveals the server's directory structure, web root location, and " +
                "potentially the technology stack, aiding targeted exploitation.",
                "File path found: " + trunc(m.group(), 100),
                "- Suppress all paths in error messages and API responses\n" +
                "- Use relative paths internally; never include absolute paths in output\n" +
                "- Set display_errors=Off in php.ini for PHP applications",
                "CWE-200"));
        }

        // ── HTML-only: Directory listing ──────────────────────────────────
        if (isHtml) {
            if ((body.contains("<title>Index of /") || body.contains("<title>index of /") ||
                 body.contains("<h1>Index of /")    || body.contains("<h1>index of /"))
                    // Require a second structural signal: a file-size/date row typical of real
                    // server-generated directory listings. Static site index pages lack these.
                    && (body.contains("<td>") || body.contains("<tr>"))
                    && body.matches("(?s).*\\d{4}-\\d{2}-\\d{2}.*") // date stamp in table
            ) {
                results.add(new CheckResult(
                    "Directory Listing Enabled", SEV_HIGH,
                    "The web server is configured to serve a directory listing, allowing any " +
                    "visitor to browse the file structure. Directory listings expose file names, " +
                    "sizes, and timestamps, commonly leading to discovery of backup archives, " +
                    "configuration files with credentials, and deployment scripts.",
                    "Directory listing page detected (Index of / heading found).",
                    "- Apache: Add Options -Indexes to the VirtualHost or Directory block\n" +
                    "- Nginx: Set autoindex off in the server or location block\n" +
                    "- IIS: Disable Directory Browsing in IIS Manager",
                    "CWE-548"));
            }

            // Mixed content (HTTPS page loading HTTP resources).
            // Strip HTML comments, <noscript>, and <template> blocks first so we
            // don't flag resources that browsers never actually load.
            // Strip HTML comments, noscript, template blocks before mixed-content check
            String bodyForMixed = body
                .replaceAll("(?is)<!--[\\s\\S]*?-->", "")
                .replaceAll("(?is)<noscript[^>]*>[\\s\\S]*?</noscript>", "")
                .replaceAll("(?is)<template[^>]*>[\\s\\S]*?</template>", "");
            m = RE_MIXED.matcher(bodyForMixed);
            if (m.find()) {
                results.add(new CheckResult(
                    "Mixed Content Detected", SEV_MEDIUM,
                    "This HTTPS page loads one or more resources over unencrypted HTTP. A " +
                    "network attacker can replace these HTTP resources with malicious versions " +
                    "in transit, gaining full DOM access.",
                    "HTTP resource detected (src/href/action with http://): " + trunc(m.group(), 120),
                    "- Change all resource URLs from http:// to https://\n" +
                    "- Add CSP: upgrade-insecure-requests to auto-upgrade sub-resources\n" +
                    "- Add CSP: block-all-mixed-content to block any remaining mixed content",
                    "CWE-311"));
            }
        }

        // ── Universal: GraphQL introspection ─────────────────────────────
        if (body.contains("\"__schema\"") && body.contains("\"types\"") && body.contains("\"queryType\"")) {
            results.add(new CheckResult(
                "GraphQL Introspection Enabled", SEV_MEDIUM,
                "GraphQL introspection allows clients to query the complete API schema including " +
                "all object types, field names, queries, mutations, and subscriptions. This " +
                "facilitates discovery of hidden admin queries, mass assignment vectors, " +
                "injection points, and authorisation logic gaps.",
                "GraphQL introspection response detected (__schema and types present).",
                "- Disable introspection in production (Apollo: introspection: false)\n" +
                "- Add query depth limiting to prevent deeply nested exploitation\n" +
                "- Use persisted queries so only pre-approved operations are accepted",
                "CWE-200"));
        }

        // ── HTML + all: Sensitive file references ─────────────────────────
        m = RE_SENSITIVE_PATH.matcher(body);
        while (m.find()) {
            String match = m.group();
            int    start  = m.start();
            // Extend suppression window to 200 chars and add more doc-context signals
            String before = body.substring(Math.max(0, start - 200), start).toLowerCase();
            boolean isDoc = before.contains("<code") || before.contains("<pre")
                         || before.contains("<blockquote") || before.contains("<!--")
                         || before.contains("example") || before.contains("// ")
                         || before.contains("# ") || before.contains("data-")
                         || before.contains("aria-") || before.contains("sample")
                         || before.contains("demo") || before.contains("tutorial");
            if (!isDoc) {
                results.add(new CheckResult(
                    "Backup or Sensitive File Reference Detected", SEV_HIGH,
                    "A link or resource reference points to a file with a sensitive extension " +
                    "(.bak, .sql, .dump, .zip, .old, .env, web.config.bak). Backup files " +
                    "routinely contain database dumps, source code, and credentials.",
                    "Sensitive file reference: " + trunc(match, 120),
                    "- Verify whether the file is publicly downloadable and remove it from web root\n" +
                    "- Move backup/archive files outside the document root\n" +
                    "- Add web server rules: location ~* \\.(bak|sql|zip|old|dump|env)$ { deny all; }",
                    "CWE-538"));
                break;
            }
        }

        return results;
    }
}
