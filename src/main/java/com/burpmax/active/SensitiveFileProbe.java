package com.burpmax.active;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.*;
import static com.burpmax.model.Finding.*;

/**
 * Sensitive File Exposure probe.
 *
 * Requests a curated list of well-known sensitive files/directories at the
 * target host root and confirms exposure by matching the response BODY
 * against a content signature unique to each file type. This avoids the
 * single biggest false-positive source for this check class: a SPA that
 * returns "200 OK + index.html" for every unknown path. A 200 status alone
 * is never sufficient — the response body must contain content that only
 * the real sensitive file would produce.
 *
 * Files probed (high-signal subset, one request each):
 *   - .git/config, .git/HEAD          → exposed source control
 *   - .env                            → environment secrets
 *   - .svn/entries                    → exposed Subversion metadata
 *   - .DS_Store                       → macOS directory listing leak
 *   - web.config                      → IIS/.NET config (may contain conn strings)
 *   - composer.json, package.json     → dependency manifest (version disclosure)
 *   - Dockerfile, docker-compose.yml  → build/infra disclosure
 *   - .htaccess                       → Apache config leak
 *   - phpinfo.php                     → full PHP environment dump
 *   - server-status (Apache mod_status) → internal request table
 *   - backup archives (.zip/.sql/.bak) at common names
 *   - WordPress wp-config.php backups
 *
 * Design notes:
 *   - One HTTP request per candidate path. The probe is registered in Tier 2
 *     (fast) but is gated by a per-host run-once guard so a 30-path sweep is
 *     performed at most once per host per scan, not once per endpoint.
 *   - The base request is rebuilt from the endpoint's original request so
 *     auth cookies / headers are preserved (some files are only exposed to
 *     authenticated users behind a misconfigured static handler).
 *   - Every candidate path is registered as a probe URL so the passive
 *     scanner ignores the probe-generated traffic.
 *   - A baseline request to a guaranteed-nonexistent random path is taken
 *     first. If the server returns 200 with a body for that random path
 *     (catch-all SPA / soft-404), the probe still proceeds but requires the
 *     content signature to differ from that soft-404 body — preventing the
 *     SPA index page from matching every signature.
 */
public class SensitiveFileProbe {

    // Per-host run-once guard. A sensitive-file sweep is host-wide, not
    // endpoint-specific, so running it once per endpoint would send the same
    // 30 requests dozens of times. ConcurrentHashMap.newKeySet is thread-safe
    // for the parallel target threads in ActiveScanner.
    private static final Set<String> SWEPT_HOSTS =
            java.util.concurrent.ConcurrentHashMap.newKeySet();

    /** Reset between scans — called by ActiveScanner.clearProbeUrls() path. */
    public static void resetSweptHosts() { SWEPT_HOSTS.clear(); }

    // ── Candidate definition ──────────────────────────────────────────────────
    /**
     * @param path        absolute path to request (always starts with '/')
     * @param signature   regex that MUST match the response body to confirm
     * @param name        short finding label suffix
     * @param severity    finding severity
     * @param cwe          CWE id
     * @param description detail text
     */
    private record Candidate(String path, Pattern signature, String name,
                             String severity, String cwe, String description) {}

    private static Pattern ci(String regex) {
        return Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
    }

    private static final List<Candidate> CANDIDATES = List.of(
        new Candidate("/.git/config",
            ci("\\[core\\][\\s\\S]*repositoryformatversion"),
            "Exposed Git Repository (.git/config)", SEV_HIGH, "CWE-538",
            "The .git/config file is publicly accessible. An attacker can recursively "
            + "download the entire .git directory and reconstruct the complete source code "
            + "history, including secrets, credentials, and removed code that remains in "
            + "old commits."),
        new Candidate("/.git/HEAD",
            ci("^ref:\\s+refs/"),
            "Exposed Git Repository (.git/HEAD)", SEV_HIGH, "CWE-538",
            "The .git/HEAD file is publicly accessible, indicating the .git directory is "
            + "served by the web server. The full repository (source code, commit history, "
            + "and any committed secrets) can be reconstructed by an attacker."),
        new Candidate("/.env",
            ci("(?m)^\\s*[A-Z0-9_]+\\s*=\\s*\\S"),
            "Exposed Environment File (.env)", SEV_CRITICAL, "CWE-538",
            "A .env file is publicly accessible. These files typically contain database "
            + "credentials, API keys, application secrets, and third-party tokens in "
            + "plaintext. Treat every value in this file as compromised."),
        new Candidate("/.svn/entries",
            ci("(?m)^(\\d+|dir|file)\\s*$|svn://|\\bsvn\\b"),
            "Exposed Subversion Metadata (.svn/entries)", SEV_MEDIUM, "CWE-538",
            "Subversion metadata is publicly accessible, allowing partial or full source "
            + "code disclosure depending on the SVN client version used to create it."),
        new Candidate("/.DS_Store",
            Pattern.compile("\\ABud1|\\A.{0,8}Bud1.{0,4}\\x00", Pattern.DOTALL),
            "Exposed macOS Directory File (.DS_Store)", SEV_LOW, "CWE-538",
            "A .DS_Store file is publicly accessible. Parsing it reveals the names of "
            + "every file in the directory, aiding discovery of hidden or backup files."),
        new Candidate("/web.config",
            ci("<configuration[\\s>]|<system\\.web|<connectionStrings"),
            "Exposed IIS Configuration (web.config)", SEV_HIGH, "CWE-538",
            "The web.config file is publicly readable. It commonly contains database "
            + "connection strings, machine keys, and application settings that enable "
            + "further compromise."),
        new Candidate("/.htaccess",
            ci("RewriteRule|RewriteEngine|AuthType|Require\\s+|Order\\s+(allow|deny)"),
            "Exposed Apache Configuration (.htaccess)", SEV_MEDIUM, "CWE-538",
            "The .htaccess file is publicly readable, disclosing URL rewrite rules, "
            + "access control configuration, and the internal directory structure."),
        new Candidate("/composer.json",
            ci("\"(require|require-dev|autoload)\"\\s*:"),
            "Exposed Dependency Manifest (composer.json)", SEV_LOW, "CWE-200",
            "The composer.json dependency manifest is publicly accessible, disclosing "
            + "the exact PHP packages and version constraints used. Attackers cross-"
            + "reference these against CVE databases to target known vulnerabilities."),
        new Candidate("/package.json",
            ci("\"(dependencies|devDependencies|scripts)\"\\s*:"),
            "Exposed Dependency Manifest (package.json)", SEV_LOW, "CWE-200",
            "The package.json manifest is publicly accessible, disclosing the exact "
            + "Node.js dependencies and versions. This accelerates targeted exploitation "
            + "of known vulnerable package versions."),
        new Candidate("/Dockerfile",
            ci("(?m)^\\s*(FROM|RUN|COPY|ENV|EXPOSE|ENTRYPOINT|CMD)\\s+\\S"),
            "Exposed Dockerfile", SEV_MEDIUM, "CWE-538",
            "The Dockerfile is publicly readable, disclosing the base image, build steps, "
            + "exposed ports, and sometimes embedded credentials or build arguments."),
        new Candidate("/docker-compose.yml",
            ci("(?m)^\\s*(services|version|image|environment)\\s*:"),
            "Exposed Docker Compose File", SEV_MEDIUM, "CWE-538",
            "The docker-compose.yml file is publicly readable, disclosing service "
            + "topology, environment variables, exposed ports, and often database "
            + "credentials defined inline."),
        new Candidate("/phpinfo.php",
            ci("phpinfo\\(\\)|PHP Version|<title>phpinfo"),
            "Exposed phpinfo() Page", SEV_MEDIUM, "CWE-200",
            "A phpinfo() page is publicly accessible. It dumps the complete PHP "
            + "configuration, loaded modules, environment variables, server paths, and "
            + "sometimes credentials - a comprehensive reconnaissance resource."),
        new Candidate("/server-status",
            ci("Apache Server Status|Server Version:|Scoreboard:"),
            "Exposed Apache Server Status", SEV_MEDIUM, "CWE-200",
            "The Apache mod_status page is publicly accessible, exposing real-time "
            + "request data including client IPs, requested URLs of other users, and "
            + "internal vhost configuration."),
        new Candidate("/wp-config.php.bak",
            ci("DB_PASSWORD|DB_USER|DB_NAME|AUTH_KEY"),
            "Exposed WordPress Config Backup", SEV_CRITICAL, "CWE-538",
            "A backup of wp-config.php is publicly readable, exposing the WordPress "
            + "database credentials and authentication salts in plaintext."),
        new Candidate("/.aws/credentials",
            ci("aws_access_key_id|aws_secret_access_key|\\[default\\]"),
            "Exposed AWS Credentials File", SEV_CRITICAL, "CWE-538",
            "An AWS credentials file is publicly accessible, exposing access key IDs and "
            + "secret access keys that grant programmatic access to AWS resources."),
        new Candidate("/config.json",
            ci("\"(password|secret|api[_-]?key|token|database)\"\\s*:\\s*\"[^\"]+\""),
            "Exposed Application Config (config.json)", SEV_HIGH, "CWE-538",
            "An application config.json containing what appears to be a password, secret, "
            + "API key, or token is publicly accessible."),
        new Candidate("/backup.sql",
            ci("(?i)(INSERT INTO|CREATE TABLE|DROP TABLE|-- MySQL dump|PostgreSQL database dump)"),
            "Exposed Database Backup (backup.sql)", SEV_CRITICAL, "CWE-538",
            "A SQL database dump is publicly accessible, potentially exposing the entire "
            + "database contents including user records, password hashes, and PII.")
    );

    private static final String REMEDIATION =
        "PRIMARY FIX - Block sensitive paths at the web server:\n"
        + "Deny access to dotfiles, VCS directories, and config/backup files before the\n"
        + "request reaches the application.\n"
        + "  nginx:   location ~ /\\.(git|svn|env|ht) { deny all; return 404; }\n"
        + "  Apache:  <FilesMatch \"^\\.(git|env|htaccess)\"> Require all denied </FilesMatch>\n"
        + "           RedirectMatch 404 /\\.git\n"
        + "\nSECONDARY CONTROLS:\n"
        + "- Never deploy the .git/.svn directory to production - use an export/build\n"
        + "  artefact, not a working copy.\n"
        + "- Keep dependency manifests, Dockerfiles, and compose files out of the web root.\n"
        + "- Store secrets in environment variables injected at runtime or a secrets\n"
        + "  manager - never in files under the document root, even backups.\n"
        + "- Remove backup files (*.bak, *.old, *.sql, *.zip) from production hosts and\n"
        + "  block these extensions at the proxy layer.\n"
        + "- Disable mod_status / phpinfo in production, or restrict to localhost only.\n"
        + "- Rotate any credential that was reachable - assume it is compromised.";

    // ── Main entry point ──────────────────────────────────────────────────────
    static List<ActiveScanResult> probe(ProbeContext ctx, RequestBuilder rb,
                                        HttpSender sender) {
        List<ActiveScanResult> results = new ArrayList<>();

        // Host-wide sweep: run at most once per host per scan.
        // putIfAbsent-style: add() returns false if the host was already present.
        if (!SWEPT_HOSTS.add(ctx.host)) return results;

        String origin = extractOrigin(ctx.url);
        if (origin == null) return results;

        // ── Soft-404 baseline ────────────────────────────────────────────────
        // Request a guaranteed-nonexistent random path. If the server returns a
        // 200 body for it (catch-all SPA), capture that body so signature
        // matching can require the candidate response to DIFFER from it.
        String randomPath = "/burpmax-nonexistent-" + Long.toHexString(
                System.nanoTime() ^ System.identityHashCode(ctx)) + ".txt";
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

        for (Candidate c : CANDIDATES) {
            byte[] req = buildGetRequest(ctx, c.path());
            if (req == null) continue;

            ActiveScanner.registerProbeUrl(origin + c.path());

            HttpSender.Response resp = sender.send(ctx.service, req);
            if (resp == null) continue;

            // Only 200 OK responses can be a real file exposure.
            if (resp.statusCode() != 200) continue;

            String body = resp.body();
            if (body == null || body.isBlank()) continue;

            // Reject if the body is identical (or near-identical) to the soft-404
            // body — that means the server returns the same catch-all page for
            // everything and this is not a genuine file exposure.
            if (soft404Status == 200 && isSamePage(body, soft404Body)) continue;

            // Confirm by content signature — the body must contain content that
            // only the genuine sensitive file would produce.
            Matcher m = c.signature().matcher(body);
            if (!m.find()) continue;

            // Confirmation: re-request once. A genuine static file is stable;
            // a coincidental match on a dynamic page often is not.
            HttpSender.Response reResp = sender.send(ctx.service, req);
            if (reResp == null || reResp.statusCode() != 200) continue;
            if (reResp.body() == null || !c.signature().matcher(reResp.body()).find()) continue;

            String matched = m.group();
            results.add(new ActiveScanResult(
                "Sensitive File Exposure: " + c.name(), c.severity(),
                c.description() + " The file was retrieved with HTTP 200 and its content "
                + "signature was confirmed on a second request, ruling out a coincidental "
                + "soft-404 match.",
                "URL: " + origin + c.path() + " | HTTP 200 | Signature matched: "
                + trunc(sanitise(matched), 80),
                REMEDIATION, c.cwe(),
                origin + c.path(), "(path)", c.path(),
                trunc(new String(req, StandardCharsets.ISO_8859_1), 300),
                trunc(body, 200),
                req, resp.raw(), -1L));
        }
        return results;
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    /**
     * Build a GET request for {@code newPath} on the same host, reusing the
     * original request's headers (cookies, auth) but forcing GET with no body.
     * Mirrors the proven approach used by JwtProbe.buildGetRequest so session
     * context is preserved for files only exposed to authenticated users.
     */
    private static byte[] buildGetRequest(ProbeContext ctx, String newPath) {
        try {
            String reqStr = new String(ctx.originalRequest, StandardCharsets.ISO_8859_1);
            int firstSpace  = reqStr.indexOf(' ');
            int secondSpace = reqStr.indexOf(' ', firstSpace + 1);
            if (firstSpace < 0 || secondSpace < 0) return null;
            // "GET <newPath> HTTP/1.1\r\n...headers...\r\n\r\n[body]"
            String rebuilt = "GET " + newPath + reqStr.substring(secondSpace);

            // Isolate the header block (everything before the blank line).
            int hdrEnd = rebuilt.indexOf("\r\n\r\n");
            String headerBlock = hdrEnd >= 0 ? rebuilt.substring(0, hdrEnd) : rebuilt;

            // Drop body-framing headers — this is now a bodyless GET.
            StringBuilder clean = new StringBuilder();
            String[] lines = headerBlock.split("\r\n", -1);
            for (int i = 0; i < lines.length; i++) {
                String lower = lines[i].toLowerCase();
                if (lower.startsWith("content-length:")
                        || lower.startsWith("transfer-encoding:")) continue;
                if (clean.length() > 0) clean.append("\r\n");
                clean.append(lines[i]);
            }
            // Exactly one CRLFCRLF terminates the header block; no body follows.
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

    /**
     * Heuristic same-page check. Two bodies are treated as the same catch-all
     * page if their lengths are within 5% of each other AND their first 256
     * characters are identical (SPA shells are byte-stable in their head).
     */
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

    /** Strip CR/LF and control chars so multi-line file content stays on one evidence line. */
    private static String sanitise(String s) {
        if (s == null) return "";
        return s.replaceAll("[\\r\\n\\t]+", " ").trim();
    }

    private static String trunc(String s, int n) {
        return s == null ? "" : s.length() > n ? s.substring(0, n) + "..." : s;
    }
}
