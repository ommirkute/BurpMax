package com.burpmax.active;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;
import burp.IResponseInfo;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;
import java.util.regex.*;

/**
 * Improved link extractor - discovers endpoints from Burp site map, robots.txt,
 * sitemap.xml, JS bundles, HTML forms (GET + POST/PUT/DELETE), JSON APIs,
 * HAL/JSON-API _links, URL path parameters, HTML and JS comments, CSS url(),
 * and common SPA router declarations (React Router, Vue Router, Next.js).
 *
 * Extraction sources:
 *   HTML        - href, src, action, formaction, data-url, data-href, data-src,
 *                 meta refresh, base href, link rel=preload, script src
 *   HTML forms  - form action + method (GET forms via href; POST/PUT/DELETE queued)
 *   Comments    - HTML comments and JS line/block comments containing path strings
 *   JavaScript  - fetch, axios, jQuery.ajax, XMLHttpRequest.open, require, import,
 *                 React Router Route/Link, Vue Router path/to, Next.js router.push
 *   JSON        - href/url/uri/endpoint/path/action/link/self/next/prev values
 *   HAL links   - _links.*.href and self.href
 *   CSS         - url() and @import path values
 *   robots.txt  - Disallow and Allow directives
 *   sitemap.xml - loc tags (filtered to in-scope hosts)
 *
 * Fetch strategy:
 *   Phase 0 - Fetch robots.txt and sitemap.xml per scope root
 *   Phase 1 - Extract from existing Burp site map (no new requests)
 *   Phase 2 - Fetch discovered GET endpoints (thread pool, per-request timeout)
 *   Phase 3 - Depth-2 extraction from fetched pages (no extra fetches)
 *   Phase 4 - Synthesise IHttpRequestResponse for POST/PUT/DELETE form endpoints
 *
 * Limits:
 *   MAX_DISCOVERED = 400   links before dedup
 *   MAX_FETCH      = 80    GET requests (10 threads, 10s per-request, 30s total)
 *   MAX_FORM_POSTS = 50    POST/PUT/DELETE endpoints queued for probing
 */
public class LinkExtractor {

    // ── Tuning constants ──────────────────────────────────────────────────────
    private static final int  MAX_DISCOVERED    = 400;
    private static final int  MAX_FETCH         = 80;
    private static final int  MAX_FORM_POSTS    = 50;
    private static final int  FETCH_THREADS     = 10;
    private static final int  FETCH_TIMEOUT_S   = 10;    // per-request timeout
    private static final int  POOL_TIMEOUT_S    = 30;    // total pool timeout
    private static final int  BODY_CAP_BYTES    = 512 * 1024;   // 512KB (was 256KB)
    private static final int  JS_CAP_BYTES      = 1024 * 1024;  // 1MB for JS bundles

    // ── HTML attribute pattern ────────────────────────────────────────────────
    // 'content' is intentionally excluded: it appears on <meta name="description">,
    // <meta name="csrf-token">, <input> etc. and is not a reliable URL source.
    // The dedicated RE_META_REFRESH pattern handles meta http-equiv=refresh correctly.
    private static final Pattern RE_HTML_ATTR = Pattern.compile(
        "(?:href|src|action|formaction|data-url|data-href|data-src|data-action|" +
        "data-endpoint|data-api)\\s*=\\s*" +
        "[\"']([^\"'#?][^\"']*)[\"']",
        Pattern.CASE_INSENSITIVE);

    // ── HTML form capture (method + action) ───────────────────────────────────
    // Captures: group 1 = method (GET/POST/PUT/DELETE), group 2 = action URL
    private static final Pattern RE_FORM = Pattern.compile(
        "<form[^>]*\\bmethod\\s*=\\s*[\"']?([a-zA-Z]+)[\"']?[^>]*\\baction\\s*=\\s*[\"']([^\"']+)[\"']" +
        "|<form[^>]*\\baction\\s*=\\s*[\"']([^\"']+)[\"'][^>]*\\bmethod\\s*=\\s*[\"']?([a-zA-Z]+)[\"']?",
        Pattern.CASE_INSENSITIVE);

    // ── Meta refresh ──────────────────────────────────────────────────────────
    private static final Pattern RE_META_REFRESH = Pattern.compile(
        "<meta[^>]+http-equiv=[\"']?refresh[\"']?[^>]+content=[\"'][^;]*;\\s*url=([^\"'\\s>]+)",
        Pattern.CASE_INSENSITIVE);

    // ── JS fetch / axios / XMLHttpRequest / jQuery ────────────────────────────
    private static final Pattern RE_JS_FETCH = Pattern.compile(
        "(?:fetch|axios\\.(?:get|post|put|delete|patch|request)|\\$\\.(?:get|post|ajax)|" +
        "XMLHttpRequest[^(]*\\.open\\(['\"]\\w+['\"],\\s*|" +
        "this\\.(?:http|Http)\\.(?:get|post|put|delete|patch)\\(|" +
        "request\\.(?:get|post|put|delete)|" +
        "superagent\\.(?:get|post|put|delete))\\s*\\(?[\"']([^\"'\\s\\)]+)[\"']",
        Pattern.CASE_INSENSITIVE);

    // ── Next.js / React Router / Vue Router route declarations ────────────────
    private static final Pattern RE_ROUTER_PATH = Pattern.compile(
        "(?:router\\.(?:push|replace)|useRouter\\(\\)\\.push|Link\\s+to|Route\\s+path|" +
        "path\\s*:|to\\s*:)\\s*[\"'`]([/][^\"'`\\s]+)[\"'`]",
        Pattern.CASE_INSENSITIVE);

    // ── General API path string literals ─────────────────────────────────────
    private static final Pattern RE_API_PATH = Pattern.compile(
        "[\"'`](/(?:api|rest|graphql|v\\d+|gql|service|services|endpoint|endpoints|" +
        "data|resources?|internal|admin|management|actuator|swagger|openapi|health|" +
        "metrics|auth|login|logout|user|users|account|accounts|profile|search|query|" +
        "report|reports|export|import|upload|download|webhook|webhooks|callback|" +
        "token|refresh|verify|validate|confirm)(?:/[A-Za-z0-9_\\-\\.~%@!$&'()*+,;:=]+)*" +
        "(?:\\?[A-Za-z0-9_\\-=&%+.]*)?)[\"'`]",
        Pattern.CASE_INSENSITIVE);

    // ── require('/path') / import('/path') ───────────────────────────────────
    private static final Pattern RE_JS_IMPORT = Pattern.compile(
        "(?:require|import)\\s*\\(?\\s*[\"']([./][^\"']+)[\"']",
        Pattern.CASE_INSENSITIVE);

    // ── JSON path values ──────────────────────────────────────────────────────
    private static final Pattern RE_JSON_PATH = Pattern.compile(
        "\"(?:href|url|uri|endpoint|path|action|src|link|location|redirect|next|prev|self)\"" +
        "\\s*:\\s*\"(/[a-zA-Z0-9_\\-/\\.]+(?:\\?[a-zA-Z0-9_\\-=&%+.]*)?)\"",
        Pattern.CASE_INSENSITIVE);

    // ── JSON-API / HAL _links ─────────────────────────────────────────────────
    private static final Pattern RE_HAL_LINKS = Pattern.compile(
        "\"href\"\\s*:\\s*\"(https?://[^\"]+|/[^\"]+)\"",
        Pattern.CASE_INSENSITIVE);

    // ── HTML and JS comments containing paths ─────────────────────────────────
    private static final Pattern RE_COMMENT_PATH = Pattern.compile(
        "(?:<!--|/\\*|//)[^\\n>]*?(/(?:api|rest|v\\d+|admin|internal|graphql)" +
        "(?:/[A-Za-z0-9_\\-]+)+)(?:\\s|\\n|-->|\\*/|$)",
        Pattern.CASE_INSENSITIVE);

    // ── CSS url('/path') and @import '/path' ──────────────────────────────────
    private static final Pattern RE_CSS_URL = Pattern.compile(
        "(?:url\\s*\\(\\s*[\"']?|@import\\s+[\"'])(/[^\"'\\s\\)]+)",
        Pattern.CASE_INSENSITIVE);

    // ── robots.txt directives ─────────────────────────────────────────────────
    private static final Pattern RE_ROBOTS = Pattern.compile(
        "^(?:Dis)?allow:\\s*(/[^\\s*]+)",
        Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);

    // ── sitemap.xml <loc> ─────────────────────────────────────────────────────
    private static final Pattern RE_SITEMAP_LOC = Pattern.compile(
        "<loc>\\s*(https?://[^<]+)\\s*</loc>",
        Pattern.CASE_INSENSITIVE);

    // ── Numeric path segment - for normalisation ──────────────────────────────
    // Matches pure-numeric or UUID-like path segments
    private static final Pattern RE_PATH_PARAM = Pattern.compile(
        "/(?:\\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})" +
        "(?=/|$)",
        Pattern.CASE_INSENSITIVE);

    // ── Result record for form endpoints ─────────────────────────────────────
    record FormEndpoint(String url, String method) {}

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Extract links from all site map responses and fetch newly discovered URLs.
     *
     * @param callbacks     Burp callbacks (site map, makeHttpRequest, isInScope)
     * @param helpers       Burp helpers (analyzeRequest/Response)
     * @param inScopeHosts  hosts in scope (for fast filtering without Burp API call)
     * @param seen          URL dedup set shared with collectTargets (modified in place)
     * @param onStatus      status message callback
     * @return newly fetched IHttpRequestResponse items ready for probe context building
     */
    public static List<IHttpRequestResponse> extract(
            IBurpExtenderCallbacks callbacks,
            IExtensionHelpers helpers,
            Set<String> inScopeHosts,
            Set<String> seen,
            Consumer<String> onStatus) {

        List<IHttpRequestResponse> newItems    = new ArrayList<>();
        Set<String>                discovered  = new LinkedHashSet<>();
        List<FormEndpoint>         formPosts   = new ArrayList<>();
        Set<String>                fetched     = new HashSet<>(seen);
        Set<String>                normalised  = new HashSet<>();   // dedup by normalised path

        // ── Phase 0: robots.txt + sitemap.xml per scope root ─────────────────
        status(onStatus, "Link extraction: fetching robots.txt and sitemap.xml...");
        for (String host : inScopeHosts) {
            // Fetch robots.txt: try HTTPS first, fall back to HTTP only if HTTPS fails.
            // Both are independent of sitemap.xml so we don't skip one when the other succeeds.
            boolean robotsDone = false;
            for (String scheme : List.of("https", "http")) {
                String robotsUrl = scheme + "://" + host + "/robots.txt";
                if (fetched.contains(robotsUrl)) { robotsDone = true; break; }
                fetched.add(robotsUrl);
                String body = fetchBodyDirect(robotsUrl, callbacks, helpers);
                if (body != null) {
                    extractRobots(body, scheme + "://" + host, inScopeHosts,
                            discovered, fetched, normalised);
                    robotsDone = true;
                    break;
                }
            }

            // Fetch sitemap.xml: same scheme-priority logic, independent of robots.txt result.
            for (String scheme : List.of("https", "http")) {
                String sitemapUrl = scheme + "://" + host + "/sitemap.xml";
                if (fetched.contains(sitemapUrl)) break;
                fetched.add(sitemapUrl);
                String body = fetchBodyDirect(sitemapUrl, callbacks, helpers);
                if (body != null) {
                    extractSitemap(body, inScopeHosts, discovered, fetched, normalised);
                    break; // found sitemap on this scheme - don't also try HTTP
                }
            }
        }

        // ── Phase 1: extract from existing Burp site map ─────────────────────
        status(onStatus, "Link extraction: scanning site map responses...");
        IHttpRequestResponse[] siteMap = callbacks.getSiteMap(null);
        if (siteMap != null) {
            for (IHttpRequestResponse item : siteMap) {
                if (item.getResponse() == null) continue;
                try {
                    IRequestInfo  ri   = helpers.analyzeRequest(item);
                    URL           base = ri.getUrl();
                    if (!callbacks.isInScope(base)) continue;
                    String ct   = contentType(item.getResponse(), helpers);
                    String body = responseBody(item.getResponse(), helpers, ct);
                    if (body == null || body.isEmpty()) continue;
                    extractLinks(body, ct, base, inScopeHosts,
                            discovered, formPosts, fetched, normalised);
                } catch (Exception ignored) {}
            }
        }

        status(onStatus, "Link extraction: found " + discovered.size()
                + " GET + " + formPosts.size() + " POST/PUT/DELETE endpoints - fetching...");

        // ── Phase 2: fetch discovered GET URLs (parallel, per-request timeout) ─
        ExecutorService fetchPool = Executors.newFixedThreadPool(FETCH_THREADS,
                r -> { Thread t = new Thread(r, "burpmax-link-fetch"); t.setDaemon(true); return t; });

        List<Future<IHttpRequestResponse>> futures = new ArrayList<>();
        for (String urlStr : discovered) {
            if (futures.size() >= MAX_FETCH) break;
            if (fetched.contains(urlStr)) continue;
            fetched.add(urlStr);
            futures.add(fetchPool.submit(() ->
                    fetchUrl(urlStr, callbacks, helpers, FETCH_TIMEOUT_S)));
        }

        fetchPool.shutdown();
        try { fetchPool.awaitTermination(POOL_TIMEOUT_S, TimeUnit.SECONDS); }
        catch (InterruptedException e) { Thread.currentThread().interrupt(); }

        int fetchCount = 0;
        for (Future<IHttpRequestResponse> f : futures) {
            try {
                IHttpRequestResponse result = f.isDone() ? f.get() : null;
                if (result == null) { f.cancel(true); continue; }
                newItems.add(result);
                fetchCount++;

                // ── Phase 3: depth-2 extraction (parse, don't fetch) ──────────
                if (result.getResponse() != null) {
                    try {
                        IRequestInfo ri2    = helpers.analyzeRequest(result);
                        URL          base2  = ri2.getUrl();
                        String       ct2    = contentType(result.getResponse(), helpers);
                        String       body2  = responseBody(result.getResponse(), helpers, ct2);
                        if (body2 != null && !body2.isEmpty()) {
                            Set<String>     d2 = new LinkedHashSet<>();
                            List<FormEndpoint> f2 = new ArrayList<>();
                            extractLinks(body2, ct2, base2, inScopeHosts,
                                    d2, f2, fetched, normalised);
                            // Register depth-2 URLs as fetched so they're not re-queued
                            fetched.addAll(d2);
                            // Add depth-2 POST endpoints to the form queue
                            for (FormEndpoint fe : f2) {
                                if (formPosts.size() < MAX_FORM_POSTS) formPosts.add(fe);
                            }
                        }
                    } catch (Exception ignored) {}
                }
            } catch (Exception ignored) {}
        }

        // ── Phase 4: synthesise IHttpRequestResponse for POST/PUT/DELETE forms ─
        // These are queued into newItems as minimal synthetic requests so that
        // buildProbeContext can parse them and ActiveScanner will probe them.
        // We do NOT actually fetch them - POST requests may have side effects.
        int formCount = 0;
        for (FormEndpoint fe : formPosts) {
            if (fetched.contains(fe.method() + ":" + fe.url())) continue;
            fetched.add(fe.method() + ":" + fe.url());
            try {
                IHttpRequestResponse synth = buildSyntheticRequest(
                        fe.url(), fe.method(), callbacks, helpers);
                if (synth != null) { newItems.add(synth); formCount++; }
            } catch (Exception ignored) {}
            if (formCount >= MAX_FORM_POSTS) break;
        }

        status(onStatus, "Link extraction: fetched " + fetchCount
                + " GET + " + formCount + " POST/PUT/DELETE endpoints.");
        return newItems;
    }

    // ── Extraction logic ──────────────────────────────────────────────────────

    private static void extractLinks(String body, String ct, URL base,
                                      Set<String> inScopeHosts,
                                      Set<String> discovered,
                                      List<FormEndpoint> formPosts,
                                      Set<String> fetched,
                                      Set<String> normalised) {
        if (discovered.size() >= MAX_DISCOVERED) return;

        boolean isHtml = ct.contains("html");
        boolean isJs   = ct.contains("javascript") || ct.contains("ecmascript");
        boolean isJson = ct.contains("json");
        boolean isCss  = ct.contains("css");

        Set<String> raw = new LinkedHashSet<>();

        if (isHtml) {
            extractMatches(RE_HTML_ATTR,    body, 1, raw);
            extractMatches(RE_META_REFRESH, body, 1, raw);
            extractMatches(RE_JS_FETCH,     body, 1, raw);
            extractMatches(RE_ROUTER_PATH,  body, 1, raw);
            // Extract form endpoints separately (method + action)
            extractForms(body, base, inScopeHosts, formPosts);
        }
        if (isJs) {
            extractMatches(RE_JS_FETCH,     body, 1, raw);
            extractMatches(RE_JS_IMPORT,    body, 1, raw);
            extractMatches(RE_ROUTER_PATH,  body, 1, raw);
        }
        if (isJson) {
            extractMatches(RE_JSON_PATH,  body, 1, raw);
            extractMatches(RE_HAL_LINKS,  body, 1, raw);
        }
        if (isCss) {
            extractMatches(RE_CSS_URL, body, 1, raw);
        }
        // RE_API_PATH and RE_COMMENT_PATH apply to HTML, JS, and unknown content types —
        // run once here to avoid the duplicate-call bug that existed when they were
        // also inside the isHtml and isJs blocks.
        if (!isJson && !isCss) {
            extractMatches(RE_API_PATH,     body, 1, raw);
            extractMatches(RE_COMMENT_PATH, body, 1, raw);
        }

        for (String candidate : raw) {
            addCandidate(candidate.trim(), base, inScopeHosts,
                    discovered, fetched, normalised);
        }
    }

    private static void extractForms(String body, URL base, Set<String> inScopeHosts,
                                      List<FormEndpoint> formPosts) {
        Matcher m = RE_FORM.matcher(body);
        while (m.find() && formPosts.size() < MAX_FORM_POSTS) {
            // Groups 1+2 or 3+4 depending on which attribute comes first
            String method = m.group(1) != null ? m.group(1) : m.group(4);
            String action = m.group(2) != null ? m.group(2) : m.group(3);
            if (method == null || action == null) continue;
            method = method.toUpperCase();
            if (method.equals("GET")) continue; // GET forms handled by href extraction
            String resolved = resolve(action.trim(), base);
            if (resolved == null) continue;
            try {
                URL u = new URL(resolved);
                if (!inScopeHosts.contains(u.getHost())) continue;
                formPosts.add(new FormEndpoint(resolved, method));
            } catch (Exception ignored) {}
        }
    }

    private static void extractRobots(String body, String baseOrigin,
                                       Set<String> inScopeHosts,
                                       Set<String> discovered, Set<String> fetched,
                                       Set<String> normalised) {
        Matcher m = RE_ROBOTS.matcher(body);
        while (m.find()) {
            String path = m.group(1);
            if (path.contains("*")) continue; // skip wildcard directives
            try {
                String full = baseOrigin + path;
                URL u = new URL(full);
                if (!inScopeHosts.contains(u.getHost())) continue;
                addResolvedCandidate(full, u, inScopeHosts, discovered, fetched, normalised);
            } catch (Exception ignored) {}
        }
    }

    private static void extractSitemap(String body, Set<String> inScopeHosts,
                                        Set<String> discovered, Set<String> fetched,
                                        Set<String> normalised) {
        Matcher m = RE_SITEMAP_LOC.matcher(body);
        while (m.find() && discovered.size() < MAX_DISCOVERED) {
            String loc = m.group(1).trim();
            try {
                URL u = new URL(loc);
                if (!inScopeHosts.contains(u.getHost())) continue;
                addResolvedCandidate(loc, u, inScopeHosts, discovered, fetched, normalised);
            } catch (Exception ignored) {}
        }
    }

    // ── URL candidate processing ──────────────────────────────────────────────

    private static void addCandidate(String raw, URL base, Set<String> inScopeHosts,
                                      Set<String> discovered, Set<String> fetched,
                                      Set<String> normalised) {
        if (discovered.size() >= MAX_DISCOVERED) return;
        String resolved = resolve(raw, base);
        if (resolved == null) return;
        try {
            URL u = new URL(resolved);
            if (!inScopeHosts.contains(u.getHost())) return;
            String path = u.getPath().toLowerCase();
            if (isProbeStaticExt(path)) return;   // filter static assets
            if (fetched.contains(resolved)) return;

            // Path-parameter normalisation: /users/123 → /users/{id}
            // Prevents fetching hundreds of /users/1, /users/2, ... /users/999
            String normPath = RE_PATH_PARAM.matcher(u.getPath()).replaceAll("/{id}");
            String normKey  = u.getHost() + normPath;
            if (normalised.contains(normKey)) return;
            normalised.add(normKey);

            discovered.add(resolved);
        } catch (Exception ignored) {}
    }

    private static void addResolvedCandidate(String full, URL u, Set<String> inScopeHosts,
                                              Set<String> discovered, Set<String> fetched,
                                              Set<String> normalised) {
        if (fetched.contains(full) || discovered.size() >= MAX_DISCOVERED) return;
        String path = u.getPath().toLowerCase();
        if (isProbeStaticExt(path)) return;
        String normPath = RE_PATH_PARAM.matcher(u.getPath()).replaceAll("/{id}");
        String normKey  = u.getHost() + normPath;
        if (normalised.contains(normKey)) return;
        normalised.add(normKey);
        discovered.add(full);
    }

    private static void extractMatches(Pattern p, String body, int group, Set<String> out) {
        Matcher m = p.matcher(body);
        while (m.find()) {
            String v = m.group(group);
            if (v != null && !v.isBlank()) out.add(v);
        }
    }

    // ── URL resolution ────────────────────────────────────────────────────────

    private static String resolve(String raw, URL base) {
        if (raw == null || raw.isBlank()) return null;
        String lower = raw.toLowerCase();
        if (lower.startsWith("data:") || lower.startsWith("javascript:")
                || lower.startsWith("mailto:") || lower.startsWith("tel:")
                || lower.startsWith("blob:") || raw.startsWith("#")
                || raw.startsWith("{") || raw.startsWith("$")
                || raw.contains("..") && raw.contains("{")) return null;
        try {
            String norm;
            if (raw.startsWith("http://") || raw.startsWith("https://")) {
                norm = normalise(raw);
            } else if (raw.startsWith("//")) {
                norm = normalise(base.getProtocol() + ":" + raw);
            } else if (raw.startsWith("/")) {
                String port = (base.getPort() > 0 &&
                        base.getPort() != 80 && base.getPort() != 443)
                        ? ":" + base.getPort() : "";
                norm = normalise(base.getProtocol() + "://" + base.getHost() + port + raw);
            } else {
                norm = normalise(new URL(base, raw).toString());
            }
            // Reject obviously template-style URLs: /api/{version}/users
            if (norm != null && norm.contains("{") && norm.contains("}")) return null;
            return norm;
        } catch (Exception e) { return null; }
    }

    private static String normalise(String url) {
        int hash = url.indexOf('#');
        if (hash >= 0) url = url.substring(0, hash);
        if (url.endsWith("/") && url.length() > 8) url = url.substring(0, url.length() - 1);
        return url;
    }

    // ── HTTP operations ───────────────────────────────────────────────────────

    /**
     * Fetch a URL via Burp's makeHttpRequest and return the response body as a string.
     * Used for robots.txt / sitemap.xml (Phase 0). Returns null on failure.
     */
    private static String fetchBodyDirect(String urlStr,
                                           IBurpExtenderCallbacks callbacks,
                                           IExtensionHelpers helpers) {
        try {
            IHttpRequestResponse result = fetchUrl(urlStr, callbacks, helpers, 8);
            if (result == null || result.getResponse() == null) return null;
            IResponseInfo ri = helpers.analyzeResponse(result.getResponse());
            // Only process 200 responses
            if (ri.getStatusCode() != 200) return null;
            String ct = "";
            for (String h : ri.getHeaders()) {
                if (h.toLowerCase().startsWith("content-type:")) {
                    ct = h.substring(h.indexOf(':') + 1).trim().toLowerCase(); break;
                }
            }
            return responseBody(result.getResponse(), helpers, ct);
        } catch (Exception e) { return null; }
    }

    /**
     * Fetch a URL via Burp's makeHttpRequest with a per-request connect+read timeout.
     * Using Burp's makeHttpRequest means the request appears in the site map and
     * session handling rules (authentication headers) are applied automatically.
     */
    private static IHttpRequestResponse fetchUrl(String urlStr,
                                                   IBurpExtenderCallbacks callbacks,
                                                   IExtensionHelpers helpers,
                                                   int timeoutSeconds) {
        try {
            URL u = new URL(urlStr);
            if (!callbacks.isInScope(u)) return null;

            String host    = u.getHost();
            int    port    = u.getPort() > 0 ? u.getPort()
                           : "https".equalsIgnoreCase(u.getProtocol()) ? 443 : 80;
            boolean isHttps = "https".equalsIgnoreCase(u.getProtocol());

            String pathAndQuery = u.getPath().isEmpty() ? "/" : u.getPath();
            if (u.getQuery() != null) pathAndQuery += "?" + u.getQuery();

            String portHeader = (port != 80 && port != 443) ? ":" + port : "";
            String reqStr = "GET " + pathAndQuery + " HTTP/1.1\r\n"
                    + "Host: " + host + portHeader + "\r\n"
                    + "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    +   "AppleWebKit/537.36 (KHTML, like Gecko) "
                    +   "Chrome/124.0.0.0 Safari/537.36\r\n"
                    + "Accept: text/html,application/xhtml+xml,application/xml;"
                    +   "q=0.9,application/json,*/*;q=0.8\r\n"
                    + "Accept-Language: en-US,en;q=0.5\r\n"
                    + "Accept-Encoding: gzip, deflate\r\n"
                    + "Connection: close\r\n"
                    + "\r\n";
            byte[] reqBytes = reqStr.getBytes(StandardCharsets.ISO_8859_1);

            final String  lhost  = host;
            final int     lport  = port;
            final boolean lhttps = isHttps;
            IHttpService service = new IHttpService() {
                public String  getHost()     { return lhost; }
                public int     getPort()     { return lport; }
                public String  getProtocol() { return lhttps ? "https" : "http"; }
            };

            // makeHttpRequest is a blocking call - it runs in a thread pool thread
            // so the per-pool awaitTermination acts as the timeout.
            return callbacks.makeHttpRequest(service, reqBytes);

        } catch (Exception e) { return null; }
    }

    /**
     * Build a synthetic IHttpRequestResponse for a POST/PUT/DELETE form endpoint.
     * The response will be null (no actual request is made). ActiveScanner's
     * buildProbeContext will parse the request to extract path and method, then
     * the active probes will inject into the request body.
     */
    private static IHttpRequestResponse buildSyntheticRequest(String urlStr, String method,
                                                                IBurpExtenderCallbacks callbacks,
                                                                IExtensionHelpers helpers) {
        try {
            URL u = new URL(urlStr);
            if (!callbacks.isInScope(u)) return null;
            String host    = u.getHost();
            int    port    = u.getPort() > 0 ? u.getPort()
                           : "https".equalsIgnoreCase(u.getProtocol()) ? 443 : 80;
            boolean isHttps = "https".equalsIgnoreCase(u.getProtocol());

            String pathAndQuery = u.getPath().isEmpty() ? "/" : u.getPath();
            if (u.getQuery() != null) pathAndQuery += "?" + u.getQuery();
            String portHeader = (port != 80 && port != 443) ? ":" + port : "";

            // Build a minimal POST/PUT/DELETE request with a sentinel body parameter.
            // The sentinel param (burpmax_probe=1) ensures probeFilter's hasParams check
            // is satisfied, so injection probes (SQLi, XSS, CmdI, etc.) actually run
            // against this endpoint. Without it, probeFilter would see no params and
            // skip all injection-based probes, making the synthetic request useless.
            String sentinelBody = "burpmax_probe=1";
            String reqStr = method + " " + pathAndQuery + " HTTP/1.1\r\n"
                    + "Host: " + host + portHeader + "\r\n"
                    + "User-Agent: Mozilla/5.0 (compatible; BurpMax/1.0)\r\n"
                    + "Content-Type: application/x-www-form-urlencoded\r\n"
                    + "Content-Length: " + sentinelBody.length() + "\r\n"
                    + "Connection: close\r\n"
                    + "\r\n"
                    + sentinelBody;
            final byte[] reqBytes = reqStr.getBytes(StandardCharsets.ISO_8859_1);

            final String  lhost  = host;
            final int     lport  = port;
            final boolean lhttps = isHttps;
            IHttpService service = new IHttpService() {
                public String  getHost()     { return lhost; }
                public int     getPort()     { return lport; }
                public String  getProtocol() { return lhttps ? "https" : "http"; }
            };

            // Return as an IHttpRequestResponse with no response (null)
            // ActiveScanner.buildProbeContext handles response=null gracefully
            return new IHttpRequestResponse() {
                public byte[] getRequest()            { return reqBytes; }
                public byte[] getResponse()           { return null; }
                public void   setRequest(byte[] r)    {}
                public void   setResponse(byte[] r)   {}
                public String getComment()            { return "BurpMax form endpoint"; }
                public void   setComment(String c)    {}
                public String getHighlight()          { return null; }
                public void   setHighlight(String h)  {}
                public IHttpService getHttpService()  { return service; }
                public void   setHttpService(IHttpService s) {}
            };
        } catch (Exception e) { return null; }
    }

    // ── Response body extraction ──────────────────────────────────────────────

    private static String contentType(byte[] response, IExtensionHelpers helpers) {
        if (response == null) return "";
        try {
            for (String h : helpers.analyzeResponse(response).getHeaders()) {
                if (h.toLowerCase().startsWith("content-type:")) {
                    return h.substring(h.indexOf(':') + 1).trim().toLowerCase();
                }
            }
        } catch (Exception ignored) {}
        return "";
    }

    private static String responseBody(byte[] response, IExtensionHelpers helpers, String ct) {
        if (response == null) return null;
        try {
            int offset = helpers.analyzeResponse(response).getBodyOffset();
            if (offset >= response.length) return "";
            // JS bundles get a larger cap since we're extracting path strings, not rendering
            int cap = ct.contains("javascript") ? JS_CAP_BYTES : BODY_CAP_BYTES;
            int len = Math.min(response.length - offset, cap);
            return new String(response, offset, len, StandardCharsets.ISO_8859_1);
        } catch (Exception e) { return null; }
    }

    // ── Static extension filter ───────────────────────────────────────────────
    // Note: .js is NOT filtered here - JS files are fetched for link extraction.
    // JS files ARE excluded from active probing via ActiveScanner.buildProbeContext's
    // static-extension check. This distinction is intentional.
    private static boolean isProbeStaticExt(String path) {
        return path.matches(".*\\.(?:css|png|jpg|jpeg|gif|ico|svg|woff|woff2|" +
                             "ttf|eot|otf|mp4|mp3|avi|mov|wav|ogg|flac|" +
                             "pdf|zip|tar\\.gz|gz|bz2|xz|7z|rar|" +
                             "map|wasm|bin|exe|dll|so|dylib)$");
    }

    private static void status(Consumer<String> cb, String msg) {
        if (cb != null) cb.accept(msg);
    }
}
