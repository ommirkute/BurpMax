package com.burpmax.active;

import burp.IExtensionHelpers;
import burp.IParameter;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Builds modified HTTP request byte arrays for active probes.
 * Uses Burp's IExtensionHelpers where possible for correct HTTP construction.
 *
 * JSON body handling (setJsonParam):
 *   Parameters extracted from JSON bodies are keyed by dot-notation paths
 *   (e.g. "user.name", "items.0.price"). This class walks the original JSON
 *   body string to locate each leaf node and replaces its value in-place,
 *   preserving all surrounding structure. It handles:
 *     - String values  : "key":"value"   → "key":"<payload>"
 *     - Numeric values : "key":42        → "key":"<payload>"   (quoted for injection)
 *     - Boolean values : "key":true      → "key":"<payload>"
 *     - Null values    : "key":null      → "key":"<payload>"
 *     - Nested objects : walked by path segments ("user.address.city")
 *     - Array elements : walked by index ("items.0.name")
 *   The approach uses careful string-level JSON walking rather than a full
 *   parse-modify-serialise cycle to avoid dependency on a JSON library and to
 *   preserve the original request's whitespace, ordering, and encoding exactly.
 */
public class RequestBuilder {

    private final IExtensionHelpers helpers;

    public RequestBuilder(IExtensionHelpers helpers) {
        this.helpers = helpers;
    }

    // ── Public API ─────────────────────────────────────────────────────────────

    /**
     * Build a probe request with a single parameter replaced by the payload.
     * Routes to the correct injection strategy based on parameter origin:
     *   - Query string param  → helpers.updateParameter (URL-encoded)
     *   - Form body param     → helpers.updateParameter (form-encoded)
     *   - JSON body param     → path-aware JSON leaf replacement
     * Falls back to returning the original request unmodified if injection fails.
     */
    public byte[] buildProbeRequest(ProbeContext ctx, String paramName, String payload) {
        byte[] req = ctx.originalRequest;
        try {
            if (ctx.isQueryParam(paramName)) {
                req = setQueryParam(req, paramName, payload);
            } else if (ctx.isBodyParam(paramName)) {
                req = setFormParam(req, paramName, payload);
            } else if (ctx.isJsonParam(paramName)) {
                req = setJsonParam(req, paramName, payload);
            } else if (ctx.isXmlParam(paramName)) {
                req = setXmlParam(req, paramName, payload);
            }
        } catch (Exception ignored) {
            // Return original on any failure — probe will send it, get no match, move on
        }
        return req;
    }

    /**
     * Build a request with the given header value replaced or added.
     * Public — used by probes that inject payloads into HTTP headers.
     */
    public byte[] injectHeader(byte[] req, String headerName, String value) {
        return addOrReplaceHeader(req, headerName, value);
    }

    /** Build a request with the Host header replaced (used by HostHeaderProbe). */
    public byte[] buildHostHeaderRequest(ProbeContext ctx, String hostValue) {
        return replaceHeader(ctx.originalRequest, "Host", hostValue);
    }

    /** Build a request with a custom Origin header (used by CorsMisconfigProbe). */
    public byte[] buildOriginRequest(ProbeContext ctx, String origin) {
        return addOrReplaceHeader(ctx.originalRequest, "Origin", origin);
    }

    /** Build a request with the path component of the request line replaced (PathTraversalProbe). */
    public byte[] buildPathRequest(ProbeContext ctx, String newPath) {
        byte[] req    = ctx.originalRequest;
        String reqStr = new String(req, StandardCharsets.ISO_8859_1);
        int firstSpace  = reqStr.indexOf(' ');
        int secondSpace = reqStr.indexOf(' ', firstSpace + 1);
        if (firstSpace < 0 || secondSpace < 0) return req;
        String newReqStr = reqStr.substring(0, firstSpace + 1) + newPath
                         + reqStr.substring(secondSpace);
        return newReqStr.getBytes(StandardCharsets.ISO_8859_1);
    }

    // ── Parameter injection ────────────────────────────────────────────────────

    private byte[] setQueryParam(byte[] req, String name, String value) {
        try {
            IParameter param = helpers.buildParameter(name,
                    URLEncoder.encode(value, "UTF-8"), IParameter.PARAM_URL);
            return helpers.updateParameter(req, param);
        } catch (Exception e) {
            return req;
        }
    }

    private byte[] setFormParam(byte[] req, String name, String value) {
        try {
            IParameter param = helpers.buildParameter(name,
                    URLEncoder.encode(value, "UTF-8"), IParameter.PARAM_BODY);
            return helpers.updateParameter(req, param);
        } catch (Exception e) {
            return req;
        }
    }

    /**
     * Append a new query parameter to the request URL without modifying existing params.
     * Used by NoSQL injection parameter-pollution probes which need to add NEW keys
     * like "username[$gt]" that are not in the original request.
     *
     * If the request already has query params, appends "&name=value".
     * If not, appends "?name=value" to the path.
     *
     * @param req   original request bytes
     * @param name  new parameter name (e.g. "username[$gt]")
     * @param value parameter value (may be empty string)
     * @return modified request bytes, or original if modification fails
     */
    public byte[] appendQueryParam(byte[] req, String name, String value) {
        try {
            String encodedName  = java.net.URLEncoder.encode(name,  "UTF-8");
            String encodedValue = java.net.URLEncoder.encode(value, "UTF-8");
            String pair = encodedName + "=" + encodedValue;

            String reqStr    = new String(req, StandardCharsets.ISO_8859_1);
            int    lineEnd   = reqStr.indexOf("\r\n");
            if (lineEnd < 0) return req;
            String requestLine = reqStr.substring(0, lineEnd);
            String rest        = reqStr.substring(lineEnd);

            // Request line: METHOD SP path[?query] SP HTTP/version
            int firstSpace  = requestLine.indexOf(' ');
            int secondSpace = requestLine.lastIndexOf(' ');
            if (firstSpace < 0 || secondSpace <= firstSpace) return req;

            String pathAndQuery = requestLine.substring(firstSpace + 1, secondSpace);
            String version      = requestLine.substring(secondSpace);
            String method       = requestLine.substring(0, firstSpace);

            String separator = pathAndQuery.contains("?") ? "&" : "?";
            String newPathAndQuery = pathAndQuery + separator + pair;

            String newReqStr = method + " " + newPathAndQuery + version + rest;
            return newReqStr.getBytes(StandardCharsets.ISO_8859_1);
        } catch (Exception e) {
            return req;
        }
    }

    /**
     * Replace an XML body leaf text node identified by a dot-notation path.
     * Uses XmlBodyParser.replaceXmlLeaf() for path-aware replacement.
     * Handles nested elements, repeated siblings, namespace prefixes, and CDATA.
     * Recalculates Content-Length after substitution.
     */
    private byte[] setXmlParam(byte[] req, String dotPath, String payload) {
        String reqStr    = new String(req, java.nio.charset.StandardCharsets.ISO_8859_1);
        int    bodyStart = reqStr.indexOf("\r\n\r\n");
        if (bodyStart < 0) return req;
        bodyStart += 4;
        String headers = reqStr.substring(0, bodyStart);
        String body    = reqStr.substring(bodyStart);
        String modBody = XmlBodyParser.replaceXmlLeaf(body, dotPath, payload);
        if (modBody == null) return req;
        byte[] newBody    = modBody.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        String newHeaders = headers.replaceFirst(
                "(?i)Content-Length:\\s*\\d+", "Content-Length: " + newBody.length);
        byte[] headerBytes = newHeaders.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
        byte[] result      = new byte[headerBytes.length + newBody.length];
        System.arraycopy(headerBytes, 0, result, 0, headerBytes.length);
        System.arraycopy(newBody,     0, result, headerBytes.length, newBody.length);
        return result;
    }

    /**
     * Replace a JSON body leaf value identified by a dot-notation path.
     *
     * Algorithm:
     *   1. Split the dot-path into segments (e.g. "user.address.city" → ["user","address","city"]).
     *   2. Walk the raw JSON string segment by segment using lightweight string scanning:
     *        - Object key segment: find "segment": then skip whitespace to locate the value start.
     *        - Array index segment: count past N comma-separated values at the current depth.
     *   3. Once the target leaf position is located, determine its current value span
     *      (string, number, boolean, or null) and replace it with the quoted payload.
     *   4. Recalculate Content-Length and splice the updated body back into the request.
     *
     * This preserves all surrounding JSON structure — keys, whitespace, ordering — exactly
     * as the server would expect, and correctly handles nested and array containers.
     *
     * If the path cannot be located (e.g. the parameter was removed or the body changed),
     * the original request is returned unmodified.
     */
    private byte[] setJsonParam(byte[] req, String dotPath, String payload) {
        String reqStr   = new String(req, StandardCharsets.ISO_8859_1);
        int    bodyStart = reqStr.indexOf("\r\n\r\n");
        if (bodyStart < 0) return req;
        bodyStart += 4;

        String headers = reqStr.substring(0, bodyStart);
        String body    = reqStr.substring(bodyStart);

        String modifiedBody = replaceJsonLeaf(body, dotPath, payload);
        if (modifiedBody == null) return req;  // path not found - skip this injection

        byte[] newBody    = modifiedBody.getBytes(StandardCharsets.UTF_8);
        String newHeaders = headers.replaceFirst(
                "(?i)Content-Length:\\s*\\d+",
                "Content-Length: " + newBody.length);

        byte[] headerBytes = newHeaders.getBytes(StandardCharsets.ISO_8859_1);
        byte[] result      = new byte[headerBytes.length + newBody.length];
        System.arraycopy(headerBytes, 0, result, 0, headerBytes.length);
        System.arraycopy(newBody,     0, result, headerBytes.length, newBody.length);
        return result;
    }

    /**
     * Delegates to the shared JsonWalker which eliminates the duplicate implementation
     * that previously existed here and in ActiveScanner.
     */
    public static String replaceJsonLeaf(String json, String dotPath, String payload) {
        return JsonWalker.replaceLeaf(json, dotPath, payload);
    }
    /**
     * Determine the span [start, end) of the JSON value starting at {@code pos}.
     * Delegates to JsonWalker.valueSpan (shared implementation).
     */
    public static int[] valueSpan(String json, int pos) {
        return JsonWalker.valueSpan(json, pos);
    }

    /** Delegates to JsonWalker.escapeJson (shared implementation). */
    public static String escapeJson(String s) {
        return JsonWalker.escapeJson(s);
    }

    // ── Header injection ───────────────────────────────────────────────────────

    private byte[] replaceHeader(byte[] req, String headerName, String value) {
        String reqStr   = new String(req, StandardCharsets.ISO_8859_1);
        // Matcher.quoteReplacement is required: probe payloads commonly contain $ and \
        // characters (e.g. SQL payloads like "' OR 1=1--", SSTI like "${7*7}").
        // Without it, replaceFirst interprets $1 as a back-reference and \ as an escape,
        // either throwing IllegalArgumentException or silently corrupting the output.
        String replaced = reqStr.replaceFirst(
                "(?im)^" + java.util.regex.Pattern.quote(headerName) + ":\\s*[^\r\n]*",
                java.util.regex.Matcher.quoteReplacement(headerName + ": " + value));
        return replaced.getBytes(StandardCharsets.ISO_8859_1);
    }

    private byte[] addOrReplaceHeader(byte[] req, String headerName, String value) {
        String reqStr = new String(req, StandardCharsets.ISO_8859_1);
        if (reqStr.toLowerCase().contains(headerName.toLowerCase() + ":")) {
            return replaceHeader(req, headerName, value);
        }
        // Insert before the FIRST blank line only (headers/body separator).
        // Must NOT use String.replace() — it replaces ALL occurrences of
        // \r\n\r\n, corrupting multipart bodies or payloads that contain CRLFCRLF.
        int sep = reqStr.indexOf("\r\n\r\n");
        if (sep < 0) return req;   // malformed request - leave untouched
        String inserted = reqStr.substring(0, sep)
                + "\r\n" + headerName + ": " + value
                + reqStr.substring(sep);   // sep points to \r\n\r\n, keep it
        return inserted.getBytes(StandardCharsets.ISO_8859_1);
    }
}
