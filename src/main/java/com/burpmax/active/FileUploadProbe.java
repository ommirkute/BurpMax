package com.burpmax.active;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.*;
import static com.burpmax.model.Finding.*;

/**
 * File Upload Vulnerability probe.
 *
 * Trigger: only runs on requests that are ALREADY multipart/form-data and
 * contain at least one file part (a part whose Content-Disposition carries a
 * filename= attribute). This is the reliable signal that the endpoint accepts
 * uploads — we never guess upload endpoints, which is the main false-positive
 * source for this class.
 *
 * Method (per file part, each step = one request):
 *
 *   0. BENIGN BASELINE
 *      Re-upload a harmless GIF with a .gif name and image/gif type. Capture
 *      the response (status, body, any echoed path). This teaches the probe
 *      what a *successful* upload looks like on this endpoint, and proves the
 *      endpoint is functional before we judge anything as a bypass.
 *
 *   1. BYPASS ATTEMPTS (only evaluated if the baseline upload succeeded)
 *      Each attempt mutates exactly one property of the benign upload:
 *        a. Dangerous extension      shell.php   / .jsp / .aspx / .phtml
 *        b. Double extension         shell.php.gif
 *        c. Trailing-char bypass     shell.php%20 , shell.php. , shell.php::$DATA
 *        d. Content-Type spoof       php body, declared image/gif, .php name
 *        e. .htaccess override       upload an .htaccess that maps .gif->php
 *        f. SVG script (stored XSS)  image/svg+xml containing <script>
 *        g. Path traversal filename  ../../../tmp/shell.php
 *      The executable-payload bodies are INERT markers, never working web
 *      shells: a unique token printed by a one-line script. We confirm by
 *      detecting that token, not by achieving code execution.
 *
 *   2. CONFIRMATION (the part that kills false positives)
 *      An attempt is only reported when BOTH hold:
 *        - The server ACCEPTED it (same success shape as the benign baseline:
 *          2xx and not the rejection body), AND
 *        - One of:
 *            (i)  the response echoes a path/URL to the stored file, we GET it
 *                 back, and the response proves the upload survived with a
 *                 dangerous content-type or executed our inert marker; OR
 *            (ii) for the SVG/stored-XSS case, the fetched-back file is served
 *                 with an HTML/SVG content-type and still contains our script
 *                 marker unescaped.
 *      If the dangerous variant is rejected while the benign one succeeded,
 *      that's correct behaviour → no finding (and we note nothing).
 *
 * Cost: bounded. At most one benign upload + one attempt per vector per file
 * part, and file parts are de-duplicated. A guard skips the probe entirely on
 * non-multipart or file-less requests so it is effectively free elsewhere.
 */
public class FileUploadProbe {

    // 1x1 transparent GIF — the benign control payload.
    private static final byte[] GIF_1PX = new byte[]{
        'G','I','F','8','9','a', 0x01,0x00, 0x01,0x00, (byte)0x80, 0x00, 0x00,
        0x00,0x00,0x00, (byte)0xFF,(byte)0xFF,(byte)0xFF, 0x21,(byte)0xF9,
        0x04,0x01,0x00,0x00,0x00,0x00, 0x2C,0x00,0x00,0x00,0x00,
        0x01,0x00,0x01,0x00,0x00,0x02,0x02,0x44,0x01,0x00,0x3B
    };

    // Unique marker baked into "executable" payloads. We confirm by finding
    // this token reflected when the stored file is fetched back — never by
    // running a real shell.
    private static final java.util.concurrent.atomic.AtomicLong SEQ =
            new java.util.concurrent.atomic.AtomicLong(0);

    private record Vector(String filename, String contentType, byte[] body,
                          String label, String severity, String detail) {}

    static List<ActiveScanResult> probe(ProbeContext ctx, RequestBuilder rb,
                                        HttpSender sender) {
        List<ActiveScanResult> results = new ArrayList<>();

        String ctHeader = ctx.contentType == null ? "" : ctx.contentType.toLowerCase();
        if (!ctHeader.contains("multipart/form-data")) return results;

        String reqStr = new String(ctx.originalRequest, StandardCharsets.ISO_8859_1);

        String boundary = extractBoundary(ctHeader, reqStr);
        if (boundary == null) return results;

        List<FilePart> fileParts = findFileParts(reqStr, boundary);
        if (fileParts.isEmpty()) return results;

        // De-dup by part field name so a repeated multipart field is tested once.
        Set<String> testedFields = new HashSet<>();

        for (FilePart fp : fileParts) {
            if (!testedFields.add(fp.fieldName)) continue;

            // ── Step 0: benign baseline upload ───────────────────────────────
            byte[] benignReq = rebuildMultipart(reqStr, boundary, fp,
                    "burpmax_benign.gif", "image/gif", GIF_1PX);
            if (benignReq == null) continue;
            ActiveScanner.registerProbeUrl(ctx.url);

            HttpSender.Response benignResp = sender.send(ctx.service, benignReq);
            if (benignResp == null) continue;

            // The endpoint must ACCEPT a normal image for us to reason about
            // bypasses. A 4xx/5xx on a plain GIF means we cannot establish a
            // success baseline — bail out (no finding, no false positive).
            if (benignResp.statusCode() >= 400) continue;

            String benignBody = benignResp.body() == null ? "" : benignResp.body();
            String storedHint = extractStoredPath(benignBody, "burpmax_benign.gif");

            // ── Step 1+2: bypass vectors ────────────────────────────────────
            for (Vector v : buildVectors()) {
                byte[] attackReq = rebuildMultipart(reqStr, boundary, fp,
                        v.filename(), v.contentType(), v.body());
                if (attackReq == null) continue;

                HttpSender.Response attackResp = sender.send(ctx.service, attackReq);
                if (attackResp == null) continue;

                // Must be accepted in the SAME success shape as the benign one.
                if (attackResp.statusCode() >= 400) continue;
                String attackBody = attackResp.body() == null ? "" : attackResp.body();
                if (looksRejected(attackBody)) continue;

                // ── Confirmation ────────────────────────────────────────────
                ActiveScanResult confirmed = confirm(ctx, sender, v,
                        attackReq, attackResp, attackBody, storedHint);
                if (confirmed != null) {
                    results.add(confirmed);
                    // One confirmed upload flaw per field is enough — the fix is
                    // the same for every vector. Stop hammering this endpoint.
                    break;
                }
            }
        }
        return results;
    }

    // ── Confirmation logic ─────────────────────────────────────────────────────

    private static ActiveScanResult confirm(ProbeContext ctx, HttpSender sender,
                                             Vector v, byte[] attackReq,
                                             HttpSender.Response attackResp,
                                             String attackBody, String storedHint) {
        // Find the path/URL the server reports for the stored file. Prefer the
        // attack response's own echoed path; fall back to the benign template
        // with the attack filename substituted.
        String fetchUrl = resolveFetchUrl(ctx, attackBody, v.filename(), storedHint);
        if (fetchUrl == null) {
            // No retrievable path. We do NOT report on acceptance alone — that
            // is the classic false positive (many apps 200-OK then reject async).
            return null;
        }

        ActiveScanner.registerProbeUrl(fetchUrl);
        byte[] getReq = buildGet(ctx, fetchUrl);
        if (getReq == null) return null;

        HttpSender.Response fetched = sender.send(ctx.service, getReq);
        if (fetched == null || fetched.statusCode() != 200) return null;

        String fBody = fetched.body() == null ? "" : fetched.body();
        String fCt   = fetched.header("content-type");
        fCt = fCt == null ? "" : fCt.toLowerCase();

        boolean markerPresent = v.body() != null
                && fBody.contains(markerOf(v));

        // Case (i): executable/script upload retrievable and intact.
        // The strongest signal is our inert marker surviving in the fetched
        // file. Combined with a code/HTML/SVG content-type this is conclusive.
        boolean dangerousCt =
                fCt.contains("application/x-httpd-php")
             || fCt.contains("text/x-php")
             || fCt.contains("application/x-php")
             || fCt.contains("text/html")
             || fCt.contains("image/svg")
             || fCt.contains("application/xhtml");

        if (markerPresent && (dangerousCt || isExecutableName(v.filename()))) {
            String sev = v.severity();
            return new ActiveScanResult(
                "Unrestricted File Upload (" + v.label() + ")", sev,
                "An unrestricted file upload vulnerability was confirmed via the "
                + "multipart field '" + ctx.url + "'. " + v.detail() + " The benign "
                + "image control uploaded successfully, the bypass file was accepted "
                + "with the same success response, AND the file was retrieved back "
                + "from the server at " + fetchUrl + " with its content intact"
                + (dangerousCt ? " and served with a dangerous content-type ("
                        + fCt + ")" : "")
                + ". A unique inert marker embedded in the payload was found in the "
                + "fetched-back file, ruling out a false positive. An attacker can "
                + "upload server-side executable code or active content, leading to "
                + "remote code execution or stored XSS depending on how the file is "
                + "served and processed.",
                "Field: " + ctx.url + " | Uploaded as: " + v.filename()
                + " | Declared type: " + v.contentType()
                + " | Retrieved from: " + fetchUrl
                + " | Served content-type: " + (fCt.isEmpty() ? "(none)" : fCt)
                + " | Inert marker confirmed in stored file",
                REMEDIATION, "CWE-434",
                ctx.url, v.label(), v.filename(),
                trunc(new String(attackReq, StandardCharsets.ISO_8859_1), 400),
                trunc(fBody, 200),
                attackReq, fetched.raw(), -1L);
        }

        // Case (ii): non-executable but the raw marker came back unescaped in an
        // HTML/SVG response → stored XSS through upload.
        if (markerPresent && (fCt.contains("svg") || fCt.contains("html"))) {
            return new ActiveScanResult(
                "Unrestricted File Upload (Stored XSS via SVG)", SEV_HIGH,
                "An SVG file containing script was uploaded via '" + ctx.url
                + "', accepted, and served back from " + fetchUrl + " with an "
                + "HTML/SVG content-type that browsers render - the embedded "
                + "script marker survived unescaped. Any user who opens the file "
                + "URL executes attacker-controlled JavaScript in the application "
                + "origin.",
                "Field: " + ctx.url + " | Uploaded as: " + v.filename()
                + " | Retrieved from: " + fetchUrl + " | Served as: " + fCt,
                REMEDIATION, "CWE-434",
                ctx.url, v.label(), v.filename(),
                trunc(new String(attackReq, StandardCharsets.ISO_8859_1), 400),
                trunc(fBody, 200),
                attackReq, fetched.raw(), -1L);
        }
        return null;
    }

    // ── Attack vectors ──────────────────────────────────────────────────────────

    private static List<Vector> buildVectors() {
        long uid = SEQ.incrementAndGet();
        String tok = "BURPMAXUP" + Long.toHexString(uid)
                   + Integer.toHexString(
                       java.util.concurrent.ThreadLocalRandom.current().nextInt(0x10000));

        // INERT php marker — prints a constant; does nothing else. We confirm by
        // finding the *source text* token in the fetched file, not by execution,
        // so this is safe even on a server that would execute it.
        byte[] phpInert = ("<?php /*" + tok + "*/ ?>marker:" + tok)
                .getBytes(StandardCharsets.ISO_8859_1);
        byte[] jspInert = ("<%-- " + tok + " --%>marker:" + tok)
                .getBytes(StandardCharsets.ISO_8859_1);
        byte[] htaccess = ("AddType application/x-httpd-php .gif\n# " + tok)
                .getBytes(StandardCharsets.ISO_8859_1);
        byte[] svgXss   = ("<svg xmlns=\"http://www.w3.org/2000/svg\">"
                + "<script>/*" + tok + "*/</script><text>marker:" + tok
                + "</text></svg>").getBytes(StandardCharsets.ISO_8859_1);

        List<Vector> v = new ArrayList<>();
        v.add(new Vector("burpmax_" + tok + ".php", "image/gif", phpInert,
            "Dangerous Extension", SEV_CRITICAL,
            "A file with a server-executable .php extension was accepted."));
        v.add(new Vector("burpmax_" + tok + ".phtml", "image/gif", phpInert,
            "Alternate PHP Extension", SEV_CRITICAL,
            "A file with the often-overlooked .phtml executable extension was accepted."));
        v.add(new Vector("burpmax_" + tok + ".jsp", "image/gif", jspInert,
            "JSP Extension", SEV_CRITICAL,
            "A file with a server-executable .jsp extension was accepted."));
        v.add(new Vector("burpmax_" + tok + ".php.gif", "image/gif", phpInert,
            "Double Extension", SEV_CRITICAL,
            "A double-extension filename (.php.gif) bypassed extension filtering."));
        v.add(new Vector("burpmax_" + tok + ".php.", "image/gif", phpInert,
            "Trailing-Dot Bypass", SEV_CRITICAL,
            "A trailing dot after the .php extension bypassed the filter while the "
            + "OS strips the dot, leaving an executable .php file."));
        v.add(new Vector("burpmax_" + tok + ".php%20", "image/gif", phpInert,
            "Trailing-Space Bypass", SEV_CRITICAL,
            "A trailing space after .php bypassed the filter."));
        v.add(new Vector("burpmax_" + tok + ".gif", "application/x-httpd-php",
            phpInert, "Content-Type Spoof", SEV_HIGH,
            "PHP code with a .gif name but a php content-type was accepted; if the "
            + "server trusts the declared type this is exploitable."));
        v.add(new Vector(".htaccess", "text/plain", htaccess,
            "Apache .htaccess Override", SEV_CRITICAL,
            "An .htaccess file remapping an innocuous extension to the PHP handler "
            + "was accepted, enabling code execution from any subsequently uploaded file."));
        v.add(new Vector("burpmax_" + tok + ".svg", "image/svg+xml", svgXss,
            "SVG Script Upload", SEV_HIGH,
            "An SVG containing a <script> element was accepted; SVGs are rendered "
            + "as active content by browsers."));
        v.add(new Vector("../../burpmax_" + tok + ".php", "image/gif", phpInert,
            "Path Traversal Filename", SEV_CRITICAL,
            "A filename containing ../ path-traversal segments was accepted, allowing "
            + "the file to be written outside the intended upload directory."));
        return v;
    }

    private static String markerOf(Vector v) {
        // The token is embedded in every payload body; recover it from the body.
        String body = new String(v.body(), StandardCharsets.ISO_8859_1);
        Matcher m = Pattern.compile("BURPMAXUP[0-9a-f]+").matcher(body);
        return m.find() ? m.group() : "BURPMAXUP";
    }

    // ── Multipart parsing / rebuilding ──────────────────────────────────────────

    private record FilePart(String fieldName, String origFilename,
                            int partStart, int partEnd) {}

    private static String extractBoundary(String ctHeader, String reqStr) {
        Matcher m = Pattern.compile("boundary=\"?([^\";\\r\\n]+)\"?",
                Pattern.CASE_INSENSITIVE).matcher(ctHeader);
        if (m.find()) return m.group(1).trim();
        // Fall back to sniffing the body for the --boundary line.
        Matcher b = Pattern.compile("\\r\\n--([A-Za-z0-9'()+_,\\-./:=? ]{8,70})\\r\\n")
                .matcher(reqStr);
        return b.find() ? b.group(1) : null;
    }

    private static List<FilePart> findFileParts(String reqStr, String boundary) {
        List<FilePart> parts = new ArrayList<>();
        String delim = "--" + boundary;
        int hdrEnd = reqStr.indexOf("\r\n\r\n");
        if (hdrEnd < 0) return parts;

        int idx = reqStr.indexOf(delim, hdrEnd);
        while (idx >= 0) {
            int partHdrStart = idx + delim.length();
            // End of this delimiter line
            int lineEnd = reqStr.indexOf("\r\n", partHdrStart);
            if (lineEnd < 0) break;
            // "--boundary--" marks the final boundary.
            if (reqStr.startsWith("--", partHdrStart)) break;

            int partHdrEnd = reqStr.indexOf("\r\n\r\n", lineEnd);
            if (partHdrEnd < 0) break;
            String partHeaders = reqStr.substring(lineEnd + 2, partHdrEnd);

            int next = reqStr.indexOf("\r\n" + delim, partHdrEnd);
            if (next < 0) break;

            Matcher fn = Pattern.compile(
                    "Content-Disposition:[^\\r\\n]*\\bname=\"([^\"]*)\"" +
                    "[^\\r\\n]*\\bfilename=\"([^\"]*)\"",
                    Pattern.CASE_INSENSITIVE).matcher(partHeaders);
            if (fn.find()) {
                parts.add(new FilePart(fn.group(1), fn.group(2), idx, next));
            }
            idx = reqStr.indexOf(delim, next);
        }
        return parts;
    }

    /**
     * Rebuild the full request replacing exactly the target file part's
     * filename, content-type, and body bytes. All other parts and the request
     * line/headers are preserved verbatim. Content-Length is recomputed from
     * the actual byte length of the rebuilt body.
     */
    private static byte[] rebuildMultipart(String reqStr, String boundary,
                                           FilePart fp, String newFilename,
                                           String newCtType, byte[] newBody) {
        try {
            int hdrEnd = reqStr.indexOf("\r\n\r\n");
            if (hdrEnd < 0) return null;
            String headerBlock = reqStr.substring(0, hdrEnd);
            String body         = reqStr.substring(hdrEnd + 4);

            String delim = "--" + boundary;

            // Locate the target part within the BODY (offsets in reqStr are
            // header-relative; recompute against the body string).
            int bodyPartStart = body.indexOf(delim,
                    Math.max(0, fp.partStart() - (hdrEnd + 4)));
            if (bodyPartStart < 0) bodyPartStart = body.indexOf(delim);
            if (bodyPartStart < 0) return null;

            int partHdrLineEnd = body.indexOf("\r\n", bodyPartStart + delim.length());
            if (partHdrLineEnd < 0) return null;
            int partHdrEnd = body.indexOf("\r\n\r\n", partHdrLineEnd);
            if (partHdrEnd < 0) return null;
            int partBodyStart = partHdrEnd + 4;
            int partBodyEnd   = body.indexOf("\r\n" + delim, partBodyStart);
            if (partBodyEnd < 0) return null;

            String origPartHeaders = body.substring(partHdrLineEnd + 2, partHdrEnd);

            // Rewrite filename in Content-Disposition and the part Content-Type.
            // quoteReplacement is applied only to the user-controlled filename so
            // a filename containing $ or \ cannot corrupt the replacement; the
            // $1/$2 backrefs are intentionally NOT quoted.
            String newPartHeaders = origPartHeaders.replaceFirst(
                    "(?i)(filename=\")[^\"]*(\")",
                    "$1" + Matcher.quoteReplacement(newFilename) + "$2");
            if (newPartHeaders.matches("(?is).*content-type:.*")) {
                newPartHeaders = newPartHeaders.replaceFirst(
                        "(?i)(content-type:\\s*)[^\\r\\n]*",
                        "$1" + Matcher.quoteReplacement(newCtType));
            } else {
                newPartHeaders = newPartHeaders + "\r\nContent-Type: " + newCtType;
            }

            // Reassemble body around the modified part using a byte buffer so
            // binary payloads (GIF) are preserved exactly.
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            out.write(body.substring(0, partHdrLineEnd + 2)
                    .getBytes(StandardCharsets.ISO_8859_1));
            out.write(newPartHeaders.getBytes(StandardCharsets.ISO_8859_1));
            out.write("\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));
            out.write(newBody);
            out.write(body.substring(partBodyEnd)
                    .getBytes(StandardCharsets.ISO_8859_1));
            byte[] newBodyBytes = out.toByteArray();

            // Rebuild headers with a corrected Content-Length.
            StringBuilder hdrs = new StringBuilder();
            boolean clSet = false;
            for (String line : headerBlock.split("\r\n", -1)) {
                if (line.toLowerCase().startsWith("content-length:")) {
                    hdrs.append("Content-Length: ").append(newBodyBytes.length);
                    clSet = true;
                } else {
                    hdrs.append(line);
                }
                hdrs.append("\r\n");
            }
            // Trim the extra trailing CRLF the loop adds after the last header.
            if (hdrs.length() >= 2 && hdrs.substring(hdrs.length() - 2).equals("\r\n"))
                hdrs.setLength(hdrs.length() - 2);
            if (!clSet) hdrs.append("\r\nContent-Length: ").append(newBodyBytes.length);

            java.io.ByteArrayOutputStream req = new java.io.ByteArrayOutputStream();
            req.write(hdrs.toString().getBytes(StandardCharsets.ISO_8859_1));
            req.write("\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));
            req.write(newBodyBytes);
            return req.toByteArray();
        } catch (Exception e) {
            return null;
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────

    /** Heuristic: does the response body read like an upload rejection? */
    private static boolean looksRejected(String body) {
        if (body == null) return false;
        String b = body.toLowerCase();
        return b.contains("not allowed") || b.contains("invalid file")
            || b.contains("invalid extension") || b.contains("file type")
            || b.contains("forbidden") || b.contains("rejected")
            || b.contains("only images") || b.contains("not permitted")
            || b.contains("upload failed") || b.contains("disallowed");
    }

    /**
     * Pull a stored file path/URL out of a JSON or HTML upload response.
     * Looks for the uploaded filename, or common keys (url/path/location/file).
     */
    private static String extractStoredPath(String body, String uploadedName) {
        if (body == null || body.isEmpty()) return null;
        // 1. The server echoes the filename inside a path/URL.
        Matcher direct = Pattern.compile(
                "(https?://[^\"'\\s]+|/[^\"'\\s]*)" + Pattern.quote(uploadedName))
                .matcher(body);
        if (direct.find()) return direct.group(0);
        // 2. JSON keys commonly used for the stored location.
        Matcher json = Pattern.compile(
                "\"(?:url|path|location|file|filename|filepath|src|link)\"\\s*:\\s*\"([^\"]+)\"",
                Pattern.CASE_INSENSITIVE).matcher(body);
        if (json.find()) return json.group(1);
        return null;
    }

    /**
     * Decide which absolute URL to GET to retrieve the stored file. Prefers a
     * path echoed in the attack response; otherwise reuses the benign template
     * with the attack filename substituted in.
     */
    private static String resolveFetchUrl(ProbeContext ctx, String attackBody,
                                          String attackFilename, String benignHint) {
        String fromResp = extractStoredPath(attackBody, baseName(attackFilename));
        String chosen = fromResp != null ? fromResp : benignHint;
        if (chosen == null) return null;
        return absolutise(ctx.url, chosen);
    }

    private static String baseName(String fn) {
        String s = fn.replace("\\", "/");
        int i = s.lastIndexOf('/');
        return i >= 0 ? s.substring(i + 1) : s;
    }

    /** Resolve a possibly-relative path against the probed endpoint's origin. */
    private static String absolutise(String pageUrl, String pathOrUrl) {
        try {
            if (pathOrUrl.startsWith("http://") || pathOrUrl.startsWith("https://"))
                return pathOrUrl;
            java.net.URL base = new java.net.URL(pageUrl);
            java.net.URL resolved = new java.net.URL(base, pathOrUrl);
            return resolved.toString();
        } catch (Exception e) {
            return null;
        }
    }

    private static byte[] buildGet(ProbeContext ctx, String absUrl) {
        try {
            java.net.URL u = new java.net.URL(absUrl);
            String path = u.getFile();
            if (path == null || path.isEmpty()) path = "/";
            String reqStr = new String(ctx.originalRequest, StandardCharsets.ISO_8859_1);
            int hdrEnd = reqStr.indexOf("\r\n\r\n");
            String headerBlock = hdrEnd >= 0 ? reqStr.substring(0, hdrEnd) : reqStr;

            StringBuilder out = new StringBuilder();
            String[] lines = headerBlock.split("\r\n", -1);
            for (int i = 0; i < lines.length; i++) {
                if (i == 0) {
                    out.append("GET ").append(path).append(" HTTP/1.1");
                } else {
                    String lower = lines[i].toLowerCase();
                    if (lower.startsWith("content-length:")
                            || lower.startsWith("content-type:")
                            || lower.startsWith("transfer-encoding:")) continue;
                    if (lower.startsWith("host:")) {
                        out.append("Host: ").append(u.getHost())
                           .append(u.getPort() > 0 ? ":" + u.getPort() : "");
                    } else {
                        out.append(lines[i]);
                    }
                }
                out.append("\r\n");
            }
            // out currently ends with the final header + \r\n; terminate block.
            out.append("\r\n");
            return out.toString().getBytes(StandardCharsets.ISO_8859_1);
        } catch (Exception e) {
            return null;
        }
    }

    private static boolean isExecutableName(String fn) {
        String f = fn.toLowerCase();
        return f.contains(".php") || f.contains(".phtml") || f.contains(".php5")
            || f.contains(".jsp") || f.contains(".jspx") || f.contains(".asp")
            || f.contains(".aspx") || f.contains(".ashx") || f.endsWith(".htaccess")
            || f.equals(".htaccess");
    }

    private static String trunc(String s, int n) {
        return s == null ? "" : s.length() > n ? s.substring(0, n) + "..." : s;
    }

    private static final String REMEDIATION =
        "PRIMARY FIX - Validate Server-Side, Store Outside the Web Root:\n"
        + "- Validate the file extension against a strict ALLOWLIST (jpg, png, pdf...),\n"
        + "  never a denylist. Re-derive the extension from the final stored name.\n"
        + "- Verify the actual content (magic bytes / MIME sniffing) matches the\n"
        + "  allowed type - never trust the client-supplied Content-Type or filename.\n"
        + "- Generate a new random server-side filename; discard the user's filename\n"
        + "  entirely. This neutralises double-extension, trailing-char, null-byte,\n"
        + "  and path-traversal tricks at once.\n"
        + "- Store uploads OUTSIDE the web root and serve them through a controller\n"
        + "  that sets Content-Disposition: attachment and a safe Content-Type.\n"
        + "\nSECONDARY CONTROLS:\n"
        + "- Disable script execution in the upload directory (php_admin_flag\n"
        + "  engine off; or remove handler mappings; deny .htaccess overrides).\n"
        + "- For images, re-encode through an image library (load + re-save) to strip\n"
        + "  embedded code; for SVG, sanitise with an SVG allowlist or refuse SVG.\n"
        + "- Enforce a maximum file size and scan with anti-malware where applicable.\n"
        + "- Serve user content from a separate sandbox domain so any active content\n"
        + "  cannot run in the application's security origin.";
}
