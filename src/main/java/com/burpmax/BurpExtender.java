package com.burpmax;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.ITab;
import burp.IExtensionHelpers;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IExtensionStateListener;

import com.burpmax.model.Finding;
import com.burpmax.scanner.Dispatcher;
import com.burpmax.session.SessionManager;
import com.burpmax.store.FindingStore;
import com.burpmax.ui.UIBuilder;

import javax.swing.*;
import java.awt.*;
import java.io.PrintWriter;
import java.util.*;
import java.util.List;

/**
 * BurpMax v1.0 - Active & Passive Vulnerability Scanner for Burp Suite
 * Entry point registered with Burp via the burp.IBurpExtender contract.
 */
public class BurpExtender implements IBurpExtender, IHttpListener, ITab, IExtensionStateListener,
                                      IContextMenuFactory {

    public static final String EXT_NAME = "BurpMax";
    public static final String VERSION  = "1.0.0";

    // Package-private — IBurpExtenderCallbacks grants full Burp internals access.
    // Making it public would allow any other Burp extension in the same JVM to
    // obtain a reference and abuse it. Package-private restricts access to this
    // compilation unit; UIBuilder receives callbacks via constructor injection.
    IBurpExtenderCallbacks callbacks;
    volatile boolean       paused = false;

    private IExtensionHelpers helpers;
    private FindingStore      store;
    private SessionManager    session;
    private UIBuilder         ui;
    private PrintWriter       stdout;
    private PrintWriter       stderr;

    // ── IBurpExtender ─────────────────────────────────────────────────────────

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks cbs) {
        this.callbacks = cbs;
        this.helpers   = cbs.getHelpers();
        this.store     = new FindingStore();
        this.stdout    = new PrintWriter(cbs.getStdout(), true);
        this.stderr    = new PrintWriter(cbs.getStderr(), true);

        cbs.setExtensionName(EXT_NAME);

        // Session manager
        session = new SessionManager(store, cbs);
        session.loadPathFromSettings();

        // Build UI on EDT
        SwingUtilities.invokeLater(() -> {
            ui = UIBuilder.create(store, session, cbs, () -> paused = !paused);
            cbs.addSuiteTab(this);

            // Auto-restore session if save path is known
            if (session.getSavePath() != null) {
                session.restoreAsync(session.getSavePath(),
                    (restored, skipped) ->
                        stdout.println("[BurpMax] Session restored: " + restored + " findings."),
                    err -> stdout.println("[BurpMax] Session restore skipped: " + err));
            }
        });

        // Register HTTP listener and state listener (for clean shutdown)
        cbs.registerHttpListener(this);
        cbs.registerExtensionStateListener(this);
        cbs.registerContextMenuFactory(this);
        stdout.println("[BurpMax] v" + VERSION + " loaded - passive + active scanning ready.");
    }

    /** Called by Burp when the extension is unloaded — shut down background threads. */
    @Override
    public void extensionUnloaded() {
        paused = true;
        if (ui != null) ui.cancelActiveScan();
        if (session != null) session.shutdown();
        // Clear the static PROBE_URLS set so a reload in the same JVM session
        // does not suppress passive scanning on previously-probed URLs.
        com.burpmax.active.ActiveScanner.clearProbeUrls();
    }

    // ── ITab ──────────────────────────────────────────────────────────────────

    @Override public String getTabCaption()   { return "BurpMax"; }
    @Override public Component getUiComponent() {
        return ui != null ? ui.panel : new JPanel();
    }

    // ── IContextMenuFactory ───────────────────────────────────────────────────

    /**
     * Adds "Scan with BurpMax" to the right-click context menu in Proxy history,
     * Repeater, and the site map. Launches a single-target active scan against
     * the selected request without disturbing any running full scan.
     */
    @Override
    public java.util.List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] messages = invocation.getSelectedMessages();
        if (messages == null || messages.length == 0) return java.util.Collections.emptyList();

        // Only show the menu item for contexts where a full HTTP request is available
        byte ctx = invocation.getInvocationContext();
        boolean relevant = ctx == IContextMenuInvocation.CONTEXT_PROXY_HISTORY
                || ctx == IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE
                || ctx == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST
                || ctx == IContextMenuInvocation.CONTEXT_REPEATER_REQUEST;
        if (!relevant) return java.util.Collections.emptyList();

        JMenuItem item = new JMenuItem("Scan with BurpMax");
        item.addActionListener(e -> {
            if (ui == null) return;
            com.burpmax.active.ActiveScanner scanner = ui.getActiveScanner();
            if (scanner == null) return;

            // Scan each selected message. If a full-scope scan is already running,
            // warn the user rather than silently queueing (scanSingleAsync blocks if
            // running is true, so the first call would silently fail).
            if (scanner.isRunning()) {
                JOptionPane.showMessageDialog(null,
                    "A full active scan is already in progress.\n" +
                    "Cancel it first, or wait for it to complete before using single-target scan.",
                    "BurpMax - Scan in progress", JOptionPane.WARNING_MESSAGE);
                return;
            }

            // scanSingleAsync uses the running flag so only one scan runs at a time.
            // For multiple selections, queue all of them: the first starts immediately,
            // the rest are queued on a background thread that waits for each to complete.
            if (messages.length == 1) {
                scanner.scanSingleAsync(messages[0]);
            } else {
                final IHttpRequestResponse[] msgs = messages.clone();
                Thread queuer = new Thread(() -> {
                    for (IHttpRequestResponse msg : msgs) {
                        // Wait until the previous single scan finishes before starting next
                        while (scanner.isRunning()) {
                            try { Thread.sleep(500); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); return; }
                        }
                        if (Thread.currentThread().isInterrupted()) return;
                        scanner.scanSingleAsync(msg);
                        // Give scanSingleAsync time to flip the running flag before next iteration
                        try { Thread.sleep(200); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); return; }
                    }
                }, "burpmax-scan-queue");
                queuer.setDaemon(true);
                queuer.start();
            }
            stdout.println("[BurpMax] Single-target scan queued for "
                    + messages.length + " request(s).");
        });
        return java.util.List.of(item);
    }

    // ── IHttpListener ─────────────────────────────────────────────────────────

    @Override
    public void processHttpMessage(int toolFlag, boolean isRequest, IHttpRequestResponse messageInfo) {
        if (isRequest || paused) return;
        try {
            process(messageInfo);
        } catch (Exception e) {
            stderr.println("[BurpMax] Error: " + e);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────

    private void process(IHttpRequestResponse messageInfo) {
        byte[] reqBytes  = messageInfo.getRequest();
        byte[] respBytes = messageInfo.getResponse();
        if (respBytes == null) return;
        if (reqBytes  == null) reqBytes = new byte[0];

        // Parse request first — reuse reqInfo for both URL and headers
        IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);
        var urlObj = reqInfo.getUrl();
        if (!callbacks.isInScope(urlObj)) return;

        String url  = urlObj.toString();
        String host = urlObj.getHost();

        // Suppress passive scanning on URLs generated by the active scanner.
        // This prevents probe payloads (path traversal sequences, SSRF URLs,
        // canary strings) from triggering false positive passive findings.
        // Two conditions warrant suppression:
        //   1. The URL is an exact registered probe target (base URL).
        //   2. The URL contains path traversal sequences — these are always
        //      probe-generated; no legitimate app URL contains /../ or /%2F..
        if (com.burpmax.active.ActiveScanner.isProbeUrl(url)) return;
        if (isTraversalUrl(url)) return;

        // Parse response
        IResponseInfo respInfo   = helpers.analyzeResponse(respBytes);
        int           statusCode = respInfo.getStatusCode();

        // Skip 404 (pure not-found, no content to scan).
        // Do NOT skip 5xx: error responses commonly contain stack traces,
        // SQL error messages, and debug output — exactly what BodyChecker
        // and ApiResponseChecker are designed to detect.
        if (statusCode == 404) return;

        Map<String, String> reqHdrs = parseHeaders(reqInfo.getHeaders(), true);

        // Parse response headers — guard against empty list
        Map<String, String> respHdrs  = new LinkedHashMap<>();
        List<String>        setCookies = new ArrayList<>();
        List<String>        respHeaders = respInfo.getHeaders();
        int start = respHeaders.size() > 1 ? 1 : respHeaders.size();
        for (String h : respHeaders.subList(start, respHeaders.size())) {
            int colon = h.indexOf(':');
            if (colon < 0) continue;
            String k = h.substring(0, colon).trim().toLowerCase();
            String v = h.substring(colon + 1).trim();
            respHdrs.put(k, v);
            if ("set-cookie".equals(k)) setCookies.add(v);
        }

        // Response body (limit 512KB)
        int    bodyOffset = respInfo.getBodyOffset();
        // Clamp bodyOffset to valid range before computing bodyLen
        bodyOffset = Math.max(0, Math.min(bodyOffset, respBytes.length));
        int    bodyLen    = Math.min(respBytes.length - bodyOffset, 512_000);
        byte[] bodyBytes  = Arrays.copyOfRange(respBytes, bodyOffset, bodyOffset + bodyLen);
        String body;
        try { body = helpers.bytesToString(bodyBytes); }
        catch (Exception e) { body = ""; }

        String contentType = respHdrs.getOrDefault("content-type", "");

        // Extract request body (limit 64KB — we only need it for credential checks)
        int    reqBodyOffset = reqInfo.getBodyOffset();
        int    reqBodyLen    = Math.min(reqBytes.length - reqBodyOffset, 65_536);
        String reqBody = "";
        if (reqBodyLen > 0) {
            try {
                reqBody = helpers.bytesToString(
                        Arrays.copyOfRange(reqBytes, reqBodyOffset, reqBodyOffset + reqBodyLen));
            } catch (Exception ignored) {}
        }

        List<Finding> findings = Dispatcher.dispatch(
                reqHdrs, respHdrs, setCookies,
                body, contentType,
                reqInfo.getMethod(),
                host, url, statusCode,
                reqBody,
                reqBytes, respBytes,
                messageInfo.getHttpService());

        for (Finding f : findings) {
            if (store.add(f)) {
                stdout.println(String.format("[BurpMax] %s | %s | %s [HTTP %d]",
                        f.severity.toUpperCase(),
                        sanitizeLog(f.name),
                        sanitizeLog(f.endpoint),
                        f.statusCode));
            }
        }
    }

    /** Returns true if the URL contains path traversal sequences injected by the active scanner. */
    private static boolean isTraversalUrl(String url) {
        if (url == null) return false;
        String lower = url.toLowerCase();
        // Standard traversal sequences and their URL-encoded forms
        return lower.contains("/../") || lower.contains("/..%2f") || lower.contains("/..%5c")
            || lower.contains("/....//") || lower.contains("/../..") || lower.contains("%2e%2e")
            || lower.contains("..%252f") || lower.contains("..%255c")
            || lower.contains("..%c0%af") || lower.contains("..%e0%80%af")
            || lower.contains("/.%2e/") || lower.contains("/%2e%2e/")
            || lower.contains("..\\..\\") || lower.contains("%00.png") || lower.contains("%00.jpg")
            || lower.contains(";/../") || lower.contains("%3b/../");
    }

    /** Strip CR/LF from log output to prevent log injection. */
    private static String sanitizeLog(String s) {
        if (s == null) return "";
        return s.replace("\r", "").replace("\n", " ").replace("\t", " ");
    }

    private Map<String, String> parseHeaders(List<String> headers, boolean skipFirst) {
        Map<String, String> out = new LinkedHashMap<>();
        int start = skipFirst ? 1 : 0;
        for (int i = start; i < headers.size(); i++) {
            String h = headers.get(i);
            int colon = h.indexOf(':');
            if (colon < 0) continue;
            String k = h.substring(0, colon).trim().toLowerCase();
            String v = h.substring(colon + 1).trim();
            out.put(k, v);
        }
        return out;
    }

}
