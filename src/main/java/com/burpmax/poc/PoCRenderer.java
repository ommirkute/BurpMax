package com.burpmax.poc;

import java.awt.*;
import java.awt.BasicStroke;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.util.*;
import java.util.List;
import javax.imageio.ImageIO;

/**
 * Renders a probe HTTP request + response side-by-side into a PNG image
 * styled like Burp Suite's Repeater editor, with finding-aware annotations.
 *
 * Six quality improvements over the previous version:
 *
 *  1. Probe request bytes used instead of original — the rendered request is
 *     the actual mutated request that triggered the finding, not the clean original.
 *
 *  2. Payload highlight in request panel — the injected payload string is located
 *     in the request line-by-line and rendered with a yellow highlight behind it,
 *     making the injection point immediately visible.
 *
 *  3. Evidence highlight in response body — the evidence string (DB error, reflected
 *     marker, header value) is located in the response and highlighted in the same
 *     yellow/red style. Response is scrolled to show the evidence within the first
 *     visible lines rather than from line 1 when it appears deep in the body.
 *
 *  4. Response scroll to evidence — if the evidence match is found below line N,
 *     the response panel starts rendering from (matchLine - CONTEXT_LINES) so the
 *     relevant content is always visible. A scroll indicator is shown.
 *
 *  5. Time-based annotation overlay — for timing-based findings (timingMs > 0),
 *     a banner is painted across the bottom of the response panel showing the
 *     observed delay vs baseline, since the response body itself contains no evidence.
 *
 *  6. Finding-type-aware rendering — the name field routes to specialised highlight
 *     logic: XSS uses marker search, SQLi uses error string search, CORS/SSRF use
 *     header search, time-based findings suppress body search and show the banner.
 *
 * Preserved from original:
 *  - Request line (method + path + version) highlighted orange bold
 *  - Status line colour-coded by HTTP status code (2xx green, 3xx orange, 4xx/5xx red)
 *  - Host header red-bordered in request panel
 *  - Header name (blue bold) / value (grey) syntax colouring
 *  - Line numbers in gutter
 *  - Dynamic image height driven by content, capped at MAX_LINES
 *  - Truncation notice when content is cut off
 */
public class PoCRenderer {

    // ── Layout ────────────────────────────────────────────────────────────────
    private static final int IMG_WIDTH      = 2400;  // increased from 1800 for crisp PDF scaling
    private static final int PANEL_WIDTH    = IMG_WIDTH / 2;
    private static final int HEADER_H       = 48;
    private static final int PADDING_TOP    = 14;
    private static final int PADDING_LEFT   = 14;
    private static final int LINE_NUM_W     = 56;
    private static final int FONT_SIZE      = 18;
    private static final int LINE_H         = 22;
    private static final int MAX_LINES      = 200;
    private static final int MIN_LINES      = 15;
    private static final int BOTTOM_PAD     = 36;   // extra for timing banner
    private static final int CONTEXT_LINES  = 4;    // lines before evidence to show when scrolling

    private static final int MAX_REQ_CHARS  = 16_384;
    private static final int MAX_RESP_CHARS = 32_768;

    // ── Colors ────────────────────────────────────────────────────────────────
    private static final Color C_BG           = new Color(0xFF, 0xFF, 0xFF);
    private static final Color C_LINE_NUM     = new Color(0x99, 0x99, 0x99);
    private static final Color C_LINE_NUM_BG  = new Color(0xF0, 0xF0, 0xF0);
    private static final Color C_TEXT         = new Color(0x20, 0x20, 0x20);
    private static final Color C_TITLE_ACCENT = new Color(0xFF, 0x6B, 0x35);
    private static final Color C_TRUNCATED    = new Color(0x99, 0x44, 0x44);
    private static final Color C_RED_BORDER   = new Color(0xCC, 0x22, 0x22);

    // Syntax highlight
    private static final Color C_REQ_LINE    = new Color(0xD4, 0x6A, 0x00);   // request line
    private static final Color C_HEADER_NAME = new Color(0x00, 0x5C, 0xC8);   // header names
    private static final Color C_HEADER_VAL  = new Color(0x44, 0x44, 0x44);   // header values
    private static final Color C_STATUS_2xx  = new Color(0x28, 0x7A, 0x28);
    private static final Color C_STATUS_3xx  = new Color(0xD4, 0x6A, 0x00);
    private static final Color C_STATUS_4xx  = new Color(0xCC, 0x22, 0x22);
    private static final Color C_STATUS_5xx  = new Color(0xCC, 0x22, 0x22);

    // Annotation colors
    private static final Color C_PAYLOAD_BG  = new Color(0xFF, 0xF0, 0x80);   // yellow highlight
    private static final Color C_PAYLOAD_BD  = new Color(0xCC, 0x88, 0x00);   // amber border
    private static final Color C_EVIDENCE_BG = new Color(0xFF, 0xE8, 0xE8);   // light red highlight
    private static final Color C_TIMING_BG   = new Color(0xFF, 0xF3, 0xCD);   // warm amber banner
    private static final Color C_TIMING_TEXT = new Color(0x7D, 0x4B, 0x00);
    private static final Color C_SCROLL_BG   = new Color(0xE8, 0xF4, 0xFF);   // blue scroll notice
    private static final Color C_SCROLL_TEXT = new Color(0x00, 0x50, 0xA0);

    // HTTP methods
    private static final Set<String> HTTP_METHODS = Set.of(
            "GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS","TRACE","CONNECT");

    // ── Fonts ─────────────────────────────────────────────────────────────────
    private static final Font FONT_MONO   = new Font(Font.MONOSPACED, Font.PLAIN,  FONT_SIZE);
    private static final Font FONT_MONO_B = new Font(Font.MONOSPACED, Font.BOLD,   FONT_SIZE);
    private static final Font FONT_TITLE  = new Font(Font.SANS_SERIF, Font.BOLD,   13);
    private static final Font FONT_ANNOT  = new Font(Font.SANS_SERIF, Font.BOLD,   11);

    // ── Public API ────────────────────────────────────────────────────────────

    /** Context passed by DocxExporter carrying everything the renderer needs. */
    public static class PoCContext {
        public final String findingName;
        public final String payload;      // injected payload string (may be null)
        public final String parameter;    // injection point name (may be null)
        public final String evidence;     // evidence string for response search
        public final long   timingMs;     // observed delay for time-based (-1 = none)

        public PoCContext(String findingName, String payload, String parameter,
                          String evidence, long timingMs) {
            this.findingName = findingName != null ? findingName : "";
            this.payload     = payload;
            this.parameter   = parameter;
            this.evidence    = evidence;
            this.timingMs    = timingMs;
        }
    }

    /** Result carrying PNG bytes and dimensions (avoids re-decoding PNG). */
    public static class RenderResult {
        public final byte[] png;
        public final int    widthPx;
        public final int    heightPx;
        RenderResult(byte[] png, int w, int h) { this.png=png; this.widthPx=w; this.heightPx=h; }
    }

    /** Primary entry point used by DocxExporter. */
    public static RenderResult renderWithDimensions(byte[] rawRequest, byte[] rawResponse,
                                                     PoCContext ctx) throws Exception {
        byte[] png = render(rawRequest, rawResponse, ctx);
        // Compute height (same formula as in render())
        String reqT  = toText(rawRequest,  MAX_REQ_CHARS);
        String respT = toText(rawResponse, MAX_RESP_CHARS);
        int lines = Math.max(Math.max(
                Math.min(splitLines(reqT).size(),  MAX_LINES),
                Math.min(splitLines(respT).size(), MAX_LINES)), MIN_LINES);
        int h = HEADER_H + PADDING_TOP + lines * LINE_H + BOTTOM_PAD;
        return new RenderResult(png, IMG_WIDTH, h);
    }

    /** Legacy overload — called with just evidence string (passive findings). */
    public static RenderResult renderWithDimensions(byte[] rawRequest, byte[] rawResponse,
                                                     String evidence) throws Exception {
        return renderWithDimensions(rawRequest, rawResponse,
                new PoCContext("", null, null, evidence, -1L));
    }

    /** Render to raw PNG bytes. */
    public static byte[] render(byte[] rawRequest, byte[] rawResponse,
                                PoCContext ctx) throws Exception {
        String reqText  = toText(rawRequest,  MAX_REQ_CHARS);
        String respText = toText(rawResponse, MAX_RESP_CHARS);
        boolean reqTrunc  = rawRequest  != null && rawRequest.length  > MAX_REQ_CHARS;
        boolean respTrunc = rawResponse != null && rawResponse.length > MAX_RESP_CHARS;

        List<String> reqLines  = splitLines(reqText);
        List<String> respLines = splitLines(respText);

        // Determine response scroll offset based on evidence location
        boolean isTimeBased = suppressBodyEvidence(ctx);
        int     respOffset  = 0;
        int     evidenceLine = -1;

        if (!isTimeBased && ctx.evidence != null) {
            evidenceLine = findEvidenceLine(respLines, ctx);
            if (evidenceLine > CONTEXT_LINES + 5) {
                respOffset = Math.max(0, evidenceLine - CONTEXT_LINES);
            }
        }

        int reqCount  = Math.min(reqLines.size(),                    MAX_LINES);
        int respCount = Math.min(respLines.size() - respOffset,      MAX_LINES);
        int lineCount = Math.max(Math.max(reqCount, respCount), MIN_LINES);
        int imgHeight = HEADER_H + PADDING_TOP + lineCount * LINE_H + BOTTOM_PAD;

        BufferedImage img = new BufferedImage(IMG_WIDTH, imgHeight, BufferedImage.TYPE_INT_RGB);
        Graphics2D    g   = img.createGraphics();
        g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING,
                           RenderingHints.VALUE_TEXT_ANTIALIAS_LCD_HRGB);
        g.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);

        // Background
        g.setColor(C_BG);
        g.fillRect(0, 0, IMG_WIDTH, imgHeight);

        // Header bars
        drawHeader(g, 0,           "Request");
        drawHeader(g, PANEL_WIDTH, "Response");

        // Center divider
        g.setColor(new Color(0xCC, 0xCC, 0xCC));
        g.fillRect(PANEL_WIDTH, 0, 1, imgHeight);

        // ── Request panel ──────────────────────────────────────────────────
        DrawResult reqResult = drawRequestPanel(g, reqLines, ctx, reqTrunc, imgHeight);

        // ── Response panel ─────────────────────────────────────────────────
        DrawResult respResult = drawResponsePanel(g, respLines, ctx, respTrunc,
                                                   respOffset, evidenceLine, imgHeight);

        // ── Outer border ───────────────────────────────────────────────────
        g.setColor(Color.BLACK);
        g.setStroke(new BasicStroke(2.0f));
        g.drawRect(1, 1, IMG_WIDTH - 2, imgHeight - 2);
        g.setStroke(new BasicStroke(1.0f));

        g.dispose();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(img, "png", baos);
        return baos.toByteArray();
    }

    /** Legacy render with string evidence only. */
    public static byte[] render(byte[] rawRequest, byte[] rawResponse,
                                String evidence) throws Exception {
        return render(rawRequest, rawResponse,
                new PoCContext("", null, null, evidence, -1L));
    }

    // ── Request panel ─────────────────────────────────────────────────────────

    private static DrawResult drawRequestPanel(Graphics2D g, List<String> lines,
                                                PoCContext ctx, boolean truncated,
                                                int imgHeight) {
        int startY = HEADER_H;
        g.setFont(FONT_MONO);
        FontMetrics fm = g.getFontMetrics();
        int availW = PANEL_WIDTH - LINE_NUM_W - PADDING_LEFT - 4;

        int line0Width = 0;
        boolean inHeaders = true;

        // Pre-locate payload in the request lines for highlight rendering
        PayloadLocation payloadLoc = ctx.payload != null
                ? findPayloadInLines(lines, ctx.payload, 0) : null;

        for (int i = 0; i < Math.min(lines.size(), MAX_LINES); i++) {
            String line   = lines.get(i);
            int    lineTop = startY + PADDING_TOP + i * LINE_H;
            int    y       = lineTop + fm.getAscent();
            int    textX   = LINE_NUM_W + PADDING_LEFT;

            if (line.trim().isEmpty()) inHeaders = false;

            drawGutter(g, 0, lineTop, i + 1, fm);

            if (i == 0) {
                // Request line: METHOD /path HTTP/version — always highlight orange
                // Also highlight payload if it appears in the URL (query param injection)
                boolean payloadInRequestLine = payloadLoc != null && payloadLoc.lineIdx == 0;
                if (payloadInRequestLine) {
                    // Draw normal request line first, then overlay payload highlight
                    line0Width = drawRequestLine(g, fm, line, textX, y, availW);
                    drawLineWithPayloadHighlight(g, fm, line, 0, textX, y, availW,
                            payloadLoc.charOffset, ctx.payload);
                } else {
                    line0Width = drawRequestLine(g, fm, line, textX, y, availW);
                }
                drawRedBorder(g, 0, startY, 0, line0Width);
                g.setFont(FONT_MONO);
                fm = g.getFontMetrics();
            } else if (inHeaders) {
                // Check for Host header — red-border + orange treatment
                boolean isHost = lineMatchesHeader(line, "host");
                if (isHost) {
                    int hostW = drawHostLine(g, fm, line, textX, y, availW);
                    drawRedBorder(g, 0, startY, i, hostW);
                } else {
                    drawHeaderLine(g, fm, line, textX, y, availW);
                }
            } else {
                // Body line — check for payload highlight
                if (payloadLoc != null && payloadLoc.lineIdx == i) {
                    drawLineWithPayloadHighlight(g, fm, line, 0, textX, y, availW,
                                                 payloadLoc.charOffset, ctx.payload);
                } else {
                    g.setFont(FONT_MONO);
                    g.setColor(C_TEXT);
                    g.drawString(clip(line, fm, availW), textX, y);
                }
            }

            // Payload highlight in header lines (e.g. injected header value)
            if (inHeaders && i > 0 && payloadLoc != null && payloadLoc.lineIdx == i) {
                // Overlay yellow highlight on the value portion
                drawHeaderPayloadHighlight(g, fm, line, 0, textX, y, availW, ctx.payload);
            }
        }

        drawTruncationNotice(g, 0, startY, lines.size(), truncated);
        return new DrawResult(line0Width);
    }

    // ── Response panel ────────────────────────────────────────────────────────

    private static DrawResult drawResponsePanel(Graphics2D g, List<String> lines,
                                                 PoCContext ctx, boolean truncated,
                                                 int scrollOffset, int evidenceLineAbs,
                                                 int imgHeight) {
        int startY = HEADER_H;
        g.setFont(FONT_MONO);
        FontMetrics fm = g.getFontMetrics();
        int availW = PANEL_WIDTH - LINE_NUM_W - PADDING_LEFT - 4;
        int panelX = PANEL_WIDTH;

        boolean isTimeBased = suppressBodyEvidence(ctx);
        int line0Width = 0;
        boolean inHeaders = true;

        // Scroll indicator
        if (scrollOffset > 0) {
            drawScrollNotice(g, panelX, startY, scrollOffset);
        }

        // Determine which response body lines contain the evidence
        String evidenceSnippet = extractEvidenceSnippet(ctx);

        for (int i = 0; i < Math.min(lines.size() - scrollOffset, MAX_LINES); i++) {
            int    absIdx  = i + scrollOffset;
            String line    = lines.get(absIdx);
            int    lineTop = startY + PADDING_TOP + i * LINE_H;
            int    y       = lineTop + fm.getAscent();
            int    textX   = panelX + LINE_NUM_W + PADDING_LEFT;

            if (line.trim().isEmpty()) inHeaders = false;

            drawGutter(g, panelX, lineTop, absIdx + 1, fm);

            if (absIdx == 0) {
                // Status line: HTTP/x.x NNN Reason
                line0Width = drawStatusLine(g, fm, line, textX, y, availW);
                drawRedBorder(g, panelX, startY, 0, line0Width);
                g.setFont(FONT_MONO);
                fm = g.getFontMetrics();
            } else if (inHeaders) {
                // Highlight the evidence header if this line matches
                boolean isEvidenceHeader = (!isTimeBased && evidenceSnippet != null
                        && isHeaderEvidence(ctx)
                        && lineContainsEvidence(line, evidenceSnippet));
                if (isEvidenceHeader) {
                    int ew = drawEvidenceLine(g, fm, line, textX, y, availW);
                    drawRedBorder(g, panelX, startY, i, ew);
                } else {
                    drawHeaderLine(g, fm, line, textX, y, availW);
                }
            } else {
                // Body line — highlight evidence substring
                boolean isEvidenceLine = (!isTimeBased && evidenceSnippet != null
                        && !isHeaderEvidence(ctx)
                        && lineContainsEvidence(line, evidenceSnippet));
                if (isEvidenceLine) {
                    drawLineWithEvidenceHighlight(g, fm, line, panelX, textX, y,
                                                  availW, evidenceSnippet);
                } else {
                    g.setFont(FONT_MONO);
                    g.setColor(C_TEXT);
                    g.drawString(clip(line, fm, availW), textX, y);
                }
            }
        }

        drawTruncationNotice(g, panelX, startY, lines.size() - scrollOffset, truncated);

        // Time-based annotation banner
        // Show timing banner only when there is a confirmed measured delay.
        // OOB blind findings (timingMs==-1) suppress body evidence but don't show a banner.
        if (hasTimingEvidence(ctx)) {
            drawTimingBanner(g, panelX, imgHeight, ctx.timingMs);
        }

        return new DrawResult(line0Width);
    }

    // ── Drawing helpers ───────────────────────────────────────────────────────

    private static void drawHeader(Graphics2D g, int x, String title) {
        g.setColor(C_BG);
        g.fillRect(x, 0, PANEL_WIDTH, HEADER_H);
        g.setColor(new Color(0xDD, 0xDD, 0xDD));
        g.fillRect(x, HEADER_H - 1, PANEL_WIDTH, 1);
        g.setColor(C_TITLE_ACCENT);
        g.fillRect(x + 8, HEADER_H - 3, 90, 3);
        g.setFont(FONT_TITLE);
        g.setColor(new Color(0x22, 0x22, 0x22));
        FontMetrics fm = g.getFontMetrics();
        int tx = x + 8 + (90 - fm.stringWidth(title)) / 2;
        int ty = (HEADER_H - fm.getHeight()) / 2 + fm.getAscent();
        g.drawString(title, tx, ty);
    }

    private static void drawGutter(Graphics2D g, int panelX, int lineTop, int lineNum, FontMetrics fm) {
        g.setColor(C_LINE_NUM_BG);
        g.fillRect(panelX, lineTop, LINE_NUM_W, LINE_H);
        g.setColor(C_LINE_NUM);
        g.setFont(FONT_MONO);
        String num = String.valueOf(lineNum);
        int nx = panelX + LINE_NUM_W - fm.stringWidth(num) - 4;
        g.drawString(num, nx, lineTop + fm.getAscent());
    }

    /**
     * Draw request line: METHOD /path HTTP/version.
     * Method and path: bold orange. Version: dim grey.
     * Returns rendered pixel width.
     */
    private static int drawRequestLine(Graphics2D g, FontMetrics fm,
                                        String line, int x, int y, int availW) {
        String[] parts = line.split(" ", 3);
        if (parts.length < 1 || !HTTP_METHODS.contains(parts[0])) {
            // Fallback: treat as status line or unknown
            if (line.startsWith("HTTP/")) return drawStatusLine(g, fm, line, x, y, availW);
            g.setFont(FONT_MONO); g.setColor(C_TEXT);
            String cl = clip(line, fm, availW); g.drawString(cl, x, y);
            return fm.stringWidth(cl);
        }

        int curX = x;
        // Method — bold orange
        g.setFont(FONT_MONO_B);
        FontMetrics bfm = g.getFontMetrics();
        g.setColor(C_REQ_LINE);
        String method = parts[0];
        g.drawString(method, curX, y);
        curX += bfm.stringWidth(method + " ");

        // Path — regular orange
        g.setFont(FONT_MONO);
        fm = g.getFontMetrics();
        if (parts.length >= 2) {
            g.setColor(C_REQ_LINE);
            int versionW = parts.length >= 3 ? fm.stringWidth(" " + parts[2]) : 0;
            String path = clip(parts[1], fm, availW - (curX - x) - versionW);
            g.drawString(path, curX, y);
            curX += fm.stringWidth(path + " ");
        }

        // Version — dim grey
        if (parts.length >= 3) {
            g.setColor(C_HEADER_VAL);
            String ver = parts[2];
            if (curX - x + fm.stringWidth(ver) <= availW) {
                g.drawString(ver, curX, y);
                curX += fm.stringWidth(ver);
            }
        }
        g.setFont(FONT_MONO);
        return curX - x;
    }

    /**
     * Draw response status line: HTTP/x.x NNN Reason.
     * Colour-coded by status code. Bold.
     * Returns rendered pixel width.
     */
    private static int drawStatusLine(Graphics2D g, FontMetrics fm,
                                       String line, int x, int y, int availW) {
        Color statusColor = C_STATUS_2xx;
        String[] parts = line.split(" ", 3);
        if (parts.length >= 2) {
            try {
                int code = Integer.parseInt(parts[1].trim());
                if      (code >= 500) statusColor = C_STATUS_5xx;
                else if (code >= 400) statusColor = C_STATUS_4xx;
                else if (code >= 300) statusColor = C_STATUS_3xx;
                else                  statusColor = C_STATUS_2xx;
            } catch (NumberFormatException ignored) {}
        }
        g.setFont(FONT_MONO_B);
        FontMetrics bfm = g.getFontMetrics();
        String clipped = clip(line, bfm, availW);
        g.setColor(statusColor);
        g.drawString(clipped, x, y);
        g.setFont(FONT_MONO);
        return bfm.stringWidth(clipped);
    }

    /** Draw Host header line with orange name (matching request line colour). */
    private static int drawHostLine(Graphics2D g, FontMetrics fm,
                                     String line, int x, int y, int availW) {
        int colon = line.indexOf(':');
        if (colon < 0) { g.setColor(C_TEXT); g.drawString(clip(line, fm, availW), x, y); return fm.stringWidth(line); }
        String name  = line.substring(0, colon + 1);
        String value = line.substring(colon + 1);
        g.setFont(FONT_MONO_B); g.setColor(C_REQ_LINE);
        g.drawString(name, x, y);
        int nameW = g.getFontMetrics().stringWidth(name);
        g.setFont(FONT_MONO); g.setColor(C_HEADER_VAL);
        String val = clip(value, fm, availW - nameW);
        g.drawString(val, x + nameW, y);
        return nameW + fm.stringWidth(val);
    }

    /** Draw standard header line: Name (blue bold) : value (grey). */
    private static void drawHeaderLine(Graphics2D g, FontMetrics fm,
                                        String line, int x, int y, int availW) {
        int colon = line.indexOf(':');
        if (colon < 0) { g.setFont(FONT_MONO); g.setColor(C_TEXT); g.drawString(clip(line, fm, availW), x, y); return; }
        String name  = line.substring(0, colon + 1);
        String value = line.substring(colon + 1);
        g.setFont(FONT_MONO_B); g.setColor(C_HEADER_NAME);
        g.drawString(name, x, y);
        int nameW = g.getFontMetrics().stringWidth(name);
        g.setFont(FONT_MONO); g.setColor(C_HEADER_VAL);
        g.drawString(clip(value, fm, availW - nameW), x + nameW, y);
    }

    /** Draw evidence header in red (name + value both red bold). Returns width. */
    private static int drawEvidenceLine(Graphics2D g, FontMetrics fm,
                                         String line, int x, int y, int availW) {
        int colon = line.indexOf(':');
        String name  = colon >= 0 ? line.substring(0, colon + 1) : line;
        String value = colon >= 0 ? line.substring(colon + 1) : "";
        g.setFont(FONT_MONO_B); g.setColor(C_RED_BORDER);
        g.drawString(name, x, y);
        int nameW = g.getFontMetrics().stringWidth(name);
        g.setFont(FONT_MONO); g.setColor(C_RED_BORDER);
        String val = clip(value, fm, availW - nameW);
        g.drawString(val, x + nameW, y);
        return nameW + fm.stringWidth(val);
    }

    /**
     * Draw a body line with the payload highlighted in yellow.
     * The payload substring gets a filled yellow rect behind it, then the text is
     * rendered in two segments: before and after the payload, with the payload in bold.
     */
    private static void drawLineWithPayloadHighlight(Graphics2D g, FontMetrics fm,
                                                      String line, int panelX,
                                                      int textX, int y, int availW,
                                                      int charOffset, String payload) {
        if (charOffset < 0 || charOffset >= line.length()) {
            g.setFont(FONT_MONO); g.setColor(C_TEXT);
            g.drawString(clip(line, fm, availW), textX, y);
            return;
        }
        int payEnd = Math.min(charOffset + payload.length(), line.length());

        String before  = line.substring(0, charOffset);
        String matched = line.substring(charOffset, payEnd);
        String after   = line.substring(payEnd);

        g.setFont(FONT_MONO);
        int beforeW  = fm.stringWidth(before);
        int matchW   = fm.stringWidth(matched);

        // Yellow highlight rect
        int lineTop = y - fm.getAscent();
        g.setColor(C_PAYLOAD_BG);
        g.fillRect(textX + beforeW - 1, lineTop, matchW + 2, LINE_H);
        // Amber border
        g.setColor(C_PAYLOAD_BD);
        g.setStroke(new BasicStroke(1.0f));
        g.drawRect(textX + beforeW - 1, lineTop, matchW + 2, LINE_H - 1);

        // Draw text: before (normal), payload (bold), after (normal)
        g.setFont(FONT_MONO); g.setColor(C_TEXT);
        g.drawString(clip(before, fm, availW), textX, y);
        g.setFont(FONT_MONO_B); g.setColor(new Color(0x80, 0x40, 0x00));
        g.drawString(matched, textX + beforeW, y);
        g.setFont(FONT_MONO); g.setColor(C_TEXT);
        int afterX = textX + beforeW + matchW;
        if (afterX - textX < availW) {
            g.drawString(clip(after, fm, availW - (afterX - textX)), afterX, y);
        }
    }

    /**
     * Draw a header line where the payload appears in the value portion.
     * Overlays a yellow highlight on the matching chars without re-drawing the header name.
     */
    private static void drawHeaderPayloadHighlight(Graphics2D g, FontMetrics fm,
                                                    String line, int panelX,
                                                    int textX, int y, int availW,
                                                    String payload) {
        int colon = line.indexOf(':');
        if (colon < 0) return;
        String name  = line.substring(0, colon + 1);
        String value = line.substring(colon + 1);

        // Find payload in the value string
        int payIdx = value.toLowerCase().indexOf(payload.toLowerCase());
        if (payIdx < 0) return;

        g.setFont(FONT_MONO_B);
        int nameW = g.getFontMetrics().stringWidth(name);
        g.setFont(FONT_MONO);

        int payStartX = textX + nameW + fm.stringWidth(value.substring(0, payIdx));
        int payW      = fm.stringWidth(payload);
        int lineTop   = y - fm.getAscent();

        g.setColor(C_PAYLOAD_BG);
        g.fillRect(payStartX - 1, lineTop, payW + 2, LINE_H);
        g.setColor(C_PAYLOAD_BD);
        g.drawRect(payStartX - 1, lineTop, payW + 2, LINE_H - 1);
    }

    /**
     * Draw a response body line with the evidence substring highlighted in red.
     */
    private static void drawLineWithEvidenceHighlight(Graphics2D g, FontMetrics fm,
                                                       String line, int panelX,
                                                       int textX, int y, int availW,
                                                       String evidenceSnippet) {
        int idx = line.toLowerCase().indexOf(evidenceSnippet.toLowerCase());
        if (idx < 0) {
            g.setFont(FONT_MONO); g.setColor(C_TEXT);
            g.drawString(clip(line, fm, availW), textX, y);
            return;
        }

        String before  = line.substring(0, idx);
        String matched = line.substring(idx, Math.min(idx + evidenceSnippet.length(), line.length()));
        String after   = line.substring(Math.min(idx + evidenceSnippet.length(), line.length()));

        g.setFont(FONT_MONO);
        int beforeW = fm.stringWidth(before);
        int matchW  = fm.stringWidth(matched);
        int lineTop = y - fm.getAscent();

        // Red highlight background
        g.setColor(C_EVIDENCE_BG);
        g.fillRect(textX + beforeW - 1, lineTop, matchW + 2, LINE_H);
        g.setColor(C_RED_BORDER);
        g.setStroke(new BasicStroke(1.0f));
        g.drawRect(textX + beforeW - 1, lineTop, matchW + 2, LINE_H - 1);

        // Draw text
        g.setColor(C_TEXT); g.drawString(clip(before, fm, availW), textX, y);
        g.setFont(FONT_MONO_B); g.setColor(C_RED_BORDER);
        g.drawString(matched, textX + beforeW, y);
        g.setFont(FONT_MONO); g.setColor(C_TEXT);
        int afterX = textX + beforeW + matchW;
        if (afterX - textX < availW)
            g.drawString(clip(after, fm, availW - (afterX - textX)), afterX, y);
    }

    /** Draw timing annotation banner at the bottom of the response panel. */
    private static void drawTimingBanner(Graphics2D g, int panelX, int imgHeight, long timingMs) {
        int bannerH = 22;
        int bannerY = imgHeight - bannerH - 1;
        g.setColor(C_TIMING_BG);
        g.fillRect(panelX + 1, bannerY, PANEL_WIDTH - 2, bannerH);
        g.setColor(new Color(0xCC, 0xA0, 0x00));
        g.setStroke(new BasicStroke(1.0f));
        g.drawLine(panelX + 1, bannerY, panelX + PANEL_WIDTH - 2, bannerY);
        g.setFont(FONT_ANNOT);
        g.setColor(C_TIMING_TEXT);
        String msg = "\u23F1  Time-based: response delayed " + (timingMs / 1000.0) + "s "
                + "(no body evidence - timing is the confirmation)";
        g.drawString(msg, panelX + 8, bannerY + 15);
    }

    /** Draw scroll-offset notice at the top of the response panel body area. */
    private static void drawScrollNotice(Graphics2D g, int panelX, int startY, int offset) {
        int noticeH = 16;
        int noticeY = startY + PADDING_TOP;
        g.setColor(C_SCROLL_BG);
        g.fillRect(panelX + LINE_NUM_W, noticeY, PANEL_WIDTH - LINE_NUM_W, noticeH);
        g.setFont(FONT_ANNOT);
        g.setColor(C_SCROLL_TEXT);
        g.drawString("  \u2193 scrolled to evidence (+" + offset + " lines)", panelX + LINE_NUM_W + 4, noticeY + 12);
    }

    private static void drawTruncationNotice(Graphics2D g, int panelX, int startY,
                                              int linesAvailable, boolean truncated) {
        if (truncated || linesAvailable > MAX_LINES) {
            g.setFont(FONT_MONO);
            FontMetrics fm = g.getFontMetrics();
            int y = startY + PADDING_TOP + MAX_LINES * LINE_H + fm.getAscent();
            g.setColor(C_TRUNCATED);
            g.drawString("  [... truncated ...]", panelX + LINE_NUM_W + PADDING_LEFT, y);
        }
    }

    private static void drawRedBorder(Graphics2D g, int panelX, int startY,
                                       int lineIdx, int textWidth) {
        int textX = panelX + LINE_NUM_W + PADDING_LEFT;
        int boxX  = textX - 2;
        int boxY  = startY + PADDING_TOP + lineIdx * LINE_H - 1;
        int boxW  = textWidth + 4;
        int boxH  = LINE_H + 1;
        g.setColor(C_RED_BORDER);
        g.setStroke(new BasicStroke(1.5f));
        g.drawRect(boxX, boxY, boxW, boxH);
        g.setStroke(new BasicStroke(1.0f));
    }

    // ── Evidence / payload location logic ────────────────────────────────────

    /**
     * Determine what to search for in the response based on finding type and evidence.
     * Returns a short, distinctive snippet (up to 60 chars) for line-level matching.
     */
    private static String extractEvidenceSnippet(PoCContext ctx) {
        if (ctx.evidence == null || ctx.evidence.isBlank()) return null;
        String ev    = ctx.evidence;
        String name  = ctx.findingName.toLowerCase();

        // XSS: look for the marker in the evidence ("Marker reflected: avxssUID-tag")
        if (name.contains("xss")) {
            int idx = ev.indexOf("avxss");
            if (idx >= 0) {
                int end = idx;
                while (end < ev.length() && (Character.isLetterOrDigit(ev.charAt(end))
                        || ev.charAt(end) == '-' || ev.charAt(end) == '_')) end++;
                return ev.substring(idx, end);
            }
            // Fall through to generic extraction
        }

        // SQLi error-based: extract the error string after "DB Error: "
        if (name.contains("sql") && ev.contains("DB Error:")) {
            int idx = ev.indexOf("DB Error:") + 9;
            String err = ev.substring(idx).trim();
            return err.length() > 60 ? err.substring(0, 60) : err;
        }

        // Header-based findings: extract header name for header search
        // (CORS, Host Header, XXX-Protection, etc.)
        int colon = ev.indexOf(':');
        if (colon > 0 && colon < 50) {
            String candidate = ev.substring(0, colon).trim();
            if (candidate.matches("[A-Za-z][A-Za-z0-9\\-]+")) return candidate.toLowerCase();
        }

        // Generic: take up to 60 chars of the evidence
        return ev.length() > 60 ? ev.substring(0, 60) : ev;
    }

    /** True if the evidence points to a response header (not a body substring). */
    private static boolean isHeaderEvidence(PoCContext ctx) {
        String name = ctx.findingName.toLowerCase();
        // Header-based: CORS, host-header, XSS-protection, content-security-policy, etc.
        if (name.contains("cors") || name.contains("host header")
                || name.contains("header injection")
                || name.contains("missing security header")
                || name.contains("x-frame") || name.contains("hsts")) return true;
        // If evidence looks like "HeaderName: value" at top level
        if (ctx.evidence != null) {
            int c = ctx.evidence.indexOf(':');
            if (c > 0 && c < 50) {
                String cand = ctx.evidence.substring(0, c).trim();
                if (cand.matches("[A-Za-z][A-Za-z0-9\\-]+") && !cand.contains(" ")) return true;
            }
        }
        return false;
    }

    private static boolean lineMatchesHeader(String line, String headerLower) {
        int c = line.indexOf(':');
        return c > 0 && line.substring(0, c).trim().toLowerCase().equals(headerLower);
    }

    private static boolean lineContainsEvidence(String line, String snippet) {
        if (snippet == null || snippet.isBlank()) return false;
        String lineLower = line.toLowerCase();
        String snipLower = snippet.toLowerCase();
        if (lineLower.contains(snipLower)) return true;
        // Also check URL-decoded form — payloads like %3Cscript%3E or %27 need matching
        try {
            String decoded = java.net.URLDecoder.decode(line, "UTF-8").toLowerCase();
            if (decoded.contains(snipLower)) return true;
        } catch (Exception ignored) {}
        return false;
    }

    /**
     * Find the first line index in respLines where the evidence snippet appears.
     * Returns -1 if not found.
     */
    private static int findEvidenceLine(List<String> lines, PoCContext ctx) {
        String snippet = extractEvidenceSnippet(ctx);
        if (snippet == null) return -1;
        for (int i = 0; i < lines.size(); i++) {
            if (lineContainsEvidence(lines.get(i), snippet)) return i;
        }
        return -1;
    }

    /**
     * Find the first occurrence of the payload string in the request lines.
     * Returns a PayloadLocation with line index and character offset, or null.
     */
    private static PayloadLocation findPayloadInLines(List<String> lines, String payload, int startLine) {
        if (payload == null || payload.isBlank()) return null;
        String pl = payload.toLowerCase();
        // Also prepare URL-encoded form for matching in query strings
        String plEncoded = null;
        try { plEncoded = java.net.URLEncoder.encode(payload, "UTF-8").toLowerCase(); } catch (Exception ignored) {}

        for (int i = startLine; i < lines.size(); i++) {
            String line  = lines.get(i);
            String lower = line.toLowerCase();
            int idx = lower.indexOf(pl);
            if (idx >= 0) return new PayloadLocation(i, idx);
            // Check URL-encoded form
            if (plEncoded != null && !plEncoded.equals(pl)) {
                idx = lower.indexOf(plEncoded);
                if (idx >= 0) return new PayloadLocation(i, idx);
            }
        }
        return null;
    }

    /**
     * True if this finding has a confirmed timing delay — show the timing banner.
     * Only fires when timingMs is a real measured value (> 0).
     */
    private static boolean hasTimingEvidence(PoCContext ctx) {
        return ctx.timingMs > 0;
    }

    /**
     * True if body evidence search should be suppressed.
     * For OOB blind findings (timingMs == -1 but name contains "blind"), there is
     * no body evidence — but we also should NOT show the timing banner because
     * timingMs == -1. So we suppress body search but let the response render normally.
     * For genuine time-based findings (timingMs > 0), suppress body search too.
     */
    private static boolean suppressBodyEvidence(PoCContext ctx) {
        if (ctx.timingMs > 0) return true;  // confirmed timing - banner covers it
        String n = ctx.findingName.toLowerCase();
        // Suppress body search for blind OOB findings — they have no response evidence
        return n.contains("time-based") || n.contains("timing");
        // NOTE: "blind" alone does NOT suppress — blind findings with probe bytes
        //       may still have body evidence if the OOB interaction detail is present.
    }

    // ── Text utilities ────────────────────────────────────────────────────────

    private static String clip(String s, FontMetrics fm, int maxWidth) {
        if (s == null) return "";
        while (s.length() > 0 && fm.stringWidth(s) > maxWidth)
            s = s.substring(0, s.length() - 1);
        return s;
    }

    private static String toText(byte[] bytes, int maxChars) {
        if (bytes == null || bytes.length == 0) return "(no data)";
        int len = Math.min(bytes.length, maxChars);
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            char c = (char)(bytes[i] & 0xFF);
            if (c == '\n' || c == '\r' || (c >= 0x20 && c < 0x7F)) sb.append(c);
            else sb.append('.');
        }
        // Strip bidi control chars
        return sb.toString()
                 .replaceAll("[\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF]", ".");
    }

    private static List<String> splitLines(String text) {
        List<String> lines = new ArrayList<>();
        if (text == null || text.isEmpty()) { lines.add("(empty)"); return lines; }
        String norm = text.replace("\r\n", "\n").replace("\r", "\n");
        for (String line : norm.split("\n", -1))
            lines.add(line.replace("\t", "    "));
        while (!lines.isEmpty() && lines.get(lines.size()-1).trim().isEmpty())
            lines.remove(lines.size()-1);
        if (lines.isEmpty()) lines.add("(empty)");
        return lines;
    }

    // ── Inner types ───────────────────────────────────────────────────────────

    private record PayloadLocation(int lineIdx, int charOffset) {}
    private record DrawResult(int line0Width) {}
}
