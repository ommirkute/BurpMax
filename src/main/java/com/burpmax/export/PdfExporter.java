package com.burpmax.export;

import com.burpmax.model.Finding;
import com.burpmax.poc.PoCRenderer;

import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;
import javax.imageio.ImageIO;

/**
 * Produces a professional PDF security assessment report directly from
 * Java2D without any external library dependency.
 *
 * PDF structure:
 *   Cover page   — title, client name, metadata, severity summary badge table
 *   TOC          — clickable links to each finding and the appendix
 *   Exec summary — overall risk rating, narrative, severity distribution table,
 *                  bar chart, top critical/high findings
 *   Findings     — one section per finding: header badge, metadata table,
 *                  description/evidence/remediation, PoC screenshot
 *   Appendix A   — compact reference table of all findings
 *
 * PDF generation approach:
 *   Each page is drawn onto a BufferedImage using Graphics2D (identical to the
 *   PoCRenderer pipeline), then the image bytes are written as a PDF image
 *   XObject. This gives pixel-perfect rendering with zero dependency on a PDF
 *   layout engine and guarantees that fonts, colours, and PoC screenshots
 *   appear exactly as designed.
 *
 *   Page dimensions: A4 at 96 dpi → 794 × 1123 px.
 *   Font stack:      Arial / SansSerif (universally available in the JVM).
 */
public class PdfExporter {

    // ── Page geometry ─────────────────────────────────────────────────────────
    private static final int PW   = 1240;   // A4 width  @ 150 dpi (794 * 150/96)
    private static final int PH   = 1754;   // A4 height @ 150 dpi (1123 * 150/96)
    private static final int ML   = 88;     // margin left  (56 * 150/96)
    private static final int MR   = 88;     // margin right
    private static final int MT   = 75;     // margin top
    private static final int MB   = 75;     // margin bottom
    private static final int CW   = PW - ML - MR;   // content width

    // ── Typography ────────────────────────────────────────────────────────────
    private static final Font F_TITLE    = new Font("Arial", Font.BOLD,   44);
    private static final Font F_H1       = new Font("Arial", Font.BOLD,   28);
    private static final Font F_H2       = new Font("Arial", Font.BOLD,   20);
    private static final Font F_H3       = new Font("Arial", Font.BOLD,   17);
    private static final Font F_BODY     = new Font("Arial", Font.PLAIN,  16);
    private static final Font F_BODY_B   = new Font("Arial", Font.BOLD,   16);
    private static final Font F_SMALL    = new Font("Arial", Font.PLAIN,  14);
    private static final Font F_SMALL_B  = new Font("Arial", Font.BOLD,   14);
    private static final Font F_MONO     = new Font(Font.MONOSPACED, Font.PLAIN, 13);
    private static final Font F_CAPTION  = new Font("Arial", Font.ITALIC, 14);

    // ── Colour palette ────────────────────────────────────────────────────────
    private static final Color C_PAGE     = Color.WHITE;
    private static final Color C_BRAND    = new Color(0x1F, 0x5C, 0x5C);
    private static final Color C_DARK     = new Color(0x1A, 0x25, 0x2F);
    private static final Color C_TEXT     = new Color(0x22, 0x22, 0x22);
    private static final Color C_MUTED    = new Color(0x77, 0x77, 0x77);
    private static final Color C_RULE     = new Color(0xCC, 0xCC, 0xCC);
    private static final Color C_TH_BG    = new Color(0x2C, 0x3E, 0x50);
    private static final Color C_ROW_ALT  = new Color(0xF8, 0xF9, 0xFA);
    private static final Color C_ROW_EVEN = new Color(0xFF, 0xFF, 0xFF);

    private static final Map<String, Color> SEV_FG = Map.of(
        Finding.SEV_CRITICAL, new Color(0x7B, 0x00, 0x00),
        Finding.SEV_HIGH,     new Color(0xC0, 0x39, 0x2B),
        Finding.SEV_MEDIUM,   new Color(0xD3, 0x54, 0x00),
        Finding.SEV_LOW,      new Color(0xB7, 0x95, 0x0B),
        Finding.SEV_INFO,     new Color(0x1A, 0x52, 0x76)
    );
    private static final Map<String, Color> SEV_BG = Map.of(
        Finding.SEV_CRITICAL, new Color(0xF9, 0xEB, 0xEA),
        Finding.SEV_HIGH,     new Color(0xFD, 0xED, 0xEC),
        Finding.SEV_MEDIUM,   new Color(0xFE, 0xF5, 0xE7),
        Finding.SEV_LOW,      new Color(0xFE, 0xFB, 0xD8),
        Finding.SEV_INFO,     new Color(0xEB, 0xF5, 0xFB)
    );
    private static final Map<String, Integer> SEV_ORDER = Map.of(
        Finding.SEV_CRITICAL, 0, Finding.SEV_HIGH, 1,
        Finding.SEV_MEDIUM,   2, Finding.SEV_LOW,  3, Finding.SEV_INFO, 4
    );

    // ── Logo ──────────────────────────────────────────────────────────────────
    private final java.awt.image.BufferedImage logoImage;

    private static java.awt.image.BufferedImage loadLogo(ReportMeta meta) {
        if (!meta.hasLogo()) return null;
        try {
            java.awt.image.BufferedImage img = ImageIO.read(new File(meta.logoPath));
            if (img == null) return null;
            // Scale to fit a 200px tall area, max 500px wide, preserving aspect ratio
            int maxH = 200, maxW = 500;
            double scale = Math.min((double) maxH / img.getHeight(), (double) maxW / img.getWidth());
            int w = (int) (img.getWidth()  * scale);
            int h = (int) (img.getHeight() * scale);
            java.awt.image.BufferedImage scaled = new java.awt.image.BufferedImage(w, h, java.awt.image.BufferedImage.TYPE_INT_ARGB);
            Graphics2D sg = scaled.createGraphics();
            sg.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BICUBIC);
            sg.drawImage(img, 0, 0, w, h, null);
            sg.dispose();
            return scaled;
        } catch (Exception e) {
            return null;
        }
    }
    private final List<byte[]>   pageImages  = new ArrayList<>();
    private       BufferedImage  page;
    private       Graphics2D     g;
    private       int            cy;         // current Y position on current page

    private final List<Finding>      sorted;
    private final ReportMeta         meta;
    private final Map<String,Integer>counts;
    private final List<PoCRenderer.RenderResult> pocImages;

    // ── Public API ────────────────────────────────────────────────────────────

    public static void export(List<Finding> findings, String filepath,
                               ReportMeta meta) throws Exception {
        if (!filepath.toLowerCase().endsWith(".pdf")) filepath += ".pdf";
        File outFile = new File(filepath).getCanonicalFile();
        if (outFile.getAbsolutePath().contains(".."))
            throw new SecurityException("Invalid export path: " + filepath);

        List<Finding> sorted = new ArrayList<>(findings);
        sorted.sort((a, b) -> Integer.compare(
            SEV_ORDER.getOrDefault(a.effectiveSeverity(), 99),
            SEV_ORDER.getOrDefault(b.effectiveSeverity(), 99)));

        // Render PoC images
        List<PoCRenderer.RenderResult> pocImages = new ArrayList<>();
        for (Finding f : sorted) {
            PoCRenderer.RenderResult img = null;
            try {
                byte[] req  = f.primaryProbeRequest()  != null ? f.primaryProbeRequest()  : f.primaryRawRequest();
                byte[] resp = f.primaryProbeResponse() != null ? f.primaryProbeResponse() : f.primaryRawResponse();
                if (req != null || resp != null) {
                    img = PoCRenderer.renderWithDimensions(req, resp, new PoCRenderer.PoCContext(
                            f.name, f.primaryPayload(), f.primaryParameter(),
                            f.evidence, f.primaryTimingMs()));
                }
            } catch (Exception ignored) {}
            pocImages.add(img);
        }

        Map<String,Integer> counts = severityCounts(sorted);

        PdfExporter exp = new PdfExporter(sorted, meta, counts, pocImages);
        exp.renderAllPages();

        writePdf(exp.pageImages, outFile);
    }

    public static void export(List<Finding> findings, String filepath) throws Exception {
        export(findings, filepath, new ReportMeta(null,null,null,null,null,null,null));
    }

    private PdfExporter(List<Finding> sorted, ReportMeta meta,
                         Map<String,Integer> counts,
                         List<PoCRenderer.RenderResult> pocImages) {
        this.sorted    = sorted;
        this.meta      = meta;
        this.counts    = counts;
        this.pocImages = pocImages;
        this.logoImage = loadLogo(meta);
    }

    // ── Page rendering orchestration ──────────────────────────────────────────

    private void renderAllPages() throws Exception {
        renderCoverPage();
        renderToc();
        renderExecSummary();
        renderVulnerabilitiesTable();
        for (int i = 0; i < sorted.size(); i++) renderFinding(i);
    }

    // ── Cover page ────────────────────────────────────────────────────────────

    private void renderCoverPage() throws Exception {
        newPage();

        // Dark header band
        g.setColor(C_DARK);
        g.fillRect(0, 0, PW, 200);

        // Brand accent strip
        g.setColor(C_BRAND);
        g.fillRect(ML, 200, CW, 6);

        // Company logo — top-right of header band, padded 20px from edge
        if (logoImage != null) {
            int logoX = PW - MR - logoImage.getWidth();
            int logoY = (200 - logoImage.getHeight()) / 2;   // vertically centred in header
            g.drawImage(logoImage, logoX, logoY, null);
        }

        // Title
        g.setFont(new Font("Arial", Font.BOLD, 22));
        g.setColor(Color.WHITE);
        drawStringCentered("SECURITY ASSESSMENT REPORT", PW / 2, 100);

        g.setFont(new Font("Arial", Font.PLAIN, 13));
        g.setColor(new Color(0xAA, 0xCC, 0xCC));
        drawStringCentered("Confidential - Restricted Distribution", PW / 2, 128);

        // Client name block
        cy = 232;
        g.setFont(new Font("Arial", Font.BOLD, 20));
        g.setColor(C_BRAND);
        drawStringCentered(meta.clientName, PW / 2, cy);
        cy += 32;

        // Horizontal rule
        g.setColor(C_RULE);
        g.drawLine(ML, cy, PW - MR, cy);
        cy += 20;

        // Metadata grid
        String[][] metas = {
            {"Target Scope",    meta.targetScope},
            {"Assessment Date", meta.assessmentDate},
            {"Engagement Type", meta.engagementType},
            {"Report Version",  meta.reportVersion},
            {"Classification",  meta.classification},
            {"Prepared By",     meta.preparedBy},
        };
        int labelColW = 180;
        for (String[] row : metas) {
            if (row[1] == null || row[1].isBlank()) continue;
            g.setFont(F_SMALL_B); g.setColor(C_TEXT);
            g.drawString(row[0] + ":", ML, cy);
            g.setFont(F_SMALL); g.setColor(C_MUTED);
            g.drawString(row[1], ML + labelColW, cy);
            cy += 22;
        }
        cy += 24;

        // Severity summary badge table
        g.setFont(F_H2); g.setColor(C_DARK);
        drawStringCentered("Finding Summary", PW / 2, cy); cy += 20;

        String[] sevs = {Finding.SEV_CRITICAL, Finding.SEV_HIGH,
                          Finding.SEV_MEDIUM, Finding.SEV_LOW, Finding.SEV_INFO};
        int badgeW = 100, badgeH = 60, gap = 14;
        int totalBadgesW = sevs.length * badgeW + (sevs.length - 1) * gap;
        int startX = (PW - totalBadgesW) / 2;
        for (int i = 0; i < sevs.length; i++) {
            String sev = sevs[i];
            int cnt    = counts.getOrDefault(sev, 0);
            Color fg   = SEV_FG.getOrDefault(sev, C_TEXT);
            Color bg   = SEV_BG.getOrDefault(sev, C_ROW_EVEN);
            int bx     = startX + i * (badgeW + gap);

            g.setColor(bg);
            g.fillRoundRect(bx, cy, badgeW, badgeH, 10, 10);
            g.setColor(fg);
            g.setStroke(new BasicStroke(1.5f));
            g.drawRoundRect(bx, cy, badgeW, badgeH, 10, 10);
            g.setStroke(new BasicStroke(1f));

            // Count
            g.setFont(new Font("Arial", Font.BOLD, 22));
            String cntStr = String.valueOf(cnt);
            drawStringCentered(cntStr, bx + badgeW / 2, cy + 28);

            // Label
            g.setFont(F_SMALL);
            drawStringCentered(sev, bx + badgeW / 2, cy + 48);
        }
        cy += badgeH + 24;

        // Overall rating
        String rating    = overallRating(counts);
        Color  ratingFg  = SEV_FG.getOrDefault(rating, C_DARK);
        Color  ratingBg  = SEV_BG.getOrDefault(rating, C_ROW_EVEN);
        g.setFont(F_H3); g.setColor(C_MUTED);
        drawStringCentered("Overall Risk Rating", PW / 2, cy); cy += 16;
        int pillW = 140, pillH = 32, pillX = (PW - pillW) / 2;
        g.setColor(ratingBg);
        g.fillRoundRect(pillX, cy, pillW, pillH, 8, 8);
        g.setColor(ratingFg);
        g.setStroke(new BasicStroke(1.5f));
        g.drawRoundRect(pillX, cy, pillW, pillH, 8, 8);
        g.setFont(new Font("Arial", Font.BOLD, 14));
        drawStringCentered(rating.toUpperCase(), PW / 2, cy + 21);
        cy += pillH + 20;

        // Bar chart
        byte[] chart = renderBarChartPng(counts, 540, 280);
        if (chart != null) {
            BufferedImage chartImg = ImageIO.read(new ByteArrayInputStream(chart));
            int imgX = (PW - chartImg.getWidth()) / 2;
            if (cy + chartImg.getHeight() < PH - MB - 60) {
                g.drawImage(chartImg, imgX, cy, null);
                cy += chartImg.getHeight() + 10;
                g.setFont(F_CAPTION); g.setColor(C_MUTED);
                drawStringCentered("Figure 1: Finding Distribution by Severity", PW / 2, cy);
                cy += 14;
            }
        }

        // ── Cover-page-only confidential notice block ──────────────────────
        // A full-width amber-tinted notice box near the bottom of the cover page,
        // followed by the generated timestamp and tool version. Only on page 1.
        int noticeY = PH - MB - 80;
        g.setColor(new Color(0xFF, 0xF8, 0xE1));   // very light amber background
        g.fillRoundRect(ML, noticeY, CW, 58, 6, 6);
        g.setColor(new Color(0xB7, 0x95, 0x0B));   // amber border
        g.setStroke(new BasicStroke(1f));
        g.drawRoundRect(ML, noticeY, CW, 58, 6, 6);

        g.setFont(F_SMALL_B); g.setColor(new Color(0x7D, 0x62, 0x08));
        drawStringCentered("CONFIDENTIAL", PW / 2, noticeY + 18);

        g.setFont(new Font("Arial", Font.PLAIN, 12)); g.setColor(new Color(0x5D, 0x4A, 0x10));
        drawStringCentered(
            "This document contains sensitive security information." +
            " Distribution is restricted to authorised personnel only.",
            PW / 2, noticeY + 34);

        // Generated line below the notice box
        String genLine = "Generated: " + LocalDateTime.now().format(
            DateTimeFormatter.ofPattern("dd MMM yyyy, HH:mm")) +
            "   |   BurpMax v1.0";
        g.setFont(F_SMALL); g.setColor(C_MUTED);
        drawStringCentered(genLine, PW / 2, noticeY + 72);

        finishPage();
    }

    // ── Table of Contents ─────────────────────────────────────────────────────

    private void renderToc() throws Exception {
        newPage();
        drawPageHeader("Table of Contents");

        // Fixed section entries with consistent line height
        int lineH = 24;
        g.setFont(F_BODY_B); g.setColor(C_BRAND);
        g.drawString("Executive Summary", ML + 16, cy);         cy += lineH;
        g.drawString("Vulnerabilities Table", ML + 16, cy);     cy += lineH + 6;

        String prevSev = null;
        for (int i = 0; i < sorted.size(); i++) {
            Finding f   = sorted.get(i);
            String  sev = f.effectiveSeverity();
            if (!sev.equals(prevSev)) {
                cy += 4;
                // Severity group label
                g.setFont(F_BODY_B);
                g.setColor(SEV_FG.getOrDefault(sev, C_TEXT));
                g.drawString(sev.toUpperCase(), ML, cy);
                cy += lineH - 4;
                prevSev = sev;
            }
            // Numbered finding entry indented under severity group
            g.setFont(F_BODY); g.setColor(C_TEXT);
            String num  = (i + 1) + ".";
            String name = truncate(f.name, 68);
            g.drawString(num,  ML + 24, cy);
            g.drawString(name, ML + 52, cy);
            cy += lineH - 4;
            if (cy > PH - MB - 30) { finishPage(); newPage(); drawPageHeader("Table of Contents (continued)"); }
        }

        cy += 10;
        drawPageFooter();
        finishPage();
    }

    // ── Executive Summary ─────────────────────────────────────────────────────

    private void renderExecSummary() throws Exception {
        newPage();
        drawPageHeader("Executive Summary");
        cy += 6;

        // Narrative
        g.setFont(F_H2); g.setColor(C_DARK);
        g.drawString("Assessment Overview", ML, cy); cy += 20;  // heading + gap before body text
        String narrative = buildNarrative();
        cy = drawWrappedText(narrative, ML, cy, CW, F_BODY, C_TEXT);
        cy += 20;  // gap between narrative and next section

        // Severity distribution table
        g.setFont(F_H2); g.setColor(C_DARK);
        g.drawString("Severity Distribution", ML, cy); cy += 16;  // gap between heading and table

        // Severity | Count | Percentage — 3 cols summing to CW=1064
        String[] cols = {"Severity", "Count", "Percentage"};
        int[]    cws  = {600, 200, 264};
        cy = drawTableHeader(cols, cws, cy);

        int total = sorted.size();
        String[] sevOrder = {
            Finding.SEV_CRITICAL, Finding.SEV_HIGH,
            Finding.SEV_MEDIUM, Finding.SEV_LOW, Finding.SEV_INFO
        };
        for (int row = 0; row < sevOrder.length; row++) {
            String sev  = sevOrder[row];
            int    cnt  = counts.getOrDefault(sev, 0);
            String pct  = total > 0 ? String.format("%.1f%%", cnt * 100.0 / total) : "0.0%";
            Color  fg   = SEV_FG.getOrDefault(sev, C_TEXT);
            Color  bg   = row % 2 == 0 ? C_ROW_EVEN : C_ROW_ALT;
            String[] vals = {sev, String.valueOf(cnt), pct};
            cy = drawTableRow(vals, cws, cy, bg, fg, false);
        }
        cy += 18;

        if (cy > PH - MB - 80) { finishPage(); newPage(); drawPageHeader("Executive Summary (continued)"); }

        // Top findings
        List<Finding> top = sorted.stream()
            .filter(f -> f.effectiveSeverity().equals(Finding.SEV_CRITICAL)
                      || f.effectiveSeverity().equals(Finding.SEV_HIGH))
            .limit(5).toList();
        if (!top.isEmpty()) {
            cy += 6;  // breathing room before section heading
            if (cy > PH - MB - 100) { finishPage(); newPage(); drawPageHeader("Executive Summary (continued)"); }
            g.setFont(F_H2); g.setColor(C_DARK);
            g.drawString("Key Findings Requiring Immediate Attention", ML, cy); cy += 16;
            for (Finding f : top) {
                Color fg = SEV_FG.getOrDefault(f.effectiveSeverity(), C_TEXT);
                // Badge pill for severity
                int pillW = 72, pillH = 20, pillX = ML + 18;
                g.setColor(SEV_BG.getOrDefault(f.effectiveSeverity(), C_ROW_ALT));
                g.fillRoundRect(pillX, cy - 14, pillW, pillH, 6, 6);
                g.setColor(fg); g.setStroke(new BasicStroke(1f));
                g.drawRoundRect(pillX, cy - 14, pillW, pillH, 6, 6);
                g.setFont(F_SMALL_B); g.setColor(fg);
                drawStringCentered("[" + f.effectiveSeverity() + "]", pillX + pillW / 2, cy);
                g.setFont(F_BODY); g.setColor(C_TEXT);
                g.drawString(truncate(f.name, 66), ML + pillW + 28, cy);
                cy += 24;
            }
        }

        // Analyst notes from ReportMeta
        if (meta.analystNotes != null && !meta.analystNotes.isBlank()) {
            cy += 8;
            if (cy > PH - MB - 80) { finishPage(); newPage(); drawPageHeader("Executive Summary (continued)"); }
            g.setFont(F_H2); g.setColor(C_DARK);
            g.drawString("Analyst Notes", ML, cy); cy += 12;
            cy = drawWrappedText(meta.analystNotes, ML, cy, CW, F_BODY, C_TEXT);
        }

        drawPageFooter();
        finishPage();
    }

    // ── Individual finding pages ──────────────────────────────────────────────

    private void renderFinding(int idx) throws Exception {
        Finding f  = sorted.get(idx);
        String sev = f.effectiveSeverity();
        Color  fg  = SEV_FG.getOrDefault(sev, C_TEXT);
        Color  bg  = SEV_BG.getOrDefault(sev, C_ROW_EVEN);

        newPage();

        // Finding header — full-width dark band with severity badge on right
        int hdrH = 42;
        g.setColor(C_DARK);
        g.fillRect(ML, MT, CW, hdrH);
        // Severity badge on the right of the header band
        int badgeW = 100;
        g.setColor(fg);
        g.fillRect(PW - MR - badgeW, MT, badgeW, hdrH);

        // Finding number + name in the dark band
        g.setFont(F_H2); g.setColor(Color.WHITE);
        String titleText = truncate((idx + 1) + ".  " + f.name, 68);
        g.drawString(titleText, ML + 12, MT + 27);

        // Severity label centered in the badge
        g.setFont(F_BODY_B); g.setColor(Color.WHITE);
        drawStringCentered(sev, PW - MR - badgeW / 2, MT + 27);

        cy = MT + hdrH + 14;

        // Metadata grid — CWE + Host only; CVSS score shown inline with vector below
        int[] mw = {200, 864};   // sum = CW (1064)
        cy = drawTableHeader(new String[]{"CWE", "Host"}, mw, cy);
        cy = drawTableRow(new String[]{nvl(f.cwe), nvl(f.host)},
                          mw, cy, C_ROW_ALT, C_TEXT, false);

        // CVSS: score + vector on the same label row
        double score = f.effectiveCvssScore();
        String scoreStr = score > 0 ? String.format("%.1f", score) : "N/A";
        boolean hasVector = f.cvssVector != null && !f.cvssVector.isBlank();
        if (score > 0 || hasVector) {
            // Label row shows "CVSS Score: X.X" so score is never buried
            cy = drawLabelRow("CVSS Score: " + scoreStr, cy);
            if (hasVector) {
                cy = drawValueRow(f.cvssVector, cy, F_MONO);
            }
        }

        // Affected endpoints
        if (f.affectedEndpoints.size() > 1) {
            cy = drawLabelRow("Affected Endpoints (" + f.affectedEndpoints.size() + ")", cy);
            for (Finding.EndpointEntry ep : f.affectedEndpoints.subList(0, Math.min(5, f.affectedEndpoints.size()))) {
                cy = drawValueRow(ep.endpoint + "  [HTTP " + (ep.statusCode > 0 ? ep.statusCode : "-") + "]", cy, F_BODY);
            }
            if (f.affectedEndpoints.size() > 5) {
                cy = drawValueRow("... and " + (f.affectedEndpoints.size() - 5) + " more endpoints", cy, F_SMALL);
            }
        } else {
            String epUrl = f.affectedEndpoints.isEmpty() ? nvl(f.url) : f.affectedEndpoints.get(0).endpoint;
            cy = drawLabelRow("Affected Endpoint", cy);
            cy = drawValueRow(epUrl, cy, F_BODY);
        }

        // Description, Evidence, Remediation, Analyst Note
        cy = drawLabelRow("Description", cy);
        cy = drawWrappedValueRow(nvl(f.description), cy);

        cy = drawLabelRow("Remediation", cy);
        cy = drawWrappedValueRow(nvl(f.remediation), cy);


        cy += 10;

        // PoC image — may need a new page if not enough vertical space
        PoCRenderer.RenderResult poc = pocImages.get(idx);
        if (poc != null) {
            if (cy > PH - MB - 100) { finishPage(); newPage(); drawPageHeader("PoC: " + truncate(f.name, 60)); }
            g.setFont(F_H2); g.setColor(C_DARK);
            g.drawString("Proof of Concept", ML, cy); cy += 8;

            // Scale PoC to fit content width — always scale to fill width for max sharpness
            double scale = (double) CW / poc.widthPx;
            int imgW = CW;
            int imgH = (int)(poc.heightPx * scale);

            // New page if doesn't fit
            if (cy + imgH > PH - MB - 30) {
                finishPage();
                newPage();
                drawPageHeader("PoC: " + truncate(f.name, 60));
                scale = (double) CW / poc.widthPx;
                imgW = CW;
                imgH = (int)(poc.heightPx * scale);
            }

            // Decode and draw with bicubic interpolation for sharpness
            BufferedImage pocImg = ImageIO.read(new ByteArrayInputStream(poc.png));
            if (pocImg != null) {
                Object prevInterp = g.getRenderingHint(RenderingHints.KEY_INTERPOLATION);
                g.setRenderingHint(RenderingHints.KEY_INTERPOLATION,
                        RenderingHints.VALUE_INTERPOLATION_BICUBIC);
                g.setRenderingHint(RenderingHints.KEY_RENDERING,
                        RenderingHints.VALUE_RENDER_QUALITY);
                g.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
                        RenderingHints.VALUE_ANTIALIAS_ON);
                g.drawImage(pocImg, ML, cy, imgW, imgH, null);
                if (prevInterp != null)
                    g.setRenderingHint(RenderingHints.KEY_INTERPOLATION, prevInterp);
                cy += imgH + 6;
                g.setFont(F_CAPTION); g.setColor(C_MUTED);
                drawStringCentered("Figure " + (idx + 1) + ": " + f.name, PW / 2, cy);
                cy += 14;
            }
        } else {
            cy += 4;
            g.setFont(F_BODY); g.setColor(C_MUTED);
            g.drawString("\u24d8  Proof of concept not available \u2014 finding restored from session without live traffic.",
                          ML, cy);
            cy += 14;
        }

        drawPageFooter();
        finishPage();
    }

    // ── Vulnerabilities Table ─────────────────────────────────────────────────

    private void renderVulnerabilitiesTable() throws Exception {
        newPage();
        drawPageHeader("Vulnerabilities Table");
        cy += 4;

        g.setFont(F_BODY); g.setColor(C_MUTED);
        g.drawString("Complete reference of all findings ordered by severity for development and remediation teams.", ML, cy);
        cy += 12;

        int[] cws = {40, 110, 80, 584, 250};   // sum = CW (1064), no CVSS column
        cy = drawTableHeader(new String[]{"No.", "Severity", "CWE", "Finding", "Host"}, cws, cy);

        for (int i = 0; i < sorted.size(); i++) {
            Finding f   = sorted.get(i);
            String  sev = f.effectiveSeverity();
            Color   fg  = SEV_FG.getOrDefault(sev, C_TEXT);
            Color   rowBg = i % 2 == 0 ? C_ROW_EVEN : C_ROW_ALT;
            cy = drawTableRow(
                new String[]{String.valueOf(i+1), sev, nvl(f.cwe),
                             truncate(f.name, 60), nvl(f.host)},
                cws, cy, rowBg, fg, false);
            if (cy > PH - MB - 20) { finishPage(); newPage(); drawPageHeader("Vulnerabilities Table (continued)"); }
        }

        cy += 16;
        drawPageFooter();
        finishPage();
    }

    // ── Drawing primitives ────────────────────────────────────────────────────

    private void drawPageHeader(String title) {
        // Brand accent bar at top of content area
        g.setColor(C_BRAND);
        g.fillRect(ML, MT, CW, 4);
        // Title sits below the accent bar with clear breathing room
        cy = MT + 24;
        g.setFont(F_H1); g.setColor(C_DARK);
        g.drawString(title, ML, cy);
        cy += 6;
        // Thin rule under the title
        g.setColor(C_RULE);
        g.drawLine(ML, cy, PW - MR, cy);
        cy += 14;
    }

    private void drawPageHeader2(String title) {
        cy += 8;
        g.setColor(C_BRAND);
        g.fillRect(ML, cy, CW, 2);
        cy += 14;
        g.setFont(F_H1); g.setColor(C_DARK);
        g.drawString(title, ML, cy);
        cy += 18;
        g.setColor(C_RULE);
        g.drawLine(ML, cy, PW - MR, cy);
        cy += 10;
    }

    private void drawPageFooter() {
        int footerY = PH - MB + 10;
        g.setColor(C_RULE);
        g.drawLine(ML, footerY, PW - MR, footerY);
        g.setFont(F_SMALL); g.setColor(C_MUTED);
        g.drawString(meta.clientName + " \u2014 Security Assessment Report \u2014 " + meta.classification,
                     ML, footerY + 14);
        String pageNum = "Page " + (pageImages.size() + 1);
        FontMetrics fm = g.getFontMetrics();
        g.drawString(pageNum, PW - MR - fm.stringWidth(pageNum), footerY + 14);
    }

    private int drawTableHeader(String[] cols, int[] widths, int y) {
        int x = ML, rowH = 26;
        g.setColor(C_TH_BG);
        g.fillRect(ML, y, CW, rowH);
        g.setFont(F_SMALL_B); g.setColor(Color.WHITE);
        for (int i = 0; i < cols.length && i < widths.length; i++) {
            g.drawString(cols[i], x + 8, y + 17);
            x += widths[i];
        }
        return y + rowH;
    }

    private int drawTableRow(String[] vals, int[] widths, int y, Color bg, Color fg, boolean bold) {
        int x = ML, rowH = 22;
        g.setColor(bg); g.fillRect(ML, y, CW, rowH);
        Font cellFont = bold ? F_SMALL_B : F_SMALL;
        g.setFont(cellFont);
        FontMetrics fm = g.getFontMetrics();
        for (int i = 0; i < vals.length && i < widths.length; i++) {
            g.setColor(i == 0 ? fg : C_TEXT);
            // Pixel-aware truncation: clip to cell width minus 12px padding
            String txt = truncateToWidth(nvl(vals[i]), widths[i] - 12, fm);
            g.drawString(txt, x + 6, y + 15);
            x += widths[i];
        }
        // Row border
        g.setColor(C_RULE);
        g.drawLine(ML, y + rowH, PW - MR, y + rowH);
        return y + rowH;
    }

    /** Truncates text to fit within maxPx pixels using the given FontMetrics. */
    private static String truncateToWidth(String s, int maxPx, FontMetrics fm) {
        if (s == null) return "";
        if (fm.stringWidth(s) <= maxPx) return s;
        String ellipsis = "\u2026";
        int ellW = fm.stringWidth(ellipsis);
        while (s.length() > 1 && fm.stringWidth(s) + ellW > maxPx)
            s = s.substring(0, s.length() - 1);
        return s + ellipsis;
    }

    private int drawLabelRow(String label, int y) {
        g.setColor(C_TH_BG); g.fillRect(ML, y, CW, 24);
        g.setFont(F_SMALL_B); g.setColor(Color.WHITE);
        g.drawString(label, ML + 8, y + 16);
        return y + 24;
    }

    private int drawValueRow(String value, int y, Font font) {
        g.setColor(C_ROW_ALT); g.fillRect(ML, y, CW, 22);
        g.setFont(font); g.setColor(C_TEXT);
        FontMetrics fm = g.getFontMetrics();
        g.drawString(truncateToWidth(nvl(value), CW - 12, fm), ML + 6, y + 15);
        g.setColor(C_RULE); g.drawLine(ML, y + 22, PW - MR, y + 22);
        return y + 22;
    }

    /**
     * Draws a wrapped text value block. Handles page overflow by rendering as many
     * lines as fit on the current page, then continuing on a new page.
     * Each sub-block has a top-padding of 6px and a bottom border rule.
     */
    private int drawWrappedValueRow(String value, int y) throws Exception {
        if (value == null || value.isBlank()) return drawValueRow("N/A", y, F_BODY);
        String[] lines = wrapText(value, CW - 16, F_SMALL);
        int lineH = 18;
        int padTop = 8, padBot = 10;

        for (int i = 0; i < lines.length; ) {
            // How many lines fit on remaining page?
            int avail = PH - MB - y - padTop - padBot;
            if (avail < lineH * 2) {
                // Not enough room for even 2 lines — start fresh page
                finishPage(); newPage();
                drawPageHeader("(continued)");
            }
            avail = PH - MB - y - padTop - padBot;
            int fitsN = Math.max(1, avail / lineH);
            int batch = Math.min(fitsN, lines.length - i);
            int blockH = batch * lineH + padTop + padBot;

            g.setColor(C_ROW_ALT); g.fillRect(ML, y, CW, blockH);
            int ty = y + padTop + lineH - 4;
            g.setFont(F_SMALL); g.setColor(C_TEXT);
            for (int j = 0; j < batch; j++, i++) {
                g.drawString(lines[i], ML + 8, ty);
                ty += lineH;
            }
            g.setColor(C_RULE); g.drawLine(ML, y + blockH, PW - MR, y + blockH);
            y += blockH;

            if (i < lines.length) {
                // More lines remain — page break
                finishPage(); newPage();
                drawPageHeader("(continued)");
            }
        }
        return y;
    }

    private int drawWrappedText(String text, int x, int y, int maxW, Font font, Color color) {
        if (text == null || text.isBlank()) return y;
        g.setFont(font); g.setColor(color);
        String[] lines = wrapText(text, maxW, font);
        FontMetrics fm = g.getFontMetrics();
        for (String line : lines) {
            g.drawString(line, x, y);
            y += fm.getHeight() + 2;
            if (y > PH - MB - 20) break;
        }
        return y;
    }

    private void drawStringCentered(String text, int cx, int y) {
        FontMetrics fm = g.getFontMetrics();
        g.drawString(text, cx - fm.stringWidth(text) / 2, y);
    }

    // ── Page lifecycle ────────────────────────────────────────────────────────

    private void newPage() {
        page = new BufferedImage(PW, PH, BufferedImage.TYPE_INT_RGB);
        g    = page.createGraphics();
        g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING,
                           RenderingHints.VALUE_TEXT_ANTIALIAS_LCD_HRGB);
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
                           RenderingHints.VALUE_ANTIALIAS_ON);
        g.setRenderingHint(RenderingHints.KEY_RENDERING,
                           RenderingHints.VALUE_RENDER_QUALITY);
        g.setColor(C_PAGE);
        g.fillRect(0, 0, PW, PH);
        cy = MT;
    }

    private void finishPage() throws Exception {
        if (g != null) g.dispose();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(page, "png", baos);
        pageImages.add(baos.toByteArray());
        page = null; g = null;
    }

    // ── Text utilities ────────────────────────────────────────────────────────

    private String[] wrapText(String text, int maxPx, Font font) {
        BufferedImage tmp = new BufferedImage(1, 1, BufferedImage.TYPE_INT_RGB);
        Graphics2D tg = tmp.createGraphics();
        tg.setFont(font);
        FontMetrics fm = tg.getFontMetrics();
        tg.dispose();

        List<String> result = new ArrayList<>();
        // Handle newlines in the text
        for (String paragraph : text.split("\n")) {
            String[] words = paragraph.split(" ");
            StringBuilder line = new StringBuilder();
            for (String word : words) {
                String candidate = line.isEmpty() ? word : line + " " + word;
                if (fm.stringWidth(candidate) <= maxPx) {
                    if (!line.isEmpty()) line.append(" ");
                    line.append(word);
                } else {
                    if (!line.isEmpty()) result.add(line.toString());
                    // Long word — truncate if needed
                    while (fm.stringWidth(word) > maxPx && word.length() > 4)
                        word = word.substring(0, word.length() - 1);
                    line = new StringBuilder(word);
                }
            }
            if (!line.isEmpty()) result.add(line.toString());
        }
        return result.toArray(new String[0]);
    }

    private static String truncate(String s, int maxChars) {
        if (s == null) return "";
        return s.length() <= maxChars ? s : s.substring(0, maxChars - 1) + "\u2026";
    }

    private static String nvl(String s) { return s != null ? s : ""; }

    // ── Narrative ─────────────────────────────────────────────────────────────

    private String buildNarrative() {
        int total = sorted.size();
        int crit  = counts.getOrDefault(Finding.SEV_CRITICAL, 0);
        int high  = counts.getOrDefault(Finding.SEV_HIGH, 0);
        StringBuilder n = new StringBuilder();
        n.append("A ").append(meta.engagementType.toLowerCase())
         .append(" was conducted against ").append(meta.targetScope)
         .append(" for ").append(meta.clientName)
         .append(" on ").append(meta.assessmentDate).append(". ")
         .append("The assessment identified ").append(total).append(" finding").append(total != 1 ? "s" : "");
        if (total > 0) {
            n.append(": ");
            List<String> parts = new ArrayList<>();
            for (String s : new String[]{Finding.SEV_CRITICAL,Finding.SEV_HIGH,Finding.SEV_MEDIUM,Finding.SEV_LOW,Finding.SEV_INFO})
                if (counts.getOrDefault(s,0) > 0) parts.add(counts.get(s) + " " + s);
            n.append(String.join(", ", parts)).append(".");
        } else {
            n.append(".");
        }
        if (crit > 0)       n.append(" Critical findings require immediate emergency remediation.");
        else if (high > 0)  n.append(" High severity findings should be addressed as an urgent priority.");
        else if (total > 0) n.append(" No critical or high severity issues were identified.");
        return n.toString();
    }

    private static String overallRating(Map<String,Integer> counts) {
        for (String s : new String[]{Finding.SEV_CRITICAL,Finding.SEV_HIGH,
                                      Finding.SEV_MEDIUM,Finding.SEV_LOW})
            if (counts.getOrDefault(s,0) > 0) return s;
        return Finding.SEV_INFO;
    }

    // ── Bar chart ─────────────────────────────────────────────────────────────

    private static byte[] renderBarChartPng(Map<String,Integer> counts, int W, int H) {
        try {
            int PAD_L=48, PAD_R=20, PAD_T=24, PAD_B=56;
            int chartW=W-PAD_L-PAD_R, chartH=H-PAD_T-PAD_B;
            BufferedImage img = new BufferedImage(W, H, BufferedImage.TYPE_INT_RGB);
            Graphics2D g = img.createGraphics();
            g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g.setColor(Color.WHITE); g.fillRect(0,0,W,H);

            String[] sevLabels = {Finding.SEV_CRITICAL,Finding.SEV_HIGH,
                                   Finding.SEV_MEDIUM,Finding.SEV_LOW,Finding.SEV_INFO};
            int n=sevLabels.length;
            int maxVal = counts.values().stream().mapToInt(v->v).max().orElse(1);
            if(maxVal==0) maxVal=1;
            int gridMax=(int)(Math.ceil(maxVal/2.0)*2); if(gridMax<2) gridMax=2;
            int gap=12, barW=(chartW-(n-1)*gap)/n;

            // Grid lines
            g.setFont(new Font(Font.SANS_SERIF,Font.PLAIN,9)); g.setColor(new Color(0xEE,0xEE,0xEE));
            for(int step=0;step<=4;step++){
                int gv=(int)((double)step/4*gridMax);
                int gy=PAD_T+chartH-(int)((double)gv/gridMax*chartH);
                g.drawLine(PAD_L,gy,PAD_L+chartW,gy);
                g.setColor(new Color(0xAA,0xAA,0xAA));
                g.drawString(String.valueOf(gv),PAD_L-g.getFontMetrics().stringWidth(String.valueOf(gv))-4,gy+4);
                g.setColor(new Color(0xEE,0xEE,0xEE));
            }

            for(int i=0;i<n;i++){
                String sev=sevLabels[i]; int cnt=counts.getOrDefault(sev,0);
                Color fg=SEV_FG.getOrDefault(sev,new Color(0x33,0x33,0x33));
                Color bg=SEV_BG.getOrDefault(sev,new Color(0xF5,0xF5,0xF5));
                int bx=PAD_L+i*(barW+gap), bh=(int)((double)cnt/gridMax*chartH), by=PAD_T+chartH-bh;
                g.setColor(bg); g.fillRoundRect(bx,PAD_T,barW,chartH,6,6);
                if(cnt>0){
                    GradientPaint gp=new GradientPaint(bx,by,fg.brighter(),bx,by+bh,fg);
                    g.setPaint(gp); g.fillRoundRect(bx,by,barW,bh,6,6); g.setPaint(null);
                }
                g.setFont(new Font(Font.SANS_SERIF,Font.BOLD,11)); g.setColor(cnt>0?fg:new Color(0xBB,0xBB,0xBB));
                FontMetrics cfm=g.getFontMetrics(); String cs=String.valueOf(cnt);
                g.drawString(cs,bx+(barW-cfm.stringWidth(cs))/2,by-3);
                g.setFont(new Font(Font.SANS_SERIF,Font.BOLD,9)); g.setColor(fg);
                FontMetrics lfm=g.getFontMetrics();
                g.drawString(sev,bx+(barW-lfm.stringWidth(sev))/2,PAD_T+chartH+14);
            }
            g.setColor(new Color(0xDD,0xDD,0xDD));
            g.drawLine(PAD_L,PAD_T,PAD_L,PAD_T+chartH); g.drawLine(PAD_L,PAD_T+chartH,PAD_L+chartW,PAD_T+chartH);
            g.dispose();
            ByteArrayOutputStream baos=new ByteArrayOutputStream(); ImageIO.write(img,"png",baos);
            return baos.toByteArray();
        } catch(Exception e){ return null; }
    }

    // ── PDF file writer ───────────────────────────────────────────────────────
    // Produces a PDF 1.4 file where each page is a full-page image XObject.

    private static void writePdf(List<byte[]> pages, File outFile) throws Exception {
        // Encode each page PNG as base64 in an image XObject
        List<byte[]> encodedPages = new ArrayList<>();
        for (byte[] png : pages) encodedPages.add(png);  // raw PNG stream

        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        List<Long> xrefs = new ArrayList<>();  // byte offsets of each object

        // PDF header
        write(buf, "%PDF-1.4\n%\u00e2\u00e3\u00cf\u00d3\n");

        int objNum = 0;
        int pageCount = pages.size();

        // Object numbering:
        //   1        = catalog
        //   2        = pages root
        //   3..N+2   = page objects
        //   N+3..2N+2 = image XObjects (one per page)

        int catalogObj = ++objNum;   // 1
        int pagesObj   = ++objNum;   // 2
        int firstPageObj = objNum + 1;

        // Page objects
        List<Integer> pageObjNums  = new ArrayList<>();
        List<Integer> imageObjNums = new ArrayList<>();
        for (int i = 0; i < pageCount; i++) {
            pageObjNums.add(++objNum);
        }
        for (int i = 0; i < pageCount; i++) {
            imageObjNums.add(++objNum);
        }
        int contentStart = objNum + 1;  // content stream objects
        List<Integer> contentObjNums = new ArrayList<>();
        for (int i = 0; i < pageCount; i++) {
            contentObjNums.add(++objNum);
        }

        // Write catalog
        xrefs.add(ensureSize(xrefs, catalogObj, (long) buf.size()));
        write(buf, catalogObj + " 0 obj\n<< /Type /Catalog /Pages " + pagesObj + " 0 R >>\nendobj\n");

        // Write pages root
        xrefs.add(ensureSize(xrefs, pagesObj, (long) buf.size()));
        StringBuilder kids = new StringBuilder("[");
        for (int i = 0; i < pageCount; i++) {
            if (i > 0) kids.append(" ");
            kids.append(pageObjNums.get(i)).append(" 0 R");
        }
        kids.append("]");
        write(buf, pagesObj + " 0 obj\n<< /Type /Pages /Kids " + kids +
              " /Count " + pageCount + " >>\nendobj\n");

        // Write page + image + content objects
        for (int i = 0; i < pageCount; i++) {
            byte[] png      = encodedPages.get(i);
            int    pageObj  = pageObjNums.get(i);
            int    imgObj   = imageObjNums.get(i);
            int    contObj  = contentObjNums.get(i);
            String imgName  = "Im" + i;

            // Page object
            xrefs.add(ensureSize(xrefs, pageObj, (long) buf.size()));
            write(buf, pageObj + " 0 obj\n" +
                  "<< /Type /Page /Parent " + pagesObj + " 0 R\n" +
                  "   /MediaBox [0 0 " + PW + " " + PH + "]\n" +
                  "   /Resources << /XObject << /" + imgName + " " + imgObj + " 0 R >> >>\n" +
                  "   /Contents " + contObj + " 0 R\n" +
                  ">>\nendobj\n");

            // Image XObject — PNG stream
            xrefs.add(ensureSize(xrefs, imgObj, (long) buf.size()));
            byte[] imgStream = buildPngImageStream(png, PW, PH);
            write(buf, imgObj + " 0 obj\n" +
                  "<< /Type /XObject /Subtype /Image\n" +
                  "   /Width " + PW + " /Height " + PH + "\n" +
                  "   /ColorSpace /DeviceRGB /BitsPerComponent 8\n" +
                  "   /Filter /FlateDecode\n" +
                  "   /DecodeParms << /Predictor 15 /Colors 3 /BitsPerComponent 8 /Columns " + PW + " >>\n" +
                  "   /Length " + imgStream.length + "\n" +
                  ">>\nstream\n");
            buf.write(imgStream);
            write(buf, "\nendstream\nendobj\n");

            // Content stream: draw image full-page
            String content = "q " + PW + " 0 0 " + PH + " 0 0 cm /" + imgName + " Do Q\n";
            byte[] contentBytes = content.getBytes(StandardCharsets.ISO_8859_1);
            xrefs.add(ensureSize(xrefs, contObj, (long) buf.size()));
            write(buf, contObj + " 0 obj\n" +
                  "<< /Length " + contentBytes.length + " >>\nstream\n");
            buf.write(contentBytes);
            write(buf, "\nendstream\nendobj\n");
        }

        // Cross-reference table
        long xrefOffset = buf.size();
        int totalObjs = objNum + 1;  // 0-indexed includes free object
        write(buf, "xref\n0 " + totalObjs + "\n");
        write(buf, "0000000000 65535 f \n");  // free object entry
        for (int i = 1; i < totalObjs; i++) {
            long off = (i < xrefs.size()) ? xrefs.get(i) : 0L;
            write(buf, String.format("%010d 00000 n \n", off));
        }

        // Trailer
        write(buf, "trailer\n<< /Size " + totalObjs + " /Root " + catalogObj + " 0 R >>\n");
        write(buf, "startxref\n" + xrefOffset + "\n%%EOF\n");

        // Write to file
        try (FileOutputStream fos = new FileOutputStream(outFile)) {
            buf.writeTo(fos);
        }
    }

    /**
     * Decode a PNG image and re-encode its raw RGB pixels as a FlateDecode stream
     * with PNG predictor (predictor 15) for efficient embedding in a PDF image XObject.
     */
    private static byte[] buildPngImageStream(byte[] png, int w, int h) throws Exception {
        BufferedImage img = ImageIO.read(new ByteArrayInputStream(png));
        // Build raw RGB row data with PNG filter byte 1 (Sub filter)
        ByteArrayOutputStream raw = new ByteArrayOutputStream(w * h * 3 + h);
        for (int y = 0; y < img.getHeight(); y++) {
            raw.write(1);  // PNG Sub filter per row
            int prevR=0, prevG=0, prevB=0;
            for (int x = 0; x < img.getWidth(); x++) {
                int rgb = img.getRGB(x, y);
                int r = (rgb >> 16) & 0xFF, gv = (rgb >> 8) & 0xFF, b = rgb & 0xFF;
                raw.write((r - prevR) & 0xFF);
                raw.write((gv - prevG) & 0xFF);
                raw.write((b - prevB) & 0xFF);
                prevR=r; prevG=gv; prevB=b;
            }
        }
        // Deflate compress
        ByteArrayOutputStream deflated = new ByteArrayOutputStream();
        try (java.util.zip.DeflaterOutputStream dos =
                 new java.util.zip.DeflaterOutputStream(deflated,
                     new java.util.zip.Deflater(java.util.zip.Deflater.BEST_SPEED))) {
            dos.write(raw.toByteArray());
        }
        return deflated.toByteArray();
    }

    private static long ensureSize(List<Long> list, int idx, long value) {
        while (list.size() <= idx) list.add(0L);
        list.set(idx, value);
        return value;
    }

    private static void write(OutputStream os, String s) throws Exception {
        os.write(s.getBytes(StandardCharsets.ISO_8859_1));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static Map<String,Integer> severityCounts(List<Finding> findings) {
        Map<String,Integer> m = new LinkedHashMap<>();
        m.put(Finding.SEV_CRITICAL,0); m.put(Finding.SEV_HIGH,0);
        m.put(Finding.SEV_MEDIUM,0);   m.put(Finding.SEV_LOW,0);
        m.put(Finding.SEV_INFO,0);
        for (Finding f : findings) m.merge(f.effectiveSeverity(), 1, Integer::sum);
        return m;
    }
}
