package com.burpmax.export;

import com.burpmax.model.Finding;
import com.burpmax.poc.PoCRenderer;

import java.io.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.zip.*;

public class DocxExporter {

    private static final DateTimeFormatter FMT     = DateTimeFormatter.ofPattern("dd MMM yyyy, HH:mm");

    private static final Map<String, String> SEV_COLORS = Map.of(
            Finding.SEV_CRITICAL, "7B0000",
            Finding.SEV_HIGH,     "C0392B",
            Finding.SEV_MEDIUM,   "D35400",
            Finding.SEV_LOW,      "B7950B",
            Finding.SEV_INFO,     "1A5276"
    );
    private static final Map<String, String> SEV_BG = Map.of(
            Finding.SEV_CRITICAL, "F9EBEA",
            Finding.SEV_HIGH,     "FDEDEC",
            Finding.SEV_MEDIUM,   "FEF5E7",
            Finding.SEV_LOW,      "FEFBD8",
            Finding.SEV_INFO,     "EBF5FB"
    );
    private static final Map<String, Integer> SEV_ORDER = Map.of(
            Finding.SEV_CRITICAL, 0, Finding.SEV_HIGH, 1,
            Finding.SEV_MEDIUM, 2,   Finding.SEV_LOW, 3, Finding.SEV_INFO, 4);

    // Max width = 16.5cm in EMU; max height = A4 usable height ~24.7cm
    private static final long MAX_CX_EMU = 5943600L;
    private static final long MAX_CY_EMU = 8996220L;  // ~24.7cm - fits on one A4 page

    /**
     * Convert pixel dimensions to EMU, capped to fit on a single A4 page.
     * Avoids decoding the PNG again since we already have the dimensions.
     */
    private static long[] dimsToEmu(int widthPx, int heightPx) {
        long cx = MAX_CX_EMU;
        long cy = (long)((double) heightPx / widthPx * cx);
        // Cap cy to A4 page height so image never overflows onto next page
        if (cy > MAX_CY_EMU) cy = MAX_CY_EMU;
        return new long[]{cx, cy};
    }

    public static void export(List<Finding> findings, String filepath, ReportMeta meta) throws Exception {
        // Enforce .docx extension
        if (!filepath.toLowerCase().endsWith(".docx")) filepath += ".docx";
        File outFile = new File(filepath).getCanonicalFile();
        if (outFile.getAbsolutePath().contains(".."))
            throw new SecurityException("Invalid export path: " + filepath);

        List<Finding> sorted = new ArrayList<>(findings);
        sorted.sort((a, b) -> Integer.compare(
                SEV_ORDER.getOrDefault(a.effectiveSeverity(), 99),
                SEV_ORDER.getOrDefault(b.effectiveSeverity(), 99)));

        List<PoCRenderer.RenderResult> pocImages = new ArrayList<>();
        for (Finding f : sorted) {
            PoCRenderer.RenderResult img = null;
            try {
                // Use probe request/response when available (shows the mutated request
                // and the confirming response), fall back to original traffic.
                byte[] req  = f.primaryProbeRequest()  != null ? f.primaryProbeRequest()  : f.primaryRawRequest();
                byte[] resp = f.primaryProbeResponse() != null ? f.primaryProbeResponse() : f.primaryRawResponse();
                if (req != null || resp != null) {
                    PoCRenderer.PoCContext ctx = new PoCRenderer.PoCContext(
                            f.name,
                            f.primaryPayload(),
                            f.primaryParameter(),
                            f.evidence,
                            f.primaryTimingMs());
                    img = PoCRenderer.renderWithDimensions(req, resp, ctx);
                }
            } catch (Exception ignored) {}
            pocImages.add(img);
        }

        Map<String, Integer> counts = severityCounts(sorted);

        // Render chart PNG locally — no static field, thread-safe
        byte[] chartPng = buildChartPng(counts);

        StringBuilder body = new StringBuilder();
        appendCoverPage(body, meta, sorted, counts);
        appendPageBreak(body);
        appendTableOfContents(body, sorted);
        appendPageBreak(body);
        appendExecutiveSummary(body, sorted, counts, meta);
        appendPageBreak(body);
        appendVulnerabilitiesTable(body, sorted);
        appendPageBreak(body);
        appendDetailedFindings(body, sorted, pocImages);

        StringBuilder rels = buildRels(sorted, pocImages, chartPng != null, meta.hasLogo());
        String docXml = buildDocXml(body.toString());
        try (ZipOutputStream zip = new ZipOutputStream(new FileOutputStream(outFile))) {
            putEntry(zip, "[Content_Types].xml", contentTypesXml(pocImages, chartPng != null));
            putEntry(zip, "_rels/.rels",          rootRelsXml());
            putEntry(zip, "word/document.xml",    docXml);
            putEntry(zip, "word/_rels/document.xml.rels", rels.toString());
            if (chartPng != null) {
                zip.putNextEntry(new ZipEntry("word/media/severity_chart.png"));
                zip.write(chartPng); zip.closeEntry();
            }
            // Embed company logo PNG
            if (meta.hasLogo()) {
                try {
                    byte[] logoBytes = java.nio.file.Files.readAllBytes(
                            java.nio.file.Paths.get(meta.logoPath));
                    zip.putNextEntry(new ZipEntry("word/media/logo.png"));
                    zip.write(logoBytes); zip.closeEntry();
                } catch (Exception ignored) {} // logo missing at write time - skip silently
            }
            for (int i = 0; i < sorted.size(); i++) {
                PoCRenderer.RenderResult img = pocImages.get(i);
                if (img != null) {
                    zip.putNextEntry(new ZipEntry("word/media/poc_" + i + ".png"));
                    zip.write(img.png); zip.closeEntry();
                }
            }
        }
    }

    public static void export(List<Finding> findings, String filepath) throws Exception {
        export(findings, filepath, new ReportMeta(null,null,null,null,null));
    }

    // ── Cover Page ────────────────────────────────────────────────────────────
    private static void appendCoverPage(StringBuilder b, ReportMeta meta,
                                         List<Finding> sorted, Map<String, Integer> counts) {
        for (int i = 0; i < 6; i++) b.append(para("", false, 20, "FFFFFF"));
        // Logo image — if present, render as a centred image on the cover page
        if (meta.hasLogo()) {
            b.append(imageParaCentered("logo"));
            b.append(para("", false, 12, "FFFFFF"));
        }
        b.append(paraCentered("SECURITY ASSESSMENT REPORT", true, 48, "1A252F"));
        b.append(para("", false, 20, "FFFFFF"));
        b.append(paraCentered(meta.clientName, true, 36, "1F5C5C"));
        b.append(para("", false, 20, "FFFFFF"));
        b.append(paraRule("1F5C5C"));
        b.append(para("", false, 20, "FFFFFF"));
        b.append(paraCentered("Target Scope:   " + meta.targetScope,      false, 22, "444444"));
        b.append(paraCentered("Assessment Date:   " + meta.assessmentDate, false, 22, "444444"));
        b.append(paraCentered("Report Version:   " + meta.reportVersion,   false, 22, "444444"));
        b.append(paraCentered("Prepared By:   " + meta.preparedBy,         false, 22, "444444"));
        b.append(para("", false, 20, "FFFFFF"));
        b.append(paraCentered("Finding Summary", true, 24, "1F5C5C"));
        b.append(para("", false, 14, "FFFFFF"));
        b.append(coverSummaryTable(counts));
        b.append(para("", false, 20, "FFFFFF"));
        for (int i = 0; i < 4; i++) b.append(para("", false, 20, "FFFFFF"));
        b.append(para("", false, 20, "FFFFFF"));
        // Amber confidential notice box — cover page only
        b.append(confidentialNoticeBox());
        b.append(para("", false, 10, "FFFFFF"));
        b.append(paraCentered("Generated: " + LocalDateTime.now().format(FMT) +
                "   |   BurpMax v1.0", false, 16, "AAAAAA"));
    }

    private static String coverSummaryTable(Map<String, Integer> counts) {
        StringBuilder sb = new StringBuilder();
        sb.append("<w:tbl><w:tblPr><w:tblW w:w=\"9000\" w:type=\"dxa\"/><w:jc w:val=\"center\"/>")
          .append("<w:tblBorders><w:top w:val=\"none\"/><w:left w:val=\"none\"/>")
          .append("<w:bottom w:val=\"none\"/><w:right w:val=\"none\"/>")
          .append("<w:insideH w:val=\"none\"/><w:insideV w:val=\"none\"/>")
          .append("</w:tblBorders></w:tblPr><w:tr>");
        for (String sev : new String[]{Finding.SEV_CRITICAL,Finding.SEV_HIGH,Finding.SEV_MEDIUM,Finding.SEV_LOW,Finding.SEV_INFO}) {
            int cnt = counts.getOrDefault(sev, 0);
            String fg = SEV_COLORS.getOrDefault(sev,"000000"), bg = SEV_BG.getOrDefault(sev,"FFFFFF");
            sb.append("<w:tc><w:tcPr><w:shd w:fill=\"").append(bg).append("\" w:val=\"clear\"/>")
              .append("<w:tcMar><w:top w:w=\"80\" w:type=\"dxa\"/><w:bottom w:w=\"80\" w:type=\"dxa\"/>")
              .append("<w:left w:w=\"80\" w:type=\"dxa\"/><w:right w:w=\"80\" w:type=\"dxa\"/></w:tcMar></w:tcPr>")
              .append("<w:p><w:pPr><w:jc w:val=\"center\"/></w:pPr>")
              .append("<w:r><w:rPr><w:b/><w:color w:val=\"").append(fg).append("\"/>")
              .append("<w:sz w:val=\"48\"/><w:rFonts w:ascii=\"Arial\" w:hAnsi=\"Arial\"/></w:rPr>")
              .append("<w:t>").append(cnt).append("</w:t></w:r></w:p>")
              .append("<w:p><w:pPr><w:jc w:val=\"center\"/></w:pPr>")
              .append("<w:r><w:rPr><w:color w:val=\"").append(fg).append("\"/>")
              .append("<w:sz w:val=\"16\"/><w:rFonts w:ascii=\"Arial\" w:hAnsi=\"Arial\"/></w:rPr>")
              .append("<w:t>").append(esc(sev)).append("</w:t></w:r></w:p></w:tc>");
        }
        sb.append("</w:tr></w:tbl>");
        return sb.toString();
    }

    /** Amber confidential notice box — rendered only on the cover page. */
    private static String confidentialNoticeBox() {
        return "<w:tbl>" +
               "<w:tblPr><w:tblW w:w=\"9000\" w:type=\"dxa\"/><w:jc w:val=\"center\"/>" +
               "<w:tblBorders>" +
               "<w:top w:val=\"single\" w:sz=\"6\" w:color=\"B7950B\"/>" +
               "<w:left w:val=\"single\" w:sz=\"6\" w:color=\"B7950B\"/>" +
               "<w:bottom w:val=\"single\" w:sz=\"6\" w:color=\"B7950B\"/>" +
               "<w:right w:val=\"single\" w:sz=\"6\" w:color=\"B7950B\"/>" +
               "</w:tblBorders>" +
               "<w:shd w:fill=\"FFF8E1\" w:val=\"clear\"/></w:tblPr>" +
               "<w:tr><w:tc>" +
               "<w:tcPr><w:shd w:fill=\"FFF8E1\" w:val=\"clear\"/>" +
               "<w:tcMar><w:top w:w=\"120\" w:type=\"dxa\"/><w:bottom w:w=\"120\" w:type=\"dxa\"/>" +
               "<w:left w:w=\"180\" w:type=\"dxa\"/><w:right w:w=\"180\" w:type=\"dxa\"/></w:tcMar>" +
               "</w:tcPr>" +
               "<w:p><w:pPr><w:jc w:val=\"center\"/></w:pPr>" +
               "<w:r><w:rPr><w:b/><w:color w:val=\"7D6208\"/><w:sz w:val=\"20\"/>" +
               "<w:rFonts w:ascii=\"Arial\" w:hAnsi=\"Arial\"/></w:rPr>" +
               "<w:t>CONFIDENTIAL</w:t></w:r></w:p>" +
               "<w:p><w:pPr><w:jc w:val=\"center\"/></w:pPr>" +
               "<w:r><w:rPr><w:color w:val=\"5D4A10\"/><w:sz w:val=\"18\"/>" +
               "<w:rFonts w:ascii=\"Arial\" w:hAnsi=\"Arial\"/></w:rPr>" +
               "<w:t xml:space=\"preserve\">This document contains sensitive security information." +
               " Distribution is restricted to authorised personnel only.</w:t>" +
               "</w:r></w:p>" +
               "</w:tc></w:tr></w:tbl>";
    }

    // ── Table of Contents ─────────────────────────────────────────────────────
    private static void appendTableOfContents(StringBuilder b, List<Finding> sorted) {
        b.append(para("Table of Contents", true, 32, "1F5C5C"));
        b.append(paraRule("1F5C5C"));
        b.append(para("", false, 14, "FFFFFF"));
        // Fixed sections first
        b.append(tocEntryLinked("Executive Summary", "1F5C5C", "exec_summary"));
        b.append(tocEntryLinked("Vulnerabilities Table", "1F5C5C", "vuln_table"));
        b.append(para("", false, 10, "FFFFFF"));
        String currentSev = null; int num = 1;
        for (Finding f : sorted) {
            String sev = f.effectiveSeverity();
            if (!sev.equals(currentSev)) {
                if (currentSev != null) b.append(para("", false, 10, "FFFFFF"));
                b.append(para(sev.toUpperCase(), true, 20, SEV_COLORS.getOrDefault(sev,"000000")));
                currentSev = sev;
            }
            // Clickable TOC entry — hyperlinks to the bookmark on the finding heading
            b.append(tocEntryLinked(num + ".  " + f.name, sev, findingBookmark(num)));
            num++;
        }
        b.append(para("", false, 14, "FFFFFF"));
    }

    /** Unique bookmark ID for finding number n. */
    private static String findingBookmark(int n) { return "finding_" + n; }

    /** TOC entry with internal hyperlink to bookmark. */
    private static String tocEntryLinked(String text, String sev, String bookmarkId) {
        String color = SEV_COLORS.getOrDefault(sev, "333333");
        return "<w:p><w:pPr><w:ind w:left=\"360\"/></w:pPr>" +
               "<w:hyperlink w:anchor=\"" + bookmarkId + "\" xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">" +
               "<w:r><w:rPr><w:color w:val=\"" + color + "\"/><w:sz w:val=\"20\"/>" +
               "<w:rStyle w:val=\"Hyperlink\"/>" +
               "<w:rFonts w:ascii=\"Arial\" w:hAnsi=\"Arial\"/></w:rPr>" +
               "<w:t xml:space=\"preserve\">" + esc(text) + "</w:t></w:r>" +
               "</w:hyperlink></w:p>";
    }

    /** Inserts a bookmark anchor at the current position. */
    private static String bookmarkAnchor(String id, int uid) {
        return "<w:bookmarkStart w:id=\"" + uid + "\" w:name=\"" + id + "\"/>" +
               "<w:bookmarkEnd w:id=\"" + uid + "\"/>";
    }

    // ── Executive Summary ─────────────────────────────────────────────────────
    private static void appendExecutiveSummary(StringBuilder b, List<Finding> sorted,
                                                Map<String, Integer> counts, ReportMeta meta) {
        b.append(bookmarkAnchor("exec_summary", 3000));
        b.append(para("Executive Summary", true, 32, "1F5C5C"));
        b.append(paraRule("1F5C5C"));
        b.append(para("", false, 14, "FFFFFF"));
        String rating      = overallRating(counts);
        String ratingColor = SEV_COLORS.getOrDefault(rating, "1A252F");
        String ratingBg    = SEV_BG.getOrDefault(rating, "F0F0F0");
        b.append(para("Overall Risk Rating", true, 24, "1A252F"));
        b.append(para("", false, 8, "FFFFFF"));
        // Coloured badge pill — matches severity colour coding used throughout report
        b.append(riskRatingBadge(rating, ratingColor, ratingBg));
        b.append(para("", false, 14, "FFFFFF"));
        b.append(para("Assessment Overview", true, 22, "1A252F"));
        b.append(para(buildNarrative(sorted, counts, meta), false, 20, "333333"));
        b.append(para("", false, 14, "FFFFFF"));
        b.append(para("Severity Distribution", true, 22, "1A252F"));
        b.append(para("", false, 10, "FFFFFF"));
        b.append(severityTable(counts, sorted.size()));
        b.append(para("", false, 14, "FFFFFF"));
        b.append(para("Finding Distribution by Severity", true, 22, "1A252F"));
        b.append(para("", false, 10, "FFFFFF"));
        b.append(severityBarChart());
        b.append(para("", false, 14, "FFFFFF"));
        List<Finding> topFindings = sorted.stream()
                .filter(f -> f.effectiveSeverity().equals(Finding.SEV_CRITICAL)
                          || f.effectiveSeverity().equals(Finding.SEV_HIGH))
                .limit(5).toList();
        if (!topFindings.isEmpty()) {
            b.append(para("Key Findings Requiring Immediate Attention", true, 22, "1A252F"));
            b.append(para("", false, 10, "FFFFFF"));
            for (Finding f : topFindings) {
                String col = SEV_COLORS.getOrDefault(f.effectiveSeverity(),"000000");
                // Note: para() calls esc() on the full string internally — safe
                b.append(para("  \u2022  [" + f.effectiveSeverity() + "]  "
                        + f.name + "  \u2014  " + f.host, false, 20, col));
            }
        }
    }

    private static String buildNarrative(List<Finding> sorted, Map<String, Integer> counts, ReportMeta meta) {
        int total=sorted.size(), crit=counts.getOrDefault(Finding.SEV_CRITICAL,0),
            high=counts.getOrDefault(Finding.SEV_HIGH,0);
        StringBuilder n = new StringBuilder();
        n.append("A passive security assessment was conducted against ").append(meta.targetScope)
         .append(" for ").append(meta.clientName).append(" on ").append(meta.assessmentDate)
         .append(". The assessment identified ").append(total).append(" finding").append(total!=1?"s":"");
        if (total > 0) {
            n.append(": ");
            List<String> parts = new ArrayList<>();
            for (String s : new String[]{Finding.SEV_CRITICAL,Finding.SEV_HIGH,Finding.SEV_MEDIUM,Finding.SEV_LOW,Finding.SEV_INFO}) {
                int c = counts.getOrDefault(s,0);
                if (c > 0) parts.add(c + " " + s);
            }
            n.append(String.join(", ", parts)).append(".");
        } else n.append(".");
        if (crit > 0) n.append(" The most severe finding is '").append(sorted.get(0).name).append("' which requires immediate remediation.");
        else if (high > 0) n.append(" High severity findings should be addressed as a priority.");
        else if (total > 0) n.append(" No critical or high severity issues were identified.");
        return n.toString();
    }

    private static String overallRating(Map<String, Integer> counts) {
        for (String s : new String[]{Finding.SEV_CRITICAL,Finding.SEV_HIGH,Finding.SEV_MEDIUM,Finding.SEV_LOW})
            if (counts.getOrDefault(s,0) > 0) return s;
        return Finding.SEV_INFO;
    }

    private static String severityTable(Map<String, Integer> counts, int total) {
        StringBuilder sb = new StringBuilder();
        sb.append("<w:tbl>").append(tblPr("9000"));
        // 3 columns: Severity | Count | Percentage  (Risk Level column removed)
        sb.append("<w:tr>").append(th("Severity","1F5C5C")).append(th("Count","1F5C5C"))
          .append(th("Percentage","1F5C5C")).append("</w:tr>");
        for (String sev : new String[]{Finding.SEV_CRITICAL,Finding.SEV_HIGH,Finding.SEV_MEDIUM,Finding.SEV_LOW,Finding.SEV_INFO}) {
            int cnt = counts.getOrDefault(sev,0);
            String pct = total>0 ? String.format("%.1f%%",(cnt*100.0/total)) : "0.0%";
            String fg=SEV_COLORS.getOrDefault(sev,"000000"), bg=SEV_BG.getOrDefault(sev,"FFFFFF");
            sb.append("<w:tr>")
              .append(tdColor(sev,fg,bg))
              .append(td(String.valueOf(cnt)))
              .append(td(pct))
              .append("</w:tr>");
        }
        sb.append("</w:tbl>"); return sb.toString();
    }

    // ── Detailed Findings ─────────────────────────────────────────────────────
    private static void appendDetailedFindings(StringBuilder b, List<Finding> sorted,
                                                List<PoCRenderer.RenderResult> pocImages) {
        b.append(para("Detailed Findings", true, 32, "1F5C5C"));
        b.append(paraRule("1F5C5C"));
        b.append(para("", false, 14, "FFFFFF"));

        for (int idx = 0; idx < sorted.size(); idx++) {
            Finding f   = sorted.get(idx);
            PoCRenderer.RenderResult poc = pocImages.get(idx);

            // Every finding after the first starts on a new page
            if (idx > 0) appendPageBreak(b);

            // Insert bookmark anchor so TOC hyperlinks work
            b.append(bookmarkAnchor(findingBookmark(idx + 1), 1000 + idx));

            b.append(findingHeader(idx+1, f));
            b.append(para("", false, 10, "FFFFFF"));
            b.append(buildFindingTable(f));
            b.append(para("", false, 14, "FFFFFF"));
            b.append(para("Proof of Concept", true, 22, "1F3050"));
            if (poc != null) {
                b.append(para("", false, 8, "FFFFFF"));
                long[] emu = dimsToEmu(poc.widthPx, poc.heightPx);
                b.append(buildImageXml("rId"+(10+idx), emu[0], emu[1], idx+1));
                b.append(paraCaption("Figure " + (idx+1) + ": " + f.name));
            } else {
                b.append(para("Proof of Concept not available \u2014 finding was detected in a " +
                    "restored session without live request/response data.", false, 18, "888888"));
            }
        }
    }

    private static String findingHeader(int num, Finding f) {
        String sev=f.effectiveSeverity(), col=SEV_COLORS.getOrDefault(sev,"000000"), bg=SEV_BG.getOrDefault(sev,"FFFFFF");
        String override = f.severityOverride!=null ? " (overridden from "+f.severity+")" : "";
        return "<w:tbl>"+tblPr("9000")+"<w:tr>" +
               "<w:tc><w:tcPr><w:shd w:fill=\""+bg+"\" w:val=\"clear\"/></w:tcPr>" +
               "<w:p><w:r><w:rPr><w:b/><w:color w:val=\""+col+"\"/><w:sz w:val=\"28\"/>" +
               "<w:rFonts w:ascii=\"Arial\" w:hAnsi=\"Arial\"/></w:rPr>" +
               "<w:t xml:space=\"preserve\">"+num+".  "+esc(f.name)+"</w:t></w:r></w:p></w:tc>" +
               "<w:tc><w:tcPr><w:tcW w:w=\"1500\" w:type=\"dxa\"/><w:shd w:fill=\""+col+"\" w:val=\"clear\"/></w:tcPr>" +
               "<w:p><w:pPr><w:jc w:val=\"center\"/></w:pPr>" +
               "<w:r><w:rPr><w:b/><w:color w:val=\"FFFFFF\"/><w:sz w:val=\"22\"/>" +
               "<w:rFonts w:ascii=\"Arial\" w:hAnsi=\"Arial\"/></w:rPr>" +
               "<w:t>"+esc(sev+override)+"</w:t></w:r></w:p></w:tc></w:tr></w:tbl>";
    }

    private static String buildFindingTable(Finding f) {
        StringBuilder sb = new StringBuilder();
        sb.append("<w:tbl>").append(tblPr("9000"));

        // Metadata row: CWE | Host | CVSS
        double score = f.effectiveCvssScore();
        String scoreStr = score == 0.0 ? "N/A" : String.format("%.1f", score);
        String scoreSeverity = score >= 9.0 ? "CRITICAL" : score >= 7.0 ? "HIGH"
                : score >= 4.0 ? "MEDIUM" : score > 0 ? "LOW" : "";
        String scoreDisplay  = score > 0
                ? scoreStr + (scoreSeverity.isEmpty() ? "" : " (" + scoreSeverity + ")") : "N/A";
        String scoreColor = score >= 9.0 ? "7B0000" : score >= 7.0 ? "C0392B"
                          : score >= 4.0 ? "D35400" : score > 0 ? "B7950B" : "888888";

        // Metadata row: CWE | Host only (CVSS Score moved to CVSS Score label row below)
        sb.append("<w:tr>")
          .append(th("CWE",  "2C3E50"))
          .append(th("Host", "2C3E50", 2))   // Host spans 2 cols so table stays 3-col grid
          .append("</w:tr>")
          .append("<w:tr>")
          .append(td(nvl(f.cwe)))
          .append("<w:tc><w:tcPr><w:gridSpan w:val=\"2\"/>")
          .append("<w:shd w:fill=\"F8F9FA\" w:val=\"clear\"/></w:tcPr>")
          .append("<w:p><w:r><w:rPr><w:color w:val=\"222222\"/><w:sz w:val=\"20\"/>")
          .append("<w:rFonts w:ascii=\"Arial\" w:hAnsi=\"Arial\"/></w:rPr>")
          .append("<w:t xml:space=\"preserve\">").append(esc(nvl(f.host))).append("</w:t>")
          .append("</w:r></w:p></w:tc>")
          .append("</w:tr>");

        // CVSS: score in label row header + vector value below
        boolean hasVector = f.cvssVector != null && !f.cvssVector.isEmpty();
        if (score > 0 || hasVector) {
            // Label header shows "CVSS Score: X.X" so the score is always visible
            String cvssLabel = "CVSS Score: " + scoreDisplay;
            sb.append("<w:tr>").append(th(cvssLabel,"2C3E50",3)).append("</w:tr>");
            if (hasVector) {
                sb.append("<w:tr><w:tc><w:tcPr><w:gridSpan w:val=\"3\"/>")
                  .append("<w:shd w:fill=\"F8F9FA\" w:val=\"clear\"/></w:tcPr>")
                  .append("<w:p><w:r><w:rPr><w:color w:val=\"444444\"/><w:sz w:val=\"18\"/>")
                  .append("<w:rFonts w:ascii=\"Courier New\" w:hAnsi=\"Courier New\"/></w:rPr>")
                  .append("<w:t xml:space=\"preserve\">").append(esc(f.cvssVector)).append("</w:t>")
                  .append("</w:r></w:p></w:tc></w:tr>");
            }
        }

        List<Finding.EndpointEntry> eps = f.affectedEndpoints;
        if (eps.size() > 1) {
            // Header spans full width; data rows: URL (spanning 2 cols) + HTTP Status
            sb.append("<w:tr>").append(th("Affected Endpoints ("+eps.size()+")","2C3E50",3)).append("</w:tr>");
            // Sub-header for columns
            sb.append("<w:tr>").append(th("URL","2C3E50",2)).append(th("Status","2C3E50")).append("</w:tr>");
            for (Finding.EndpointEntry e : eps) {
                String status = e.statusCode > 0 ? "HTTP " + e.statusCode : "-";
                sb.append("<w:tr>")
                  .append(tdSpan(e.endpoint, 2))
                  .append(td(status))
                  .append("</w:tr>");
            }
        } else {
            // Single endpoint — 2 meaningful columns, no empty third
            sb.append("<w:tr>").append(th("Affected Endpoint","2C3E50",2)).append(th("Status","2C3E50")).append("</w:tr>");
            String epUrl    = eps.isEmpty() ? nvl(f.url) : eps.get(0).endpoint;
            String epStatus = eps.isEmpty() ? "-"
                    : (eps.get(0).statusCode > 0 ? "HTTP " + eps.get(0).statusCode : "-");
            sb.append("<w:tr>")
              .append(tdSpan(epUrl, 2))
              .append(td(epStatus))
              .append("</w:tr>");
        }
        sb.append(labelRow("Description")).append(wrapRow(f.description));
        sb.append(labelRow("Remediation")).append(wrapRow(f.remediation));
        // Analyst note intentionally excluded from report output
        sb.append("</w:tbl>"); return sb.toString();
    }

    // ── Vulnerabilities Table ─────────────────────────────────────────────────
    private static void appendVulnerabilitiesTable(StringBuilder b, List<Finding> sorted) {
        b.append(bookmarkAnchor("vuln_table", 2000));
        b.append(para("Vulnerabilities Table", true, 32, "1F5C5C"));
        b.append(paraRule("1F5C5C"));
        b.append(para("A complete reference of all findings ordered by severity for use by development and remediation teams.", false, 20, "444444"));
        b.append(para("", false, 14, "FFFFFF"));
        StringBuilder sb = new StringBuilder();
        sb.append("<w:tbl>").append(tblPr("9000"));
        // 6 columns: No. | Severity | Finding | Host | CWE | CVSS 4.0  (Status removed)
        sb.append("<w:tr>").append(th("No.","1F5C5C")).append(th("Severity","1F5C5C"))
          .append(th("Finding","1F5C5C")).append(th("Host","1F5C5C")).append(th("CWE","1F5C5C"))
          .append(th("CVSS\u00a74.0","1F5C5C")).append("</w:tr>");
        for (int i=0; i<sorted.size(); i++) {
            Finding f=sorted.get(i); String sev=f.effectiveSeverity();
            String fg=SEV_COLORS.getOrDefault(sev,"000000"), bg=SEV_BG.getOrDefault(sev,"FFFFFF");
            double score = f.effectiveCvssScore();
            String scoreStr = score > 0 ? String.format("%.1f", score) : "-";
            sb.append("<w:tr>").append(td(String.valueOf(i+1))).append(tdColor(sev,fg,bg))
              .append(td(f.name)).append(td(f.host)).append(td(f.cwe))
              .append(td(scoreStr)).append("</w:tr>");
        }
        sb.append("</w:tbl>"); b.append(sb);
    }

    // ── XML primitives ────────────────────────────────────────────────────────
    private static void appendPageBreak(StringBuilder b) {
        b.append("<w:p><w:r><w:br w:type=\"page\"/></w:r></w:p>");
    }
    /** Centred paragraph embedding a DOCX image relationship by rId. */
    private static String imageParaCentered(String rId) {
        // cx/cy in EMU: 4cm wide × proportional height. We use a fixed 4cm (1440000 EMU)
        // width; actual dimensions are scaled by Word on render.
        long cx = 1_440_000L;   // 4 cm in EMU
        long cy = 720_000L;     // 2 cm - Word scales to fit actual aspect ratio
        return "<w:p><w:pPr><w:jc w:val=\"center\"/></w:pPr>"
             + "<w:r><w:rPr/><w:drawing><wp:inline>"
             + "<wp:extent cx=\"" + cx + "\" cy=\"" + cy + "\"/>"
             + "<wp:docPr id=\"9999\" name=\"logo\"/>"
             + "<a:graphic xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\">"
             + "<a:graphicData uri=\"http://schemas.openxmlformats.org/drawingml/2006/picture\">"
             + "<pic:pic xmlns:pic=\"http://schemas.openxmlformats.org/drawingml/2006/picture\">"
             + "<pic:nvPicPr><pic:cNvPr id=\"9998\" name=\"logo\"/><pic:cNvPicPr/></pic:nvPicPr>"
             + "<pic:blipFill><a:blip r:embed=\"rId" + rId + "\""
             + " xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"/>"
             + "<a:stretch><a:fillRect/></a:stretch></pic:blipFill>"
             + "<pic:spPr><a:xfrm><a:off x=\"0\" y=\"0\"/><a:ext cx=\"" + cx + "\" cy=\"" + cy + "\"/></a:xfrm>"
             + "<a:prstGeom prst=\"rect\"><a:avLst/></a:prstGeom></pic:spPr>"
             + "</pic:pic></a:graphicData></a:graphic>"
             + "</wp:inline></w:drawing></w:r></w:p>\n";
    }

    private static String para(String t, boolean bold, int sz, String col) {
        return "<w:p><w:r><w:rPr>"+(bold?"<w:b/>":"")+"<w:sz w:val=\""+sz+"\"/><w:color w:val=\""+col+"\"/>" +
               "<w:rFonts w:ascii=\"Arial\" w:hAnsi=\"Arial\"/></w:rPr><w:t xml:space=\"preserve\">"+esc(t)+"</w:t></w:r></w:p>";
    }
    private static String paraCentered(String t, boolean bold, int sz, String col) {
        return "<w:p><w:pPr><w:jc w:val=\"center\"/></w:pPr><w:r><w:rPr>"+(bold?"<w:b/>":"") +
               "<w:sz w:val=\""+sz+"\"/><w:color w:val=\""+col+"\"/>" +
               "<w:rFonts w:ascii=\"Arial\" w:hAnsi=\"Arial\"/></w:rPr><w:t xml:space=\"preserve\">"+esc(t)+"</w:t></w:r></w:p>";
    }
    private static String paraCaption(String t) {
        return "<w:p><w:pPr><w:jc w:val=\"center\"/></w:pPr><w:r><w:rPr><w:i/><w:sz w:val=\"18\"/>" +
               "<w:color w:val=\"555555\"/><w:rFonts w:ascii=\"Arial\" w:hAnsi=\"Arial\"/></w:rPr>" +
               "<w:t xml:space=\"preserve\">"+esc(t)+"</w:t></w:r></w:p>";
    }
    private static String paraRule(String col) {
        return "<w:p><w:pPr><w:pBdr><w:bottom w:val=\"single\" w:sz=\"6\" w:color=\""+col+"\"/></w:pBdr></w:pPr></w:p>";
    }
    private static String labelRow(String label) {
        return "<w:tr><w:tc><w:tcPr><w:gridSpan w:val=\"3\"/><w:shd w:fill=\"2C3E50\" w:val=\"clear\"/></w:tcPr>" +
               "<w:p><w:r><w:rPr><w:b/><w:color w:val=\"FFFFFF\"/><w:sz w:val=\"20\"/>" +
               "<w:rFonts w:ascii=\"Arial\" w:hAnsi=\"Arial\"/></w:rPr><w:t>"+esc(label)+"</w:t></w:r></w:p></w:tc></w:tr>";
    }
    private static String wrapRow(String value) {
        return "<w:tr><w:tc><w:tcPr><w:gridSpan w:val=\"3\"/><w:shd w:fill=\"FAFAFA\" w:val=\"clear\"/></w:tcPr>" +
               "<w:p><w:r><w:rPr><w:color w:val=\"222222\"/><w:sz w:val=\"20\"/>" +
               "<w:rFonts w:ascii=\"Arial\" w:hAnsi=\"Arial\"/></w:rPr><w:t xml:space=\"preserve\">"+esc(value)+"</w:t></w:r></w:p></w:tc></w:tr>";
    }
    private static String th(String l, String bg) {
        return "<w:tc><w:tcPr><w:shd w:fill=\""+bg+"\" w:val=\"clear\"/></w:tcPr>" +
               "<w:p><w:r><w:rPr><w:b/><w:color w:val=\"FFFFFF\"/><w:sz w:val=\"20\"/>" +
               "<w:rFonts w:ascii=\"Arial\" w:hAnsi=\"Arial\"/></w:rPr><w:t>"+esc(l)+"</w:t></w:r></w:p></w:tc>";
    }
    private static String th(String l, String bg, int span) {
        return "<w:tc><w:tcPr><w:gridSpan w:val=\""+span+"\"/><w:shd w:fill=\""+bg+"\" w:val=\"clear\"/></w:tcPr>" +
               "<w:p><w:r><w:rPr><w:b/><w:color w:val=\"FFFFFF\"/><w:sz w:val=\"20\"/>" +
               "<w:rFonts w:ascii=\"Arial\" w:hAnsi=\"Arial\"/></w:rPr><w:t>"+esc(l)+"</w:t></w:r></w:p></w:tc>";
    }
    private static String td(String v) {
        return "<w:tc><w:tcPr><w:shd w:fill=\"F8F9FA\" w:val=\"clear\"/></w:tcPr>" +
               "<w:p><w:r><w:rPr><w:color w:val=\"222222\"/><w:sz w:val=\"20\"/>" +
               "<w:rFonts w:ascii=\"Arial\" w:hAnsi=\"Arial\"/></w:rPr><w:t xml:space=\"preserve\">"+esc(v)+"</w:t></w:r></w:p></w:tc>";
    }
    /** Cell that spans multiple columns (gridSpan). */
    private static String tdSpan(String v, int span) {
        return "<w:tc><w:tcPr><w:gridSpan w:val=\""+span+"\"/><w:shd w:fill=\"F8F9FA\" w:val=\"clear\"/></w:tcPr>" +
               "<w:p><w:r><w:rPr><w:color w:val=\"222222\"/><w:sz w:val=\"20\"/>" +
               "<w:rFonts w:ascii=\"Arial\" w:hAnsi=\"Arial\"/></w:rPr><w:t xml:space=\"preserve\">"+esc(v)+"</w:t></w:r></w:p></w:tc>";
    }
    private static String tdColor(String v, String fg, String bg) {
        return "<w:tc><w:tcPr><w:shd w:fill=\""+bg+"\" w:val=\"clear\"/></w:tcPr>" +
               "<w:p><w:r><w:rPr><w:b/><w:color w:val=\""+fg+"\"/><w:sz w:val=\"20\"/>" +
               "<w:rFonts w:ascii=\"Arial\" w:hAnsi=\"Arial\"/></w:rPr><w:t>"+esc(v)+"</w:t></w:r></w:p></w:tc>";
    }
    // ── Severity Bar Chart ────────────────────────────────────────────────────

    private static final String CHART_REL_ID = "rIdChart1";

    /**
     * Renders a vertical bar chart of findings by severity.
     * Returns the PNG bytes directly — no static state.
     */
    private static byte[] buildChartPng(Map<String, Integer> counts) {
        try { return renderBarChart(counts); }
        catch (Exception e) { return null; }
    }

    /**
     * Returns the DOCX XML paragraph that embeds the chart image.
     */
    private static String severityBarChart() {
        long cx = 3600000L;
        long cy = 2314286L;
        // Centred paragraph for the chart image
        return "<w:p><w:pPr><w:jc w:val=\"center\"/></w:pPr><w:r><w:drawing>" +
            "<wp:inline xmlns:wp=\"http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing\">" +
            "<wp:extent cx=\"" + cx + "\" cy=\"" + cy + "\"/>" +
            "<wp:docPr id=\"9001\" name=\"SeverityChart\"/>" +
            "<a:graphic xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\">" +
            "<a:graphicData uri=\"http://schemas.openxmlformats.org/drawingml/2006/picture\">" +
            "<pic:pic xmlns:pic=\"http://schemas.openxmlformats.org/drawingml/2006/picture\">" +
            "<pic:nvPicPr><pic:cNvPr id=\"9001\" name=\"severity_chart.png\"/>" +
            "<pic:cNvPicPr/></pic:nvPicPr>" +
            "<pic:blipFill>" +
            "<a:blip r:embed=\"" + CHART_REL_ID +
            "\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"/>" +
            "<a:stretch><a:fillRect/></a:stretch></pic:blipFill>" +
            "<pic:spPr><a:xfrm><a:off x=\"0\" y=\"0\"/>" +
            "<a:ext cx=\"" + cx + "\" cy=\"" + cy + "\"/></a:xfrm>" +
            "<a:prstGeom prst=\"rect\"><a:avLst/></a:prstGeom></pic:spPr>" +
            "</pic:pic></a:graphicData></a:graphic>" +
            "</wp:inline></w:drawing></w:r></w:p>";
    }

    private static byte[] renderBarChart(Map<String, Integer> counts) throws Exception {
        // Chart dimensions — 560x360px matching the approved preview
        int W = 560, H = 360;
        int PAD_L = 50, PAD_R = 30, PAD_T = 30, PAD_B = 70;
        int chartW = W - PAD_L - PAD_R;
        int chartH = H - PAD_T - PAD_B;

        java.awt.image.BufferedImage img =
            new java.awt.image.BufferedImage(W, H, java.awt.image.BufferedImage.TYPE_INT_RGB);
        java.awt.Graphics2D g = img.createGraphics();
        g.setRenderingHint(java.awt.RenderingHints.KEY_ANTIALIASING,
                           java.awt.RenderingHints.VALUE_ANTIALIAS_ON);
        g.setRenderingHint(java.awt.RenderingHints.KEY_TEXT_ANTIALIASING,
                           java.awt.RenderingHints.VALUE_TEXT_ANTIALIAS_LCD_HRGB);

        // White background
        g.setColor(java.awt.Color.WHITE);
        g.fillRect(0, 0, W, H);

        String[] sevLabels = {
            Finding.SEV_CRITICAL, Finding.SEV_HIGH, Finding.SEV_MEDIUM,
            Finding.SEV_LOW, Finding.SEV_INFO
        };
        int[] barColors = { 0x7B0000, 0xC0392B, 0xD35400, 0xB7950B, 0x1A5276 };
        int[] bgColors  = { 0xF9EBEA, 0xFDEDEC, 0xFEF5E7, 0xFEFBD8, 0xEBF5FB };
        int   n         = sevLabels.length;

        int maxVal = counts.values().stream().mapToInt(Integer::intValue).max().orElse(1);
        if (maxVal == 0) maxVal = 1;
        // Round maxVal up to a nice number for grid
        int gridMax = (int)(Math.ceil(maxVal / 2.0) * 2);
        if (gridMax < 2) gridMax = 2;

        int gap  = 14;
        int barW = (chartW - (n - 1) * gap) / n;

        java.awt.Font gridFont  = new java.awt.Font(java.awt.Font.SANS_SERIF, java.awt.Font.PLAIN, 10);
        java.awt.Font labelFont = new java.awt.Font(java.awt.Font.SANS_SERIF, java.awt.Font.BOLD, 11);
        java.awt.Font countFont = new java.awt.Font(java.awt.Font.SANS_SERIF, java.awt.Font.BOLD, 14);

        // ── Horizontal grid lines ──────────────────────────────────────────
        g.setFont(gridFont);
        int gridSteps = Math.min(gridMax, 5);
        for (int step = 0; step <= gridSteps; step++) {
            int gv = (int)((double) step / gridSteps * gridMax);
            int gy = PAD_T + chartH - (int)((double) gv / gridMax * chartH);
            // Grid line
            g.setColor(new java.awt.Color(0xEE, 0xEE, 0xEE));
            g.drawLine(PAD_L, gy, PAD_L + chartW, gy);
            // Y-axis label
            g.setColor(new java.awt.Color(0x99, 0x99, 0x99));
            java.awt.FontMetrics fm = g.getFontMetrics();
            String lbl = String.valueOf(gv);
            g.drawString(lbl, PAD_L - fm.stringWidth(lbl) - 6,
                         gy + fm.getAscent() / 2 - 1);
        }

        // ── Draw each vertical bar ─────────────────────────────────────────
        for (int i = 0; i < n; i++) {
            String sev  = sevLabels[i];
            int    cnt  = counts.getOrDefault(sev, 0);
            int    bx   = PAD_L + i * (barW + gap);
            int    bh   = (int)((double) cnt / gridMax * chartH);
            int    by   = PAD_T + chartH - bh;

            // Light tint background pill (full chart height)
            g.setColor(new java.awt.Color(bgColors[i]));
            g.fillRoundRect(bx, PAD_T, barW, chartH, 6, 6);

            // Drop shadow
            g.setColor(new java.awt.Color(0, 0, 0, 18));
            g.fillRoundRect(bx + 3, by + 3, barW, bh, 6, 6);

            // Bar fill with vertical gradient
            if (cnt > 0) {
                java.awt.Color top = new java.awt.Color(barColors[i]).brighter();
                java.awt.Color bot = new java.awt.Color(barColors[i]);
                java.awt.GradientPaint gp = new java.awt.GradientPaint(
                    bx, by, top, bx, by + bh, bot);
                g.setPaint(gp);
                g.fillRoundRect(bx, by, barW, bh, 6, 6);
                g.setPaint(null);
            }

            // Count label above bar
            g.setFont(countFont);
            java.awt.FontMetrics cfm = g.getFontMetrics();
            String cntStr = String.valueOf(cnt);
            int cntX = bx + (barW - cfm.stringWidth(cntStr)) / 2;
            g.setColor(cnt > 0
                ? new java.awt.Color(barColors[i])
                : new java.awt.Color(0xBB, 0xBB, 0xBB));
            g.drawString(cntStr, cntX, by - 5);

            // Severity label below x-axis
            g.setFont(labelFont);
            java.awt.FontMetrics lfm = g.getFontMetrics();
            g.setColor(new java.awt.Color(barColors[i]));
            int lblX = bx + (barW - lfm.stringWidth(sev)) / 2;
            g.drawString(sev, lblX, PAD_T + chartH + 20);
        }

        // ── Axes ──────────────────────────────────────────────────────────
        g.setColor(new java.awt.Color(0xDD, 0xDD, 0xDD));
        g.setStroke(new java.awt.BasicStroke(1.5f));
        g.drawLine(PAD_L, PAD_T, PAD_L, PAD_T + chartH);          // Y-axis
        g.drawLine(PAD_L, PAD_T + chartH, PAD_L + chartW, PAD_T + chartH); // X-axis
        g.setStroke(new java.awt.BasicStroke(1f));

        // ── Outer border ──────────────────────────────────────────────────
        g.setColor(new java.awt.Color(0xE0, 0xE0, 0xE0));
        g.drawRect(0, 0, W - 1, H - 1);

        g.dispose();

        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        javax.imageio.ImageIO.write(img, "png", baos);
        return baos.toByteArray();
    }

    /**
     * Renders the overall risk rating as a coloured pill badge matching the severity colour scheme.
     * Width is constrained so it reads as a badge not a full-width bar.
     */
    private static String riskRatingBadge(String rating, String fgColor, String bgColor) {
        return "<w:tbl>" +
               "<w:tblPr><w:tblW w:w=\"2800\" w:type=\"dxa\"/>" +
               "<w:tblBorders>" +
               "<w:top w:val=\"single\" w:sz=\"4\" w:color=\"" + fgColor + "\"/>" +
               "<w:left w:val=\"single\" w:sz=\"4\" w:color=\"" + fgColor + "\"/>" +
               "<w:bottom w:val=\"single\" w:sz=\"4\" w:color=\"" + fgColor + "\"/>" +
               "<w:right w:val=\"single\" w:sz=\"4\" w:color=\"" + fgColor + "\"/>" +
               "</w:tblBorders>" +
               "<w:shd w:fill=\"" + bgColor + "\" w:val=\"clear\"/>" +
               "</w:tblPr>" +
               "<w:tr><w:tc>" +
               "<w:tcPr><w:shd w:fill=\"" + bgColor + "\" w:val=\"clear\"/>" +
               "<w:tcMar><w:top w:w=\"80\" w:type=\"dxa\"/><w:bottom w:w=\"80\" w:type=\"dxa\"/>" +
               "<w:left w:w=\"120\" w:type=\"dxa\"/><w:right w:w=\"120\" w:type=\"dxa\"/></w:tcMar>" +
               "</w:tcPr>" +
               "<w:p><w:pPr><w:jc w:val=\"center\"/></w:pPr>" +
               "<w:r><w:rPr><w:b/><w:color w:val=\"" + fgColor + "\"/>" +
               "<w:sz w:val=\"36\"/><w:rFonts w:ascii=\"Arial\" w:hAnsi=\"Arial\"/></w:rPr>" +
               "<w:t>" + esc(rating.toUpperCase()) + "</w:t></w:r></w:p>" +
               "</w:tc></w:tr></w:tbl>";
    }

    private static String tblPr(String w) {
        return "<w:tblPr><w:tblW w:w=\""+w+"\" w:type=\"dxa\"/><w:tblBorders>" +
               "<w:top w:val=\"single\" w:sz=\"4\" w:color=\"CCCCCC\"/>" +
               "<w:left w:val=\"single\" w:sz=\"4\" w:color=\"CCCCCC\"/>" +
               "<w:bottom w:val=\"single\" w:sz=\"4\" w:color=\"CCCCCC\"/>" +
               "<w:right w:val=\"single\" w:sz=\"4\" w:color=\"CCCCCC\"/>" +
               "<w:insideH w:val=\"single\" w:sz=\"4\" w:color=\"CCCCCC\"/>" +
               "<w:insideV w:val=\"single\" w:sz=\"4\" w:color=\"CCCCCC\"/>" +
               "</w:tblBorders></w:tblPr>";
    }
    private static String buildImageXml(String rid, long cx, long cy, int id) {
        return "<w:p><w:r><w:drawing><wp:inline xmlns:wp=\"http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing\">" +
               "<wp:extent cx=\""+cx+"\" cy=\""+cy+"\"/><wp:docPr id=\""+id+"\" name=\"PoC_"+id+"\"/>" +
               "<a:graphic xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\">" +
               "<a:graphicData uri=\"http://schemas.openxmlformats.org/drawingml/2006/picture\">" +
               "<pic:pic xmlns:pic=\"http://schemas.openxmlformats.org/drawingml/2006/picture\">" +
               "<pic:nvPicPr><pic:cNvPr id=\""+id+"\" name=\"poc_"+id+".png\"/><pic:cNvPicPr/></pic:nvPicPr>" +
               "<pic:blipFill><a:blip r:embed=\""+rid+"\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"/>" +
               "<a:stretch><a:fillRect/></a:stretch></pic:blipFill>" +
               "<pic:spPr><a:xfrm><a:off x=\"0\" y=\"0\"/><a:ext cx=\""+cx+"\" cy=\""+cy+"\"/></a:xfrm>" +
               "<a:prstGeom prst=\"rect\"><a:avLst/></a:prstGeom></pic:spPr>" +
               "</pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>";
    }
    private static String buildDocXml(String body) {
        return "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
               "<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">" +
               "<w:body>"+body+"<w:sectPr><w:pgSz w:w=\"12240\" w:h=\"15840\"/>" +
               "<w:pgMar w:top=\"1080\" w:right=\"1080\" w:bottom=\"1080\" w:left=\"1080\"/>" +
               "</w:sectPr></w:body></w:document>";
    }
    private static StringBuilder buildRels(List<Finding> sorted,
                                            List<PoCRenderer.RenderResult> pocImages,
                                            boolean hasChart, boolean hasLogo) {
        StringBuilder r = new StringBuilder();
        r.append("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>")
         .append("<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">");
        if (hasLogo) {
            r.append("<Relationship Id=\"rIdlogo\" ")
             .append("Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/image\" ")
             .append("Target=\"media/logo.png\"/>");
        }
        if (hasChart) {
            r.append("<Relationship Id=\"" + CHART_REL_ID + "\" ")
             .append("Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/image\" ")
             .append("Target=\"media/severity_chart.png\"/>");
        }
        for (int i=0; i<sorted.size(); i++)
            if (pocImages.get(i)!=null)
                r.append("<Relationship Id=\"rId").append(10+i).append("\" ")
                 .append("Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/image\" ")
                 .append("Target=\"media/poc_").append(i).append(".png\"/>");
        r.append("</Relationships>"); return r;
    }

    private static String contentTypesXml(List<PoCRenderer.RenderResult> imgs, boolean hasChart) {
        boolean hasPng = hasChart || imgs.stream().anyMatch(b->b!=null);
        return "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
               "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">" +
               "<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>" +
               "<Default Extension=\"xml\" ContentType=\"application/xml\"/>" +
               (hasPng?"<Default Extension=\"png\" ContentType=\"image/png\"/>":"") +
               "<Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/>" +
               "</Types>";
    }
    private static String rootRelsXml() {
        return "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
               "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">" +
               "<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/></Relationships>";
    }
    private static Map<String,Integer> severityCounts(List<Finding> findings) {
        Map<String,Integer> m = new LinkedHashMap<>();
        m.put(Finding.SEV_CRITICAL,0); m.put(Finding.SEV_HIGH,0); m.put(Finding.SEV_MEDIUM,0);
        m.put(Finding.SEV_LOW,0); m.put(Finding.SEV_INFO,0);
        for (Finding f : findings) m.merge(f.effectiveSeverity(),1,Integer::sum);
        return m;
    }
    private static void putEntry(ZipOutputStream zip, String name, String content) throws Exception {
        zip.putNextEntry(new ZipEntry(name));
        zip.write(content.getBytes("UTF-8")); zip.closeEntry();
    }
    private static String nvl(String s) { return s != null ? s : ""; }
    private static String esc(String s) {
        if (s==null) return "";
        return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\"","&quot;");
    }
}
