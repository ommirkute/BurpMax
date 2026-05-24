package com.burpmax.export;

/**
 * Metadata entered by the analyst before export.
 * Populates the cover page and executive summary of both DOCX and PDF reports.
 */
public class ReportMeta {
    public final String clientName;
    public final String targetScope;
    public final String assessmentDate;
    public final String reportVersion;
    public final String preparedBy;
    public final String classification;   // e.g. "Confidential", "Restricted", "Internal"
    public final String engagementType;   // e.g. "Web Application Penetration Test", "VAPT"
    public final String analystNotes;     // free-text notes for executive summary
    public final String logoPath;         // absolute path to company logo PNG/JPG, or "" for none

    /** Full constructor with logo path. */
    public ReportMeta(String clientName, String targetScope,
                      String assessmentDate, String reportVersion,
                      String preparedBy, String classification,
                      String engagementType, String analystNotes,
                      String logoPath) {
        this.clientName     = blank(clientName,     "Confidential Client");
        this.targetScope    = blank(targetScope,     "Web Application");
        this.assessmentDate = blank(assessmentDate,  java.time.LocalDate.now().toString());
        this.reportVersion  = blank(reportVersion,   "1.0");
        this.preparedBy     = blank(preparedBy,      "Security Analyst");
        this.classification = blank(classification,  "Confidential");
        this.engagementType = blank(engagementType,  "Web Application Penetration Test");
        this.analystNotes   = analystNotes != null ? analystNotes.trim() : "";
        this.logoPath       = (logoPath != null) ? logoPath.trim() : "";
    }

    /** Constructor without logo (backwards-compatible). */
    public ReportMeta(String clientName, String targetScope,
                      String assessmentDate, String reportVersion,
                      String preparedBy, String classification,
                      String engagementType, String analystNotes) {
        this(clientName, targetScope, assessmentDate, reportVersion,
             preparedBy, classification, engagementType, analystNotes, "");
    }

    /** Constructor without logo or notes. */
    public ReportMeta(String clientName, String targetScope,
                      String assessmentDate, String reportVersion,
                      String preparedBy, String classification,
                      String engagementType) {
        this(clientName, targetScope, assessmentDate, reportVersion,
             preparedBy, classification, engagementType, null, "");
    }

    /** Legacy 5-arg constructor — keeps existing callers working. */
    public ReportMeta(String clientName, String targetScope,
                      String assessmentDate, String reportVersion,
                      String preparedBy) {
        this(clientName, targetScope, assessmentDate, reportVersion,
             preparedBy, null, null, null, "");
    }

    /** @return true if a logo file path is set and the file exists and is readable. */
    public boolean hasLogo() {
        if (logoPath == null || logoPath.isEmpty()) return false;
        java.io.File f = new java.io.File(logoPath);
        return f.exists() && f.isFile() && f.canRead();
    }

    private static String blank(String s, String def) {
        if (s == null || s.trim().isEmpty()) return def;
        String trimmed = s.trim();
        return trimmed.length() > 200 ? trimmed.substring(0, 200) : trimmed;
    }
}
