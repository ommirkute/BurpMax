package com.burpmax.export;

import com.burpmax.model.Finding;

import java.io.*;
import java.util.*;

public class CsvExporter {

    private static final Map<String, Integer> SEV_ORDER = Map.of(
            "Critical", 0, "High", 1, "Medium", 2, "Low", 3, "Informational", 4);

    public static void export(List<Finding> findings, String filepath) throws Exception {
        // Enforce .csv extension and canonicalize path — canonicalization resolves
        // any ".." components, preventing directory traversal via crafted save paths.
        if (!filepath.toLowerCase().endsWith(".csv")) filepath += ".csv";
        java.io.File outFile = new java.io.File(filepath).getCanonicalFile();
        if (outFile.getAbsolutePath().contains(".."))
            throw new SecurityException("Invalid export path: " + filepath);

        // Sort by severity
        List<Finding> sorted = new ArrayList<>(findings);
        sorted.sort((a, b) -> Integer.compare(
                SEV_ORDER.getOrDefault(a.effectiveSeverity(), 99),
                SEV_ORDER.getOrDefault(b.effectiveSeverity(), 99)));

        try (PrintWriter w = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(outFile), "UTF-8"))) {
            w.print("\uFEFF");
            w.println("No,Severity,Name,Host,Endpoint,HTTP Status,CWE,Evidence,Description,Remediation,Timestamp");
            int i = 1;
            for (Finding f : sorted) {
                String ep = f.affectedEndpoints.isEmpty() ? f.url
                        : f.affectedEndpoints.get(0).endpoint;
                int sc = f.affectedEndpoints.isEmpty() ? f.statusCode
                        : f.affectedEndpoints.get(0).statusCode;

                w.printf("%d,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s%n",
                        i++,
                        csv(f.effectiveSeverity()),
                        csv(f.name),
                        csv(f.host),
                        csv(ep),
                        sc > 0 ? sc : "",
                        csv(f.cwe),
                        csv(f.evidence),
                        csv(f.description),
                        csv(f.remediation),
                        csv(f.timestamp));
            }
        }
    }

    private static String csv(String s) {
        if (s == null) return "\"\"";
        // Sanitize CRLF to prevent row injection
        String clean = s.replace("\r\n", " ").replace("\n", " ").replace("\r", "");
        // Prevent CSV formula injection (Excel/LibreOffice execute cells starting with =, +, -, @, |, \t)
        if (!clean.isEmpty() && "=+-@|\t".indexOf(clean.charAt(0)) >= 0) {
            clean = "'" + clean;
        }
        return "\"" + clean.replace("\"", "\"\"") + "\"";
    }
}
