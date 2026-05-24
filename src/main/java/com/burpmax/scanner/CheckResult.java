package com.burpmax.scanner;

/**
 * Value object returned by each check module.
 */
public class CheckResult {
    public final String name;
    public final String severity;
    public final String description;
    public final String evidence;
    public final String remediation;
    public final String cwe;

    public CheckResult(String name, String severity, String description,
                       String evidence, String remediation, String cwe) {
        this.name        = name;
        this.severity    = severity;
        this.description = description;
        this.evidence    = evidence;
        this.remediation = remediation;
        this.cwe         = cwe;
    }
}
