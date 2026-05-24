package com.burpmax.ui;

import com.burpmax.model.Finding;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

public class FindingTableModel extends AbstractTableModel {

    @java.io.Serial
    private static final long serialVersionUID = 1L;

    private static final String[] COLS = {"#", "Severity", "Finding", "Endpoint", "HTTP", "CWE", "CVSS", "Status"};
    private transient final List<Finding> rows = new ArrayList<>();

    public void setFindings(List<Finding> findings) {
        rows.clear();
        rows.addAll(findings);
        fireTableDataChanged();
    }

    public Finding getFinding(int row) {
        return row >= 0 && row < rows.size() ? rows.get(row) : null;
    }

    @Override public int getRowCount()    { return rows.size(); }
    @Override public int getColumnCount() { return COLS.length; }
    @Override public String getColumnName(int col) { return COLS[col]; }

    @Override
    public Object getValueAt(int row, int col) {
        Finding f = rows.get(row);
        return switch (col) {
            case 0 -> row + 1;
            case 1 -> f.effectiveSeverity() + (f.severityOverride != null ? "*" : "");
            case 2 -> {
                String n = f.suppressed ? "[FP] " + f.name : f.name;
                yield (f.analystNote != null && !f.analystNote.isEmpty() && !f.suppressed)
                        ? "\u270e " + n : n;
            }
            case 3 -> f.affectedEndpoints.size() > 1
                    ? f.affectedEndpoints.size() + " endpoints"
                    : f.endpoint;
            case 4 -> {
                int sc = f.affectedEndpoints.isEmpty() ? f.statusCode
                        : f.affectedEndpoints.get(0).statusCode;
                yield sc > 0 ? String.valueOf(sc) : "-";
            }
            case 5 -> f.cwe;
            case 6 -> String.format("%.1f", f.effectiveCvssScore());
            case 7 -> f.remediationStatus;
            default -> "";
        };
    }

    @Override public Class<?> getColumnClass(int col) {
        return col == 0 ? Integer.class : String.class;
    }
}
