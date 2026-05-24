package com.burpmax.ui;

import com.burpmax.export.CsvExporter;
import com.burpmax.export.DocxExporter;
import com.burpmax.export.PdfExporter;
import com.burpmax.export.ScanDiff;
import com.burpmax.model.Finding;
import com.burpmax.session.SessionManager;
import com.burpmax.store.FindingStore;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.*;
import java.io.File;
import java.time.LocalTime;
import java.util.ArrayList;
import java.util.List;
import java.time.format.DateTimeFormatter;

import static com.burpmax.ui.Theme.*;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpService;

/**
 * Builds and owns the BurpMax tab UI.
 * All methods that touch Swing components must be called on the EDT.
 */
public class UIBuilder {

    public  final JPanel                  panel;
    private final FindingStore            store;
    private final SessionManager          session;
    private final IBurpExtenderCallbacks  callbacks;    // typed - no reflection needed
    private final Runnable                pauseToggle;  // supplied by BurpExtender

    private com.burpmax.active.ActiveScanner activeScanner;
    private JButton      activeScanBtn;
    private JLabel       activeScanStatus;
    private JProgressBar activeScanProgress;
    private javax.swing.Timer statusHideTimer;  // tracked so it can be cancelled on rescan

    /** Called by BurpExtender.extensionUnloaded() to prevent orphaned threads. */
    public void cancelActiveScan() {
        if (activeScanner != null && activeScanner.isRunning()) {
            activeScanner.cancel();
        }
        if (statusHideTimer != null) {
            statusHideTimer.stop();
            statusHideTimer = null;
        }
    }

    /** Returns the active scanner for use by context menu integrations. */
    public com.burpmax.active.ActiveScanner getActiveScanner() { return activeScanner; }

    // Table
    private final FindingTableModel tblModel  = new FindingTableModel();
    private final JTable            table;
    private final JLabel            summaryLbl= darkLabel("0 findings");

    // Summary badges
    private final JLabel lblTotal = badge("0", C_TEXT);
    private final JLabel lblCrit  = badge("0", C_CRITICAL);
    private final JLabel lblHigh  = badge("0", C_HIGH);
    private final JLabel lblMed   = badge("0", C_MEDIUM);
    private final JLabel lblLow   = badge("0", C_LOW);

    // Detail panel
    private final JLabel    detTitle  = darkLabel("");
    private final JLabel    detBadge  = new JLabel("");
    private final JTextArea descArea  = codeArea();
    private final JTextArea evArea    = codeArea();
    private final JTextArea remArea   = codeArea();
    private final JTextArea noteArea  = codeArea();
    private final JTextArea affArea   = codeArea();
    private final JPanel    affStrip  = new JPanel(new BorderLayout());
    private final JLabel    affCount  = darkLabel("");
    private final JLabel    cvssLabel = darkLabel("");  // shows CVSS 4.0 score + vector
    @SuppressWarnings("unchecked")
    private final JComboBox<String> statusCombo =
            new JComboBox<>(com.burpmax.model.Finding.ALL_STATUSES);
    private final JPanel    fpBanner  = new JPanel(new BorderLayout());
    private final JButton   repeaterBtn;
    private final JButton   fpBtn;
    private final JButton   overrideBtn;
    private JLabel          saveStatusLbl;

    // State
    private Finding  selectedFinding = null;
    private boolean  showSuppressed  = false;
    private String   filterSev       = null;
    private String   filterText      = null;   // free-text search across key fields
    private volatile boolean  paused          = false;
    private boolean  noteUpdating    = false;
    private List<Finding> visibleFindings;

    private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("HH:mm");

    // ─────────────────────────────────────────────────────────────────────────

    /** Static factory — avoids this-escape warning from calling overridable methods in constructor. */
    public static UIBuilder create(FindingStore store, SessionManager session,
                                    IBurpExtenderCallbacks callbacks, Runnable pauseToggle) {
        UIBuilder ui = new UIBuilder(store, session, callbacks, pauseToggle);
        ui.buildUI();
        store.addListener(() -> SwingUtilities.invokeLater(ui::refresh));
        // Autosave on every finding store mutation (passive scan, active scan, analyst edits).
        // scheduleAutoSave() is debounced (2 s) so rapid passive scan bursts produce one save.
        // Previously autosave was only triggered by UI analyst actions, meaning passive findings
        // accumulated in memory without ever being written to disk during an active browsing session.
        store.addListener(session::scheduleAutoSave);
        return ui;
    }

    private UIBuilder(FindingStore store, SessionManager session,
                      IBurpExtenderCallbacks callbacks, Runnable pauseToggle) {
        this.store       = store;
        this.session     = session;
        this.callbacks   = callbacks;
        this.pauseToggle = pauseToggle;

        panel = new JPanel(new BorderLayout());
        panel.setBackground(C_ROOT);

        // Build non-overridable components inline
        table       = new JTable(tblModel);
        repeaterBtn = ghostBtn("Send to Repeater");
        fpBtn       = ghostBtn("Mark as FP");
        overrideBtn = ghostBtn("Override Severity");
    }

    // ── UI Construction ───────────────────────────────────────────────────────

    private void buildUI() {
        panel.add(buildToolbar(),  BorderLayout.NORTH);
        panel.add(buildMain(),     BorderLayout.CENTER);
        panel.add(buildStatusBar(),BorderLayout.SOUTH);
    }

    private JPanel buildToolbar() {
        // ── Three-row toolbar layout ──────────────────────────────────────────
        // Row 1 (top):    Brand  |  Session + Export + Misc buttons
        // Row 2 (middle): Active Scan button + progress bar + status label
        // Row 3 (bottom): Badge counts bar
        // Splitting into rows prevents all controls from competing for one line,
        // which caused the overlap visible when a scan is running.

        JPanel tb = new JPanel(new BorderLayout());
        tb.setBackground(C_HEADER_BG);
        tb.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, C_TOOLBAR_BD),
                BorderFactory.createEmptyBorder(0, 0, 0, 0)));

        // ── Row 1: Brand left | session/export buttons right ─────────────────
        JPanel row1 = new JPanel(new BorderLayout());
        row1.setOpaque(false);
        row1.setBorder(BorderFactory.createEmptyBorder(8, 16, 4, 16));

        JPanel brandPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        brandPanel.setOpaque(false);
        JLabel brand = new JLabel("BurpMax");
        brand.setFont(new Font("Arial", Font.BOLD, 18));
        brand.setForeground(C_ACCENT_BLU);
        brandPanel.add(brand);

        // Session controls (left cluster of row1 buttons)
        JButton saveBtn  = ghostBtn("💾 Save");
        JButton loadBtn  = ghostBtn("📂 Load");
        JButton clearBtn = dangerBtn("Clear All");
        JButton pauseBtn = ghostBtn("⏸ Pause");

        // Export controls
        JButton csvBtn   = primaryBtn("CSV");
        JButton pdfBtn   = primaryBtn("PDF");
        JButton wordBtn  = primaryBtn("Word");
        JButton diffBtn  = ghostBtn("Scan Diff");

        // Save-path tooltip so users know where the file goes
        saveBtn.setToolTipText(
            "<html>Save findings to JSON file.<br>" +
            "First click: choose file location.<br>" +
            "Subsequent clicks: save to same location.<br>" +
            "<i>Right-click to change save location.</i></html>");
        loadBtn.setToolTipText("Load a previously saved BurpMax session file");

        // Save status label (shown between Save and Load buttons)
        saveStatusLbl = new JLabel("");
        saveStatusLbl.setFont(FONT_TINY);
        saveStatusLbl.setForeground(C_TEXT_MUTED);
        saveStatusLbl.setPreferredSize(new Dimension(160, 16));

        session.setStatusUpdater((success, msg) -> SwingUtilities.invokeLater(() -> {
            if (success) {
                saveStatusLbl.setForeground(new Color(0x27, 0xAE, 0x60));  // green
                saveStatusLbl.setText("\u2713 " + msg + " " + LocalTime.now().format(TIME_FMT));
            } else {
                saveStatusLbl.setForeground(new Color(0xC0, 0x39, 0x2B));  // red
                saveStatusLbl.setText("\u26a0 " + msg);
            }
        }));

        // Action listeners
        pauseBtn.addActionListener(e -> {
            paused = !paused;
            pauseBtn.setText(paused ? "▶ Resume" : "⏸ Pause");
            setExtenderPaused(paused);
        });
        clearBtn.addActionListener(e -> {
            int r = JOptionPane.showConfirmDialog(panel,
                    "Clear all findings? This cannot be undone.",
                    "Clear All", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (r == JOptionPane.YES_OPTION) store.clear();
        });
        csvBtn.addActionListener(e  -> doExport("csv"));
        pdfBtn.addActionListener(e  -> doExport("pdf"));
        wordBtn.addActionListener(e -> doExport("docx"));
        diffBtn.addActionListener(e -> doScanDiff());

        // Save always prompts for file location so the user is always in control.
        // After a save the button tooltip shows the chosen path.
        saveBtn.addActionListener(e -> chooseSavePath());
        loadBtn.addActionListener(e -> chooseLoadPath());

        // ── Row 1 right: buttons ─────────────────────────────────────────────
        // saveStatusLbl: no fixed preferred size — only takes space when text present
        saveStatusLbl.setPreferredSize(null);

        JPanel row1Right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        row1Right.setOpaque(false);
        row1Right.add(saveStatusLbl);
        row1Right.add(saveBtn);
        row1Right.add(loadBtn);
        row1Right.add(Box.createHorizontalStrut(6));
        row1Right.add(clearBtn);
        row1Right.add(pauseBtn);
        row1Right.add(Box.createHorizontalStrut(6));
        row1Right.add(csvBtn);
        row1Right.add(pdfBtn);
        row1Right.add(wordBtn);
        row1Right.add(diffBtn);

        row1.add(brandPanel, BorderLayout.WEST);
        row1.add(row1Right,  BorderLayout.EAST);

        // ── Row 2: Active Scan + progress/status (same padding as row1) ────────
        JPanel row2 = new JPanel(new BorderLayout());
        row2.setOpaque(false);
        row2.setBorder(BorderFactory.createEmptyBorder(0, 16, 6, 16));

        activeScanBtn = new JButton("⚡  Active Scan");
        activeScanBtn.setBackground(new Color(0x6B, 0x21, 0xA8));
        activeScanBtn.setForeground(Color.WHITE);
        activeScanBtn.setFont(FONT_MONO_B);
        activeScanBtn.setFocusPainted(false);
        activeScanBtn.setBorderPainted(false);
        activeScanBtn.setBorder(BorderFactory.createEmptyBorder(4, 14, 4, 14));
        activeScanBtn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        activeScanBtn.setOpaque(true);
        activeScanBtn.setToolTipText("Actively probe all in-scope endpoints for vulnerabilities");
        activeScanBtn.addActionListener(e -> toggleActiveScan());

        activeScanProgress = new JProgressBar(0, 100);
        activeScanProgress.setStringPainted(true);
        activeScanProgress.setString("");
        activeScanProgress.setVisible(false);
        activeScanProgress.setPreferredSize(new Dimension(200, 18));
        activeScanProgress.setForeground(new Color(0x6B, 0x21, 0xA8));

        activeScanStatus = new JLabel("");
        activeScanStatus.setFont(FONT_TINY);
        activeScanStatus.setForeground(new Color(0xA7, 0x8B, 0xFA));
        activeScanStatus.setVisible(false);

        // Checkpoint resume notification — shown in row2 immediately at startup
        com.burpmax.active.ScanCheckpoint existing =
                com.burpmax.active.ScanCheckpoint.load(callbacks);
        if (existing != null && existing.hasPending()) {
            activeScanStatus.setText(String.format(
                    "\u26a0  Interrupted scan: %d endpoints remaining (%d%% done)"
                    + "  \u2014  click Active Scan to resume",
                    existing.pendingUrls.size(), existing.percentComplete()));
            activeScanStatus.setForeground(new Color(0xFB, 0xBF, 0x24));
            activeScanStatus.setVisible(true);
        }

        // Row2: Active Scan button pinned left; progress+status fill remaining space
        JPanel row2Left = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        row2Left.setOpaque(false);
        row2Left.add(activeScanBtn);

        JPanel row2Center = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        row2Center.setOpaque(false);
        row2Center.add(activeScanProgress);
        row2Center.add(activeScanStatus);

        row2.add(row2Left,   BorderLayout.WEST);
        row2.add(row2Center, BorderLayout.CENTER);

        // ── Toolbar assembly ─────────────────────────────────────────────────
        JPanel topRows = new JPanel();
        topRows.setOpaque(false);
        topRows.setLayout(new BoxLayout(topRows, BoxLayout.Y_AXIS));
        topRows.add(row1);
        topRows.add(row2);

        tb.add(topRows,         BorderLayout.CENTER);
        tb.add(buildBadgeBar(), BorderLayout.SOUTH);
        return tb;
    }

    private JPanel buildBadgeBar() {
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 6));
        bar.setOpaque(false);
        bar.add(muted("Total:")); bar.add(lblTotal);
        bar.add(muted("Crit:"));  bar.add(lblCrit);
        bar.add(muted("High:"));  bar.add(lblHigh);
        bar.add(muted("Med:"));   bar.add(lblMed);
        bar.add(muted("Low:"));   bar.add(lblLow);
        bar.add(Box.createHorizontalStrut(20));
        bar.add(summaryLbl);

        // Filter buttons
        bar.add(Box.createHorizontalStrut(20));
        for (String sev : new String[]{null, Finding.SEV_CRITICAL, Finding.SEV_HIGH,
                Finding.SEV_MEDIUM, Finding.SEV_LOW, Finding.SEV_INFO}) {
            String label = sev == null ? "All" : sev;
            JButton fb = ghostBtn(label);
            if (sev != null) fb.setForeground(SEV_FG.getOrDefault(sev, C_TEXT_DIM));
            final String sevFinal = sev;
            fb.addActionListener(e -> { filterSev = sevFinal; refresh(); });
            bar.add(fb);
        }

        // Show FP toggle
        JButton fpToggle = ghostBtn("Show FP");
        fpToggle.addActionListener(e -> {
            showSuppressed = !showSuppressed;
            fpToggle.setText(showSuppressed ? "Hide FP" : "Show FP");
            refresh();
        });
        bar.add(fpToggle);

        // ── Free-text search ──────────────────────────────────────
        bar.add(Box.createHorizontalStrut(16));

        JLabel searchLbl = new JLabel("[ search ]");
        searchLbl.setFont(FONT_TINY);
        searchLbl.setForeground(C_TEXT_MUTED);

        JTextField searchField = new JTextField(18);
        searchField.setFont(FONT_MONO);
        searchField.setBackground(C_SURFACE);
        searchField.setForeground(C_TEXT_MUTED);
        searchField.setCaretColor(C_TEXT);
        searchField.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(C_BORDER, 1),
                BorderFactory.createEmptyBorder(2, 6, 2, 6)));
        searchField.setToolTipText(
            "<html>Filter by keyword (name, host, URL, CWE, description, evidence)."
            + "<br>Space-separated terms are AND-ed: <b>xss admin</b> matches both.</html>");

        final String PLACEHOLDER = "Search findings...";
        searchField.setText(PLACEHOLDER);

        searchField.addFocusListener(new java.awt.event.FocusAdapter() {
            @Override public void focusGained(java.awt.event.FocusEvent e) {
                if (PLACEHOLDER.equals(searchField.getText())) {
                    searchField.setText("");
                    searchField.setForeground(C_TEXT);
                }
            }
            @Override public void focusLost(java.awt.event.FocusEvent e) {
                if (searchField.getText().isBlank()) {
                    searchField.setText(PLACEHOLDER);
                    searchField.setForeground(C_TEXT_MUTED);
                    filterText = null;
                    refresh();
                }
            }
        });

        searchField.getDocument().addDocumentListener(
                new javax.swing.event.DocumentListener() {
                    private void update() {
                        String t = searchField.getText();
                        filterText = (t.isBlank() || PLACEHOLDER.equals(t)) ? null : t;
                        refresh();
                    }
                    public void insertUpdate(javax.swing.event.DocumentEvent e)  { update(); }
                    public void removeUpdate(javax.swing.event.DocumentEvent e)  { update(); }
                    public void changedUpdate(javax.swing.event.DocumentEvent e) { update(); }
                });

        JButton clearSearch = ghostBtn("x");
        clearSearch.setFont(new Font("Arial", Font.BOLD, 11));
        clearSearch.setToolTipText("Clear search filter");
        clearSearch.addActionListener(e -> {
            searchField.setText(PLACEHOLDER);
            searchField.setForeground(C_TEXT_MUTED);
            filterText = null;
            refresh();
        });

        bar.add(searchLbl);
        bar.add(searchField);
        bar.add(clearSearch);

        return bar;
    }

    private JSplitPane buildMain() {
        // Left: findings table
        JPanel leftPanel = new JPanel(new BorderLayout());
        leftPanel.setBackground(C_SURFACE);
        leftPanel.setBorder(BorderFactory.createMatteBorder(0,0,0,1,C_BORDER));

        styleTable();
        JScrollPane tableScroll = new JScrollPane(table);
        tableScroll.setBackground(C_ROOT);
        tableScroll.getViewport().setBackground(C_ROOT);
        tableScroll.setBorder(BorderFactory.createEmptyBorder());

        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = table.getSelectedRow();
                if (row >= 0 && visibleFindings != null && row < visibleFindings.size()) {
                    populateDetail(visibleFindings.get(row));
                }
            }
        });

        leftPanel.add(tableScroll, BorderLayout.CENTER);

        // Right: detail panel
        JPanel rightPanel = buildDetailPanel();

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, rightPanel);
        split.setDividerLocation(660);
        split.setBackground(C_ROOT);
        split.setBorder(BorderFactory.createEmptyBorder());
        split.setDividerSize(4);
        return split;
    }

    private JPanel buildDetailPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBackground(C_HEADER_BG);

        // Title row
        JPanel titleRow = new JPanel(new BorderLayout());
        titleRow.setOpaque(false);
        titleRow.setBorder(BorderFactory.createEmptyBorder(12,16,8,16));
        detTitle.setFont(new Font("Arial", Font.BOLD, 14));
        detTitle.setForeground(C_TEXT_HEAD);
        detBadge.setOpaque(true);
        detBadge.setFont(FONT_TINY);
        detBadge.setBorder(BorderFactory.createEmptyBorder(2,8,2,8));
        titleRow.add(detTitle, BorderLayout.CENTER);
        titleRow.add(detBadge, BorderLayout.EAST);

        // FP banner
        fpBanner.setBackground(new Color(60,15,15));
        fpBanner.setBorder(BorderFactory.createEmptyBorder(6,16,6,16));
        JLabel fpLbl = new JLabel("⚠ Marked as False Positive");
        fpLbl.setForeground(C_HIGH);
        fpLbl.setFont(FONT_UI_B);
        fpBanner.add(fpLbl, BorderLayout.WEST);
        fpBanner.setVisible(false);

        // Action buttons
        JPanel btnBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 6));
        btnBar.setOpaque(false);
        repeaterBtn.addActionListener(e -> sendToRepeater());
        fpBtn.addActionListener(e -> toggleFP());
        overrideBtn.addActionListener(e -> doOverride());
        JButton copyBtn = ghostBtn("Copy URL");
        copyBtn.addActionListener(e -> copyUrl());
        btnBar.add(repeaterBtn); btnBar.add(fpBtn); btnBar.add(overrideBtn); btnBar.add(copyBtn);

        // ── CVSS + Status row ─────────────────────────────────────────────────
        JPanel metaRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 4));
        metaRow.setOpaque(false);
        metaRow.setBorder(BorderFactory.createEmptyBorder(0, 12, 0, 12));

        // CVSS score label
        JLabel cvssCaption = new JLabel("CVSS 4.0:");
        cvssCaption.setFont(FONT_TINY);
        cvssCaption.setForeground(C_TEXT_MUTED);
        cvssLabel.setFont(FONT_UI_B);
        cvssLabel.setForeground(C_ACCENT_BLU);
        metaRow.add(cvssCaption);
        metaRow.add(cvssLabel);

        // Status dropdown
        JLabel statusCaption = new JLabel("Status:");
        statusCaption.setFont(FONT_TINY);
        statusCaption.setForeground(C_TEXT_MUTED);
        statusCombo.setFont(FONT_SMALL);
        statusCombo.setBackground(C_SURFACE);
        statusCombo.setForeground(C_TEXT);
        statusCombo.setMaximumSize(new Dimension(160, 24));
        statusCombo.addActionListener(e -> {
            if (selectedFinding != null && !noteUpdating) {
                String sel = (String) statusCombo.getSelectedItem();
                if (sel != null) {
                    selectedFinding.remediationStatus = sel;
                    // Keep suppressed flag in sync: FP status = suppressed
                    if (com.burpmax.model.Finding.STATUS_FP.equals(sel)) {
                        selectedFinding.suppressed = true;
                        fpBanner.setVisible(true);
                        fpBtn.setText("Unmark FP");
                    } else if (selectedFinding.suppressed
                            && !com.burpmax.model.Finding.STATUS_FP.equals(sel)) {
                        selectedFinding.suppressed = false;
                        fpBanner.setVisible(false);
                        fpBtn.setText("Mark as FP");
                    }
                    tblModel.fireTableDataChanged();
                    session.scheduleAutoSave();
                }
            }
        });
        metaRow.add(statusCaption);
        metaRow.add(statusCombo);

        // Scrollable content
        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.setBackground(C_HEADER_BG);
        content.add(titleRow);
        content.add(fpBanner);
        content.add(btnBar);
        content.add(metaRow);
        content.add(codeBlock("Description", descArea));
        content.add(codeBlock("Evidence", evArea));
        content.add(codeBlock("Remediation", remArea));

        // Affected endpoints strip
        affStrip.setOpaque(false);
        affStrip.setBorder(BorderFactory.createEmptyBorder(4,16,4,16));
        affCount.setFont(FONT_SMALL);
        affCount.setForeground(C_TEXT_MUTED);
        affStrip.add(affCount, BorderLayout.NORTH);
        JScrollPane affScroll = new JScrollPane(affArea);
        affScroll.setPreferredSize(new Dimension(300, 60));
        styleScrollPane(affScroll);
        affStrip.add(affScroll, BorderLayout.CENTER);
        affStrip.setVisible(false);
        content.add(affStrip);

        // Analyst note
        JPanel noteStrip = new JPanel(new BorderLayout());
        noteStrip.setOpaque(false);
        noteStrip.setBorder(BorderFactory.createEmptyBorder(4,16,4,16));
        JLabel noteLbl = new JLabel("ANALYST NOTE");
        noteLbl.setFont(FONT_TINY);
        noteLbl.setForeground(C_TEXT_MUTED);
        noteLbl.setBorder(BorderFactory.createEmptyBorder(0,0,4,0));
        noteStrip.add(noteLbl, BorderLayout.NORTH);
        JScrollPane noteScroll = new JScrollPane(noteArea);
        noteScroll.setPreferredSize(new Dimension(300, 70));
        styleScrollPane(noteScroll);
        noteStrip.add(noteScroll, BorderLayout.CENTER);
        noteArea.getDocument().addDocumentListener(new DocumentListener() {
            private void update() {
                if (!noteUpdating && selectedFinding != null) {
                    selectedFinding.analystNote = noteArea.getText();
                    session.scheduleAutoSave();
                }
            }
            public void insertUpdate(DocumentEvent e)  { update(); }
            public void removeUpdate(DocumentEvent e)  { update(); }
            public void changedUpdate(DocumentEvent e) { update(); }
        });
        content.add(noteStrip);

        JScrollPane detailScroll = new JScrollPane(content);
        styleScrollPane(detailScroll);
        detailScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);

        JPanel wrapper = new JPanel(new BorderLayout());
        wrapper.setBackground(C_HEADER_BG);
        wrapper.add(detailScroll, BorderLayout.CENTER);
        return wrapper;
    }

    private JPanel buildStatusBar() {
        JPanel bar = new JPanel(new BorderLayout());
        bar.setBackground(C_HEADER_BG);
        bar.setBorder(BorderFactory.createMatteBorder(1,0,0,0,C_BORDER));

        JLabel status = muted("BurpMax v1.0 | Passive + Active scanning");
        status.setBorder(BorderFactory.createEmptyBorder(4, 16, 4, 12));
        bar.add(status, BorderLayout.WEST);

        JLabel credit = muted("Developed by Omkar Mirkute");
        credit.setBorder(BorderFactory.createEmptyBorder(4, 12, 4, 16));
        bar.add(credit, BorderLayout.EAST);
        return bar;
    }

    // ── Table styling ─────────────────────────────────────────────────────────

    private void styleTable() {
        table.setBackground(C_ROOT);
        table.setForeground(C_TEXT);
        table.setSelectionBackground(C_SEL_ROW);
        table.setSelectionForeground(C_TEXT);
        table.setGridColor(C_BORDER2);
        table.setRowHeight(24);
        table.setFont(FONT_MONO);
        table.setShowGrid(true);
        table.setIntercellSpacing(new Dimension(0, 1));
        table.setFillsViewportHeight(true);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);

        JTableHeader header = table.getTableHeader();
        header.setBackground(C_HEADER_BG);
        header.setForeground(C_TEXT_MUTED);
        header.setFont(FONT_TINY);
        header.setBorder(BorderFactory.createMatteBorder(0,0,1,0,C_BORDER));

        // Column widths
        int[] widths = {35, 90, 280, 200, 55, 90};
        for (int i = 0; i < widths.length; i++) {
            table.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        }

        // Severity renderer
        table.getColumnModel().getColumn(1).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable t, Object val, boolean sel,
                    boolean focus, int row, int col) {
                super.getTableCellRendererComponent(t, val, sel, focus, row, col);
                String sev = val != null ? val.toString().replace("*","").trim() : "";
                setForeground(SEV_FG.getOrDefault(sev, C_TEXT_DIM));
                setBackground(sel ? C_SEL_ROW : C_ROOT);
                setFont(FONT_MONO_B);
                setBorder(BorderFactory.createEmptyBorder(0,4,0,4));
                return this;
            }
        });

        // Default renderer for other cols
        DefaultTableCellRenderer def = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable t, Object val, boolean sel,
                    boolean focus, int row, int col) {
                super.getTableCellRendererComponent(t, val, sel, focus, row, col);
                setBackground(sel ? C_SEL_ROW : C_ROOT);
                setForeground(C_TEXT_DIM);
                setFont(FONT_MONO);
                setBorder(BorderFactory.createEmptyBorder(0,4,0,4));
                return this;
            }
        };
        for (int c : new int[]{0,2,3,4,5}) {
            table.getColumnModel().getColumn(c).setCellRenderer(def);
        }
    }

    // ── Refresh ───────────────────────────────────────────────────────────────

    /**
     * True if every space-separated term in query appears somewhere in the finding.
     * Searched fields: name, host, url, cwe, evidence, description, analystNote, severity.
     */
    private static boolean matchesText(Finding f, String query) {
        String[] terms = query.split("\\s+");
        String haystack = (nvl(f.name) + " " + nvl(f.host) + " " + nvl(f.url)
                + " " + nvl(f.cwe) + " " + nvl(f.evidence)
                + " " + nvl(f.description) + " " + nvl(f.analystNote)
                + " " + nvl(f.effectiveSeverity())).toLowerCase();
        for (String term : terms) {
            if (!term.isBlank() && !haystack.contains(term)) return false;
        }
        return true;
    }

    private static String nvl(String s) { return s != null ? s : ""; }

    public void refresh() {
        List<Finding> all = store.getAll();
        final String ft = (filterText != null && !filterText.isBlank())
                ? filterText.toLowerCase().strip() : null;
        visibleFindings = all.stream()
                .filter(f -> (showSuppressed || !f.suppressed) &&
                             (filterSev == null || filterSev.equals(f.effectiveSeverity())) &&
                             (ft == null || matchesText(f, ft)))
                .toList();

        tblModel.setFindings(visibleFindings);

        // Summary badges — when a filter is active, lblTotal shows the filtered count
        // so it matches the summary label. Without a filter it shows all non-suppressed.
        var s = store.summary();
        int fp = store.getSuppressed().size();
        boolean filtered = filterSev != null || (filterText != null && !filterText.isBlank());
        int badgeCount = filtered ? visibleFindings.size() : store.getVisible().size();
        lblTotal.setText(String.valueOf(badgeCount));
        lblCrit.setText(String.valueOf(s.getOrDefault(Finding.SEV_CRITICAL, 0)));
        lblHigh.setText(String.valueOf(s.getOrDefault(Finding.SEV_HIGH, 0)));
        lblMed.setText(String.valueOf(s.getOrDefault(Finding.SEV_MEDIUM, 0)));
        lblLow.setText(String.valueOf(s.getOrDefault(Finding.SEV_LOW, 0)));

        String filtStr   = filterSev  != null ? " [" + filterSev + "]" : "";
        String searchStr = (filterText != null && !filterText.isBlank())
                ? " ‹" + filterText.strip() + "›" : "";
        String fpStr     = fp > 0 ? "  |  " + fp + " FP" : "";
        summaryLbl.setText(visibleFindings.size() + " findings" + filtStr + searchStr + fpStr);

        // Trigger session auto-save
        session.scheduleAutoSave();
    }

    // ── Detail panel population ───────────────────────────────────────────────

    private void populateDetail(Finding f) {
        selectedFinding = f;

        boolean hasReq = f.primaryRawRequest() != null && f.primaryHttpService() != null;
        repeaterBtn.setEnabled(hasReq);
        repeaterBtn.setToolTipText(hasReq ? null
                : "Request not available - only findings captured in this session can be sent to Repeater");

        detTitle.setText(f.name);
        String eff = f.effectiveSeverity();
        detBadge.setText(eff.toUpperCase() + (f.severityOverride != null ? " *" : ""));
        detBadge.setBackground(SEV_BG.getOrDefault(eff, C_SURFACE));
        detBadge.setForeground(SEV_FG.getOrDefault(eff, C_TEXT_DIM));
        detBadge.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(SEV_BD.getOrDefault(eff, C_BORDER), 1),
                BorderFactory.createEmptyBorder(2,8,2,8)));

        descArea.setText(f.description); descArea.setCaretPosition(0);
        evArea.setText(f.evidence);      evArea.setCaretPosition(0);
        remArea.setText(f.remediation);  remArea.setCaretPosition(0);
        fpBanner.setVisible(f.suppressed);

        // CVSS 4.0 score display
        double score = f.effectiveCvssScore();
        String vector = (f.cvssVector != null && !f.cvssVector.isEmpty()) ? f.cvssVector : "";
        cvssLabel.setText(String.format("%.1f", score)
                + (vector.isEmpty() ? "" : "  \u2014  " + vector));
        cvssLabel.setForeground(score >= 9.0 ? C_CRITICAL
                              : score >= 7.0 ? C_HIGH
                              : score >= 4.0 ? C_MEDIUM
                              : score >= 0.1 ? C_LOW
                              : C_TEXT_MUTED);

        // Status dropdown — suppress ActionListener during programmatic change
        noteUpdating = true;
        try { statusCombo.setSelectedItem(f.remediationStatus); }
        finally { noteUpdating = false; }

        if (f.affectedEndpoints.size() > 1) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < f.affectedEndpoints.size(); i++) {
                Finding.EndpointEntry e = f.affectedEndpoints.get(i);
                sb.append("[").append(i+1).append("]  ").append(e.endpoint)
                  .append("  (HTTP ").append(e.statusCode > 0 ? e.statusCode : "-").append(")\n");
            }
            affArea.setText(sb.toString()); affArea.setCaretPosition(0);
            affCount.setText(f.affectedEndpoints.size() + " endpoints affected");
            affStrip.setVisible(true);
        } else {
            affStrip.setVisible(false);
        }

        noteUpdating = true;
        try { noteArea.setText(f.analystNote != null ? f.analystNote : ""); }
        finally { noteUpdating = false; }
    }

    // ── Actions ───────────────────────────────────────────────────────────────

    private void sendToRepeater() {
        if (selectedFinding == null) return;
        try {
            Object svcObj = selectedFinding.primaryHttpService();
            byte[] req    = selectedFinding.primaryRawRequest();
            if (svcObj == null || req == null) return;

            // Cast to IHttpService — safe because we stored the real Burp object
            IHttpService svc = (IHttpService) svcObj;
            callbacks.sendToRepeater(
                    svc.getHost(), svc.getPort(),
                    svc.getProtocol().equalsIgnoreCase("https"),
                    req, selectedFinding.name);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(panel, "Could not send to Repeater: " + e.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void toggleFP() {
        if (selectedFinding == null) return;
        selectedFinding.suppressed = !selectedFinding.suppressed;
        if (selectedFinding.suppressed) {
            selectedFinding.remediationStatus = com.burpmax.model.Finding.STATUS_FP;
        } else if (com.burpmax.model.Finding.STATUS_FP.equals(selectedFinding.remediationStatus)) {
            selectedFinding.remediationStatus = com.burpmax.model.Finding.STATUS_OPEN;
        }
        fpBtn.setText(selectedFinding.suppressed ? "Unmark FP" : "Mark as FP");
        fpBanner.setVisible(selectedFinding.suppressed);
        noteUpdating = true;
        try { statusCombo.setSelectedItem(selectedFinding.remediationStatus); }
        finally { noteUpdating = false; }
        refresh();
    }

    private void doOverride() {
        if (selectedFinding == null) return;
        String[] options = {Finding.SEV_CRITICAL, Finding.SEV_HIGH, Finding.SEV_MEDIUM,
                            Finding.SEV_LOW, Finding.SEV_INFO, "Remove Override"};
        String choice = (String) JOptionPane.showInputDialog(panel,
                "Select severity override:", "Override Severity",
                JOptionPane.PLAIN_MESSAGE, null, options, selectedFinding.effectiveSeverity());
        if (choice == null) return;
        selectedFinding.severityOverride = "Remove Override".equals(choice) ? null : choice;
        populateDetail(selectedFinding);
        refresh();
    }

    private void copyUrl() {
        if (selectedFinding == null) return;
        Toolkit.getDefaultToolkit().getSystemClipboard()
               .setContents(new StringSelection(selectedFinding.url), null);
    }

    private void doScanDiff() {
        if (store.getAll().isEmpty()) {
            JOptionPane.showMessageDialog(panel, "No findings to diff against. Run a scan first.",
                "Scan Diff", JOptionPane.INFORMATION_MESSAGE); return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select Baseline Session File (.json)");
        chooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter(
                "BurpMax Session (*.json)", "json"));
        if (chooser.showOpenDialog(panel) != JFileChooser.APPROVE_OPTION) return;
        String baselinePath = chooser.getSelectedFile().getAbsolutePath();

        Thread t = new Thread(() -> {
            try {
                com.burpmax.export.ScanDiff.Result diff =
                        com.burpmax.export.ScanDiff.compare(store, baselinePath);
                SwingUtilities.invokeLater(() -> showDiffResult(diff, baselinePath));
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() ->
                    JOptionPane.showMessageDialog(panel,
                        "Diff failed: " + ex.getMessage(), "Error",
                        JOptionPane.ERROR_MESSAGE));
            }
        }, "burpmax-diff");
        t.setDaemon(true); t.start();
    }

    private void showDiffResult(com.burpmax.export.ScanDiff.Result diff,
                                 String baselinePath) {
        JPanel p = new JPanel();
        p.setLayout(new javax.swing.BoxLayout(p, javax.swing.BoxLayout.Y_AXIS));
        p.setBackground(C_SURFACE);
        p.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        // Summary header
        JLabel summary = new JLabel("<html><b>Scan Diff Result</b><br><br>" +
                "<b>" + diff.newFindings().size() + "</b> new findings&nbsp;&nbsp;" +
                "<b>" + diff.existingFindings().size() + "</b> existing&nbsp;&nbsp;" +
                "<b>" + diff.resolvedCount() + "</b> resolved<br><br>" +
                "<font color='#777777'>Baseline: " + baselinePath + "</font></html>");
        summary.setFont(FONT_UI); summary.setForeground(C_TEXT);
        p.add(summary);
        p.add(Box.createVerticalStrut(12));

        if (!diff.newFindings().isEmpty()) {
            JLabel newLbl = new JLabel("<html><b style='color:#C0392B'>⬆ New Findings ("
                    + diff.newFindings().size() + "):</b></html>");
            newLbl.setFont(FONT_UI); p.add(newLbl); p.add(Box.createVerticalStrut(4));
            for (com.burpmax.model.Finding f : diff.newFindings().subList(
                    0, Math.min(10, diff.newFindings().size()))) {
                JLabel l = new JLabel("  ●  [" + f.effectiveSeverity() + "]  " + f.name);
                l.setFont(FONT_SMALL); l.setForeground(C_TEXT); p.add(l);
            }
            if (diff.newFindings().size() > 10)
                p.add(new JLabel("  ... and " + (diff.newFindings().size()-10) + " more"));
            p.add(Box.createVerticalStrut(8));
        }

        if (diff.resolvedCount() > 0) {
            JLabel resLbl = new JLabel("<html><b style='color:#287A28'>✔ Resolved ("
                    + diff.resolvedCount() + "):</b></html>");
            resLbl.setFont(FONT_UI); p.add(resLbl); p.add(Box.createVerticalStrut(4));
            for (String name : diff.resolvedNames().subList(
                    0, Math.min(10, diff.resolvedNames().size()))) {
                JLabel l = new JLabel("  ✔  " + name);
                l.setFont(FONT_SMALL); l.setForeground(C_TEXT); p.add(l);
            }
            if (diff.resolvedCount() > 10)
                p.add(new JLabel("  ... and " + (diff.resolvedCount()-10) + " more"));
            p.add(Box.createVerticalStrut(8));
        }

        if (!diff.hasChanges()) {
            JLabel noChange = new JLabel("✔  No changes detected - findings match baseline.");
            noChange.setFont(FONT_UI); noChange.setForeground(C_TEXT); p.add(noChange);
        }

        // Options: export diff as PDF, or close
        int choice = JOptionPane.showOptionDialog(panel, p, "Scan Diff",
                JOptionPane.YES_NO_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE, null,
                new Object[]{"Export New as PDF", "Export New as CSV", "Close"}, "Close");

        if (choice == 0 && !diff.newFindings().isEmpty()) {
            // Export new findings as PDF
            com.burpmax.export.ReportMeta meta = showMetaDialog(
                    diff.newFindings().size() + " new findings", "pdf");
            if (meta == null) return;
            JFileChooser fc = new JFileChooser();
            fc.setSelectedFile(new File("burpmax_diff_new.pdf"));
            if (fc.showSaveDialog(panel) != JFileChooser.APPROVE_OPTION) return;
            String path = fc.getSelectedFile().getAbsolutePath();
            final com.burpmax.export.ReportMeta finalMeta = meta;
            final java.util.List<com.burpmax.model.Finding> newF = diff.newFindings();
            new Thread(() -> {
                try {
                    com.burpmax.export.PdfExporter.export(newF, path, finalMeta);
                    SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(panel,
                        "Exported " + newF.size() + " new findings to:\n" + path,
                        "Export Complete", JOptionPane.INFORMATION_MESSAGE));
                } catch (Exception ex) {
                    SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(panel,
                        "Export failed: " + ex.getMessage(), "Error",
                        JOptionPane.ERROR_MESSAGE));
                }
            }, "burpmax-diff-export").start();
        } else if (choice == 1 && !diff.newFindings().isEmpty()) {
            JFileChooser fc = new JFileChooser();
            fc.setSelectedFile(new File("burpmax_diff_new.csv"));
            if (fc.showSaveDialog(panel) != JFileChooser.APPROVE_OPTION) return;
            String path = fc.getSelectedFile().getAbsolutePath();
            final java.util.List<com.burpmax.model.Finding> newF = diff.newFindings();
            new Thread(() -> {
                try {
                    com.burpmax.export.CsvExporter.export(newF, path);
                    SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(panel,
                        "Exported to:\n" + path, "Export Complete",
                        JOptionPane.INFORMATION_MESSAGE));
                } catch (Exception ex) {
                    SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(panel,
                        "Export failed: " + ex.getMessage(), "Error",
                        JOptionPane.ERROR_MESSAGE));
                }
            }, "burpmax-diff-csv").start();
        }
    }

    private void doExport(String fmt) {
        // Export what is currently visible — respects active severity filter + suppressed state
        List<Finding> findings = getFilteredFindings();
        if (findings.isEmpty()) {
            JOptionPane.showMessageDialog(panel,
                filterSev != null
                    ? "No " + filterSev + " findings to export. Clear the filter to export all."
                    : "No findings to export.",
                "Export", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        String scope = filterSev != null
            ? findings.size() + " " + filterSev + " findings"
            : findings.size() + " findings (all severities)";

        com.burpmax.export.ReportMeta meta = null;
        if ("docx".equals(fmt) || "pdf".equals(fmt)) {
            meta = showMetaDialog(scope, fmt);
            if (meta == null) return;
        }

        String defaultName = filterSev != null
            ? "burpmax_" + filterSev.toLowerCase() + "_findings." + fmt
            : "burpmax_report." + fmt;

        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File(defaultName));
        if (chooser.showSaveDialog(panel) != JFileChooser.APPROVE_OPTION) return;
        String path = chooser.getSelectedFile().getAbsolutePath();

        final com.burpmax.export.ReportMeta finalMeta = meta;
        final List<Finding> finalFindings = findings;
        Thread t = new Thread(() -> {
            try {
                if ("csv".equals(fmt)) {
                    com.burpmax.export.CsvExporter.export(finalFindings, path);
                } else if ("pdf".equals(fmt)) {
                    com.burpmax.export.PdfExporter.export(finalFindings, path, finalMeta);
                } else {
                    com.burpmax.export.DocxExporter.export(finalFindings, path, finalMeta);
                }
                SwingUtilities.invokeLater(() ->
                    JOptionPane.showMessageDialog(panel,
                        "Exported " + finalFindings.size() + " findings to:\n" + path,
                        "Export Complete", JOptionPane.INFORMATION_MESSAGE));
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() ->
                    JOptionPane.showMessageDialog(panel, "Export failed: " + ex.getMessage(),
                        "Error", JOptionPane.ERROR_MESSAGE));
            }
        }, "burpmax-export");
        t.setDaemon(true);
        t.start();
    }

    /** Returns findings matching the current severity filter (excludes suppressed). */
    private List<Finding> getFilteredFindings() {
        List<Finding> out = new ArrayList<>();
        for (Finding f : store.getVisible()) {
            if (filterSev == null || filterSev.equals(f.effectiveSeverity())) out.add(f);
        }
        return out;
    }

    /** Shows a dialog to collect report metadata. Returns null if cancelled. */
    // ── Report metadata persistence ───────────────────────────────────────────
    private String metaClient   = "Confidential Client";
    private String metaScope    = "Web Application";
    private String metaDate     = java.time.LocalDate.now().toString();
    private String metaVersion  = "1.0";
    private String metaAuthor   = "Security Analyst";
    private String metaClass    = "Confidential";
    private String metaEngType  = "Web Application Penetration Test";
    private String metaNotes    = "";
    private String metaLogoPath = "";

    private com.burpmax.export.ReportMeta showMetaDialog(String scope, String fmt) {
        java.awt.Window owner = SwingUtilities.getWindowAncestor(panel);
        javax.swing.JDialog dlg = (owner instanceof java.awt.Frame)
                ? new javax.swing.JDialog((java.awt.Frame) owner,
                        ("pdf".equals(fmt) ? "PDF" : "Word") + " Report Details", true)
                : new javax.swing.JDialog((java.awt.Dialog) owner,
                        ("pdf".equals(fmt) ? "PDF" : "Word") + " Report Details", true);
        dlg.setResizable(false);

        JPanel form = new JPanel(new java.awt.GridBagLayout());
        form.setBackground(C_SURFACE);
        form.setBorder(BorderFactory.createEmptyBorder(20, 20, 12, 20));
        java.awt.GridBagConstraints lc = new java.awt.GridBagConstraints();
        lc.gridx = 0; lc.anchor = java.awt.GridBagConstraints.EAST;
        lc.insets = new java.awt.Insets(5, 0, 5, 10);
        java.awt.GridBagConstraints fc = new java.awt.GridBagConstraints();
        fc.gridx = 1; fc.fill = java.awt.GridBagConstraints.HORIZONTAL;
        fc.weightx = 1.0; fc.insets = new java.awt.Insets(5, 0, 5, 0);

        JTextField fClient  = metaField(metaClient);
        JTextField fScope   = metaField(metaScope);
        JTextField fDate    = metaField(metaDate);
        JTextField fVersion = metaField(metaVersion);
        JTextField fAuthor  = metaField(metaAuthor);
        JTextField fNotes   = metaField(metaNotes);

        JComboBox<String> fClass = new JComboBox<>(new String[]{
            "Confidential", "Restricted", "Internal", "Public"});
        fClass.setSelectedItem(metaClass);
        fClass.setBackground(C_DEEP); fClass.setForeground(C_TEXT); fClass.setFont(FONT_UI);

        JComboBox<String> fEngType = new JComboBox<>(new String[]{
            "Web Application Penetration Test", "API Security Assessment",
            "Mobile Application Assessment", "Network Penetration Test",
            "Red Team Exercise", "Vulnerability Assessment", "Source Code Review",
            "Cloud Security Assessment", "VAPT"});
        fEngType.setSelectedItem(metaEngType);
        fEngType.setEditable(true);
        fEngType.setBackground(C_DEEP); fEngType.setForeground(C_TEXT); fEngType.setFont(FONT_UI);

        JTextField fLogo = metaField(metaLogoPath);
        fLogo.setEditable(false);
        JButton browseBtn = ghostBtn("Browse...");
        JPanel logoRow = new JPanel(new BorderLayout(6, 0));
        logoRow.setOpaque(false);
        logoRow.add(fLogo, BorderLayout.CENTER);
        logoRow.add(browseBtn, BorderLayout.EAST);
        browseBtn.addActionListener(ev -> {
            javax.swing.JFileChooser fc2 = new javax.swing.JFileChooser();
            fc2.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter(
                    "Images (PNG, JPG)", "png", "jpg", "jpeg"));
            if (fc2.showOpenDialog(dlg) == javax.swing.JFileChooser.APPROVE_OPTION)
                fLogo.setText(fc2.getSelectedFile().getAbsolutePath());
        });

        String[][] labelNames = {
            {"Client / Organisation:"}, {"Target Scope:"}, {"Assessment Date:"},
            {"Report Version:"}, {"Prepared By:"}, {"Classification:"},
            {"Engagement Type:"}, {"Analyst Notes:"}, {"Company Logo (optional):"}
        };
        java.awt.Component[] fields = {
            fClient, fScope, fDate, fVersion, fAuthor, fClass, fEngType, fNotes, logoRow
        };
        for (int i = 0; i < labelNames.length; i++) {
            lc.gridy = i; fc.gridy = i;
            JLabel lbl = new JLabel(labelNames[i][0]);
            lbl.setFont(FONT_SMALL); lbl.setForeground(C_TEXT_MUTED);
            form.add(lbl, lc);
            form.add(fields[i], fc);
        }

        JPanel footer = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 10));
        footer.setBackground(new Color(0x0F, 0x16, 0x26));
        footer.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, C_BORDER));
        JButton cancelBtn = ghostBtn("Cancel");
        cancelBtn.addActionListener(ev -> dlg.dispose());
        JButton generateBtn = new JButton("Generate report");
        generateBtn.setFont(FONT_UI_B);
        generateBtn.setForeground(Color.WHITE);
        generateBtn.setBackground(new Color(0x6B, 0x21, 0xA8));
        generateBtn.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(0x7C, 0x3A, 0xED), 1),
                BorderFactory.createEmptyBorder(5, 14, 5, 14)));
        generateBtn.setFocusPainted(false);
        generateBtn.setOpaque(true);
        generateBtn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        final boolean[] confirmed = {false};
        generateBtn.addActionListener(ev -> { confirmed[0] = true; dlg.dispose(); });
        dlg.getRootPane().setDefaultButton(generateBtn);
        footer.add(cancelBtn); footer.add(generateBtn);

        JPanel root = new JPanel(new BorderLayout());
        root.setBackground(C_SURFACE);
        root.add(form, BorderLayout.CENTER);
        root.add(footer, BorderLayout.SOUTH);
        dlg.setContentPane(root);
        dlg.pack();
        dlg.setMinimumSize(new Dimension(520, dlg.getHeight()));
        dlg.setLocationRelativeTo(panel);
        dlg.setVisible(true);

        if (!confirmed[0]) return null;

        metaClient   = fClient.getText().trim();
        metaScope    = fScope.getText().trim();
        metaDate     = fDate.getText().trim();
        metaVersion  = fVersion.getText().trim();
        metaAuthor   = fAuthor.getText().trim();
        metaClass    = (String) fClass.getSelectedItem();
        metaEngType  = fEngType.getEditor().getItem().toString().trim();
        metaNotes    = fNotes.getText().trim();
        metaLogoPath = fLogo.getText().trim();

        return new com.burpmax.export.ReportMeta(
                metaClient, metaScope, metaDate, metaVersion,
                metaAuthor, metaClass, metaEngType, metaNotes, metaLogoPath);
    }

    private static JTextField metaField(String defaultValue) {
        JTextField f = new JTextField(defaultValue, 20);
        f.setFont(FONT_UI);
        f.setBackground(C_DEEP);
        f.setForeground(C_TEXT);
        f.setCaretColor(C_TEXT);
        f.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(C_BORDER, 1),
                BorderFactory.createEmptyBorder(4, 6, 4, 6)));
        // Select all on focus so user knows the default is overrideable
        f.addFocusListener(new java.awt.event.FocusAdapter() {
            @Override public void focusGained(java.awt.event.FocusEvent e) {
                f.selectAll();
            }
        });
        return f;
    }

    private static JLabel metaLabel(String text) {
        JLabel l = new JLabel(text);
        l.setFont(FONT_UI);
        l.setForeground(C_TEXT_DIM);
        return l;
    }

    private void chooseSavePath() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Choose session save location");
        chooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter(
                "BurpMax session files (*.json)", "json"));
        // Pre-select current path if one exists, otherwise default filename
        String current = session.getSavePath();
        if (current != null) {
            chooser.setSelectedFile(new File(current));
        } else {
            chooser.setSelectedFile(new File(
                System.getProperty("user.home"), "burpmax_session.json"));
        }
        if (chooser.showSaveDialog(panel) != JFileChooser.APPROVE_OPTION) return;
        String path = chooser.getSelectedFile().getAbsolutePath();
        if (!path.endsWith(".json")) path += ".json";
        session.setSavePath(path);
        session.saveNow();
    }

    private void chooseLoadPath() {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter(
                "BurpMax session files (*.json)", "json"));
        chooser.setSelectedFile(new File("burpmax_session.json"));
        if (chooser.showOpenDialog(panel) != JFileChooser.APPROVE_OPTION) return;
        String path = chooser.getSelectedFile().getAbsolutePath();

        // If findings already exist, ask whether to replace or merge
        boolean hasExisting = store.size() > 0;
        final boolean[] doReplace = {false};
        if (hasExisting) {
            // Hand-built JDialog for the same reason as the resume dialog above:
            // JOptionPane does not reliably render HTML in Burp's L&F.
            final int[] loadChoice = {2};  // default = Cancel
            Window loadOwner = SwingUtilities.getWindowAncestor(panel);
            JDialog loadDlg = (loadOwner instanceof Frame)
                    ? new JDialog((Frame) loadOwner, "Load Session", true)
                    : new JDialog((Dialog) loadOwner, "Load Session", true);

            JEditorPane loadMsgPane = new JEditorPane();
            loadMsgPane.setContentType("text/html");
            loadMsgPane.setText(
                "<html><body style=\"font-family:Dialog,Arial,sans-serif;font-size:12px\"><p>"
                + "You have <b>" + store.size() + "</b> existing finding(s).<br><br>"
                + "<b>Replace</b> - clear current findings and load from file.<br>"
                + "<b>Merge</b> - add new findings from file, keep existing ones."
                + "</p></body></html>");
            loadMsgPane.setEditable(false);
            loadMsgPane.setOpaque(false);
            loadMsgPane.setBorder(BorderFactory.createEmptyBorder(4, 4, 12, 4));
            loadMsgPane.setPreferredSize(new Dimension(420, 80));

            JLabel loadIconLbl = new JLabel(UIManager.getIcon("OptionPane.questionIcon"));
            loadIconLbl.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 12));

            JPanel loadMsgPanel = new JPanel(new BorderLayout());
            loadMsgPanel.setBorder(BorderFactory.createEmptyBorder(12, 12, 4, 12));
            loadMsgPanel.add(loadIconLbl, BorderLayout.WEST);
            loadMsgPanel.add(loadMsgPane, BorderLayout.CENTER);

            JButton btnReplace = new JButton("Replace existing findings");
            JButton btnMerge   = new JButton("Merge with existing");
            JButton btnLoadCancel = new JButton("Cancel");
            btnReplace   .addActionListener(e -> { loadChoice[0] = 0; loadDlg.dispose(); });
            btnMerge     .addActionListener(e -> { loadChoice[0] = 1; loadDlg.dispose(); });
            btnLoadCancel.addActionListener(e -> { loadChoice[0] = 2; loadDlg.dispose(); });
            loadDlg.getRootPane().registerKeyboardAction(
                e -> { loadChoice[0] = 2; loadDlg.dispose(); },
                KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_ESCAPE, 0),
                JComponent.WHEN_IN_FOCUSED_WINDOW);
            loadDlg.getRootPane().setDefaultButton(btnMerge);

            JPanel loadBtnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 8));
            loadBtnPanel.setBorder(BorderFactory.createEmptyBorder(0, 12, 4, 12));
            loadBtnPanel.add(btnReplace);
            loadBtnPanel.add(btnMerge);
            loadBtnPanel.add(btnLoadCancel);

            loadDlg.setLayout(new BorderLayout());
            loadDlg.add(loadMsgPanel, BorderLayout.CENTER);
            loadDlg.add(loadBtnPanel, BorderLayout.SOUTH);
            loadDlg.pack();
            loadDlg.setLocationRelativeTo(panel);
            loadDlg.setVisible(true);  // blocks until disposed

            int choice = loadChoice[0];
            if (choice == 2) return;  // Cancel or ESC
            doReplace[0] = (choice == 0);
        }

        if (doReplace[0]) store.clear();

        session.loadAsync(path,
            (restored, skipped) -> {
                String msg = (doReplace[0] ? "Replaced: " : "Merged: ")
                        + "restored " + restored + " findings.";
                if (skipped > 0) msg += " (" + skipped + " skipped - duplicate or malformed)";
                JOptionPane.showMessageDialog(panel, msg, "Session Loaded",
                        JOptionPane.INFORMATION_MESSAGE);
            },
            err -> JOptionPane.showMessageDialog(panel, "Load failed: " + err, "Error",
                        JOptionPane.ERROR_MESSAGE));
    }

    private void toggleActiveScan() {
        if (activeScanner != null && activeScanner.isRunning()) {
            // Cancel running scan
            activeScanner.cancel();
            activeScanBtn.setText("⚡ Active Scan");
            activeScanBtn.setBackground(new Color(0x6B, 0x21, 0xA8));
            activeScanProgress.setIndeterminate(false);
            activeScanProgress.setVisible(false);
            activeScanProgress.setValue(0);
            return;
        }

        // ── Check for interrupted checkpoint and offer resume ─────────────────
        final boolean[] doResume = {false};
        com.burpmax.active.ScanCheckpoint existing =
                com.burpmax.active.ScanCheckpoint.load(callbacks);
        if (existing != null && existing.hasPending()) {
            // Build a JDialog directly instead of using JOptionPane.
            // JOptionPane does not reliably render HTML in its message area across
            // all Swing look-and-feels (including the one Burp Suite uses): passing
            // a JLabel as the message object works in standard Java L&Fs but Burp's
            // custom L&F can bypass the component and convert it back to a string,
            // showing raw HTML tags. A hand-built JDialog owns its own layout and
            // always renders the JLabel correctly.
            final int[] resumeChoice = {2};  // default = Cancel
            Window owner = SwingUtilities.getWindowAncestor(panel);
            JDialog resumeDlg = (owner instanceof Frame)
                    ? new JDialog((Frame) owner, "", true)
                    : new JDialog((Dialog) owner, "", true);
            resumeDlg.setUndecorated(true);
            resumeDlg.setResizable(false);

            // ── Root panel: dark surface with border ──────────────────────────
            JPanel resumeRoot = new JPanel(new BorderLayout());
            resumeRoot.setBackground(C_SURFACE);
            resumeRoot.setBorder(BorderFactory.createLineBorder(C_BORDER, 1));

            // ── Title band: dark header bar matching BurpMax toolbar ──────────
            JPanel titleBand = new JPanel(new BorderLayout());
            titleBand.setBackground(C_HEADER_BG);
            titleBand.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, C_BORDER),
                BorderFactory.createEmptyBorder(10, 16, 10, 12)));

            // Lightning icon + title text (same orange as the Active Scan button icon)
            JLabel titleLbl = new JLabel("\u26a1  Resume interrupted scan?");
            titleLbl.setFont(FONT_UI_B);
            titleLbl.setForeground(C_TEXT_HEAD);
            titleBand.add(titleLbl, BorderLayout.WEST);

            // ESC / X close button in title bar
            JButton closeX = new JButton("\u2715");
            closeX.setFont(new Font("Arial", Font.PLAIN, 11));
            closeX.setForeground(C_TEXT_MUTED);
            closeX.setBackground(C_HEADER_BG);
            closeX.setBorder(BorderFactory.createEmptyBorder(2, 8, 2, 4));
            closeX.setFocusPainted(false);
            closeX.setContentAreaFilled(false);
            closeX.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            closeX.addActionListener(e -> { resumeChoice[0] = 2; resumeDlg.dispose(); });
            titleBand.add(closeX, BorderLayout.EAST);

            // ── Body: checkpoint stats + message ─────────────────────────────
            JPanel resumeBody = new JPanel();
            resumeBody.setLayout(new BoxLayout(resumeBody, BoxLayout.Y_AXIS));
            resumeBody.setBackground(C_SURFACE);
            resumeBody.setBorder(BorderFactory.createEmptyBorder(20, 20, 16, 20));
            // Minimum width ensures the dialog never packs narrower than the content
            resumeBody.setMinimumSize(new Dimension(560, 0));

            // Stat pill row: "138 remaining  |  0 total  |  100% done"
            int pending  = existing.pendingUrls.size();
            int total    = existing.totalTargets;
            int pct      = existing.percentComplete();

            JPanel statRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
            statRow.setBackground(C_SURFACE);
            statRow.setAlignmentX(Component.LEFT_ALIGNMENT);

            // Helper: build a small coloured stat pill
            for (Object[] pill : new Object[][]{
                { pending + " remaining",  new Color(0x1E,0x3A,0x5F), new Color(0x60,0xA5,0xFA) },
                { total  + " total",       new Color(0x1B,0x2E,0x1B), new Color(0x6E,0xE7,0xB7) },
                { pct    + "% done",       new Color(0x3D,0x2E,0x05), new Color(0xFB,0xBF,0x24) }
            }) {
                JLabel lbl = new JLabel(" " + pill[0] + " ");
                lbl.setFont(FONT_UI_B);
                lbl.setForeground((Color) pill[2]);
                lbl.setBackground((Color) pill[1]);
                lbl.setOpaque(true);
                lbl.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createLineBorder(((Color) pill[2]).darker(), 1),
                    BorderFactory.createEmptyBorder(3, 6, 3, 6)));
                statRow.add(lbl);
            }
            resumeBody.add(statRow);
            resumeBody.add(Box.createVerticalStrut(14));

            // Divider line
            JSeparator sep = new JSeparator(JSeparator.HORIZONTAL);
            sep.setForeground(C_BORDER);
            sep.setBackground(C_BORDER);
            sep.setMaximumSize(new Dimension(Integer.MAX_VALUE, 1));
            sep.setAlignmentX(Component.LEFT_ALIGNMENT);
            resumeBody.add(sep);
            resumeBody.add(Box.createVerticalStrut(14));

            // Message text via JEditorPane (guaranteed HTML rendering in all L&Fs)
            JEditorPane msgPane = new JEditorPane();
            msgPane.setContentType("text/html");
            msgPane.setText(
                "<html><body style=\"font-family:Arial,sans-serif;font-size:12px;"
                + "color:#E2E8F0;background:transparent;margin:0;padding:0\">"
                + "An interrupted scan checkpoint was found.<br>"
                + "Choose <b style=\"color:#93C5FD\">Resume scan</b> to continue from where it left off,"
                + " or <b style=\"color:#6EE7B7\">Start fresh</b> to begin a new scan."
                + "</body></html>");
            msgPane.setEditable(false);
            msgPane.setOpaque(false);
            msgPane.setBackground(C_SURFACE);
            msgPane.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));
            // Wide enough for two full lines at 12px; height 56 gives clear two-line breathing room
            msgPane.setPreferredSize(new Dimension(520, 56));
            msgPane.setMaximumSize(new Dimension(Integer.MAX_VALUE, 80));
            msgPane.setAlignmentX(Component.LEFT_ALIGNMENT);
            resumeBody.add(msgPane);

            // ── Footer: button row ────────────────────────────────────────────
            JPanel resumeFooter = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 12));
            resumeFooter.setBackground(C_SURFACE);
            resumeFooter.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, C_BORDER),
                BorderFactory.createEmptyBorder(0, 16, 0, 16)));

            // Cancel button: ghost style
            JButton btnCancel = new JButton("Cancel");
            btnCancel.setFont(FONT_UI);
            btnCancel.setForeground(C_TEXT_MUTED);
            btnCancel.setBackground(C_SURFACE);
            btnCancel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(C_BORDER, 1),
                BorderFactory.createEmptyBorder(5, 14, 5, 14)));
            btnCancel.setFocusPainted(false);
            btnCancel.setOpaque(true);
            btnCancel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));

            // Start fresh button: teal/green ghost style
            JButton btnFresh = new JButton("Start fresh");
            btnFresh.setFont(FONT_UI);
            btnFresh.setForeground(new Color(0x6E, 0xE7, 0xB7));
            btnFresh.setBackground(new Color(0x1B, 0x2E, 0x1B));
            btnFresh.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(0x34, 0x7A, 0x50), 1),
                BorderFactory.createEmptyBorder(5, 14, 5, 14)));
            btnFresh.setFocusPainted(false);
            btnFresh.setOpaque(true);
            btnFresh.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));

            // Resume scan button: primary blue/purple style (matches Start scan button)
            JButton btnResume = new JButton("Resume scan");
            btnResume.setFont(FONT_UI_B);
            btnResume.setForeground(Color.WHITE);
            btnResume.setBackground(new Color(0x6B, 0x21, 0xA8));
            btnResume.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(0x7C, 0x3A, 0xED), 1),
                BorderFactory.createEmptyBorder(5, 14, 5, 14)));
            btnResume.setFocusPainted(false);
            btnResume.setOpaque(true);
            btnResume.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));

            btnCancel.addActionListener(e -> { resumeChoice[0] = 2; resumeDlg.dispose(); });
            btnFresh .addActionListener(e -> { resumeChoice[0] = 1; resumeDlg.dispose(); });
            btnResume.addActionListener(e -> { resumeChoice[0] = 0; resumeDlg.dispose(); });

            resumeFooter.add(btnCancel);
            resumeFooter.add(btnFresh);
            resumeFooter.add(btnResume);

            // ESC closes as Cancel
            resumeDlg.getRootPane().registerKeyboardAction(
                e -> { resumeChoice[0] = 2; resumeDlg.dispose(); },
                KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_ESCAPE, 0),
                JComponent.WHEN_IN_FOCUSED_WINDOW);
            resumeDlg.getRootPane().setDefaultButton(btnResume);

            resumeRoot.add(titleBand,    BorderLayout.NORTH);
            resumeRoot.add(resumeBody,   BorderLayout.CENTER);
            resumeRoot.add(resumeFooter, BorderLayout.SOUTH);

            resumeDlg.setContentPane(resumeRoot);
            resumeDlg.pack();
            // Enforce a minimum width so the title, pills and message text are never clipped.
            // pack() picks the tightest fit which can be too narrow on some L&Fs.
            int dlgW = Math.max(resumeDlg.getWidth(), 600);
            int dlgH = resumeDlg.getHeight();
            resumeDlg.setSize(dlgW, dlgH);
            resumeDlg.setMinimumSize(new Dimension(dlgW, dlgH));
            resumeDlg.setLocationRelativeTo(panel);
            resumeDlg.setVisible(true);  // blocks until disposed

            if (resumeChoice[0] == 2) return;  // Cancel or ESC
            doResume[0] = (resumeChoice[0] == 0);
        }

        // ── Option C dialog — minimal clean design ───────────────────────────────
        int currentDelay = activeScanner != null ? activeScanner.getRequestDelayMs() : 150;

        // Mutable result holder so lambda can write confirmed values
        final int[] resultDelay   = {currentDelay};
        final boolean[] resultOob = {false};
        final int[] resultOobIdx  = {0};
        final int[] resultPollSec = {30};
        final String[] resultOobUrl = {"https://oast.pro"};
        final boolean[] confirmed   = {false};
        // Auth result holders
        final boolean[] resultAuthEnabled = {false};
        final int[]     resultAuthMode    = {0};   // 0=static, 1=login
        final String[]  resultAuthHeader  = {"Authorization"};
        final String[]  resultAuthToken   = {""};
        final String[]  resultAuthRegex   = {""};
        final String[]  resultLoginReq    = {""};
        final String[]  resultHealthUrl   = {""};
        // Scan policy: probes the user has explicitly disabled.
        // AtomicReference used as a mutable final container so the lambda closures
        // below can both read and replace the set without a raw-type array.
        final java.util.concurrent.atomic.AtomicReference<java.util.Set<String>> resultSkipProbes =
            new java.util.concurrent.atomic.AtomicReference<>(
                activeScanner != null ? new java.util.HashSet<>(activeScanner.getSkipProbes())
                                      : new java.util.HashSet<>());

        // ── Dialog shell ─────────────────────────────────────────────────────
        java.awt.Window owner = SwingUtilities.getWindowAncestor(panel);
        javax.swing.JDialog dlg = (owner instanceof java.awt.Frame)
            ? new javax.swing.JDialog((java.awt.Frame) owner, "Active Scan", true)
            : new javax.swing.JDialog((java.awt.Dialog) owner, "Active Scan", true);
        dlg.setUndecorated(false);
        dlg.setResizable(false);

        // ── Root panel ───────────────────────────────────────────────────────
        javax.swing.JPanel root = new javax.swing.JPanel();
        root.setLayout(new java.awt.BorderLayout());
        root.setBackground(C_SURFACE);
        root.setBorder(BorderFactory.createLineBorder(C_BORDER, 1));

        // ── Body panel (padded) ───────────────────────────────────────────────
        javax.swing.JPanel body = new javax.swing.JPanel();
        body.setLayout(new javax.swing.BoxLayout(body, javax.swing.BoxLayout.Y_AXIS));
        body.setBackground(C_SURFACE);
        body.setBorder(BorderFactory.createEmptyBorder(20, 20, 16, 20));

        // ── Permission badge (amber pill) ─────────────────────────────────────
        javax.swing.JLabel badge = new javax.swing.JLabel("  ⚠  Permission required");
        badge.setFont(new java.awt.Font("Arial", java.awt.Font.BOLD, 10));
        badge.setForeground(new Color(0xFB, 0xBF, 0x24));          // amber-400
        badge.setBackground(new Color(0x3D, 0x2E, 0x05));          // amber-900 dark
        badge.setOpaque(true);
        badge.setBorder(BorderFactory.createEmptyBorder(3, 8, 3, 8));
        badge.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);

        // ── Title ─────────────────────────────────────────────────────────────
        javax.swing.JLabel title = new javax.swing.JLabel("Start active scan?");
        title.setFont(new java.awt.Font("Arial", java.awt.Font.BOLD, 14));
        title.setForeground(C_TEXT_HEAD);
        title.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);

        // ── Description ───────────────────────────────────────────────────────
        javax.swing.JTextPane desc = new javax.swing.JTextPane();
        desc.setContentType("text/html");
        desc.setText("<html><body style='font-family:Arial;font-size:11pt;margin:0;padding:0'>"
            + "Sends probe requests to every in-scope endpoint.<br>"
            + "Only run against targets you have explicit permission to test."
            + "</body></html>");
        desc.setEditable(false);
        desc.setOpaque(false);
        desc.setForeground(C_TEXT_MUTED);
        desc.setBackground(C_SURFACE);
        desc.setBorder(null);
        desc.setPreferredSize(new Dimension(440, 42));
        desc.setMaximumSize(new Dimension(440, 42));
        desc.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);

        // ── Thin divider ─────────────────────────────────────────────────────
        javax.swing.JSeparator sep1 = new javax.swing.JSeparator();
        sep1.setForeground(C_BORDER);
        sep1.setBackground(C_SURFACE);
        sep1.setMaximumSize(new Dimension(Integer.MAX_VALUE, 1));
        sep1.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);

        // ── Delay row ────────────────────────────────────────────────────────
        javax.swing.JLabel delayRowLbl = new javax.swing.JLabel("Delay");
        delayRowLbl.setFont(FONT_SMALL);
        delayRowLbl.setForeground(C_TEXT_MUTED);
        delayRowLbl.setPreferredSize(new Dimension(48, 20));

        javax.swing.JSlider delaySlider = new javax.swing.JSlider(0, 1000, currentDelay);
        delaySlider.setBackground(C_SURFACE);
        delaySlider.setPaintTicks(false);
        delaySlider.setPaintLabels(false);
        delaySlider.setBorder(null);

        javax.swing.JLabel delayVal = new javax.swing.JLabel(currentDelay + " ms");
        delayVal.setFont(new java.awt.Font("Arial", java.awt.Font.BOLD, 11));
        delayVal.setForeground(C_TEXT);
        delayVal.setPreferredSize(new Dimension(46, 20));
        delayVal.setHorizontalAlignment(javax.swing.SwingConstants.RIGHT);
        delaySlider.addChangeListener(e -> {
            int v = delaySlider.getValue();
            delayVal.setText(v + " ms");
            resultDelay[0] = v;
        });

        javax.swing.JPanel delayRow = new javax.swing.JPanel(new java.awt.BorderLayout(8, 0));
        delayRow.setBackground(C_SURFACE);
        delayRow.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);
        delayRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 28));
        delayRow.add(delayRowLbl, java.awt.BorderLayout.WEST);
        delayRow.add(delaySlider, java.awt.BorderLayout.CENTER);
        delayRow.add(delayVal,   java.awt.BorderLayout.EAST);

        // ── OOB toggle row ────────────────────────────────────────────────────
        // Icon box
        javax.swing.JLabel oobIcon = new javax.swing.JLabel("◉");   // filled circle = radar-like
        oobIcon.setFont(new java.awt.Font("Arial", java.awt.Font.BOLD, 14));
        oobIcon.setForeground(new Color(0x60, 0xA5, 0xFA));               // blue-400
        oobIcon.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        oobIcon.setPreferredSize(new Dimension(28, 28));

        // Text block
        javax.swing.JPanel oobTextBlock = new javax.swing.JPanel();
        oobTextBlock.setLayout(new javax.swing.BoxLayout(oobTextBlock, javax.swing.BoxLayout.Y_AXIS));
        oobTextBlock.setBackground(new Color(0x12, 0x20, 0x38));          // slightly lighter card
        javax.swing.JLabel oobMainLbl = new javax.swing.JLabel("OOB detection");
        oobMainLbl.setFont(FONT_UI_B);
        oobMainLbl.setForeground(C_TEXT);
        javax.swing.JLabel oobSubLbl  = new javax.swing.JLabel("SSRF · XXE · Log4Shell · blind vulns");
        oobSubLbl.setFont(FONT_SMALL);
        oobSubLbl.setForeground(C_TEXT_MUTED);
        oobTextBlock.add(oobMainLbl);
        oobTextBlock.add(oobSubLbl);

        // Toggle switch (custom painted)
        final boolean[] oobOn = {false};
        final Color COL_TRACK_OFF = new Color(0x28, 0x3C, 0x5A);
        final Color COL_TRACK_ON  = new Color(0x6B, 0x21, 0xA8);
        final Color COL_THUMB     = Color.WHITE;
        javax.swing.JToggleButton oobToggle = new javax.swing.JToggleButton() {
            @Override protected void paintComponent(java.awt.Graphics g0) {
                java.awt.Graphics2D g2 = (java.awt.Graphics2D) g0;
                g2.setRenderingHint(java.awt.RenderingHints.KEY_ANTIALIASING,
                                    java.awt.RenderingHints.VALUE_ANTIALIAS_ON);
                int w = getWidth(), h = getHeight();
                g2.setColor(isSelected() ? COL_TRACK_ON : COL_TRACK_OFF);
                g2.fillRoundRect(0, 0, w, h, h, h);
                int tx = isSelected() ? w - h + 3 : 3;
                g2.setColor(COL_THUMB);
                g2.fillOval(tx, 3, h - 6, h - 6);
            }
        };
        oobToggle.setPreferredSize(new Dimension(40, 22));
        oobToggle.setMinimumSize(new Dimension(40, 22));
        oobToggle.setMaximumSize(new Dimension(40, 22));
        oobToggle.setBorder(null);
        oobToggle.setFocusPainted(false);
        oobToggle.setContentAreaFilled(false);
        oobToggle.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));

        javax.swing.JPanel oobToggleRow = new javax.swing.JPanel(new java.awt.BorderLayout(8, 0));
        oobToggleRow.setBackground(new Color(0x12, 0x20, 0x38));
        oobToggleRow.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(0x1E, 0x35, 0x58), 1),
            BorderFactory.createEmptyBorder(8, 10, 8, 10)));
        oobToggleRow.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);
        oobToggleRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 52));
        oobToggleRow.add(oobIcon,      java.awt.BorderLayout.WEST);
        oobToggleRow.add(oobTextBlock, java.awt.BorderLayout.CENTER);
        oobToggleRow.add(oobToggle,    java.awt.BorderLayout.EAST);

        // ── OOB backend row (revealed when toggle ON) ─────────────────────────
        String[] oobBackends = {"interactsh (oast.pro - public)", "interactsh (self-hosted)", "Burp Collaborator (Pro only)"};
        javax.swing.JComboBox<String> oobBackendBox = new javax.swing.JComboBox<>(oobBackends);
        oobBackendBox.setBackground(new Color(0x12, 0x20, 0x38));
        oobBackendBox.setForeground(C_TEXT);
        oobBackendBox.setFont(FONT_SMALL);

        javax.swing.JLabel oobPollLbl = new javax.swing.JLabel("Poll wait");
        oobPollLbl.setFont(FONT_SMALL);
        oobPollLbl.setForeground(C_TEXT_MUTED);
        oobPollLbl.setPreferredSize(new Dimension(56, 20));

        javax.swing.JSlider oobPollSlider = new javax.swing.JSlider(5, 120, 30);
        oobPollSlider.setBackground(C_SURFACE);
        oobPollSlider.setPaintTicks(false);
        oobPollSlider.setPaintLabels(false);
        oobPollSlider.setBorder(null);

        javax.swing.JLabel oobPollVal = new javax.swing.JLabel("30s");
        oobPollVal.setFont(new java.awt.Font("Arial", java.awt.Font.BOLD, 11));
        oobPollVal.setForeground(C_TEXT);
        oobPollVal.setPreferredSize(new Dimension(30, 20));
        oobPollVal.setHorizontalAlignment(javax.swing.SwingConstants.RIGHT);
        oobPollSlider.addChangeListener(e -> {
            oobPollVal.setText(oobPollSlider.getValue() + "s");
            resultPollSec[0] = oobPollSlider.getValue();
        });

        javax.swing.JTextField oobServerField = new javax.swing.JTextField("https://oast.pro");
        oobServerField.setBackground(new Color(0x0B, 0x16, 0x28));
        oobServerField.setForeground(C_TEXT_DIM);
        oobServerField.setFont(FONT_MONO);
        oobServerField.setCaretColor(C_TEXT);
        oobServerField.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(C_BORDER, 1),
            BorderFactory.createEmptyBorder(3, 6, 3, 6)));

        javax.swing.JPanel oobPollRow = new javax.swing.JPanel(new java.awt.BorderLayout(8, 0));
        oobPollRow.setBackground(C_SURFACE);
        oobPollRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 24));
        oobPollRow.add(oobPollLbl,    java.awt.BorderLayout.WEST);
        oobPollRow.add(oobPollSlider, java.awt.BorderLayout.CENTER);
        oobPollRow.add(oobPollVal,    java.awt.BorderLayout.EAST);

        javax.swing.JPanel oobDetailPanel = new javax.swing.JPanel();
        oobDetailPanel.setLayout(new javax.swing.BoxLayout(oobDetailPanel, javax.swing.BoxLayout.Y_AXIS));
        oobDetailPanel.setBackground(C_SURFACE);
        oobDetailPanel.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);
        oobDetailPanel.add(oobBackendBox);
        oobDetailPanel.add(Box.createVerticalStrut(4));
        oobDetailPanel.add(oobServerField);
        oobDetailPanel.add(Box.createVerticalStrut(6));
        oobDetailPanel.add(oobPollRow);
        oobDetailPanel.setVisible(false);

        // OOB server row visibility
        oobBackendBox.addActionListener(ev -> {
            boolean selfHosted = oobBackendBox.getSelectedIndex() == 1;
            oobServerField.setVisible(selfHosted);
            oobDetailPanel.revalidate();
            dlg.pack();
        });
        oobServerField.setVisible(false);

        // Toggle wiring
        oobToggle.addActionListener(ev -> {
            boolean on = oobToggle.isSelected();
            oobOn[0] = on;
            resultOob[0] = on;
            oobDetailPanel.setVisible(on);
            dlg.pack();
        });

        // ── Assemble body ─────────────────────────────────────────────────────
        body.add(badge);
        body.add(Box.createVerticalStrut(10));
        body.add(title);
        body.add(Box.createVerticalStrut(5));
        body.add(desc);
        body.add(Box.createVerticalStrut(14));
        body.add(sep1);
        body.add(Box.createVerticalStrut(12));
        body.add(delayRow);
        body.add(Box.createVerticalStrut(12));
        body.add(oobToggleRow);
        body.add(Box.createVerticalStrut(6));
        body.add(oobDetailPanel);

        // ── Auth section ──────────────────────────────────────────────────────
        // Separator
        javax.swing.JSeparator sep2 = new javax.swing.JSeparator();
        sep2.setForeground(C_BORDER);
        sep2.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);
        sep2.setMaximumSize(new java.awt.Dimension(Integer.MAX_VALUE, 1));

        // Toggle row
        javax.swing.JCheckBox authToggle = new javax.swing.JCheckBox("Authenticated scan");
        authToggle.setFont(FONT_UI_B);
        authToggle.setForeground(C_TEXT_HEAD);
        authToggle.setBackground(C_SURFACE);
        authToggle.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);

        javax.swing.JPanel authToggleRow = new javax.swing.JPanel(new java.awt.BorderLayout());
        authToggleRow.setBackground(C_SURFACE);
        authToggleRow.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);
        authToggleRow.setMaximumSize(new java.awt.Dimension(Integer.MAX_VALUE, 24));
        authToggleRow.add(authToggle, java.awt.BorderLayout.WEST);

        // Detail panel (hidden until toggle is on)
        javax.swing.JPanel authDetailPanel = new javax.swing.JPanel();
        authDetailPanel.setLayout(new javax.swing.BoxLayout(authDetailPanel, javax.swing.BoxLayout.Y_AXIS));
        authDetailPanel.setBackground(C_SURFACE);
        authDetailPanel.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);

        // Mode selector
        String[] authModes = {"Static token / cookie", "Login sequence (replay request)"};
        javax.swing.JComboBox<String> authModeBox = new javax.swing.JComboBox<>(authModes);
        authModeBox.setFont(FONT_UI);
        authModeBox.setBackground(C_HEADER_BG);
        authModeBox.setForeground(C_TEXT_HEAD);
        authModeBox.setMaximumSize(new java.awt.Dimension(Integer.MAX_VALUE, 26));
        authModeBox.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);

        // Header name row
        javax.swing.JLabel headerLbl = new javax.swing.JLabel("Header name:");
        headerLbl.setFont(FONT_TINY);
        headerLbl.setForeground(C_TEXT_MUTED);
        javax.swing.JTextField headerField = new javax.swing.JTextField("Authorization");
        headerField.setFont(FONT_MONO);
        headerField.setBackground(C_HEADER_BG);
        headerField.setForeground(C_TEXT_HEAD);
        headerField.setCaretColor(C_TEXT_HEAD);
        headerField.setMaximumSize(new java.awt.Dimension(Integer.MAX_VALUE, 26));
        headerField.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(C_BORDER, 1),
            BorderFactory.createEmptyBorder(2, 6, 2, 6)));
        javax.swing.JPanel headerRow = new javax.swing.JPanel(new java.awt.BorderLayout(6, 0));
        headerRow.setBackground(C_SURFACE);
        headerRow.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);
        headerRow.setMaximumSize(new java.awt.Dimension(Integer.MAX_VALUE, 26));
        headerRow.add(headerLbl, java.awt.BorderLayout.WEST);
        headerRow.add(headerField, java.awt.BorderLayout.CENTER);

        // Static token value field
        javax.swing.JLabel tokenLbl = new javax.swing.JLabel("Token value:");
        tokenLbl.setFont(FONT_TINY);
        tokenLbl.setForeground(C_TEXT_MUTED);
        javax.swing.JTextField tokenField = new javax.swing.JTextField("Bearer <token>");
        tokenField.setFont(FONT_MONO);
        tokenField.setBackground(C_HEADER_BG);
        tokenField.setForeground(C_TEXT_HEAD);
        tokenField.setCaretColor(C_TEXT_HEAD);
        tokenField.setMaximumSize(new java.awt.Dimension(Integer.MAX_VALUE, 26));
        tokenField.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(C_BORDER, 1),
            BorderFactory.createEmptyBorder(2, 6, 2, 6)));
        javax.swing.JPanel tokenRow = new javax.swing.JPanel(new java.awt.BorderLayout(6, 0));
        tokenRow.setBackground(C_SURFACE);
        tokenRow.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);
        tokenRow.setMaximumSize(new java.awt.Dimension(Integer.MAX_VALUE, 26));
        tokenRow.add(tokenLbl, java.awt.BorderLayout.WEST);
        tokenRow.add(tokenField, java.awt.BorderLayout.CENTER);

        // Login token regex field (LOGIN mode)
        javax.swing.JLabel regexLbl = new javax.swing.JLabel("Token regex (group 1):");
        regexLbl.setFont(FONT_TINY);
        regexLbl.setForeground(C_TEXT_MUTED);
        javax.swing.JTextField regexField = new javax.swing.JTextField("\"token\"\\s*:\\s*\"([^\"]+)\"");
        regexField.setFont(FONT_MONO);
        regexField.setBackground(C_HEADER_BG);
        regexField.setForeground(C_TEXT_HEAD);
        regexField.setCaretColor(C_TEXT_HEAD);
        regexField.setMaximumSize(new java.awt.Dimension(Integer.MAX_VALUE, 26));
        regexField.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(C_BORDER, 1),
            BorderFactory.createEmptyBorder(2, 6, 2, 6)));
        javax.swing.JPanel regexRow = new javax.swing.JPanel(new java.awt.BorderLayout(6, 0));
        regexRow.setBackground(C_SURFACE);
        regexRow.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);
        regexRow.setMaximumSize(new java.awt.Dimension(Integer.MAX_VALUE, 26));
        regexRow.add(regexLbl, java.awt.BorderLayout.WEST);
        regexRow.add(regexField, java.awt.BorderLayout.CENTER);

        // Login request paste area (LOGIN mode)
        javax.swing.JLabel loginReqLbl = new javax.swing.JLabel("Login request (paste raw HTTP):");
        loginReqLbl.setFont(FONT_TINY);
        loginReqLbl.setForeground(C_TEXT_MUTED);
        loginReqLbl.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);
        javax.swing.JTextArea loginReqArea = new javax.swing.JTextArea(5, 40);
        loginReqArea.setFont(new java.awt.Font("Monospaced", java.awt.Font.PLAIN, 10));
        loginReqArea.setBackground(C_HEADER_BG);
        loginReqArea.setForeground(C_TEXT_HEAD);
        loginReqArea.setCaretColor(C_TEXT_HEAD);
        loginReqArea.setLineWrap(true);
        loginReqArea.setBorder(BorderFactory.createLineBorder(C_BORDER, 1));
        javax.swing.JScrollPane loginReqScroll = new javax.swing.JScrollPane(loginReqArea);
        loginReqScroll.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);
        loginReqScroll.setMaximumSize(new java.awt.Dimension(Integer.MAX_VALUE, 100));
        loginReqScroll.setBorder(null);

        // Health check URL field
        javax.swing.JLabel healthLbl = new javax.swing.JLabel("Health check URL (optional):");
        healthLbl.setFont(FONT_TINY);
        healthLbl.setForeground(C_TEXT_MUTED);
        javax.swing.JTextField healthField = new javax.swing.JTextField();
        healthField.setFont(FONT_MONO);
        healthField.setBackground(C_HEADER_BG);
        healthField.setForeground(C_TEXT_HEAD);
        healthField.setCaretColor(C_TEXT_HEAD);
        healthField.setMaximumSize(new java.awt.Dimension(Integer.MAX_VALUE, 26));
        healthField.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(C_BORDER, 1),
            BorderFactory.createEmptyBorder(2, 6, 2, 6)));
        healthField.setToolTipText("URL that returns 200 when the session is live. " +
                "Polled every 60s; 401/403 triggers re-auth.");
        javax.swing.JPanel healthRow = new javax.swing.JPanel(new java.awt.BorderLayout(6, 0));
        healthRow.setBackground(C_SURFACE);
        healthRow.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);
        healthRow.setMaximumSize(new java.awt.Dimension(Integer.MAX_VALUE, 26));
        healthRow.add(healthLbl, java.awt.BorderLayout.WEST);
        healthRow.add(healthField, java.awt.BorderLayout.CENTER);

        // Show/hide fields based on mode
        Runnable updateAuthMode = () -> {
            boolean isLoginMode = authModeBox.getSelectedIndex() == 1;
            tokenRow.setVisible(!isLoginMode);
            regexRow.setVisible(isLoginMode);
            loginReqLbl.setVisible(isLoginMode);
            loginReqScroll.setVisible(isLoginMode);
        };
        authModeBox.addActionListener(ev -> updateAuthMode.run());
        updateAuthMode.run();  // set initial state

        authDetailPanel.add(Box.createVerticalStrut(6));
        authDetailPanel.add(authModeBox);
        authDetailPanel.add(Box.createVerticalStrut(6));
        authDetailPanel.add(headerRow);
        authDetailPanel.add(Box.createVerticalStrut(4));
        authDetailPanel.add(tokenRow);
        authDetailPanel.add(regexRow);
        authDetailPanel.add(Box.createVerticalStrut(4));
        authDetailPanel.add(loginReqLbl);
        authDetailPanel.add(Box.createVerticalStrut(2));
        authDetailPanel.add(loginReqScroll);
        authDetailPanel.add(Box.createVerticalStrut(6));
        authDetailPanel.add(healthRow);
        authDetailPanel.setVisible(false);

        authToggle.addActionListener(ev -> {
            boolean on = authToggle.isSelected();
            authDetailPanel.setVisible(on);
            dlg.pack();
            dlg.setLocationRelativeTo(panel);
        });

        body.add(Box.createVerticalStrut(12));
        body.add(sep2);
        body.add(Box.createVerticalStrut(12));
        body.add(authToggleRow);
        body.add(Box.createVerticalStrut(4));
        body.add(authDetailPanel);

        // ── Scan policy section ───────────────────────────────────────────────
        javax.swing.JSeparator sep3 = new javax.swing.JSeparator();
        sep3.setForeground(C_BORDER);
        sep3.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);
        sep3.setMaximumSize(new java.awt.Dimension(Integer.MAX_VALUE, 1));

        javax.swing.JCheckBox policyToggle = new javax.swing.JCheckBox("Scan policy (disable probes)");
        policyToggle.setFont(FONT_UI_B);
        policyToggle.setForeground(C_TEXT_HEAD);
        policyToggle.setBackground(C_SURFACE);
        policyToggle.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);

        javax.swing.JPanel policyToggleRow = new javax.swing.JPanel(new java.awt.BorderLayout());
        policyToggleRow.setBackground(C_SURFACE);
        policyToggleRow.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);
        policyToggleRow.setMaximumSize(new java.awt.Dimension(Integer.MAX_VALUE, 24));
        policyToggleRow.add(policyToggle, java.awt.BorderLayout.WEST);

        javax.swing.JPanel policyDetailPanel = new javax.swing.JPanel();
        policyDetailPanel.setLayout(new java.awt.GridLayout(0, 3, 4, 2));
        policyDetailPanel.setBackground(C_SURFACE);
        policyDetailPanel.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);

        // All probe names that can be selectively disabled
        String[] probeNames = com.burpmax.active.ActiveScanner.ALL_PROBE_NAMES
                .stream().sorted().toArray(String[]::new);
        java.util.Map<String, javax.swing.JCheckBox> probeCbs = new java.util.LinkedHashMap<>();
        for (String name : probeNames) {
            javax.swing.JCheckBox cb = new javax.swing.JCheckBox(name);
            cb.setFont(FONT_TINY);
            cb.setForeground(C_TEXT_HEAD);
            cb.setBackground(C_SURFACE);
            // Restore previously selected skips from last scan
            cb.setSelected(resultSkipProbes.get().contains(name));
            policyDetailPanel.add(cb);
            probeCbs.put(name, cb);
        }
        policyDetailPanel.setVisible(false);

        policyToggle.addActionListener(ev -> {
            policyDetailPanel.setVisible(policyToggle.isSelected());
            dlg.pack();
            dlg.setLocationRelativeTo(panel);
        });

        body.add(Box.createVerticalStrut(12));
        body.add(sep3);
        body.add(Box.createVerticalStrut(8));
        body.add(policyToggleRow);
        body.add(Box.createVerticalStrut(4));
        body.add(policyDetailPanel);

        // ── Footer bar ────────────────────────────────────────────────────────
        javax.swing.JPanel footer = new javax.swing.JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.RIGHT, 8, 10));
        footer.setBackground(new Color(0x0F, 0x16, 0x26));
        footer.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, C_BORDER));

        javax.swing.JButton cancelBtn = new javax.swing.JButton("Cancel");
        cancelBtn.setFont(FONT_UI);
        cancelBtn.setForeground(C_TEXT_MUTED);
        cancelBtn.setBackground(C_SURFACE);
        cancelBtn.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(C_BORDER, 1),
            BorderFactory.createEmptyBorder(5, 14, 5, 14)));
        cancelBtn.setFocusPainted(false);
        cancelBtn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        cancelBtn.addActionListener(ev -> dlg.dispose());

        javax.swing.JButton startBtn = new javax.swing.JButton("Start scan");
        startBtn.setFont(FONT_UI_B);
        startBtn.setForeground(Color.WHITE);
        startBtn.setBackground(new Color(0x6B, 0x21, 0xA8));
        startBtn.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(0x7C, 0x3A, 0xED), 1),
            BorderFactory.createEmptyBorder(5, 14, 5, 14)));
        startBtn.setFocusPainted(false);
        startBtn.setOpaque(true);
        startBtn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        startBtn.addActionListener(ev -> {
            confirmed[0] = true;
            resultDelay[0]   = delaySlider.getValue();
            resultOob[0]     = oobToggle.isSelected();
            resultOobIdx[0]  = oobBackendBox.getSelectedIndex();
            resultPollSec[0] = oobPollSlider.getValue();
            resultOobUrl[0]  = oobServerField.getText().trim();
            // Capture auth fields
            resultAuthEnabled[0] = authToggle.isSelected();
            resultAuthMode[0]    = authModeBox.getSelectedIndex();
            resultAuthHeader[0]  = headerField.getText().trim();
            resultAuthToken[0]   = tokenField.getText().trim();
            resultAuthRegex[0]   = regexField.getText().trim();
            resultLoginReq[0]    = loginReqArea.getText();  // do NOT trim - preserves required trailing CRLF
            resultHealthUrl[0]   = healthField.getText().trim();
            // Capture scan policy (disabled probes)
            java.util.Set<String> skip = new java.util.HashSet<>();
            probeCbs.forEach((name, cb) -> { if (cb.isSelected()) skip.add(name); });
            resultSkipProbes.set(skip);
            dlg.dispose();
        });

        // Enter key confirms
        dlg.getRootPane().setDefaultButton(startBtn);

        footer.add(cancelBtn);
        footer.add(startBtn);

        root.add(body,   java.awt.BorderLayout.CENTER);
        root.add(footer, java.awt.BorderLayout.SOUTH);
        dlg.setContentPane(root);
        dlg.pack();
        dlg.setMinimumSize(dlg.getSize());
        dlg.setLocationRelativeTo(panel);
        dlg.setVisible(true);   // blocks until disposed

        if (!confirmed[0]) return;

        // Map result values back to names used in the rest of the method
        final int delayMs = resultDelay[0];
        final boolean oobEnabled = resultOob[0];
        final int oobBackendIdx = resultOobIdx[0];
        final int pollDelayMs = resultPollSec[0] * 1000;
        final String oobUrl = resultOobUrl[0].isBlank() ? "https://oast.pro" : resultOobUrl[0];

        // Alias for OOB wiring below (replaces oobServerField.getText())
        javax.swing.JTextField oobServerFieldAlias = oobServerField;

        // Create and configure scanner
        IExtensionHelpers helpers;
        try {
            helpers = callbacks.getHelpers();
        } catch (Exception e) {
            JOptionPane.showMessageDialog(panel, "Could not get Burp helpers: " + e.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        activeScanner = new com.burpmax.active.ActiveScanner(callbacks, helpers, store);
        activeScanner.setRequestDelayMs(delayMs);

        // Wire OOB client if enabled
        if (oobEnabled) {
            int backend = oobBackendIdx;
            com.burpmax.active.OobClient oob = null;
            if (backend == 2) {
                // Burp Collaborator (reflection-based, Pro only)
                oob = new com.burpmax.active.CollaboratorOobClient(callbacks);
                if (!oob.isAvailable()) {
                    JOptionPane.showMessageDialog(panel,
                        "Burp Collaborator is not available (requires Burp Suite Pro).\n"
                        + "Falling back to interactsh (oast.pro).",
                        "OOB Fallback", JOptionPane.WARNING_MESSAGE);
                    oob = null;
                }
            }
            if (oob == null) {
                // Interactsh — use custom URL for self-hosted (index 1), else oast.pro
                String serverUrl = (backend == 1 && !oobUrl.isBlank())
                        ? oobUrl
                        : "https://oast.pro";
                oob = new com.burpmax.active.InteractshOobClient(serverUrl, pollDelayMs);
                if (!oob.isAvailable()) {
                    // Non-blocking — show warning in status bar and continue scan without OOB.
                    // A modal here would block the scan thread and confuse the user.
                    final String warnMsg = "⚠ OOB server unreachable (" + serverUrl
                            + ") - OOB probes skipped. Check connectivity or use self-hosted interactsh.";
                    SwingUtilities.invokeLater(() -> {
                        activeScanStatus.setText(warnMsg);
                        activeScanStatus.setForeground(new Color(0xFF, 0xB3, 0x00)); // amber
                        activeScanStatus.setVisible(true);
                    });
                    oob = null;
                }
            }
            if (oob != null) {
                activeScanner.setOobClient(oob);
                activeScanner.setOobPollDelayMs(pollDelayMs);
            }
        }

        // Wire authenticated scan session if enabled
        if (resultAuthEnabled[0] && !resultAuthHeader[0].isEmpty()) {
            com.burpmax.active.AuthConfig authCfg;
            String healthUrl = resultHealthUrl[0].isEmpty() ? null : resultHealthUrl[0];
            if (resultAuthMode[0] == 0) {
                // Static mode
                if (resultAuthToken[0].isEmpty()) {
                    JOptionPane.showMessageDialog(panel,
                        "Auth token value is empty. Authenticated scan disabled.",
                        "Auth Config Warning", JOptionPane.WARNING_MESSAGE);
                    activeScanner.setAuthConfig(null);
                } else {
                    authCfg = com.burpmax.active.AuthConfig.staticMode(
                            resultAuthHeader[0], resultAuthToken[0],
                            healthUrl, null);
                    activeScanner.setAuthConfig(authCfg);
                }
            } else {
                // Login mode
                if (resultLoginReq[0].isEmpty() || resultAuthRegex[0].isEmpty()) {
                    JOptionPane.showMessageDialog(panel,
                        "Login request or token regex is empty. Authenticated scan disabled.",
                        "Auth Config Warning", JOptionPane.WARNING_MESSAGE);
                    activeScanner.setAuthConfig(null);
                } else {
                    // Convert login request text to bytes (ISO-8859-1 for raw HTTP)
                    // Normalise line endings: JTextArea may use \n only (platform-dependent).
                    // HTTP/1.1 requires CRLF. Normalise \r\n -> \n -> \r\n to avoid doubled \r.
                    // Do NOT trim() - the trailing \r\n\r\n header terminator must be preserved.
                    String loginReqNorm = resultLoginReq[0]
                            .replace("\r\n", "\n")
                            .replace("\n", "\r\n");
                    // Ensure there is exactly one header terminator at the end.
                    // Bodies (POST) are preserved as-is after the first \r\n\r\n.
                    if (!loginReqNorm.contains("\r\n\r\n")) {
                        loginReqNorm = loginReqNorm.stripTrailing() + "\r\n\r\n";
                    }
                    byte[] loginBytes = loginReqNorm.getBytes(
                            java.nio.charset.StandardCharsets.ISO_8859_1);
                    authCfg = com.burpmax.active.AuthConfig.loginMode(
                            resultAuthHeader[0], loginBytes,
                            resultAuthRegex[0],
                            null, 0, null,  // host/port parsed from Host header in request
                            healthUrl, null);
                    activeScanner.setAuthConfig(authCfg);
                }
            }
        } else {
            activeScanner.setAuthConfig(null);
        }

        // Apply scan policy (user-selected probe exclusions)
        activeScanner.setSkipProbes(resultSkipProbes.get());

        activeScanner.setOnStatus(msg -> SwingUtilities.invokeLater(() -> {
            activeScanStatus.setText(msg);
            activeScanStatus.setVisible(true);
        }));

        activeScanner.setOnLog(msg -> {
            try {
                java.io.PrintWriter pw = new java.io.PrintWriter(callbacks.getStdout(), true);
                pw.println("[BurpMax Active] " + msg);
            } catch (Exception ignored) {}
        });

        activeScanner.setOnComplete(() -> SwingUtilities.invokeLater(() -> {
            activeScanBtn.setText("⚡ Active Scan");
            activeScanBtn.setBackground(new Color(0x6B, 0x21, 0xA8));
            activeScanProgress.setIndeterminate(false);
            activeScanProgress.setVisible(false);
            activeScanProgress.setValue(0);
            // Cancel any previous hide timer before starting a new one
            if (statusHideTimer != null) statusHideTimer.stop();
            statusHideTimer = new javax.swing.Timer(10_000, ev -> {
                activeScanStatus.setVisible(false);
                statusHideTimer = null;
            });
            statusHideTimer.setRepeats(false);
            statusHideTimer.start();
            refresh();
        }));

        // Update button to show cancel option
        activeScanBtn.setText("⏹ Cancel Scan");
        activeScanBtn.setBackground(new Color(0x99, 0x1B, 0x1B));

        // Cancel any pending status hide timer from previous scan
        if (statusHideTimer != null) {
            statusHideTimer.stop();
            statusHideTimer = null;
        }

        // Show indeterminate progress bar immediately so the UI clearly reflects that
        // work is happening during the endpoint-collection / link-extraction phases
        // (before the scanner thread has a target count and can report real percentages).
        activeScanProgress.setIndeterminate(true);
        activeScanProgress.setString("Collecting endpoints...");
        activeScanProgress.setVisible(true);

        // Wire the progress callback. Once the scanner calls this with real numbers
        // (after collection completes), we switch to determinate mode showing X/N.
        activeScanner.setOnProgress((done, total) -> SwingUtilities.invokeLater(() -> {
            if (total > 0) {
                if (activeScanProgress.isIndeterminate()) {
                    activeScanProgress.setIndeterminate(false);
                }
                int safeDone = Math.min(done, total);
                int pct = (safeDone * 100) / total;
                activeScanProgress.setValue(pct);
                // Keep any probe name shown alongside the endpoint count
                String current = activeScanProgress.getString();
                String countStr = safeDone + "/" + total;
                // Only show count when we don't have a probe name (probe name is set by onProbeStart)
                if (current == null || !current.contains("|")) {
                    activeScanProgress.setString(countStr);
                } else {
                    // Update count part only, preserve probe name
                    String probePart = current.substring(current.indexOf('|'));
                    activeScanProgress.setString(countStr + probePart);
                }
                activeScanProgress.setVisible(true);
            }
        }));

        // Per-probe progress: update progress bar string with current probe name
        // so the tester knows exactly which check is running at any moment.
        activeScanner.setOnProbeStart(probeName -> SwingUtilities.invokeLater(() -> {
            String current = activeScanProgress.getString();
            if (current == null) current = "";
            // Extract just the X/N count prefix and append the probe name
            String countPart = current.contains("|")
                ? current.substring(0, current.indexOf('|')).trim()
                : current;
            activeScanProgress.setString(countPart + " | " + probeName);
        }));
        if (doResume[0]) {
            activeScanner.startAsyncResume();
        } else {
            activeScanner.startAsync();
        }
    }

    private void setExtenderPaused(boolean p) {
        pauseToggle.run();
    }

    // ── Widget factories ──────────────────────────────────────────────────────

    private JPanel codeBlock(String title, JTextArea area) {
        JPanel p = new JPanel(new BorderLayout());
        p.setBackground(C_HEADER_BG);
        p.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0,0,0,1,C_BORDER),
                BorderFactory.createEmptyBorder(10,16,10,16)));
        JLabel lbl = new JLabel(title.toUpperCase());
        lbl.setFont(FONT_TINY);
        lbl.setForeground(C_TEXT_MUTED);
        lbl.setBorder(BorderFactory.createEmptyBorder(0,0,6,0));
        JScrollPane scroll = new JScrollPane(area);
        styleScrollPane(scroll);
        scroll.setPreferredSize(new Dimension(300, 100));
        p.add(lbl, BorderLayout.NORTH);
        p.add(scroll, BorderLayout.CENTER);
        return p;
    }

    private static JTextArea codeArea() {
        JTextArea a = new JTextArea();
        a.setFont(FONT_MONO);
        a.setForeground(C_TEXT_DIM);
        a.setBackground(C_DEEP);
        a.setLineWrap(true);
        a.setWrapStyleWord(true);
        a.setEditable(true);
        a.setBorder(BorderFactory.createEmptyBorder(6,8,6,8));
        return a;
    }

    private static void styleScrollPane(JScrollPane sp) {
        sp.setBorder(BorderFactory.createLineBorder(new Color(19,30,46),1));
        sp.getViewport().setBackground(C_DEEP);
        sp.setBackground(C_DEEP);
    }

    private static JLabel darkLabel(String text) {
        JLabel l = new JLabel(text);
        l.setForeground(C_TEXT);
        l.setFont(FONT_UI);
        return l;
    }

    private static JLabel badge(String text, Color fg) {
        JLabel l = new JLabel(text);
        l.setFont(FONT_MONO_B);
        l.setForeground(fg);
        return l;
    }

    private static JLabel muted(String text) {
        JLabel l = new JLabel(text);
        l.setFont(FONT_SMALL);
        l.setForeground(C_TEXT_MUTED);
        return l;
    }

    private static JButton primaryBtn(String text) {
        JButton b = new JButton(text);
        b.setBackground(C_BTN_PRIMARY);
        b.setForeground(C_BTN_PRIMARY_FG);
        b.setFont(FONT_MONO_B);
        b.setFocusPainted(false);
        b.setBorderPainted(false);
        b.setBorder(BorderFactory.createEmptyBorder(5,12,5,12));
        b.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        b.setOpaque(true);
        return b;
    }

    private static JButton ghostBtn(String text) {
        JButton b = new JButton(text);
        b.setBackground(C_BTN_GHOST_BG);
        b.setForeground(C_BTN_GHOST_FG);
        b.setFont(FONT_MONO_B);
        b.setFocusPainted(false);
        b.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(C_BTN_GHOST_BD,1),
                BorderFactory.createEmptyBorder(4,10,4,10)));
        b.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        b.setOpaque(true);
        return b;
    }

    private static JButton dangerBtn(String text) {
        JButton b = new JButton(text);
        b.setBackground(C_BTN_DANGER_BG);
        b.setForeground(C_BTN_DANGER_FG);
        b.setFont(FONT_MONO_B);
        b.setFocusPainted(false);
        b.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(C_BTN_DANGER_BD,1),
                BorderFactory.createEmptyBorder(4,10,4,10)));
        b.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        b.setOpaque(true);
        return b;
    }
}
