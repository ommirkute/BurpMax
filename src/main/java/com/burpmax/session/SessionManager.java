package com.burpmax.session;

import com.burpmax.store.FindingStore;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.*;
import java.util.function.Consumer;

/**
 * Manages debounced auto-save and session restore for the finding store.
 * All file I/O is performed on a background executor thread.
 * Save debounce: 2 seconds after last mutation.
 */
public class SessionManager {

    private static final String SETTING_KEY = "burpmax_save_path";
    private static final long   DEBOUNCE_MS = 2000;

    private final FindingStore         store;
    private final Object               burpCallbacks;   // burp.IBurpExtenderCallbacks
    private final ScheduledExecutorService scheduler =
            Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "burpmax-session");
                t.setDaemon(true);
                return t;
            });

    private volatile String          savePath = null;
    private ScheduledFuture<?>       debounceTask = null;
    private final Object             debLock = new Object();

    private java.util.function.BiConsumer<Boolean, String> statusUpdater = null;   // set by UI after build

    public SessionManager(FindingStore store, Object burpCallbacks) {
        this.store         = store;
        this.burpCallbacks = burpCallbacks;
    }

    /** success=true → green tick; success=false → red warning in status label. */
    public void setStatusUpdater(java.util.function.BiConsumer<Boolean, String> fn) { this.statusUpdater = fn; }

    // ── Path management ───────────────────────────────────────────────────────

    public void loadPathFromSettings() {
        try {
            java.lang.reflect.Method m =
                    burpCallbacks.getClass().getMethod("loadExtensionSetting", String.class);
            String path = (String) m.invoke(burpCallbacks, SETTING_KEY);
            if (path != null && !path.isEmpty()) {
                // Canonicalize before trusting — prevents path traversal from tampered settings
                try {
                    savePath = new File(path).getCanonicalPath();
                } catch (Exception e) {
                    savePath = path;   // fallback: keep raw if canonicalization fails
                }
            }
        } catch (Exception ignored) {}
    }

    public void savePathToSettings() {
        try {
            java.lang.reflect.Method m =
                    burpCallbacks.getClass().getMethod("saveExtensionSetting", String.class, String.class);
            m.invoke(burpCallbacks, SETTING_KEY, savePath != null ? savePath : "");
        } catch (Exception ignored) {}
    }

    public String getSavePath() { return savePath; }

    private static final long MAX_SESSION_BYTES = 50 * 1024 * 1024L;  // 50 MB hard limit

    public void setSavePath(String path) {
        try {
            this.savePath = new File(path).getCanonicalPath();
        } catch (Exception e) {
            this.savePath = path;
        }
        savePathToSettings();
    }

    // ── Auto-save (debounced) ─────────────────────────────────────────────────

    // Guards against autosave being triggered by the startup auto-restore itself.
    // Without this, deserialize() fires listeners → scheduleAutoSave() → writes the
    // just-loaded file back to disk 2 seconds after every Burp launch unnecessarily.
    private volatile boolean isRestoring = false;

    public void scheduleAutoSave() {
        if (savePath == null || isRestoring) return;
        synchronized (debLock) {
            if (debounceTask != null) debounceTask.cancel(false);
            debounceTask = scheduler.schedule(this::doSave, DEBOUNCE_MS, TimeUnit.MILLISECONDS);
        }
    }

    public void saveNow() {
        if (savePath == null) return;
        synchronized (debLock) {
            if (debounceTask != null) debounceTask.cancel(false);
        }
        scheduler.submit(this::doSave);
    }

    private void doSave() {
        String path = savePath;
        if (path == null) return;
        String tmp = path + ".tmp";
        try {
            String data = store.serialize();
            // Ensure parent directory exists — FileOutputStream throws FileNotFoundException
            // if the parent directory is missing (e.g. first save to a new folder).
            File parentDir = new File(tmp).getParentFile();
            if (parentDir != null && !parentDir.exists()) {
                if (!parentDir.mkdirs()) {
                    updateStatus(false, "cannot create directory: " + parentDir.getPath());
                    return;
                }
            }
            try (FileOutputStream fos = new FileOutputStream(tmp);
                 OutputStreamWriter w = new OutputStreamWriter(fos, StandardCharsets.UTF_8)) {
                w.write(data);
                w.flush();
                fos.getFD().sync();
            }
            // Use Files.move with ATOMIC_MOVE — unlike File.renameTo(),
            // this throws on failure rather than silently returning false,
            // preventing data loss if the move fails mid-way.
            try {
                java.nio.file.Files.move(
                        java.nio.file.Paths.get(tmp),
                        java.nio.file.Paths.get(path),
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                        java.nio.file.StandardCopyOption.ATOMIC_MOVE);
            } catch (java.nio.file.AtomicMoveNotSupportedException e) {
                // ATOMIC_MOVE not supported on this FS — fall back to REPLACE_EXISTING only
                java.nio.file.Files.move(
                        java.nio.file.Paths.get(tmp),
                        java.nio.file.Paths.get(path),
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }
            updateStatus(true, "autosaved");
        } catch (Exception ex) {
            new File(tmp).delete();
            updateStatus(false, "error: " + ex.getMessage());
        }
    }

    // ── Load ──────────────────────────────────────────────────────────────────

    /**
     * Loads a session file on a background thread.
     *
     * <p>Both {@code onLoadComplete} and {@code onError} are dispatched to the
     * Event Dispatch Thread via {@code SwingUtilities.invokeLater} so callers
     * can safely update Swing components in either callback without wrapping.
     */
    public void loadAsync(String path,
                          java.util.function.BiConsumer<Integer,Integer> onLoadComplete,
                          Consumer<String> onError) {
        scheduler.submit(() -> {
            try {
                File f = new File(path);
                if (!f.exists()) {
                    javax.swing.SwingUtilities.invokeLater(
                            () -> onError.accept("File not found: " + path));
                    return;
                }
                if (f.length() > MAX_SESSION_BYTES) {
                    javax.swing.SwingUtilities.invokeLater(
                            () -> onError.accept("Session file too large ("
                                    + (f.length() / 1024 / 1024) + " MB). Maximum is 50 MB."));
                    return;
                }
                String json;
                try (BufferedReader br = new BufferedReader(
                        new InputStreamReader(new FileInputStream(f), StandardCharsets.UTF_8))) {
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = br.readLine()) != null) sb.append(line).append('\n');
                    json = sb.toString();
                }
                int[] result = store.deserialize(json);
                final int restored = result[0], skipped = result[1];
                // store.deserialize() already fires store listeners (which dispatch to EDT).
                // The onLoadComplete callback may also touch UI, so dispatch to EDT here too.
                javax.swing.SwingUtilities.invokeLater(
                        () -> onLoadComplete.accept(restored, skipped));
            } catch (Exception e) {
                final String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
                javax.swing.SwingUtilities.invokeLater(() -> onError.accept(msg));
            }
        });
    }

    /**
     * Restores the session from a known path on startup.
     * Identical to {@link #loadAsync} but suppresses autosave while loading so
     * the startup restore does not immediately re-write the file it just read.
     */
    public void restoreAsync(String path,
                              java.util.function.BiConsumer<Integer,Integer> onLoadComplete,
                              Consumer<String> onError) {
        isRestoring = true;
        try {
            loadAsync(path, (restored, skipped) -> {
                isRestoring = false;
                onLoadComplete.accept(restored, skipped);
            }, err -> {
                isRestoring = false;
                onError.accept(err);
            });
        } catch (Exception e) {
            // scheduler.submit() failed (executor shut down) - ensure flag is always cleared
            // so autosave is not permanently suppressed for the rest of the session.
            isRestoring = false;
            javax.swing.SwingUtilities.invokeLater(() -> onError.accept("Restore failed: " + e.getMessage()));
        }
    }

    private void updateStatus(boolean success, String msg) {
        if (statusUpdater != null) {
            try { statusUpdater.accept(success, msg); } catch (Exception ignored) {}
        }
    }

    /** Shut down background threads — called on extension unload. */
    public void shutdown() {
        synchronized (debLock) {
            if (debounceTask != null) debounceTask.cancel(false);
        }
        scheduler.shutdownNow();
    }
}
