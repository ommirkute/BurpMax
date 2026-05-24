package com.burpmax.ui;

import com.burpmax.model.Finding;

import java.awt.*;
import java.util.Map;

public final class Theme {

    // ── Background layers ─────────────────────────────────────────────────────
    public static final Color C_ROOT       = new Color(11,  15,  26);
    public static final Color C_HEADER_BG  = new Color(13,  18,  32);
    public static final Color C_SURFACE    = new Color(22,  30,  46);
    public static final Color C_DEEP       = new Color(7,   12,  20);
    public static final Color C_SEL_ROW    = new Color(20,  45,  85);
    public static final Color C_TOOLBAR_BD = new Color(30,  40,  60);

    // ── Borders ───────────────────────────────────────────────────────────────
    public static final Color C_BORDER    = new Color(40,  60,  90);
    public static final Color C_BORDER2   = new Color(25,  35,  55);

    // ── Text ──────────────────────────────────────────────────────────────────
    public static final Color C_TEXT      = new Color(226, 232, 240);
    public static final Color C_TEXT_DIM  = new Color(180, 192, 210);
    public static final Color C_TEXT_MUTED= new Color(120, 145, 175);
    public static final Color C_ACCENT_BLU= new Color(96,  165, 250);
    public static final Color C_TEXT_HEAD = new Color(241, 245, 249);

    // ── Severity FG ───────────────────────────────────────────────────────────
    public static final Color C_CRITICAL  = new Color(255, 80,  80);
    public static final Color C_HIGH      = new Color(248, 113, 113);
    public static final Color C_MEDIUM    = new Color(251, 146, 60);
    public static final Color C_LOW       = new Color(250, 204, 21);
    public static final Color C_INFO      = new Color(147, 197, 253);

    // ── Severity BG ───────────────────────────────────────────────────────────
    public static final Color C_CRIT_BG   = new Color(60,  15,  15);
    public static final Color C_HIGH_BG   = new Color(50,  15,  15);
    public static final Color C_MED_BG    = new Color(50,  30,  10);
    public static final Color C_LOW_BG    = new Color(45,  40,  5);
    public static final Color C_INFO_BG   = new Color(15,  30,  55);

    // ── Severity BD ───────────────────────────────────────────────────────────
    public static final Color C_CRIT_BD   = new Color(120, 30,  30);
    public static final Color C_HIGH_BD   = new Color(100, 30,  30);
    public static final Color C_MED_BD    = new Color(100, 60,  20);
    public static final Color C_LOW_BD    = new Color(90,  80,  10);
    public static final Color C_INFO_BD   = new Color(30,  70,  110);

    // ── Buttons ───────────────────────────────────────────────────────────────
    public static final Color C_BTN_PRIMARY    = new Color(37,  99,  235);
    public static final Color C_BTN_PRIMARY_FG = Color.WHITE;
    public static final Color C_BTN_GHOST_BG   = new Color(22,  30,  46);
    public static final Color C_BTN_GHOST_FG   = new Color(147, 197, 253);
    public static final Color C_BTN_GHOST_BD   = new Color(40,  60,  90);
    public static final Color C_BTN_DANGER_BG  = new Color(60,  15,  15);
    public static final Color C_BTN_DANGER_FG  = new Color(255, 100, 100);
    public static final Color C_BTN_DANGER_BD  = new Color(120, 30,  30);

    // ── Severity lookup maps ──────────────────────────────────────────────────
    public static final Map<String, Color> SEV_FG = Map.of(
        Finding.SEV_CRITICAL, C_CRITICAL,
        Finding.SEV_HIGH,     C_HIGH,
        Finding.SEV_MEDIUM,   C_MEDIUM,
        Finding.SEV_LOW,      C_LOW,
        Finding.SEV_INFO,     C_INFO
    );
    public static final Map<String, Color> SEV_BG = Map.of(
        Finding.SEV_CRITICAL, C_CRIT_BG,
        Finding.SEV_HIGH,     C_HIGH_BG,
        Finding.SEV_MEDIUM,   C_MED_BG,
        Finding.SEV_LOW,      C_LOW_BG,
        Finding.SEV_INFO,     C_INFO_BG
    );
    public static final Map<String, Color> SEV_BD = Map.of(
        Finding.SEV_CRITICAL, C_CRIT_BD,
        Finding.SEV_HIGH,     C_HIGH_BD,
        Finding.SEV_MEDIUM,   C_MED_BD,
        Finding.SEV_LOW,      C_LOW_BD,
        Finding.SEV_INFO,     C_INFO_BD
    );

    // ── Fonts ─────────────────────────────────────────────────────────────────
    public static final Font FONT_MONO  = new Font(Font.MONOSPACED, Font.PLAIN, 11);
    public static final Font FONT_MONO_B= new Font(Font.MONOSPACED, Font.BOLD,  11);
    public static final Font FONT_UI    = new Font("Arial", Font.PLAIN, 12);
    public static final Font FONT_UI_B  = new Font("Arial", Font.BOLD,  12);
    public static final Font FONT_SMALL = new Font("Arial", Font.PLAIN, 10);
    public static final Font FONT_TINY  = new Font("Arial", Font.BOLD,   9);

    private Theme() {}
}
