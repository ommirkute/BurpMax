package com.burpmax.scanner;

import com.burpmax.model.Finding;

import java.util.*;

public class ScannerUtils {
    public static String trunc(String s, int n) {
        if (s == null) return "";
        return s.length() > n ? s.substring(0, n) + "..." : s;
    }
}
