package com.automantle.api.util;

import java.text.Normalizer;

public final class NameUtil {

    private NameUtil() {}

    public static String generateName(String input) {
        if (input == null || input.trim().isEmpty()) {
            return "";
        }

        return Normalizer.normalize(input, Normalizer.Form.NFD)
                .toLowerCase()
                .replace(" ", "-")
                .replaceAll("[^a-z0-9-]", "")
                .replaceAll("-+", "-")
                .replaceAll("^-+|-+$", "");
    }
}
