package com.automantle.api.policy;

import java.util.Map;
import java.util.regex.Pattern;

public record HttpCredential(String placeholder, String location, String selector) {
    private static final Pattern NAME = Pattern.compile("[A-Z_][A-Z0-9_]{0,127}");
    private static final String VM_BEARER_PREFIX = "AUTOMANTLE_VM_BEARER_";

    public static boolean validName(String name) {
        return name != null && NAME.matcher(name).matches();
    }

    public static boolean isVmBearer(String name) {
        return name != null && name.startsWith(VM_BEARER_PREFIX);
    }

    public static boolean validManagedName(String name) {
        return validName(name) && !isVmBearer(name);
    }

    public HttpCredential(String placeholder, String header) {
        this(placeholder, "header", header);
    }

    public String header() {
        return location.equals("header") ? selector : null;
    }

    public Map<String, Object> metadata() {
        return Map.of("placeholder", placeholder, "location", location, "selector", selector);
    }
}
