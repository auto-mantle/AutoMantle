package com.automantle.api.policy;

import java.util.List;

public record HttpRuleMatch(
        List<String> methods,
        List<String> hosts,
        List<String> paths,
        List<HttpCredential> credentials) {
    public boolean matches(HttpAction action) {
        return methods.contains(action.method())
                && hosts.contains(action.host())
                && paths.stream().anyMatch(pattern -> matchesPath(pattern, action.path()));
    }

    private static boolean matchesPath(String pattern, String path) {
        if (pattern.endsWith("/*")) {
            return path.startsWith(pattern.substring(0, pattern.length() - 1));
        }
        return pattern.equals(path);
    }
}
