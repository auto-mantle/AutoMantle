package com.automantle.api.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.net.URI;
import java.util.Set;

@ConfigurationProperties(prefix = "app.security")
public record ApiSecurityProperties(URI frontendUrl, boolean requireHttps) {
    public ApiSecurityProperties {
        if (!isOrigin(frontendUrl)
                || !Set.of("localhost", "127.0.0.1", "[::1]", "::1")
                        .contains(frontendUrl.getHost())) {
            throw new IllegalArgumentException(
                    "Frontend URL must be a loopback HTTP(S) origin without a path, query, or"
                            + " fragment");
        }
        if (requireHttps && !"https".equalsIgnoreCase(frontendUrl.getScheme())) {
            throw new IllegalArgumentException(
                    "Frontend URL must use HTTPS when HTTPS is required");
        }
    }

    private static boolean isOrigin(URI uri) {
        if (uri == null) {
            return false;
        }
        boolean isHttp =
                "http".equalsIgnoreCase(uri.getScheme())
                        || "https".equalsIgnoreCase(uri.getScheme());
        boolean hasNoPath = uri.getPath() == null || uri.getPath().isEmpty();
        return isHttp
                && uri.getHost() != null
                && uri.getUserInfo() == null
                && hasNoPath
                && uri.getQuery() == null
                && uri.getFragment() == null;
    }
}
