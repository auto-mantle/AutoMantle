package com.automantle.api.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URI;
import java.util.Set;

public final class LocalManagementFilter extends OncePerRequestFilter {
    private static final Set<String> LOCAL_HOSTS = Set.of("localhost", "127.0.0.1", "::1", "[::1]");
    private final String frontendOrigin;

    public LocalManagementFilter(URI frontendUrl) {
        frontendOrigin = frontendUrl.toString();
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String remote = request.getRemoteAddr();
        String host = request.getServerName();
        String origin = request.getHeader("Origin");
        String ownOrigin = ownOrigin(request);
        boolean loopback =
                "127.0.0.1".equals(remote)
                        || "::1".equals(remote)
                        || "0:0:0:0:0:0:0:1".equals(remote);
        boolean trustedOrigin =
                origin == null || origin.equals(frontendOrigin) || origin.equals(ownOrigin);
        boolean hostileFetch =
                "cross-site".equals(request.getHeader("Sec-Fetch-Site"))
                        && (origin == null || !origin.equals(frontendOrigin));
        if (!loopback || !LOCAL_HOSTS.contains(host) || !trustedOrigin || hostileFetch) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Management API is local-only");
            return;
        }
        chain.doFilter(request, response);
    }

    private String ownOrigin(HttpServletRequest request) {
        String scheme = request.getScheme();
        int port = request.getServerPort();
        boolean defaultPort =
                (port == 80 && scheme.equals("http")) || (port == 443 && scheme.equals("https"));
        return scheme + "://" + request.getServerName() + (defaultPort ? "" : ":" + port);
    }
}
