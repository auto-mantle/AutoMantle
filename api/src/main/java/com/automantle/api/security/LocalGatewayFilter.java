package com.automantle.api.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Set;

public final class LocalGatewayFilter extends OncePerRequestFilter {
    private static final Set<String> LOOPBACK_ADDRESSES =
            Set.of("127.0.0.1", "::1", "0:0:0:0:0:0:0:1");
    private static final Set<String> LOCAL_HOSTS = Set.of("localhost", "127.0.0.1", "::1", "[::1]");

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        boolean loopback = LOOPBACK_ADDRESSES.contains(request.getRemoteAddr());
        boolean localHost = LOCAL_HOSTS.contains(request.getServerName());
        if (!loopback
                || !localHost
                || request.getHeader("Origin") != null
                || request.getHeader("Sec-Fetch-Site") != null
                || !"local".equals(request.getHeader("X-Automantle-Gateway"))) {
            response.sendError(
                    HttpServletResponse.SC_FORBIDDEN,
                    "Gateway API accepts local native-process requests only");
            return;
        }
        chain.doFilter(request, response);
    }
}
