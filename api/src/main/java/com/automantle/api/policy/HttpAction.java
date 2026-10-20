package com.automantle.api.policy;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public record HttpAction(
        String method,
        String host,
        String path,
        HttpBody body,
        List<HttpCredential> credentials,
        String requestSha256) {
    public HttpAction(
            String method,
            String host,
            String path,
            HttpBody body,
            List<HttpCredential> credentials) {
        this(method, host, path, body, credentials, null);
    }

    public HttpAction(String method, String host, String path) {
        this(method, host, path, null, List.of());
    }

    public HttpAction(String method, String host, String path, HttpBody body) {
        this(method, host, path, body, List.of());
    }

    public Map<String, Object> metadata() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("resource_type", "http");
        result.put("method", method);
        result.put("host", host);
        result.put("path", path);
        if (requestSha256 != null) {
            result.put("request_sha256", requestSha256);
        }
        if (body != null) {
            result.put("body", body.metadata());
        }
        if (!credentials.isEmpty()) {
            result.put("credentials", credentials.stream().map(HttpCredential::metadata).toList());
        }
        return Collections.unmodifiableMap(result);
    }
}
