package com.automantle.api.policy;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;

public record HttpBody(String contentType, int sizeBytes, String sha256, HttpBodyPreview preview) {
    private static final String EMPTY_SHA256 = hashEmptyBody();

    public static boolean matchesEmptyFingerprint(long size, String sha256) {
        return size != 0 || EMPTY_SHA256.equals(sha256);
    }

    public static boolean validSha256(String value) {
        if (value == null) {
            return false;
        }
        try {
            byte[] bytes = HexFormat.of().parseHex(value);
            return bytes.length == EMPTY_SHA256.length() / 2
                    && HexFormat.of().formatHex(bytes).equals(value);
        } catch (IllegalArgumentException error) {
            return false;
        }
    }

    private static String hashEmptyBody() {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest());
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException("SHA-256 is unavailable", error);
        }
    }

    public HttpBody(String contentType, int sizeBytes, String sha256) {
        this(contentType, sizeBytes, sha256, null);
    }

    public Map<String, Object> metadata() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("content_type", contentType);
        result.put("size_bytes", sizeBytes);
        result.put("sha256", sha256);
        if (preview != null) {
            result.put("preview", preview.metadata());
        }
        return Collections.unmodifiableMap(result);
    }
}
