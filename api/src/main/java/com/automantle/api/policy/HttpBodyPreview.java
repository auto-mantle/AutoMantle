package com.automantle.api.policy;

import java.util.Map;

public record HttpBodyPreview(String json, boolean redacted, boolean omitted) {
    public Map<String, Object> metadata() {
        return omitted ? Map.of("omitted", true) : Map.of("json", json, "redacted", redacted);
    }
}
