package com.automantle.api.policy;

import java.util.HashMap;
import java.util.Map;

final class MetadataFields {
    private final Map<?, ?> remaining;

    private MetadataFields(Map<?, ?> value) {
        remaining = new HashMap<>(value);
    }

    static MetadataFields from(Object value, String error) {
        if (!(value instanceof Map<?, ?> fields)) {
            throw new IllegalArgumentException(error);
        }
        return new MetadataFields(fields);
    }

    boolean has(String name) {
        return remaining.containsKey(name);
    }

    Object take(String name) {
        return remaining.remove(name);
    }

    String text(String name) {
        Object value = take(name);
        if (!(value instanceof String text) || text.isEmpty()) {
            throw new IllegalArgumentException("Expected a nonempty string");
        }
        return text;
    }

    void rejectUnexpected(String error) {
        if (!remaining.isEmpty()) {
            throw new IllegalArgumentException(error);
        }
    }
}
