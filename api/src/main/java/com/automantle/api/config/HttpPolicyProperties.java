package com.automantle.api.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.unit.DataSize;

@ConfigurationProperties(prefix = "app.http-policy")
public record HttpPolicyProperties(
        DataSize maxPreviewSize,
        int maxRuleValues,
        int maxCredentialPlacements,
        int maxSelectorLength,
        int maxJsonPointerLength,
        int maxContentTypeLength,
        int maxPathLength) {
    public HttpPolicyProperties {
        if (maxPreviewSize == null
                || maxPreviewSize.toBytes() <= 0
                || maxPreviewSize.toBytes() > Integer.MAX_VALUE
                || maxRuleValues < 1
                || maxCredentialPlacements < 1
                || maxSelectorLength < 1
                || maxJsonPointerLength < 1
                || maxContentTypeLength < 1
                || maxPathLength < 1) {
            throw new IllegalArgumentException("HTTP policy limits must be positive and supported");
        }
    }
}
