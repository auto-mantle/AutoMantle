package com.automantle.api.dto;

import jakarta.validation.constraints.NotNull;

import java.util.Map;
import java.util.UUID;

public record GatewayEvaluateRequest(
        @NotNull UUID agentProfileId,
        @NotNull Map<String, Object> action,
        UUID requestId,
        UUID setupSessionId) {
    public GatewayEvaluateRequest(UUID agentProfileId, Map<String, Object> action) {
        this(agentProfileId, action, null, null);
    }

    public GatewayEvaluateRequest(UUID agentProfileId, Map<String, Object> action, UUID requestId) {
        this(agentProfileId, action, requestId, null);
    }
}
