package com.automantle.api.dto;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.UUID;

public record ReportRequestHistory(
        @NotNull UUID requestId,
        @NotNull UUID agentProfileId,
        @Pattern(regexp = "[a-z0-9.-]{1,253}") String host,
        @Min(1) @Max(65535) Integer port,
        @Pattern(regexp = "[A-Za-z0-9!#$%&'*+.^_`|~\\-]+") @Size(max = 64) String method,
        @Size(max = 2048) String path,
        @NotNull Reason reason) {
    public enum Reason {
        INVALID_REQUEST,
        HTTPS_DISABLED,
        DOWNSTREAM_TLS_FAILED,
        INVALID_BODY,
        CREDENTIAL_BINDING_DENIED,
        FORWARDING_UNSUPPORTED,
        POLICY_UNAVAILABLE,
        DNS_FAILED,
        PRIVATE_DESTINATION,
        CONNECT_FAILED,
        UPSTREAM_TLS_FAILED,
        RESPONSE_BLOCKED,
        IO_FAILED,
        CANCELLED,
        COMPLETED
    }
}
