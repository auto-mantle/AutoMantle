package com.automantle.api.dto;

import com.automantle.api.entity.ApprovalExpirationReason;
import com.automantle.api.entity.ApprovalRequestStatus;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

public record ApprovalRequestResponse(
        UUID id,
        UUID ruleId,
        UUID agentProfileId,
        ApprovalRequestStatus status,
        String actionSummary,
        Map<String, Object> actionMetadata,
        UUID resolvedBy,
        Instant resolvedAt,
        Instant createdAt,
        ApprovalExpirationReason expirationReason,
        String expirationMessage) {}
