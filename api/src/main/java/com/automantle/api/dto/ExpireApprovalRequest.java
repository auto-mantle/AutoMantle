package com.automantle.api.dto;

import com.automantle.api.entity.ApprovalExpirationReason;

import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record ExpireApprovalRequest(
        @NotNull UUID agentProfileId, @NotNull ApprovalExpirationReason reason) {}
