package com.automantle.api.dto;

import com.automantle.api.entity.ApprovalRequestStatus;

import jakarta.validation.constraints.NotNull;

public record ResolveApprovalRequest(@NotNull ApprovalRequestStatus decision, boolean saveRule) {}
