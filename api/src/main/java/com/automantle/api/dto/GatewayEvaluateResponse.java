package com.automantle.api.dto;

import com.automantle.api.policy.PolicyDecisionEngine.MatchedRule;

import java.util.List;
import java.util.UUID;

public record GatewayEvaluateResponse(
        String decision, String reason, UUID approvalRequestId, List<MatchedRule> matchedRules) {}
