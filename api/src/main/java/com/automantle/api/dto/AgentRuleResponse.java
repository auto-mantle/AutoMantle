package com.automantle.api.dto;

import com.automantle.api.entity.RuleEffect;

import java.util.Map;
import java.util.UUID;

public record AgentRuleResponse(
        UUID id, UUID agentProfileId, RuleEffect effect, Map<String, Object> match) {}
