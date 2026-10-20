package com.automantle.api.dto;

import com.automantle.api.entity.RuleEffect;

import jakarta.validation.constraints.NotNull;

import java.util.Map;

public record CreateAgentRuleRequest(
        @NotNull RuleEffect effect, @NotNull Map<String, Object> match) {}
