package com.automantle.api.dto;

import com.automantle.api.entity.RuleEffect;

import java.util.Map;

public record UpdateAgentRuleRequest(RuleEffect effect, Map<String, Object> match) {}
