package com.automantle.api.controller;

import com.automantle.api.dto.AgentRuleResponse;
import com.automantle.api.dto.CreateAgentRuleRequest;
import com.automantle.api.dto.UpdateAgentRuleRequest;
import com.automantle.api.entity.AgentRuleEntity;
import com.automantle.api.exception.ResourceNotFoundException;
import com.automantle.api.service.AgentProfileService;
import com.automantle.api.service.AgentRuleService;

import jakarta.validation.Valid;

import org.springframework.http.HttpStatus;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/agents/profiles/{profileId}/rules")
@Transactional
public class AgentRuleController {
    private final AgentRuleService rules;
    private final AgentProfileService profiles;

    public AgentRuleController(AgentRuleService rules, AgentProfileService profiles) {
        this.rules = rules;
        this.profiles = profiles;
    }

    @GetMapping
    public List<AgentRuleResponse> list(@PathVariable UUID profileId) {
        profiles.getAgentProfile(profileId);
        return rules.getAgentRulesByProfile(profileId).stream().map(this::response).toList();
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public AgentRuleResponse create(
            @PathVariable UUID profileId, @Valid @RequestBody CreateAgentRuleRequest request) {
        profiles.getAgentProfile(profileId);
        return response(rules.createAgentRule(profileId, request.effect(), request.match()));
    }

    private AgentRuleEntity owned(UUID profileId, UUID ruleId) {
        profiles.getAgentProfile(profileId);
        var rule = rules.getAgentRule(ruleId);
        if (!profileId.equals(rule.getAgentProfileId())) {
            throw new ResourceNotFoundException("Rule not found in this profile");
        }
        return rule;
    }

    @GetMapping("/{ruleId}")
    public AgentRuleResponse get(@PathVariable UUID profileId, @PathVariable UUID ruleId) {
        return response(owned(profileId, ruleId));
    }

    @PatchMapping("/{ruleId}")
    public AgentRuleResponse update(
            @PathVariable UUID profileId,
            @PathVariable UUID ruleId,
            @Valid @RequestBody UpdateAgentRuleRequest request) {
        owned(profileId, ruleId);
        return response(rules.updateAgentRule(ruleId, request.effect(), request.match()));
    }

    @DeleteMapping("/{ruleId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable UUID profileId, @PathVariable UUID ruleId) {
        owned(profileId, ruleId);
        rules.deleteAgentRule(ruleId);
    }

    private AgentRuleResponse response(AgentRuleEntity r) {
        return new AgentRuleResponse(r.getId(), r.getAgentProfileId(), r.getEffect(), r.getMatch());
    }
}
