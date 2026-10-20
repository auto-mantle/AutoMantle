package com.automantle.api.service;

import com.automantle.api.entity.AgentRuleEntity;
import com.automantle.api.entity.RuleEffect;
import com.automantle.api.exception.ResourceNotFoundException;
import com.automantle.api.policy.HttpPolicyContract;
import com.automantle.api.repository.AgentRuleRepository;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class AgentRuleService {
    private final AgentRuleRepository repository;
    private final HttpPolicyContract contract;

    public AgentRuleService(AgentRuleRepository repository, HttpPolicyContract contract) {
        this.repository = repository;
        this.contract = contract;
    }

    @Transactional
    public AgentRuleEntity createAgentRule(
            UUID agentProfileId, RuleEffect effect, Map<String, Object> match) {
        contract.match(match);
        rejectCredentialConfiguration(match);
        AgentRuleEntity rule = new AgentRuleEntity(agentProfileId, effect, match);
        return repository.save(rule);
    }

    @Transactional(readOnly = true)
    public AgentRuleEntity getAgentRule(UUID id) {
        return repository
                .findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Agent rule not found"));
    }

    @Transactional(readOnly = true)
    public List<AgentRuleEntity> getAgentRulesByProfile(UUID agentProfileId) {
        return repository.findByAgentProfileId(agentProfileId);
    }

    @Transactional
    public AgentRuleEntity updateAgentRule(UUID id, RuleEffect effect, Map<String, Object> match) {
        AgentRuleEntity rule = getAgentRule(id);
        RuleEffect nextEffect = effect == null ? rule.getEffect() : effect;
        Map<String, Object> nextMatch = match == null ? rule.getMatch() : match;
        contract.match(nextMatch);
        if (match != null) {
            rejectCredentialConfiguration(nextMatch);
        }
        rule.setEffect(nextEffect);
        rule.setMatch(nextMatch);
        return repository.save(rule);
    }

    @Transactional
    public void deleteAgentRule(UUID id) {
        repository.delete(getAgentRule(id));
    }

    private static void rejectCredentialConfiguration(Map<String, Object> match) {
        if (match.containsKey("credentials")) {
            throw new IllegalArgumentException(
                    "Configure credential scope in Credentials; rules control requests");
        }
    }
}
