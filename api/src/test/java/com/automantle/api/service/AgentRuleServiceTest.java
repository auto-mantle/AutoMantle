package com.automantle.api.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.automantle.api.entity.*;
import com.automantle.api.policy.HttpPolicyFixtures;
import com.automantle.api.repository.AgentRuleRepository;

import org.junit.jupiter.api.Test;

import java.util.*;

class AgentRuleServiceTest {
    private final AgentRuleRepository repository = mock(AgentRuleRepository.class);
    private final AgentRuleService service =
            new AgentRuleService(repository, HttpPolicyFixtures.contract());
    private final UUID profileId = UUID.randomUUID(), ruleId = UUID.randomUUID();
    private final Map<String, Object> match =
            Map.of(
                    "resource_type",
                    "http",
                    "action",
                    List.of("post"),
                    "hosts",
                    List.of("api.example.com"),
                    "resource",
                    List.of("/api/*"));

    @Test
    void persistsEveryRuleEffect() {
        when(repository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));
        for (RuleEffect effect : RuleEffect.values()) {
            var rule = service.createAgentRule(profileId, effect, match);
            assertEquals(effect, rule.getEffect());
            assertEquals(match, rule.getMatch());
        }
    }

    @Test
    void updatesEffectAndPreservesOmittedFields() {
        var rule = new AgentRuleEntity(profileId, RuleEffect.REQUIRE_APPROVAL, match);
        when(repository.findById(ruleId)).thenReturn(Optional.of(rule));
        when(repository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));
        assertEquals(
                RuleEffect.REQUIRE_APPROVAL,
                service.updateAgentRule(ruleId, null, null).getEffect());
        assertEquals(
                RuleEffect.DENY,
                service.updateAgentRule(ruleId, RuleEffect.DENY, null).getEffect());
        assertEquals(match, rule.getMatch());
    }

    @Test
    void failedUpdateDoesNotMutateStoredRule() {
        AgentRuleEntity rule = new AgentRuleEntity(profileId, RuleEffect.ALLOW, match);
        when(repository.findById(ruleId)).thenReturn(Optional.of(rule));
        var invalid = new HashMap<>(match);
        invalid.remove("hosts");
        assertThrows(
                IllegalArgumentException.class,
                () -> service.updateAgentRule(ruleId, RuleEffect.DENY, invalid));
        assertEquals(RuleEffect.ALLOW, rule.getEffect());
        assertEquals(match, rule.getMatch());
        verify(repository, never()).save(any());
    }

    @Test
    void invalidRulesNeverPersist() {
        var legacy = new HashMap<>(match);
        legacy.remove("hosts");
        assertThrows(
                IllegalArgumentException.class,
                () -> service.createAgentRule(profileId, RuleEffect.ALLOW, legacy));
        verify(repository, never()).save(any());
    }

    @Test
    void credentialScopeCannotBeConfiguredInRules() {
        var credentialMatch = new HashMap<>(match);
        credentialMatch.put(
                "credentials",
                List.of(
                        Map.of(
                                "placeholder",
                                "SERVICE_TOKEN",
                                "location",
                                "json",
                                "selector",
                                "/auth/token")));
        assertThrows(
                IllegalArgumentException.class,
                () -> service.createAgentRule(profileId, RuleEffect.ALLOW, credentialMatch));
        assertThrows(
                IllegalArgumentException.class,
                () -> service.createAgentRule(profileId, RuleEffect.DENY, credentialMatch));
        var rule = new AgentRuleEntity(profileId, RuleEffect.ALLOW, match);
        when(repository.findById(ruleId)).thenReturn(Optional.of(rule));
        assertThrows(
                IllegalArgumentException.class,
                () -> service.updateAgentRule(ruleId, RuleEffect.DENY, credentialMatch));
        assertEquals(RuleEffect.ALLOW, rule.getEffect());
    }
}
