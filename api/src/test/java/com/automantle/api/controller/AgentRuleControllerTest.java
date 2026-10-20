package com.automantle.api.controller;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.automantle.api.dto.*;
import com.automantle.api.entity.*;
import com.automantle.api.exception.ResourceNotFoundException;
import com.automantle.api.service.*;

import org.junit.jupiter.api.Test;

import java.util.*;

class AgentRuleControllerTest {
    private final AgentRuleService rules = mock(AgentRuleService.class);
    private final AgentProfileService profiles = mock(AgentProfileService.class);
    private final AgentRuleController controller = new AgentRuleController(rules, profiles);

    @Test
    void everySingleRuleOperationChecksTheProfileOwner() {
        UUID profile = UUID.randomUUID(), other = UUID.randomUUID(), id = UUID.randomUUID();
        when(profiles.getAgentProfile(profile)).thenReturn(new AgentProfileEntity("first"));
        when(rules.getAgentRule(id))
                .thenReturn(new AgentRuleEntity(other, RuleEffect.ALLOW, Map.of()));
        assertThrows(ResourceNotFoundException.class, () -> controller.get(profile, id));
        assertThrows(ResourceNotFoundException.class, () -> controller.delete(profile, id));
        assertThrows(
                ResourceNotFoundException.class,
                () ->
                        controller.update(
                                profile, id, new UpdateAgentRuleRequest(RuleEffect.DENY, null)));
        verify(rules, never()).deleteAgentRule(any());
        verify(rules, never()).updateAgentRule(any(), any(), any());
    }

    @Test
    void rulesAreDirectProfileResourcesAndDeletedProfilesCannotUseThem() {
        UUID profile = UUID.randomUUID();
        var match =
                Map.<String, Object>of(
                        "resource_type",
                        "http",
                        "action",
                        List.of("get"),
                        "hosts",
                        List.of("brain.example.com"),
                        "resource",
                        List.of("/api"));
        var rule = new AgentRuleEntity(profile, RuleEffect.ALLOW, match);
        when(profiles.getAgentProfile(profile)).thenReturn(new AgentProfileEntity("first"));
        when(rules.getAgentRulesByProfile(profile)).thenReturn(List.of(rule));
        assertEquals(profile, controller.list(profile).getFirst().agentProfileId());
        when(rules.createAgentRule(profile, RuleEffect.ALLOW, match)).thenReturn(rule);
        assertEquals(
                profile,
                controller
                        .create(profile, new CreateAgentRuleRequest(RuleEffect.ALLOW, match))
                        .agentProfileId());
        when(profiles.getAgentProfile(profile))
                .thenThrow(new ResourceNotFoundException("Deleted profile"));
        assertThrows(ResourceNotFoundException.class, () -> controller.list(profile));
        assertThrows(
                ResourceNotFoundException.class,
                () ->
                        controller.create(
                                profile, new CreateAgentRuleRequest(RuleEffect.ALLOW, match)));
    }
}
