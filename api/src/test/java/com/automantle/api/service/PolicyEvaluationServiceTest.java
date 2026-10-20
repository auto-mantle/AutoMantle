package com.automantle.api.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.automantle.api.dto.*;
import com.automantle.api.entity.*;
import com.automantle.api.exception.ResourceNotFoundException;
import com.automantle.api.policy.HttpPolicyFixtures;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.*;

class PolicyEvaluationServiceTest {
    private final AgentRuleService rules = mock(AgentRuleService.class);
    private final ApprovalRequestService approvals = mock(ApprovalRequestService.class);
    private final AgentProfileService profiles = mock(AgentProfileService.class);
    private final UUID profileId = UUID.randomUUID();
    private final PolicyEvaluationService evaluator =
            new PolicyEvaluationService(
                    rules, approvals, profiles, mock(RequestHistoryService.class),
                    HttpPolicyFixtures.engine());
    private final Map<String, Object> action =
            Map.of(
                    "resource_type",
                    "http",
                    "method",
                    "POST",
                    "host",
                    "api.example.com",
                    "path",
                    "/api/users");
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
    private final List<AgentRuleEntity> entries = new ArrayList<>();

    @BeforeEach
    void setup() {
        when(profiles.getAgentProfile(profileId)).thenReturn(new AgentProfileEntity("agent"));
        when(rules.getAgentRulesByProfile(profileId)).thenReturn(entries);
    }

    private UUID addRule(RuleEffect effect) {
        var rule = mock(AgentRuleEntity.class);
        UUID id = UUID.randomUUID();
        when(rule.getId()).thenReturn(id);
        when(rule.getEffect()).thenReturn(effect);
        when(rule.getMatch()).thenReturn(match);
        entries.add(rule);
        return id;
    }

    private GatewayEvaluateResponse evaluate() {
        return evaluator.evaluateAction(new GatewayEvaluateRequest(profileId, action));
    }

    @Test
    void explicitDenyOverridesAllowAndApproval() {
        addRule(RuleEffect.ALLOW);
        addRule(RuleEffect.REQUIRE_APPROVAL);
        addRule(RuleEffect.DENY);
        assertEquals("DENY", evaluate().decision());
        verifyNoInteractions(approvals);
    }

    @Test
    void allowsWithoutApprovalAndDefaultsToDeny() {
        assertEquals("DENY", evaluate().decision());
        addRule(RuleEffect.ALLOW);
        assertEquals("ALLOW", evaluate().decision());
        verifyNoInteractions(approvals);
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void createsOneApprovalWithDeterministicRuleAndSnapshot() {
        UUID first = addRule(RuleEffect.REQUIRE_APPROVAL);
        UUID second = addRule(RuleEffect.REQUIRE_APPROVAL);
        UUID controlling = first.compareTo(second) < 0 ? first : second;
        var approval = mock(ApprovalRequestEntity.class);
        UUID id = UUID.randomUUID();
        when(approval.getId()).thenReturn(id);
        when(approvals.createRequest(any(), any(), anyString(), anyMap())).thenReturn(approval);
        var result = evaluate();
        assertEquals("REQUIRE_APPROVAL", result.decision());
        assertEquals(id, result.approvalRequestId());
        assertEquals(2, result.matchedRules().size());
        ArgumentCaptor<Map<String, Object>> metadata = ArgumentCaptor.forClass((Class) Map.class);
        verify(approvals)
                .createRequest(
                        eq(controlling),
                        eq(profileId),
                        eq("POST api.example.com/api/users"),
                        metadata.capture());
        assertEquals("post", ((Map<?, ?>) metadata.getValue().get("action")).get("method"));
        var snapshots = (List<?>) metadata.getValue().get("matchedRules");
        assertEquals(2, snapshots.size());
        snapshots.forEach(
                snapshot ->
                        assertEquals(Set.of("ruleId", "effect"), ((Map<?, ?>) snapshot).keySet()));
    }

    @Test
    void refusesDeletedOrMissingProfile() {
        when(profiles.getAgentProfile(profileId))
                .thenThrow(new ResourceNotFoundException("Profile not found"));
        assertThrows(ResourceNotFoundException.class, this::evaluate);
        verifyNoInteractions(rules, approvals);
    }

    @Test
    void malformedActionNeverCreatesApproval() {
        assertEquals(
                "DENY",
                evaluator
                        .evaluateAction(new GatewayEvaluateRequest(profileId, Map.of()))
                        .decision());
        verifyNoInteractions(approvals);
    }

    @Test
    void credentialReviewMetadataDoesNotGrantRequestPermission() {
        var input = new HashMap<>(action);
        input.put(
                "credentials",
                List.of(
                        Map.of(
                                "placeholder",
                                "SERVICE_TOKEN",
                                "location",
                                "json",
                                "selector",
                                "/auth/token")));
        assertEquals(
                "DENY",
                evaluator.evaluateAction(new GatewayEvaluateRequest(profileId, input)).decision());
        verifyNoInteractions(approvals);
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void approvalSnapshotIncludesExactCredentialPlacementsWithoutSecrets() {
        var placement =
                Map.of(
                        "placeholder",
                        "SERVICE_TOKEN",
                        "location",
                        "json",
                        "selector",
                        "/auth/token");
        var credentialMatch = new HashMap<>(match);
        credentialMatch.put("credentials", List.of(placement));
        var rule = mock(AgentRuleEntity.class);
        UUID ruleId = UUID.randomUUID();
        when(rule.getId()).thenReturn(ruleId);
        when(rule.getEffect()).thenReturn(RuleEffect.REQUIRE_APPROVAL);
        when(rule.getMatch()).thenReturn(credentialMatch);
        entries.add(rule);
        var approval = mock(ApprovalRequestEntity.class);
        when(approval.getId()).thenReturn(UUID.randomUUID());
        when(approvals.createRequest(any(), any(), anyString(), anyMap())).thenReturn(approval);
        var input = new HashMap<>(action);
        input.put("credentials", List.of(placement));
        assertEquals(
                "REQUIRE_APPROVAL",
                evaluator.evaluateAction(new GatewayEvaluateRequest(profileId, input)).decision());
        ArgumentCaptor<Map<String, Object>> metadata = ArgumentCaptor.forClass((Class) Map.class);
        verify(approvals).createRequest(eq(ruleId), eq(profileId), anyString(), metadata.capture());
        assertEquals(
                List.of(placement),
                ((Map<?, ?>) metadata.getValue().get("action")).get("credentials"));
    }
}
