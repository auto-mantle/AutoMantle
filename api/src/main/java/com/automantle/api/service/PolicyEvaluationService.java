package com.automantle.api.service;

import com.automantle.api.dto.GatewayEvaluateRequest;
import com.automantle.api.dto.GatewayEvaluateResponse;
import com.automantle.api.entity.RuleEffect;
import com.automantle.api.policy.HttpAction;
import com.automantle.api.policy.PolicyDecisionEngine;
import com.automantle.api.policy.PolicyDecisionEngine.Decision;
import com.automantle.api.policy.PolicyDecisionEngine.MatchedRule;
import com.automantle.api.policy.PolicyDecisionEngine.Rule;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

@Service
public class PolicyEvaluationService {
    private static final int MAX_SUMMARY_LENGTH = 1000;
    private static final String SUMMARY_ELLIPSIS = "...";
    private static final String SETUP_APPROVAL_REASON = "Setup connection requires approval";

    private final AgentRuleService rules;
    private final ApprovalRequestService approvals;
    private final AgentProfileService profiles;
    private final RequestHistoryService history;
    private final PolicyDecisionEngine engine;

    public PolicyEvaluationService(
            AgentRuleService rules,
            ApprovalRequestService approvals,
            AgentProfileService profiles,
            RequestHistoryService history,
            PolicyDecisionEngine engine) {
        this.rules = rules;
        this.approvals = approvals;
        this.profiles = profiles;
        this.history = history;
        this.engine = engine;
    }

    @Transactional(isolation = Isolation.SERIALIZABLE)
    public GatewayEvaluateResponse evaluateAction(GatewayEvaluateRequest request) {
        var profile = profiles.getAgentProfile(request.agentProfileId());
        var applicableRules =
                rules.getAgentRulesByProfile(request.agentProfileId()).stream()
                        .map(rule -> new Rule(rule.getId(), rule.getEffect(), rule.getMatch()))
                        .toList();
        Decision decision = engine.evaluate(request.action(), applicableRules);
        UUID requestId = request.requestId() == null ? UUID.randomUUID() : request.requestId();
        boolean setup =
                profile.setupActive(request.setupSessionId()) && decision.isUnmatchedAction();
        if (!setup && decision.effect() != RuleEffect.REQUIRE_APPROVAL) {
            history.decision(requestId, request.agentProfileId(), decision, null);
            return new GatewayEvaluateResponse(
                    decision.effect().name(), decision.reason(), null, decision.matchedRules());
        }

        var metadata = approvalMetadata(request, decision);
        UUID ruleId = null;
        if (setup) {
            metadata.put("type", "SETUP");
            metadata.put("setupSessionId", request.setupSessionId().toString());
            metadata.put("matchedRules", List.of());
            decision =
                    new Decision(
                            RuleEffect.REQUIRE_APPROVAL,
                            SETUP_APPROVAL_REASON,
                            decision.action(),
                            List.of());
        } else {
            MatchedRule controllingRule = controllingRule(decision);
            ruleId = controllingRule.ruleId();
            metadata.put(
                    "matchedRules",
                    decision.matchedRules().stream().map(this::ruleSnapshot).toList());
        }

        var approval =
                approvals.createRequest(
                        ruleId, request.agentProfileId(), summarize(decision.action()), metadata);
        history.decision(requestId, request.agentProfileId(), decision, approval.getId());
        return new GatewayEvaluateResponse(
                RuleEffect.REQUIRE_APPROVAL.name(),
                decision.reason(),
                approval.getId(),
                decision.matchedRules());
    }

    private Map<String, Object> approvalMetadata(
            GatewayEvaluateRequest request, Decision decision) {
        var actionMetadata = new LinkedHashMap<>(decision.action().metadata());
        if (request.action().containsKey("credentials")) {
            actionMetadata.put("credentials", request.action().get("credentials"));
        }
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("action", actionMetadata);
        return metadata;
    }

    private MatchedRule controllingRule(Decision decision) {
        return decision.matchedRules().stream()
                .filter(rule -> rule.effect() == RuleEffect.REQUIRE_APPROVAL)
                .findFirst()
                .orElseThrow();
    }

    private Map<String, Object> ruleSnapshot(MatchedRule rule) {
        Map<String, Object> snapshot = new LinkedHashMap<>();
        snapshot.put("ruleId", rule.ruleId().toString());
        snapshot.put("effect", rule.effect().name());
        return snapshot;
    }

    private String summarize(HttpAction action) {
        String summary =
                action.method().toUpperCase(Locale.ROOT) + " " + action.host() + action.path();
        if (action.body() != null) {
            var body = action.body();
            summary += " [" + body.sizeBytes() + " bytes; sha256 " + body.sha256() + "]";
        }
        if (summary.length() > MAX_SUMMARY_LENGTH) {
            return summary.substring(0, MAX_SUMMARY_LENGTH - SUMMARY_ELLIPSIS.length())
                    + SUMMARY_ELLIPSIS;
        }
        return summary;
    }
}
