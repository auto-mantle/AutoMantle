package com.automantle.api.service;

import com.automantle.api.dto.ApprovalRequestResponse;
import com.automantle.api.entity.ApprovalExpirationReason;
import com.automantle.api.entity.ApprovalRequestEntity;
import com.automantle.api.entity.ApprovalRequestStatus;
import com.automantle.api.entity.RuleEffect;
import com.automantle.api.exception.ApprovalConflictException;
import com.automantle.api.exception.ResourceNotFoundException;
import com.automantle.api.policy.HttpAction;
import com.automantle.api.policy.HttpPolicyContract;
import com.automantle.api.policy.PolicyDecisionEngine;
import com.automantle.api.policy.PolicyDecisionEngine.Rule;
import com.automantle.api.repository.ApprovalRequestRepository;

import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class ApprovalRequestService {

    private static final int MAX_PAGE = 100_000;
    private static final int MAX_PAGE_SIZE = 100;
    private final PolicyDecisionEngine engine;
    private final HttpPolicyContract contract;
    private final ApprovalRequestRepository repository;
    private final AgentRuleService rules;
    private final AgentProfileService profiles;

    public ApprovalRequestService(
            ApprovalRequestRepository repository,
            AgentRuleService rules,
            AgentProfileService profiles,
            PolicyDecisionEngine engine,
            HttpPolicyContract contract) {
        this.repository = repository;
        this.rules = rules;
        this.profiles = profiles;
        this.engine = engine;
        this.contract = contract;
    }

    @Transactional
    public ApprovalRequestEntity createRequest(
            UUID ruleId,
            UUID agentProfileId,
            String actionSummary,
            Map<String, Object> actionMetadata) {
        ApprovalRequestEntity entity =
                new ApprovalRequestEntity(ruleId, agentProfileId, actionSummary, actionMetadata);
        return repository.save(entity);
    }

    @Transactional
    public ApprovalRequestResponse getRequest(UUID id) {
        ApprovalRequestEntity entity = findRequest(id);

        return mapToResponse(entity);
    }

    @Transactional
    public List<ApprovalRequestResponse> getRequests() {
        return getRequests(0, MAX_PAGE_SIZE, false, false);
    }

    @Transactional
    public List<ApprovalRequestResponse> getRequests(
            int page, int limit, boolean pending, boolean setupOnly) {
        if (page < 0 || page > MAX_PAGE || limit < 1 || limit > MAX_PAGE_SIZE) {
            throw new IllegalArgumentException("Invalid approval page or limit");
        }
        var pageable = PageRequest.of(page, limit);
        List<ApprovalRequestEntity> entities =
                pending
                        ? repository.findPending(setupOnly, pageable)
                        : repository.findAllByOrderByCreatedAtDescIdDesc(pageable);
        return entities.stream().map(this::mapToResponse).collect(Collectors.toList());
    }

    @Transactional
    public ApprovalRequestResponse resolveRequest(
            UUID id, ApprovalRequestStatus decision, UUID resolvedBy) {
        return resolveRequest(id, decision, resolvedBy, false);
    }

    @Transactional
    public ApprovalRequestResponse resolveRequest(
            UUID id, ApprovalRequestStatus decision, UUID resolvedBy, boolean saveRule) {
        if (decision != ApprovalRequestStatus.APPROVED
                && decision != ApprovalRequestStatus.REJECTED) {
            throw new IllegalArgumentException("Decision must be APPROVED or REJECTED");
        }
        ApprovalRequestEntity pending = findRequest(id);
        HttpAction setupAction = validateSetupResolution(pending, decision, saveRule);
        int changed = repository.resolvePendingRequest(id, decision, resolvedBy, Instant.now());
        ApprovalRequestEntity entity = findRequest(id);
        if (changed == 0) {
            throw new ApprovalConflictException(
                    "This request is no longer pending. Refresh and try again.");
        }
        if (setupAction != null) {
            saveSetupRule(entity.getAgentProfileId(), setupAction);
        }
        return mapToResponse(entity);
    }

    @Transactional
    public void expireUnexecutedRequest(UUID id, UUID profileId, ApprovalExpirationReason reason) {
        if (profileId == null || reason == null) {
            throw new IllegalArgumentException(
                    "Request profile and expiration reason are required");
        }
        var request = findRequest(id);
        if (!profileId.equals(request.getAgentProfileId())) {
            throw new ResourceNotFoundException("Approval request not found");
        }
        repository.expireUnexecutedRequest(id, profileId, reason, Instant.now());
    }

    private ApprovalRequestEntity findRequest(UUID id) {
        return repository
                .findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Approval request not found"));
    }

    private HttpAction validateSetupResolution(
            ApprovalRequestEntity request, ApprovalRequestStatus decision, boolean saveRule) {
        var metadata = request.getActionMetadata();
        boolean setup = metadata != null && "SETUP".equals(metadata.get("type"));
        if (saveRule && (!setup || decision != ApprovalRequestStatus.APPROVED)) {
            throw new IllegalArgumentException("Only setup approval can save a rule");
        }
        if (!setup || decision != ApprovalRequestStatus.APPROVED) {
            return null;
        }
        if (!saveRule) {
            throw new IllegalArgumentException("Use Allow and save for a setup connection");
        }
        var profile = profiles.getAgentProfile(request.getAgentProfileId());
        UUID sessionId = UUID.fromString((String) metadata.get("setupSessionId"));
        if (!profile.setupActive(sessionId)) {
            throw new ApprovalConflictException("Setup has ended or expired");
        }
        @SuppressWarnings("unchecked")
        var action = (Map<String, Object>) metadata.get("action");
        HttpAction setupAction = contract.action(action);
        var currentRules =
                rules.getAgentRulesByProfile(profile.getId()).stream()
                        .map(rule -> new Rule(rule.getId(), rule.getEffect(), rule.getMatch()))
                        .toList();
        var current = engine.evaluate(action, currentRules);
        if (current.effect() == RuleEffect.DENY
                && !current.reason().equals(PolicyDecisionEngine.NO_MATCHING_RULE_REASON)) {
            throw new ApprovalConflictException("A current rule blocks this setup connection");
        }
        if (current.effect() == RuleEffect.REQUIRE_APPROVAL) {
            throw new ApprovalConflictException(
                    "A current rule requires a separate approval; retry the request");
        }
        return setupAction;
    }

    private void saveSetupRule(UUID profileId, HttpAction action) {
        var match =
                Map.<String, Object>of(
                        "resource_type",
                        "http",
                        "action",
                        List.of(action.method()),
                        "hosts",
                        List.of(action.host()),
                        "resource",
                        List.of(action.path()));
        boolean exists =
                rules.getAgentRulesByProfile(profileId).stream()
                        .anyMatch(
                                rule ->
                                        rule.getEffect() == RuleEffect.ALLOW
                                                && match.equals(rule.getMatch()));
        if (!exists) {
            rules.createAgentRule(profileId, RuleEffect.ALLOW, match);
        }
    }

    private ApprovalRequestResponse mapToResponse(ApprovalRequestEntity entity) {
        return new ApprovalRequestResponse(
                entity.getId(),
                entity.getRuleId(),
                entity.getAgentProfileId(),
                entity.getStatus(),
                entity.getActionSummary(),
                entity.getActionMetadata(),
                entity.getResolvedBy(),
                entity.getResolvedAt(),
                entity.getCreatedAt(),
                entity.getExpirationReason(),
                entity.getExpirationReason() == null
                        ? null
                        : entity.getExpirationReason().message());
    }
}
