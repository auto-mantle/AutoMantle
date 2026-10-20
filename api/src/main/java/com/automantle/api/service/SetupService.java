package com.automantle.api.service;

import com.automantle.api.exception.ApprovalConflictException;
import com.automantle.api.repository.AgentProfileRepository;
import com.automantle.api.repository.ApprovalRequestRepository;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

@Service
public class SetupService {
    public static final int MAX_LIFETIME_SECONDS = 86_400;

    private final AgentProfileService profiles;
    private final AgentProfileRepository repository;
    private final ApprovalRequestRepository approvals;

    public SetupService(
            AgentProfileService profiles,
            AgentProfileRepository repository,
            ApprovalRequestRepository approvals) {
        this.profiles = profiles;
        this.repository = repository;
        this.approvals = approvals;
    }

    public record Session(UUID id, UUID agentProfileId, Instant expiresAt) {}

    @Transactional
    public Session start(UUID profileId, int lifetimeSeconds) {
        if (lifetimeSeconds < 1 || lifetimeSeconds > MAX_LIFETIME_SECONDS) {
            throw new IllegalArgumentException("Invalid setup lifetime");
        }
        var profile = profiles.getAgentProfile(profileId);
        if (profile.setupActive(profile.getSetupSessionId())) {
            throw new ApprovalConflictException("This profile already has an active setup run");
        }
        expirePendingApprovals(profile.getSetupSessionId());
        UUID sessionId = UUID.randomUUID();
        Instant expiresAt = Instant.now().plusSeconds(lifetimeSeconds);
        profile.setSetupSession(sessionId, expiresAt);
        repository.saveAndFlush(profile);
        return new Session(sessionId, profileId, expiresAt);
    }

    @Transactional
    public void finish(UUID profileId, UUID sessionId) {
        var profile = profiles.getAgentProfile(profileId);
        if (sessionId != null && !sessionId.equals(profile.getSetupSessionId())) {
            return;
        }
        expirePendingApprovals(profile.getSetupSessionId());
        profile.setSetupSession(null, null);
        repository.save(profile);
    }

    private void expirePendingApprovals(UUID sessionId) {
        if (sessionId != null) {
            approvals.expireSetupSession(sessionId.toString(), Instant.now());
        }
    }
}
