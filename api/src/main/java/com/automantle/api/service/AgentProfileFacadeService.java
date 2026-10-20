package com.automantle.api.service;

import com.automantle.api.dto.AgentProfileResponse;
import com.automantle.api.dto.CreateAgentProfileRequest;
import com.automantle.api.dto.UpdateAgentProfileRequest;
import com.automantle.api.entity.AgentProfileEntity;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

@Service
public class AgentProfileFacadeService {

    private final AgentProfileService agentProfileService;

    public AgentProfileFacadeService(AgentProfileService agentProfileService) {
        this.agentProfileService = agentProfileService;
    }

    @Transactional
    public AgentProfileResponse createProfile(CreateAgentProfileRequest request) {
        AgentProfileEntity profile = agentProfileService.createAgentProfile(request.name());
        return mapToResponse(profile);
    }

    @Transactional(readOnly = true)
    public List<AgentProfileResponse> getProfiles() {
        List<AgentProfileEntity> profiles = agentProfileService.getAgentProfiles();
        return profiles.stream().map(this::mapToResponse).toList();
    }

    @Transactional(readOnly = true)
    public AgentProfileResponse getProfile(UUID profileId) {
        AgentProfileEntity profile = agentProfileService.getAgentProfile(profileId);
        return mapToResponse(profile);
    }

    @Transactional
    public AgentProfileResponse updateProfile(UUID profileId, UpdateAgentProfileRequest request) {
        AgentProfileEntity updated =
                agentProfileService.updateAgentProfile(profileId, request.name());
        return mapToResponse(updated);
    }

    @Transactional
    public void deleteProfile(UUID profileId) {
        agentProfileService.deleteAgentProfile(profileId);
    }

    private AgentProfileResponse mapToResponse(AgentProfileEntity entity) {
        return new AgentProfileResponse(
                entity.getId(),
                entity.getName(),
                entity.setupActive(entity.getSetupSessionId()) ? entity.getSetupExpiresAt() : null);
    }
}
