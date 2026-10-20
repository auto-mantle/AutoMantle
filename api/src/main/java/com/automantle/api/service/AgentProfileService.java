package com.automantle.api.service;

import com.automantle.api.entity.AgentProfileEntity;
import com.automantle.api.exception.ResourceNotFoundException;
import com.automantle.api.repository.AgentProfileRepository;
import com.automantle.api.util.NameUtil;

import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
public class AgentProfileService {

    private final AgentProfileRepository agentProfileRepository;

    public AgentProfileService(AgentProfileRepository agentProfileRepository) {
        this.agentProfileRepository = agentProfileRepository;
    }

    public AgentProfileEntity createAgentProfile(String rawName) {
        String name = normalizeName(rawName);
        requireAvailableName(name);

        AgentProfileEntity agentProfile = new AgentProfileEntity(name);
        return agentProfileRepository.save(agentProfile);
    }

    public AgentProfileEntity updateAgentProfile(UUID id, String rawName) {
        AgentProfileEntity agentProfile = getAgentProfile(id);

        String newName = normalizeName(rawName);

        if (!agentProfile.getName().equals(newName)) {
            requireAvailableName(newName);
            agentProfile.setName(newName);
        }

        return agentProfileRepository.save(agentProfile);
    }

    public AgentProfileEntity getAgentProfile(UUID id) {
        return agentProfileRepository
                .findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Agent Profile not found"));
    }

    public List<AgentProfileEntity> getAgentProfiles() {
        return agentProfileRepository.findAll();
    }

    public void deleteAgentProfile(UUID id) {
        agentProfileRepository.delete(getAgentProfile(id));
    }

    private String normalizeName(String rawName) {
        String name = NameUtil.generateName(rawName);
        if (name.isEmpty()) {
            throw new IllegalArgumentException("Agent Profile name cannot be empty");
        }
        return name;
    }

    private void requireAvailableName(String name) {
        if (agentProfileRepository.existsByName(name)) {
            throw new IllegalArgumentException("An Agent Profile with this name already exists.");
        }
    }
}
