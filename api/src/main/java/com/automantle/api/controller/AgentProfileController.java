package com.automantle.api.controller;

import com.automantle.api.dto.AgentProfileResponse;
import com.automantle.api.dto.CreateAgentProfileRequest;
import com.automantle.api.dto.UpdateAgentProfileRequest;
import com.automantle.api.service.AgentProfileFacadeService;

import jakarta.validation.Valid;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/agents/profiles")
public class AgentProfileController {

    private final AgentProfileFacadeService agentProfileFacadeService;

    public AgentProfileController(AgentProfileFacadeService agentProfileFacadeService) {
        this.agentProfileFacadeService = agentProfileFacadeService;
    }

    @PostMapping
    public ResponseEntity<AgentProfileResponse> createProfile(
            @Valid @RequestBody CreateAgentProfileRequest request) {
        AgentProfileResponse response = agentProfileFacadeService.createProfile(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping
    public ResponseEntity<List<AgentProfileResponse>> getProfiles() {
        List<AgentProfileResponse> responses = agentProfileFacadeService.getProfiles();
        return ResponseEntity.ok(responses);
    }

    @GetMapping("/{profileId}")
    public ResponseEntity<AgentProfileResponse> getProfile(@PathVariable UUID profileId) {
        AgentProfileResponse response = agentProfileFacadeService.getProfile(profileId);
        return ResponseEntity.ok(response);
    }

    @PatchMapping("/{profileId}")
    public ResponseEntity<AgentProfileResponse> updateProfile(
            @PathVariable UUID profileId, @Valid @RequestBody UpdateAgentProfileRequest request) {
        AgentProfileResponse response = agentProfileFacadeService.updateProfile(profileId, request);
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/{profileId}")
    public ResponseEntity<Void> deleteProfile(@PathVariable UUID profileId) {
        agentProfileFacadeService.deleteProfile(profileId);
        return ResponseEntity.noContent().build();
    }
}
