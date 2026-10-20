package com.automantle.api.controller;

import com.automantle.api.service.SetupService;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
public class SetupController {
    private final SetupService setup;

    public SetupController(SetupService setup) {
        this.setup = setup;
    }

    public record Start(
            @NotNull UUID agentProfileId,
            @Min(1) @Max(SetupService.MAX_LIFETIME_SECONDS) int lifetimeSeconds) {}

    @PostMapping("/gateway/setup")
    @ResponseStatus(HttpStatus.CREATED)
    public SetupService.Session start(@Valid @RequestBody Start request) {
        return setup.start(request.agentProfileId(), request.lifetimeSeconds());
    }

    @PostMapping("/gateway/setup/{profileId}/{sessionId}/finish")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void gatewayFinish(@PathVariable UUID profileId, @PathVariable UUID sessionId) {
        setup.finish(profileId, sessionId);
    }

    @PostMapping("/agents/profiles/{profileId}/setup/finish")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void finish(@PathVariable UUID profileId) {
        setup.finish(profileId, null);
    }
}
