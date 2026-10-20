package com.automantle.api.dto;

import java.time.Instant;
import java.util.UUID;

public record AgentProfileResponse(UUID id, String name, Instant setupExpiresAt) {}
