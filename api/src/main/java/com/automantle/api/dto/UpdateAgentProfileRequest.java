package com.automantle.api.dto;

import jakarta.validation.constraints.NotBlank;

public record UpdateAgentProfileRequest(@NotBlank String name) {}
