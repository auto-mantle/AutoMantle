package com.automantle.api.dto;

import jakarta.validation.constraints.NotBlank;

public record CreateAgentProfileRequest(@NotBlank String name) {}
