package com.automantle.api.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import org.hibernate.annotations.UuidGenerator;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "agent_profile")
public class AgentProfileEntity {

    @Id
    @GeneratedValue
    @UuidGenerator(style = UuidGenerator.Style.VERSION_7)
    private UUID id;

    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "setup_session_id")
    private UUID setupSessionId;

    @Column(name = "setup_expires_at")
    private Instant setupExpiresAt;

    public UUID getSetupSessionId() {
        return setupSessionId;
    }

    public Instant getSetupExpiresAt() {
        return setupExpiresAt;
    }

    public void setSetupSession(UUID id, Instant expiresAt) {
        setupSessionId = id;
        setupExpiresAt = expiresAt;
    }

    public boolean setupActive(UUID id) {
        return id != null
                && id.equals(setupSessionId)
                && setupExpiresAt != null
                && Instant.now().isBefore(setupExpiresAt);
    }

    public AgentProfileEntity() {}

    public AgentProfileEntity(String name) {
        setName(name);
    }

    public UUID getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        if (name == null || name.trim().isEmpty()) {
            throw new IllegalArgumentException("Agent Profile name cannot be empty");
        }
        this.name = name;
    }
}
