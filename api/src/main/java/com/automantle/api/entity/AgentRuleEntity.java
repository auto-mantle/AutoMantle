package com.automantle.api.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import org.hibernate.annotations.UuidGenerator;

import java.util.Map;
import java.util.UUID;

@Entity
@Table(name = "agent_rule")
public class AgentRuleEntity {

    @Id
    @GeneratedValue
    @UuidGenerator(style = UuidGenerator.Style.VERSION_7)
    private UUID id;

    @Column(name = "agent_profile_id", nullable = false)
    private UUID agentProfileId;

    @Enumerated(EnumType.STRING)
    @Column(name = "effect", nullable = false)
    private RuleEffect effect;

    @Convert(converter = JsonMapConverter.class)
    @Column(name = "rule_match", columnDefinition = "TEXT")
    private Map<String, Object> match;

    public AgentRuleEntity() {}

    public AgentRuleEntity(UUID agentProfileId, RuleEffect effect, Map<String, Object> match) {
        if (agentProfileId == null) {
            throw new IllegalArgumentException("Agent Profile ID cannot be null");
        }
        if (effect == null) {
            throw new IllegalArgumentException("Effect cannot be null");
        }
        this.agentProfileId = agentProfileId;
        this.effect = effect;
        this.match = match;
    }

    public UUID getId() {
        return id;
    }

    public UUID getAgentProfileId() {
        return agentProfileId;
    }

    public void setAgentProfileId(UUID agentProfileId) {
        if (agentProfileId == null) {
            throw new IllegalArgumentException("Agent Profile ID cannot be null");
        }
        this.agentProfileId = agentProfileId;
    }

    public RuleEffect getEffect() {
        return effect;
    }

    public void setEffect(RuleEffect effect) {
        if (effect == null) {
            throw new IllegalArgumentException("Effect cannot be null");
        }
        this.effect = effect;
    }

    public Map<String, Object> getMatch() {
        return match;
    }

    public void setMatch(Map<String, Object> match) {
        this.match = match;
    }
}
