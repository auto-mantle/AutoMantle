package com.automantle.api.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;

import org.hibernate.annotations.UuidGenerator;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.UUID;

@Entity
@Table(
        name = "approval_request",
        indexes = {
            @Index(name = "approval_created_id", columnList = "created_at,id"),
            @Index(name = "approval_pending_created", columnList = "status,created_at")
        })
public class ApprovalRequestEntity {

    @Id
    @GeneratedValue
    @UuidGenerator(style = UuidGenerator.Style.VERSION_7)
    private UUID id;

    @Column(name = "rule_id")
    private UUID ruleId;

    @Column(name = "agent_profile_id", nullable = false)
    private UUID agentProfileId;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    private ApprovalRequestStatus status;

    @Column(name = "action_summary", length = 1000)
    private String actionSummary;

    @Convert(converter = JsonMapConverter.class)
    @Column(name = "action_metadata", columnDefinition = "TEXT")
    private Map<String, Object> actionMetadata;

    @Enumerated(EnumType.STRING)
    @Column(name = "expiration_reason")
    private ApprovalExpirationReason expirationReason;

    public ApprovalExpirationReason getExpirationReason() {
        return expirationReason;
    }

    @Column(name = "resolved_by")
    private UUID resolvedBy;

    @Column(name = "resolved_at")
    private Instant resolvedAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    public ApprovalRequestEntity() {}

    public ApprovalRequestEntity(
            UUID ruleId,
            UUID agentProfileId,
            String actionSummary,
            Map<String, Object> actionMetadata) {
        this.ruleId = ruleId;
        this.agentProfileId = agentProfileId;
        this.status = ApprovalRequestStatus.PENDING;
        this.actionSummary = actionSummary;
        this.actionMetadata = actionMetadata;
    }

    @PrePersist
    protected void onCreate() {
        this.createdAt = Instant.now().truncatedTo(ChronoUnit.MICROS);
        this.updatedAt = Instant.now();
    }

    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = Instant.now();
    }

    public UUID getId() {
        return id;
    }

    public UUID getRuleId() {
        return ruleId;
    }

    public void setRuleId(UUID ruleId) {
        this.ruleId = ruleId;
    }

    public UUID getAgentProfileId() {
        return agentProfileId;
    }

    public void setAgentProfileId(UUID agentProfileId) {
        this.agentProfileId = agentProfileId;
    }

    public ApprovalRequestStatus getStatus() {
        return status;
    }

    public void setStatus(ApprovalRequestStatus status) {
        this.status = status;
    }

    public String getActionSummary() {
        return actionSummary;
    }

    public void setActionSummary(String actionSummary) {
        this.actionSummary = actionSummary;
    }

    public Map<String, Object> getActionMetadata() {
        return actionMetadata;
    }

    public void setActionMetadata(Map<String, Object> actionMetadata) {
        this.actionMetadata = actionMetadata;
    }

    public UUID getResolvedBy() {
        return resolvedBy;
    }

    public void setResolvedBy(UUID resolvedBy) {
        this.resolvedBy = resolvedBy;
    }

    public Instant getResolvedAt() {
        return resolvedAt;
    }

    public void setResolvedAt(Instant resolvedAt) {
        this.resolvedAt = resolvedAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }
}
