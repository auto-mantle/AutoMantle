package com.automantle.api.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "request_history")
public class RequestHistoryEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    public Long id;

    @Column(name = "request_id", nullable = false)
    public UUID requestId;

    @Column(name = "agent_profile_id", nullable = false)
    public UUID agentProfileId;

    @Column(name = "agent_name", nullable = false)
    public String agentName;

    @Column(name = "created_at", nullable = false)
    public Instant createdAt;

    @Column(name = "host")
    public String host;

    @Column(name = "port")
    public Integer port;

    @Column(name = "method")
    public String method;

    @Column(name = "path", length = 2048)
    public String path;

    @Column(name = "result", nullable = false)
    public String result;

    @Column(name = "reason", nullable = false)
    public String reason;

    @Column(name = "matched_rules", columnDefinition = "TEXT")
    public String matchedRules;

    @Column(name = "approval_id")
    public UUID approvalId;

    @Column(name = "run_id")
    public String runId;

    @Column(name = "ether_type")
    public Integer etherType;

    @Column(name = "network_protocol")
    public String protocol;

    @Column(name = "source_ip")
    public String sourceIp;

    @Column(name = "destination_ip")
    public String destinationIp;

    @Column(name = "source_port")
    public Integer sourcePort;

    @Column(name = "packet_count")
    public Long packetCount;

    @Column(name = "byte_count")
    public Long byteCount;
}
