package com.automantle.api.service;

import com.automantle.api.dto.ReportNetworkHistory;
import com.automantle.api.dto.ReportRequestHistory;
import com.automantle.api.entity.AgentProfileEntity;
import com.automantle.api.entity.ApprovalRequestEntity;
import com.automantle.api.entity.ApprovalRequestStatus;
import com.automantle.api.entity.RequestHistoryEntity;
import com.automantle.api.entity.RuleEffect;
import com.automantle.api.policy.PolicyDecisionEngine.Decision;
import com.automantle.api.repository.AgentProfileRepository;
import com.automantle.api.repository.ApprovalRequestRepository;
import com.automantle.api.repository.RequestHistoryRepository;

import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

@Service
public class RequestHistoryService {
    public static final int MAX_RECORDS = 10_000;
    public static final int RETENTION_DAYS = 30;
    private static final int PAGE_SIZE = 100;
    private static final int MAX_NETWORK_BATCH_SIZE = 128;
    private static final String ALLOWED = "ALLOWED";
    private static final String DENIED = "DENIED";
    private static final String AWAITING_APPROVAL = "AWAITING_APPROVAL";
    private static final String CANCELLED = "CANCELLED";
    private static final String FAILED = "FAILED";
    private final RequestHistoryRepository history;
    private final AgentProfileRepository profiles;
    private final ApprovalRequestRepository approvals;

    public RequestHistoryService(
            RequestHistoryRepository history,
            AgentProfileRepository profiles,
            ApprovalRequestRepository approvals) {
        this.history = history;
        this.profiles = profiles;
        this.approvals = approvals;
    }

    private RequestHistoryEntity create(UUID requestId, UUID profileId) {
        var entity = new RequestHistoryEntity();
        entity.requestId = requestId;
        entity.agentProfileId = profileId;
        entity.agentName =
                profiles.findById(profileId)
                        .map(AgentProfileEntity::getName)
                        .orElse("Deleted or unknown profile");
        entity.createdAt = Instant.now();
        return entity;
    }

    @Transactional
    public void decision(UUID requestId, UUID profileId, Decision decision, UUID approvalId) {
        var entity =
                history.findByRequestId(requestId).orElseGet(() -> create(requestId, profileId));
        if (!profileId.equals(entity.agentProfileId)) {
            throw new IllegalArgumentException("Request profile mismatch");
        }
        var action = decision.action();
        if (action != null) {
            entity.host = action.host();
            entity.method = action.method().toUpperCase(Locale.ROOT);
            entity.path = action.path();
        }
        entity.result = decisionResult(decision);
        entity.reason = decisionReason(decision);
        entity.matchedRules =
                String.join(
                        ", ",
                        decision.matchedRules().stream().map(r -> r.ruleId().toString()).toList());
        entity.approvalId = approvalId;
        history.saveAndFlush(entity);
        prune();
    }

    @Transactional
    public void report(ReportRequestHistory report) {
        var found = history.findByRequestId(report.requestId());
        if (found.isEmpty() && report.reason() == ReportRequestHistory.Reason.COMPLETED) {
            return;
        }
        var entity = found.orElseGet(() -> create(report.requestId(), report.agentProfileId()));
        if (!report.agentProfileId().equals(entity.agentProfileId)) {
            throw new IllegalArgumentException("Request profile mismatch");
        }
        if (report.host() != null) {
            entity.host = report.host();
        }
        if (report.port() != null) {
            entity.port = report.port();
        }
        if (report.method() != null) {
            entity.method = report.method();
        }
        if (report.path() != null && report.path().matches("/[A-Za-z0-9/_~!$&'()+,;=:@.\\-]*")) {
            entity.path = report.path();
        }
        if (report.reason() != ReportRequestHistory.Reason.COMPLETED) {
            entity.result = reportResult(report.reason());
            entity.reason = reportReason(report.reason());
        }
        history.saveAndFlush(entity);
        prune();
    }

    @Transactional
    public void reportNetwork(List<ReportNetworkHistory> events) {
        if (events == null || events.isEmpty() || events.size() > MAX_NETWORK_BATCH_SIZE) {
            throw new IllegalArgumentException("Invalid network audit batch");
        }
        for (var report : events) {
            if (report.packetCount() < 1 || report.byteCount() < 0) {
                throw new IllegalArgumentException("Invalid network audit counts");
            }
            var found = history.findByRequestId(report.requestId());
            if (found.isPresent()) {
                if (!report.agentProfileId().equals(found.get().agentProfileId)) {
                    throw new IllegalArgumentException("Request profile mismatch");
                }
                continue;
            }
            var entity = create(report.requestId(), report.agentProfileId());
            entity.runId = report.runId();
            entity.etherType = report.etherType();
            entity.protocol = report.protocol();
            entity.sourceIp = report.sourceIp();
            entity.destinationIp = report.destinationIp();
            entity.sourcePort = report.sourcePort();
            entity.port = report.destinationPort();
            entity.packetCount = report.packetCount();
            entity.byteCount = report.byteCount();
            entity.result = networkResult(report.reason());
            entity.reason = networkReason(report.reason());
            history.save(entity);
        }
        history.flush();
        prune();
    }

    public record Entry(
            Long id,
            Instant time,
            UUID agentProfileId,
            String agentName,
            String host,
            Integer port,
            String method,
            String path,
            String result,
            String reason,
            String matchedRules,
            UUID approvalId,
            String runId,
            Integer etherType,
            String protocol,
            String sourceIp,
            String destinationIp,
            Integer sourcePort,
            Long packetCount,
            Long byteCount) {}

    public record Page(List<Entry> items, Long nextBefore, int retentionDays, int maxRecords) {}

    @Transactional
    public Page recent(Long before, UUID profile) {
        prune();
        var rows = history.recent(before, profile, PageRequest.of(0, PAGE_SIZE + 1));
        boolean more = rows.size() > PAGE_SIZE;
        if (more) {
            rows = rows.subList(0, PAGE_SIZE);
        }
        var approvalIds = rows.stream().map(h -> h.approvalId).filter(Objects::nonNull).toList();
        Map<UUID, ApprovalRequestEntity> states = new HashMap<>();
        approvals.findAllById(approvalIds).forEach(a -> states.put(a.getId(), a));
        var items = rows.stream().map(row -> toEntry(row, states.get(row.approvalId))).toList();
        return new Page(items, more ? rows.getLast().id : null, RETENTION_DAYS, MAX_RECORDS);
    }

    private String decisionResult(Decision decision) {
        return switch (decision.effect()) {
            case ALLOW -> ALLOWED;
            case DENY -> DENIED;
            case REQUIRE_APPROVAL -> AWAITING_APPROVAL;
        };
    }

    private String decisionReason(Decision decision) {
        if (decision.action() == null) {
            return "Invalid or unsupported request";
        }
        if (decision.matchedRules().isEmpty()) {
            if (decision.effect() == RuleEffect.REQUIRE_APPROVAL) {
                return "Setup connection requires approval";
            }
            return decision.reason().startsWith("Invalid applicable rule")
                    ? "Invalid applicable rule"
                    : "No matching allow rule";
        }
        return switch (decision.effect()) {
            case ALLOW -> "Matching rules allow this request";
            case DENY -> "A matching rule explicitly denies this request";
            case REQUIRE_APPROVAL -> "A matching rule requires approval";
        };
    }

    private String reportResult(ReportRequestHistory.Reason reason) {
        return switch (reason) {
            case INVALID_REQUEST,
                    HTTPS_DISABLED,
                    DOWNSTREAM_TLS_FAILED,
                    INVALID_BODY,
                    CREDENTIAL_BINDING_DENIED,
                    PRIVATE_DESTINATION ->
                    DENIED;
            case CANCELLED -> CANCELLED;
            default -> FAILED;
        };
    }

    private String reportReason(ReportRequestHistory.Reason reason) {
        return switch (reason) {
            case INVALID_REQUEST -> "Policy denied: malformed or unsupported request";
            case HTTPS_DISABLED -> "Policy denied: HTTPS inspection is not enabled";
            case DOWNSTREAM_TLS_FAILED ->
                    "Policy denied: guest TLS could not be inspected; check gateway CA trust";
            case INVALID_BODY -> "Unsupported, incomplete, or invalid JSON body";
            case CREDENTIAL_BINDING_DENIED ->
                    "Credential binding does not permit this destination or action";
            case FORWARDING_UNSUPPORTED ->
                    "Policy allowed request, but protocol forwarding is not implemented";
            case POLICY_UNAVAILABLE -> "Policy evaluation or approval verification failed";
            case DNS_FAILED -> "Destination resolution failed";
            case PRIVATE_DESTINATION -> "Private or special-use destination blocked";
            case CONNECT_FAILED -> "Upstream connection failed";
            case UPSTREAM_TLS_FAILED -> "Upstream TLS verification or handshake failed";
            case RESPONSE_BLOCKED ->
                    "Response framing, size, encoding, or credential echo check failed";
            case IO_FAILED -> "Connection interrupted or timed out";
            case CANCELLED -> "VM stopped or request deadline reached";
            case COMPLETED -> throw new IllegalStateException();
        };
    }

    private String networkResult(ReportNetworkHistory.Reason reason) {
        return switch (reason) {
            case INSPECTION_TRANSPORT -> "INSPECTED";
            case LINK_CONTROL -> "LINK_CONTROL";
            default -> DENIED;
        };
    }

    private String networkReason(ReportNetworkHistory.Reason reason) {
        return switch (reason) {
            case INSPECTION_TRANSPORT ->
                    "Transport handed to HTTP/HTTPS inspection; upstream permission checked"
                            + " separately";
            case LINK_CONTROL -> "Policy permits local ARP for the inspection interface";
            case UNSUPPORTED_NETWORK ->
                    "Policy denied: network protocol or direct transport is not supported";
            case MALFORMED_NETWORK -> "Policy denied: malformed or unreadable network frame";
            case SOURCE_BINDING_DENIED ->
                    "Policy denied: VM source or link identity does not match";
        };
    }

    private Entry toEntry(RequestHistoryEntity entity, ApprovalRequestEntity approval) {
        String result = entity.result;
        String reason = entity.reason;
        if (approval != null
                && (AWAITING_APPROVAL.equals(result)
                        || approval.getStatus() == ApprovalRequestStatus.EXPIRED)) {
            var status = approval.getStatus();
            switch (status) {
                case APPROVED -> {
                    result = ALLOWED;
                    reason = "Human approval granted";
                }
                case REJECTED -> {
                    result = DENIED;
                    reason = "Human approval rejected";
                }
                case EXPIRED -> {
                    result = DENIED;
                    reason =
                            approval.getExpirationReason() == null
                                    ? "Approval expired before execution"
                                    : approval.getExpirationReason().message();
                }
                case PENDING -> {}
            }
        }
        return new Entry(
                entity.id,
                entity.createdAt,
                entity.agentProfileId,
                entity.agentName,
                entity.host,
                entity.port,
                entity.method,
                entity.path,
                result,
                reason,
                entity.matchedRules,
                entity.approvalId,
                entity.runId,
                entity.etherType,
                entity.protocol,
                entity.sourceIp,
                entity.destinationIp,
                entity.sourcePort,
                entity.packetCount,
                entity.byteCount);
    }

    @Transactional
    public void clear() {
        history.deleteAllInBatch();
    }

    @Scheduled(fixedDelay = 3_600_000)
    @Transactional
    public void prune() {
        history.deleteExpired(Instant.now().minus(RETENTION_DAYS, ChronoUnit.DAYS));
        if (history.count() > MAX_RECORDS) {
            var overflow =
                    history.findAll(PageRequest.of(MAX_RECORDS, 1, Sort.by("id").descending()));
            if (!overflow.isEmpty()) {
                history.deleteThrough(overflow.getContent().getFirst().id);
            }
        }
    }
}
