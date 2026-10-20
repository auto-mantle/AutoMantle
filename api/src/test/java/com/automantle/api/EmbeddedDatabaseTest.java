package com.automantle.api;

import static org.junit.jupiter.api.Assertions.*;

import com.automantle.api.dto.GatewayEvaluateRequest;
import com.automantle.api.dto.ReportRequestHistory;
import com.automantle.api.entity.*;
import com.automantle.api.entity.ApprovalExpirationReason;
import com.automantle.api.exception.ApprovalConflictException;
import com.automantle.api.repository.*;
import com.automantle.api.service.*;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.*;

class EmbeddedDatabaseTest {
    @TempDir Path directory;

    private ConfigurableApplicationContext open() {
        return new SpringApplicationBuilder(ApiApplication.class)
                .run(
                        "--server.port=0",
                        "--spring.config.import=",
                        "--AUTOMANTLE_DATA_DIR="
                                + directory.toAbsolutePath().toString().replace('\\', '/'),
                        "--logging.level.root=ERROR",
                        "--spring.main.banner-mode=off");
    }

    @Test
    void profileRulesJsonAndApprovalHistorySurviveRestart() throws Exception {
        UUID profileId, ruleId, approvalId;
        Map<String, Object> match =
                Map.of(
                        "resource_type",
                        "http",
                        "action",
                        List.of("post"),
                        "hosts",
                        List.of("api.example.com"),
                        "resource",
                        List.of("/api/*"));
        Map<String, Object> metadata;
        try (var app = open()) {
            profileId =
                    app.getBean(AgentProfileRepository.class)
                            .saveAndFlush(new AgentProfileEntity("local agent"))
                            .getId();
            var rule = new AgentRuleEntity(profileId, RuleEffect.REQUIRE_APPROVAL, match);
            ruleId = app.getBean(AgentRuleRepository.class).saveAndFlush(rule).getId();
            var result =
                    app.getBean(PolicyEvaluationService.class)
                            .evaluateAction(
                                    new GatewayEvaluateRequest(
                                            profileId,
                                            Map.of(
                                                    "resource_type",
                                                    "http",
                                                    "method",
                                                    "POST",
                                                    "host",
                                                    "api.example.com",
                                                    "path",
                                                    "/api/users")));
            assertEquals("REQUIRE_APPROVAL", result.decision());
            approvalId = result.approvalRequestId();
            var approvals = app.getBean(ApprovalRequestService.class);
            metadata = approvals.getRequest(approvalId).actionMetadata();
            assertInstanceOf(Map.class, metadata.get("action"));
            assertInstanceOf(List.class, metadata.get("matchedRules"));
            approvals.resolveRequest(approvalId, ApprovalRequestStatus.APPROVED, null);
        }
        assertTrue(directory.resolve("automantle.sqlite").toFile().isFile());
        try (var file =
                java.nio.file.Files.newInputStream(directory.resolve("automantle.sqlite"))) {
            assertEquals(
                    "SQLite format 3\0",
                    new String(file.readNBytes(16), java.nio.charset.StandardCharsets.UTF_8));
        }
        try (var app = open()) {
            assertEquals(
                    "local agent",
                    app.getBean(AgentProfileRepository.class)
                            .findById(profileId)
                            .orElseThrow()
                            .getName());
            var rules = app.getBean(AgentRuleRepository.class);
            assertEquals(match, rules.findById(ruleId).orElseThrow().getMatch());
            var rule = rules.findById(ruleId).orElseThrow();
            rule.setMatch(Map.of("resource_type", "http", "action", List.of("get")));
            rules.saveAndFlush(rule);
            assertEquals(
                    List.of("get"), rules.findById(ruleId).orElseThrow().getMatch().get("action"));
            var saved = app.getBean(ApprovalRequestService.class).getRequest(approvalId);
            assertEquals(ApprovalRequestStatus.APPROVED, saved.status());
            assertEquals(metadata, saved.actionMetadata());
            var event =
                    app.getBean(RequestHistoryService.class)
                            .recent(null, profileId)
                            .items()
                            .getFirst();
            assertEquals("ALLOWED", event.result());
            assertEquals("Human approval granted", event.reason());
            assertEquals(approvalId, event.approvalId());
        }
    }

    @Test
    void profilesAndRulesHaveNoAuditColumnsAndProfileDeletionRemovesTheRow() throws Exception {
        try (var app = open()) {
            var profiles = app.getBean(AgentProfileFacadeService.class);
            var repository = app.getBean(AgentProfileRepository.class);
            var profile =
                    profiles.createProfile(
                            new com.automantle.api.dto.CreateAgentProfileRequest(
                                    "temporary agent"));
            UUID id = profile.id();
            assertThrows(
                    IllegalArgumentException.class,
                    () ->
                            profiles.createProfile(
                                    new com.automantle.api.dto.CreateAgentProfileRequest(
                                            "temporary agent")));

            var renamed =
                    profiles.updateProfile(
                            id,
                            new com.automantle.api.dto.UpdateAgentProfileRequest("renamed agent"));
            assertEquals("renamed-agent", profiles.getProfile(id).name());
            var json =
                    tools.jackson.databind.json.JsonMapper.builder().build().valueToTree(renamed);
            for (String field : List.of("createdAt", "updatedAt", "deletedAt")) {
                assertFalse(json.has(field));
            }

            try (var connection = app.getBean(javax.sql.DataSource.class).getConnection();
                    var statement = connection.createStatement()) {
                for (String table : List.of("agent_profile", "agent_rule")) {
                    try (var columns = statement.executeQuery("PRAGMA table_info(" + table + ")")) {
                        Set<String> names = new HashSet<>();
                        while (columns.next()) {
                            names.add(columns.getString("name"));
                        }
                        assertTrue(names.contains("id"));
                        assertTrue(
                                Collections.disjoint(
                                        names, Set.of("created_at", "updated_at", "deleted_at")));
                    }
                }
            }

            profiles.deleteProfile(id);
            assertFalse(repository.existsById(id));
            assertTrue(profiles.getProfiles().isEmpty());
            assertThrows(
                    com.automantle.api.exception.ResourceNotFoundException.class,
                    () -> profiles.getProfile(id));
            var replacement =
                    profiles.createProfile(
                            new com.automantle.api.dto.CreateAgentProfileRequest("renamed agent"));
            assertNotEquals(id, replacement.id());
        }
    }

    @Test
    void concurrentDecisionsHaveExactlyOneWinner() throws Exception {
        try (var app = open();
                var executor = Executors.newFixedThreadPool(2)) {
            var approvals = app.getBean(ApprovalRequestService.class);
            var request =
                    approvals.createRequest(
                            UUID.randomUUID(), UUID.randomUUID(), "review", Map.of());
            var ready = new CountDownLatch(2);
            var start = new CountDownLatch(1);
            List<Future<Boolean>> results = new ArrayList<>();
            for (var decision :
                    List.of(ApprovalRequestStatus.APPROVED, ApprovalRequestStatus.REJECTED)) {
                results.add(
                        executor.submit(
                                () -> {
                                    ready.countDown();
                                    assertTrue(start.await(10, TimeUnit.SECONDS));
                                    try {
                                        approvals.resolveRequest(request.getId(), decision, null);
                                        return true;
                                    } catch (ApprovalConflictException expected) {
                                        return false;
                                    }
                                }));
            }
            assertTrue(ready.await(10, TimeUnit.SECONDS));
            start.countDown();
            assertEquals(
                    1,
                    (results.get(0).get(10, TimeUnit.SECONDS) ? 1 : 0)
                            + (results.get(1).get(10, TimeUnit.SECONDS) ? 1 : 0));
            var status = approvals.getRequest(request.getId()).status();
            assertEquals(status, approvals.getRequest(request.getId()).status());
        }
    }

    @Test
    void approvalQueriesPageHistoryAndSelectOnlyLiveSetupRequests() {
        try (var app = open()) {
            var approvals = app.getBean(ApprovalRequestService.class);
            UUID profile = UUID.randomUUID(), session = UUID.randomUUID();
            for (int i = 0; i < 55; i++) {
                var previous = approvals.createRequest(null, profile, "old", Map.of());
                approvals.resolveRequest(previous.getId(), ApprovalRequestStatus.REJECTED, null);
            }
            var ordinary = approvals.createRequest(null, profile, "ordinary", Map.of());
            var setup =
                    approvals.createRequest(
                            null,
                            profile,
                            "setup",
                            Map.of("type", "SETUP", "setupSessionId", session.toString()));
            assertEquals(50, approvals.getRequests(0, 50, false, false).size());
            assertEquals(7, approvals.getRequests(1, 50, false, false).size());
            assertEquals(
                    Set.of(ordinary.getId(), setup.getId()),
                    approvals.getRequests(0, 100, true, false).stream()
                            .map(r -> r.id())
                            .collect(java.util.stream.Collectors.toSet()));
            assertEquals(setup.getId(), approvals.getRequests(0, 100, true, true).getFirst().id());
            var tx =
                    new TransactionTemplate(
                            app.getBean(
                                    org.springframework.transaction.PlatformTransactionManager
                                            .class));
            int expired =
                    tx.execute(
                            status ->
                                    app.getBean(ApprovalRequestRepository.class)
                                            .expireSetupSession(session.toString(), Instant.now()));
            assertEquals(1, expired);
            assertTrue(approvals.getRequests(0, 100, true, true).isEmpty());
            assertThrows(
                    IllegalArgumentException.class,
                    () -> approvals.getRequests(0, 101, false, false));
        }
    }

    @Test
    void networkPolicyAuditCountsSurviveRestartWithoutInventingUpstreamAllows() {
        UUID profile = UUID.randomUUID();
        var denied =
                new com.automantle.api.dto.ReportNetworkHistory(
                        UUID.randomUUID(),
                        profile,
                        "automantle-vm-" + "a".repeat(32),
                        34525,
                        "IPV6",
                        "::",
                        "2606:4700:4700::1111",
                        null,
                        null,
                        9,
                        486,
                        com.automantle.api.dto.ReportNetworkHistory.Reason.UNSUPPORTED_NETWORK);
        var inspected =
                new com.automantle.api.dto.ReportNetworkHistory(
                        UUID.randomUUID(),
                        profile,
                        "automantle-vm-" + "a".repeat(32),
                        2048,
                        "TCP",
                        "10.253.0.2",
                        "10.253.0.1",
                        50000,
                        3128,
                        3,
                        162,
                        com.automantle.api.dto.ReportNetworkHistory.Reason.INSPECTION_TRANSPORT);
        try (var app = open()) {
            var history = app.getBean(RequestHistoryService.class);
            history.reportNetwork(List.of(denied, inspected));
            history.reportNetwork(List.of(denied));
            var rows = history.recent(null, profile).items();
            assertEquals(2, rows.size());
            assertEquals(
                    Set.of("DENIED", "INSPECTED"),
                    rows.stream()
                            .map(r -> r.result())
                            .collect(java.util.stream.Collectors.toSet()));
        }
        try (var app = open()) {
            var rows = app.getBean(RequestHistoryService.class).recent(null, profile).items();
            var row =
                    rows.stream()
                            .filter(r -> r.protocol().equals("IPV6"))
                            .findFirst()
                            .orElseThrow();
            assertEquals(9, row.packetCount().longValue());
            assertEquals(486, row.byteCount().longValue());
            assertEquals("2606:4700:4700::1111", row.destinationIp());
            assertEquals("DENIED", row.result());
        }
    }

    @Test
    void pendingApprovalsHaveNoDeadlineFieldsOrColumns() throws Exception {
        try (var app = open()) {
            var approvals = app.getBean(ApprovalRequestService.class);
            var request =
                    approvals.createRequest(
                            UUID.randomUUID(), UUID.randomUUID(), "review", Map.of());
            var response = approvals.getRequest(request.getId());
            assertEquals(ApprovalRequestStatus.PENDING, response.status());
            var json =
                    tools.jackson.databind.json.JsonMapper.builder().build().valueToTree(response);
            assertFalse(json.has("timeoutSeconds"));
            assertFalse(json.has("expiresAt"));
            try (var connection = app.getBean(javax.sql.DataSource.class).getConnection();
                    var statement = connection.createStatement()) {
                for (String table : List.of("agent_rule", "approval_request")) {
                    try (var columns = statement.executeQuery("PRAGMA table_info(" + table + ")")) {
                        while (columns.next()) {
                            assertNotEquals("timeout_seconds", columns.getString("name"));
                            assertNotEquals("expires_at", columns.getString("name"));
                        }
                    }
                }
            }
            assertEquals(
                    ApprovalRequestStatus.APPROVED,
                    approvals
                            .resolveRequest(request.getId(), ApprovalRequestStatus.APPROVED, null)
                            .status());
        }
    }

    @Test
    void disconnectedRequestExpiresWithCauseAndCannotBeApprovedOrExecute() {
        try (var app = open()) {
            var profiles = app.getBean(AgentProfileRepository.class);
            var profile = profiles.saveAndFlush(new AgentProfileEntity("disconnect test"));
            var rules = app.getBean(AgentRuleService.class);
            rules.createAgentRule(
                    profile.getId(),
                    RuleEffect.REQUIRE_APPROVAL,
                    Map.of(
                            "resource_type",
                            "http",
                            "action",
                            List.of("get"),
                            "hosts",
                            List.of("api.example.com"),
                            "resource",
                            List.of("/api")));
            UUID requestId = UUID.randomUUID();
            var decision =
                    app.getBean(PolicyEvaluationService.class)
                            .evaluateAction(
                                    new GatewayEvaluateRequest(
                                            profile.getId(),
                                            Map.of(
                                                    "resource_type",
                                                    "http",
                                                    "method",
                                                    "get",
                                                    "host",
                                                    "api.example.com",
                                                    "path",
                                                    "/api"),
                                            requestId));
            var approvals = app.getBean(ApprovalRequestService.class);
            UUID id = decision.approvalRequestId();
            assertThrows(
                    com.automantle.api.exception.ResourceNotFoundException.class,
                    () ->
                            approvals.expireUnexecutedRequest(
                                    id, UUID.randomUUID(), ApprovalExpirationReason.CLIENT_CLOSED));
            assertEquals(ApprovalRequestStatus.PENDING, approvals.getRequest(id).status());
            approvals.expireUnexecutedRequest(
                    id, profile.getId(), ApprovalExpirationReason.CLIENT_CLOSED);
            approvals.expireUnexecutedRequest(
                    id, profile.getId(), ApprovalExpirationReason.TRANSPORT_ERROR);
            var expired = approvals.getRequest(id);
            assertEquals(ApprovalRequestStatus.EXPIRED, expired.status());
            assertEquals(ApprovalExpirationReason.CLIENT_CLOSED, expired.expirationReason());
            assertEquals(
                    "Client closed the request channel before execution",
                    expired.expirationMessage());
            assertNotNull(expired.resolvedAt());
            assertTrue(approvals.getRequests(0, 100, true, false).isEmpty());
            assertThrows(
                    ApprovalConflictException.class,
                    () -> approvals.resolveRequest(id, ApprovalRequestStatus.APPROVED, null));
            var history =
                    app.getBean(RequestHistoryService.class)
                            .recent(null, profile.getId())
                            .items()
                            .getFirst();
            assertEquals("DENIED", history.result());
            assertEquals(expired.expirationMessage(), history.reason());
        }
    }

    @Test
    void cancellationWinsApprovalRaceBeforeDispatchAndNeverRewritesRejection() throws Exception {
        try (var app = open();
                var workers = Executors.newFixedThreadPool(2)) {
            var approvals = app.getBean(ApprovalRequestService.class);
            UUID profile = UUID.randomUUID();
            var request = approvals.createRequest(null, profile, "pending", Map.of());
            var start = new CountDownLatch(1);
            var approve =
                    workers.submit(
                            () -> {
                                start.await();
                                try {
                                    approvals.resolveRequest(
                                            request.getId(), ApprovalRequestStatus.APPROVED, null);
                                } catch (ApprovalConflictException expected) {
                                }
                                return null;
                            });
            var expire =
                    workers.submit(
                            () -> {
                                start.await();
                                approvals.expireUnexecutedRequest(
                                        request.getId(),
                                        profile,
                                        ApprovalExpirationReason.CONNECTION_RESET);
                                return null;
                            });
            start.countDown();
            approve.get(10, TimeUnit.SECONDS);
            expire.get(10, TimeUnit.SECONDS);
            assertEquals(
                    ApprovalRequestStatus.EXPIRED, approvals.getRequest(request.getId()).status());
            var rejected = approvals.createRequest(null, profile, "rejected", Map.of());
            approvals.resolveRequest(rejected.getId(), ApprovalRequestStatus.REJECTED, null);
            approvals.expireUnexecutedRequest(
                    rejected.getId(), profile, ApprovalExpirationReason.CLIENT_CLOSED);
            assertEquals(
                    ApprovalRequestStatus.REJECTED,
                    approvals.getRequest(rejected.getId()).status());
        }
    }

    @Test
    void failedTransactionsRollBackAndDatabaseSettingsAreApplied() throws Exception {
        try (var app = open()) {
            var transaction =
                    new TransactionTemplate(
                            app.getBean(
                                    org.springframework.transaction.PlatformTransactionManager
                                            .class));
            var approvals = app.getBean(ApprovalRequestService.class);
            assertThrows(
                    IllegalStateException.class,
                    () ->
                            transaction.execute(
                                    s -> {
                                        approvals.createRequest(
                                                UUID.randomUUID(),
                                                UUID.randomUUID(),
                                                "rollback",
                                                Map.of());
                                        throw new IllegalStateException("abort");
                                    }));
            assertTrue(approvals.getRequests().isEmpty());
            try (var connection = app.getBean(javax.sql.DataSource.class).getConnection();
                    var statement = connection.createStatement()) {
                try (var result = statement.executeQuery("PRAGMA journal_mode")) {
                    assertTrue(result.next());
                    assertEquals("wal", result.getString(1));
                }
                try (var result = statement.executeQuery("PRAGMA foreign_keys")) {
                    assertTrue(result.next());
                    assertEquals(1, result.getInt(1));
                }
                try (var result = statement.executeQuery("PRAGMA integrity_check")) {
                    assertTrue(result.next());
                    assertEquals("ok", result.getString(1));
                }
            }
        }
    }

    @Test
    void historyRecordsDenialsAndGatewayFailuresWithoutBodiesOrQueriesAndClearPreservesOtherData() {
        try (var app = open()) {
            var profiles = app.getBean(AgentProfileRepository.class);
            var profile = profiles.saveAndFlush(new AgentProfileEntity("history agent"));
            var history = app.getBean(RequestHistoryService.class);
            UUID requestId = UUID.randomUUID();
            var action =
                    Map.<String, Object>of(
                            "resource_type",
                            "http",
                            "method",
                            "GET",
                            "host",
                            "api.example.com",
                            "path",
                            "/models");
            app.getBean(PolicyEvaluationService.class)
                    .evaluateAction(new GatewayEvaluateRequest(profile.getId(), action, requestId));
            assertEquals("DENIED", history.recent(null, null).items().getFirst().result());
            assertEquals(
                    "No matching allow rule",
                    history.recent(null, null).items().getFirst().reason());
            history.report(
                    new ReportRequestHistory(
                            requestId,
                            profile.getId(),
                            "api.example.com",
                            443,
                            "GET",
                            "/models",
                            ReportRequestHistory.Reason.COMPLETED));
            assertEquals("DENIED", history.recent(null, null).items().getFirst().result());
            assertEquals(443, history.recent(null, null).items().getFirst().port());
            history.report(
                    new ReportRequestHistory(
                            requestId,
                            profile.getId(),
                            "api.example.com",
                            443,
                            "GET",
                            "/models",
                            ReportRequestHistory.Reason.UPSTREAM_TLS_FAILED));
            assertEquals(1, history.recent(null, null).items().size());
            assertEquals("FAILED", history.recent(null, null).items().getFirst().result());
            history.report(
                    new ReportRequestHistory(
                            UUID.randomUUID(),
                            profile.getId(),
                            "other.example.com",
                            443,
                            "CONNECT",
                            "/?key=secret-test-value",
                            ReportRequestHistory.Reason.HTTPS_DISABLED));
            var latest = history.recent(null, null).items().getFirst();
            assertEquals("DENIED", latest.result());
            assertNull(latest.path());
            assertEquals("other.example.com", latest.host());
            var json =
                    tools.jackson.databind.json.JsonMapper.builder()
                            .build()
                            .writeValueAsString(latest);
            assertFalse(json.contains("secret-test-value"));
            assertFalse(json.contains("actionMetadata"));
            assertFalse(json.contains("headers"));
            var approval =
                    app.getBean(ApprovalRequestService.class)
                            .createRequest(
                                    UUID.randomUUID(), profile.getId(), "keep approval", Map.of());
            history.clear();
            assertTrue(history.recent(null, null).items().isEmpty());
            assertTrue(profiles.existsById(profile.getId()));
            assertTrue(app.getBean(ApprovalRequestRepository.class).existsById(approval.getId()));
        }
    }

    @Test
    void historyHasStablePaginationProfileFiltersAndAgeAndCountLimits() {
        try (var app = open()) {
            var repository = app.getBean(RequestHistoryRepository.class);
            UUID profile = UUID.randomUUID();
            var rows = new ArrayList<RequestHistoryEntity>();
            for (int i = 0; i < RequestHistoryService.MAX_RECORDS + 3; i++) {
                var row = new RequestHistoryEntity();
                row.requestId = UUID.randomUUID();
                row.agentProfileId = profile;
                row.agentName = "agent";
                row.createdAt = Instant.now();
                row.result = "DENIED";
                row.reason = "No matching allow rule";
                rows.add(row);
            }
            repository.saveAllAndFlush(rows);
            var history = app.getBean(RequestHistoryService.class);
            history.prune();
            assertEquals(RequestHistoryService.MAX_RECORDS, repository.count());
            assertFalse(repository.existsById(rows.getFirst().id));
            var first = history.recent(null, profile);
            assertEquals(100, first.items().size());
            assertNotNull(first.nextBefore());
            var second = history.recent(first.nextBefore(), profile);
            assertTrue(second.items().stream().allMatch(e -> e.id() < first.nextBefore()));
            assertTrue(history.recent(null, UUID.randomUUID()).items().isEmpty());
            var old = repository.findById(rows.getLast().id).orElseThrow();
            old.createdAt = Instant.now().minus(31, ChronoUnit.DAYS);
            repository.saveAndFlush(old);
            history.prune();
            assertFalse(repository.existsById(old.id));
        }
    }

    private Map<String, Object> setupAction(String host, String path) {
        return Map.of("resource_type", "http", "method", "POST", "host", host, "path", path);
    }

    @Test
    void setupApprovalSavesExactProfileRuleAndNormalRunImmediatelyUsesIt() {
        try (var app = open()) {
            var profile =
                    app.getBean(AgentProfileRepository.class)
                            .saveAndFlush(new AgentProfileEntity("setup agent"));
            var setup = app.getBean(SetupService.class);
            var session = setup.start(profile.getId(), 1800);
            var evaluator = app.getBean(PolicyEvaluationService.class);
            var approvals = app.getBean(ApprovalRequestService.class);
            var action = setupAction("brain.example.com", "/v1/messages");
            assertEquals(
                    "DENY",
                    evaluator
                            .evaluateAction(new GatewayEvaluateRequest(profile.getId(), action))
                            .decision());
            assertEquals(
                    "DENY",
                    evaluator
                            .evaluateAction(
                                    new GatewayEvaluateRequest(
                                            profile.getId(), action, null, UUID.randomUUID()))
                            .decision());
            var prompt =
                    evaluator.evaluateAction(
                            new GatewayEvaluateRequest(
                                    profile.getId(), action, UUID.randomUUID(), session.id()));
            assertEquals("REQUIRE_APPROVAL", prompt.decision());
            assertEquals(
                    "SETUP",
                    approvals.getRequest(prompt.approvalRequestId()).actionMetadata().get("type"));
            assertNull(approvals.getRequest(prompt.approvalRequestId()).ruleId());
            assertThrows(
                    IllegalArgumentException.class,
                    () ->
                            approvals.resolveRequest(
                                    prompt.approvalRequestId(),
                                    ApprovalRequestStatus.APPROVED,
                                    null));
            approvals.resolveRequest(
                    prompt.approvalRequestId(), ApprovalRequestStatus.APPROVED, null, true);
            var rules =
                    app.getBean(AgentRuleRepository.class).findByAgentProfileId(profile.getId());
            assertEquals(1, rules.size());
            assertEquals(
                    Map.of(
                            "resource_type",
                            "http",
                            "action",
                            List.of("post"),
                            "hosts",
                            List.of("brain.example.com"),
                            "resource",
                            List.of("/v1/messages")),
                    rules.getFirst().getMatch());
            assertEquals(
                    "ALLOW",
                    evaluator
                            .evaluateAction(new GatewayEvaluateRequest(profile.getId(), action))
                            .decision());
            assertEquals(
                    "DENY",
                    evaluator
                            .evaluateAction(
                                    new GatewayEvaluateRequest(
                                            profile.getId(),
                                            setupAction("brain.example.com", "/v1/other")))
                            .decision());
            assertEquals(
                    "DENY",
                    evaluator
                            .evaluateAction(
                                    new GatewayEvaluateRequest(
                                            profile.getId(),
                                            setupAction("other.example.com", "/v1/messages")))
                            .decision());
            assertThrows(
                    ApprovalConflictException.class,
                    () ->
                            approvals.resolveRequest(
                                    prompt.approvalRequestId(),
                                    ApprovalRequestStatus.APPROVED,
                                    null,
                                    true));
            assertEquals(1, app.getBean(AgentRuleRepository.class).count());
            setup.finish(profile.getId(), session.id());
            assertEquals(
                    "DENY",
                    evaluator
                            .evaluateAction(
                                    new GatewayEvaluateRequest(
                                            profile.getId(),
                                            setupAction("new.example.com", "/api"),
                                            null,
                                            session.id()))
                            .decision());
            assertEquals(
                    "ALLOW",
                    evaluator
                            .evaluateAction(new GatewayEvaluateRequest(profile.getId(), action))
                            .decision());
        }
    }

    @Test
    void setupDoesNotBypassDeniesInvalidRulesOrCurrentApprovalRestrictions() {
        try (var app = open()) {
            var profile =
                    app.getBean(AgentProfileRepository.class)
                            .saveAndFlush(new AgentProfileEntity("restricted setup"));
            var session = app.getBean(SetupService.class).start(profile.getId(), 300);
            var evaluator = app.getBean(PolicyEvaluationService.class);
            var approvals = app.getBean(ApprovalRequestService.class);
            var action = setupAction("brain.example.com", "/api");
            var request = new GatewayEvaluateRequest(profile.getId(), action, null, session.id());
            var prompt = evaluator.evaluateAction(request);
            var rules = app.getBean(AgentRuleService.class);
            var match =
                    Map.<String, Object>of(
                            "resource_type",
                            "http",
                            "action",
                            List.of("post"),
                            "hosts",
                            List.of("brain.example.com"),
                            "resource",
                            List.of("/api"));
            var deny = rules.createAgentRule(profile.getId(), RuleEffect.DENY, match);
            assertEquals("DENY", evaluator.evaluateAction(request).decision());
            assertThrows(
                    ApprovalConflictException.class,
                    () ->
                            approvals.resolveRequest(
                                    prompt.approvalRequestId(),
                                    ApprovalRequestStatus.APPROVED,
                                    null,
                                    true));
            assertEquals(1, app.getBean(AgentRuleRepository.class).count());
            rules.updateAgentRule(deny.getId(), RuleEffect.REQUIRE_APPROVAL, null);
            var ordinary = evaluator.evaluateAction(request);
            assertEquals("REQUIRE_APPROVAL", ordinary.decision());
            assertNull(
                    approvals
                            .getRequest(ordinary.approvalRequestId())
                            .actionMetadata()
                            .get("type"));
            assertThrows(
                    IllegalArgumentException.class,
                    () ->
                            approvals.resolveRequest(
                                    ordinary.approvalRequestId(),
                                    ApprovalRequestStatus.APPROVED,
                                    null,
                                    true));
            assertThrows(
                    ApprovalConflictException.class,
                    () ->
                            approvals.resolveRequest(
                                    prompt.approvalRequestId(),
                                    ApprovalRequestStatus.APPROVED,
                                    null,
                                    true));
            assertEquals(
                    "DENY",
                    evaluator
                            .evaluateAction(
                                    new GatewayEvaluateRequest(
                                            profile.getId(), Map.of(), null, session.id()))
                            .decision());
            var invalid =
                    app.getBean(AgentRuleRepository.class).findById(deny.getId()).orElseThrow();
            invalid.setMatch(Map.of("resource_type", "http"));
            app.getBean(AgentRuleRepository.class).saveAndFlush(invalid);
            assertEquals("DENY", evaluator.evaluateAction(request).decision());
        }
    }

    @Test
    void finishExpiryAndStaleGatewayCleanupCannotGrantOrEndAnotherSetupRun() {
        try (var app = open()) {
            var profiles = app.getBean(AgentProfileRepository.class);
            var profile = profiles.saveAndFlush(new AgentProfileEntity("ending setup"));
            var setup = app.getBean(SetupService.class);
            var session = setup.start(profile.getId(), 300);
            assertThrows(ApprovalConflictException.class, () -> setup.start(profile.getId(), 300));
            var evaluator = app.getBean(PolicyEvaluationService.class);
            var action = setupAction("brain.example.com", "/api");
            var prompt =
                    evaluator.evaluateAction(
                            new GatewayEvaluateRequest(
                                    profile.getId(), action, null, session.id()));
            setup.finish(profile.getId(), null);
            var approvals = app.getBean(ApprovalRequestService.class);
            assertEquals(
                    ApprovalRequestStatus.EXPIRED,
                    approvals.getRequest(prompt.approvalRequestId()).status());
            assertThrows(
                    ApprovalConflictException.class,
                    () ->
                            approvals.resolveRequest(
                                    prompt.approvalRequestId(),
                                    ApprovalRequestStatus.APPROVED,
                                    null,
                                    true));
            var next = setup.start(profile.getId(), 300);
            setup.finish(profile.getId(), session.id());
            assertTrue(profiles.findById(profile.getId()).orElseThrow().setupActive(next.id()));
            var expired = profiles.findById(profile.getId()).orElseThrow();
            expired.setSetupSession(next.id(), Instant.now().minusSeconds(1));
            profiles.saveAndFlush(expired);
            assertEquals(
                    "DENY",
                    evaluator
                            .evaluateAction(
                                    new GatewayEvaluateRequest(
                                            profile.getId(), action, null, next.id()))
                            .decision());
            assertEquals(0, app.getBean(AgentRuleRepository.class).count());
        }
    }
}
