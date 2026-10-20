package com.automantle.api.controller;

import com.automantle.api.dto.AgentProfileResponse;
import com.automantle.api.dto.ApprovalRequestResponse;
import com.automantle.api.dto.ExpireApprovalRequest;
import com.automantle.api.dto.GatewayEvaluateRequest;
import com.automantle.api.dto.GatewayEvaluateResponse;
import com.automantle.api.dto.ReportRequestHistory;
import com.automantle.api.service.AgentProfileFacadeService;
import com.automantle.api.service.ApprovalRequestService;
import com.automantle.api.service.PolicyEvaluationService;
import com.automantle.api.service.RequestHistoryService;

import jakarta.validation.Valid;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/gateway")
public class GatewayController {
    private final PolicyEvaluationService evaluation;
    private final ApprovalRequestService approvals;
    private final RequestHistoryService history;
    private final AgentProfileFacadeService profiles;

    public GatewayController(
            PolicyEvaluationService evaluation,
            ApprovalRequestService approvals,
            RequestHistoryService history,
            AgentProfileFacadeService profiles) {
        this.evaluation = evaluation;
        this.approvals = approvals;
        this.history = history;
        this.profiles = profiles;
    }

    @GetMapping("/agent-profiles/{id}")
    public AgentProfileResponse getProfile(@PathVariable UUID id) {
        return profiles.getProfile(id);
    }

    @PostMapping("/request-history")
    @ResponseStatus(org.springframework.http.HttpStatus.NO_CONTENT)
    public void report(@Valid @RequestBody ReportRequestHistory request) {
        history.report(request);
    }

    @GetMapping("/health")
    public Map<String, String> health() {
        return Map.of("status", "ready");
    }

    @PostMapping("/evaluate")
    public GatewayEvaluateResponse evaluateAction(
            @Valid @RequestBody GatewayEvaluateRequest request) {
        return evaluation.evaluateAction(request);
    }

    @GetMapping("/approval-requests/{id}")
    public ApprovalRequestResponse getApprovalRequestStatus(@PathVariable UUID id) {
        return approvals.getRequest(id);
    }

    @PostMapping("/approval-requests/{id}/expire")
    @ResponseStatus(org.springframework.http.HttpStatus.NO_CONTENT)
    public void expireApproval(
            @PathVariable UUID id, @Valid @RequestBody ExpireApprovalRequest request) {
        approvals.expireUnexecutedRequest(id, request.agentProfileId(), request.reason());
    }
}
