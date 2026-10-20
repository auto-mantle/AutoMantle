package com.automantle.api.controller;

import com.automantle.api.dto.ApprovalRequestResponse;
import com.automantle.api.dto.ResolveApprovalRequest;
import com.automantle.api.service.ApprovalRequestService;

import jakarta.validation.Valid;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
public class ApprovalRequestController {
    private final ApprovalRequestService service;

    public ApprovalRequestController(ApprovalRequestService service) {
        this.service = service;
    }

    @GetMapping("/approval-requests")
    public ResponseEntity<List<ApprovalRequestResponse>> listRequests(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int limit,
            @RequestParam(defaultValue = "false") boolean pending,
            @RequestParam(defaultValue = "false") boolean setupOnly) {
        return ResponseEntity.ok(service.getRequests(page, limit, pending, setupOnly));
    }

    @GetMapping("/approval-requests/{id}")
    public ResponseEntity<ApprovalRequestResponse> getRequest(@PathVariable UUID id) {
        return ResponseEntity.ok(service.getRequest(id));
    }

    @PostMapping("/approval-requests/{id}/resolve")
    public ResponseEntity<ApprovalRequestResponse> resolveRequest(
            @PathVariable UUID id, @Valid @RequestBody ResolveApprovalRequest request) {
        return ResponseEntity.ok(
                service.resolveRequest(id, request.decision(), null, request.saveRule()));
    }
}
