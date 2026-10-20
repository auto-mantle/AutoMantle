package com.automantle.api.controller;

import com.automantle.api.exception.ApprovalConflictException;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

@RestControllerAdvice(
        assignableTypes = {
            AgentRuleController.class,
            SetupController.class,
            GatewayController.class,
            ApprovalRequestController.class
        })
public class PolicyInputExceptionHandler {
    @ExceptionHandler(ApprovalConflictException.class)
    public ResponseEntity<Map<String, String>> conflict(ApprovalConflictException exception) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(Map.of("message", exception.getMessage()));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> invalidInput(IllegalArgumentException exception) {
        return ResponseEntity.badRequest()
                .body(
                        Map.of(
                                "message",
                                exception.getMessage() == null
                                        ? "Invalid rule input"
                                        : exception.getMessage()));
    }
}
