package com.automantle.api.controller;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class PolicyInputExceptionHandlerTest {
    @Test void setupConflictExplainsWhyTheConnectionCannotBeApproved() {
        var response = new PolicyInputExceptionHandler().conflict(new com.automantle.api.exception.ApprovalConflictException("A current rule blocks this setup connection"));
        assertEquals(409, response.getStatusCode().value());
        assertEquals("A current rule blocks this setup connection", response.getBody().get("message"));
    }
    @Test void returnsBadRequestWithUsefulValidationMessage() {
        var response = new PolicyInputExceptionHandler().invalidInput(new IllegalArgumentException("Hosts must be exact DNS names"));
        assertEquals(400, response.getStatusCode().value());
        assertEquals("Hosts must be exact DNS names", response.getBody().get("message"));
    }
}
