package com.automantle.api.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.CONFLICT)
public class ApprovalConflictException extends RuntimeException {
    public ApprovalConflictException(String message) {
        super(message);
    }
}
