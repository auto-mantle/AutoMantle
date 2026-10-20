package com.automantle.api.entity;

public enum ApprovalExpirationReason {
    CLIENT_CLOSED("Client closed the request channel before execution"),
    CONNECTION_RESET("Client connection was reset before execution"),
    TRANSPORT_ERROR("Request transport failed before execution"),
    REQUEST_CANCELLED("Request was cancelled before execution"),
    REQUEST_DEADLINE_EXCEEDED("Gateway request lifetime ended before execution"),
    GATEWAY_STOPPED("Gateway stopped the request before execution"),
    REQUEST_NOT_EXECUTED("Request ended before execution"),
    SETUP_SESSION_ENDED("Setup session ended before execution");

    private final String message;

    ApprovalExpirationReason(String message) {
        this.message = message;
    }

    public String message() {
        return message;
    }
}
