package com.automantle.api.controller;

import com.automantle.api.service.RequestHistoryService;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.UUID;

@RestController
@RequestMapping("/request-history")
public class RequestHistoryController {
    private final RequestHistoryService history;

    public RequestHistoryController(RequestHistoryService history) {
        this.history = history;
    }

    @GetMapping
    public RequestHistoryService.Page list(
            @RequestParam(required = false) Long before,
            @RequestParam(required = false) UUID agentProfileId) {
        if (before != null && before < 1) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }
        return history.recent(before, agentProfileId);
    }

    @DeleteMapping
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void clear() {
        history.clear();
    }
}
