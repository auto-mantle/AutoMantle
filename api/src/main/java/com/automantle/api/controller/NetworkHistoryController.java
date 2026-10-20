package com.automantle.api.controller;

import com.automantle.api.dto.ReportNetworkHistory;
import com.automantle.api.service.RequestHistoryService;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Size;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class NetworkHistoryController {
    private final RequestHistoryService history;

    public NetworkHistoryController(RequestHistoryService history) {
        this.history = history;
    }

    @PostMapping("/gateway/network-history")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void report(
            @Valid @RequestBody @Size(min = 1, max = 128)
                    List<@Valid ReportNetworkHistory> events) {
        history.reportNetwork(events);
    }
}
