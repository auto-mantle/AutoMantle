package com.automantle.api.controller;

import com.automantle.api.policy.HttpPolicyContract;
import com.automantle.api.policy.HttpCredential;
import com.automantle.api.policy.HttpPolicyValidator;
import com.automantle.api.service.VmGatewayService;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import tools.jackson.databind.JsonNode;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

@RestController
@RequestMapping("/credentials")
public class CredentialController {
    private static final int MAX_SCOPES = 100;
    private static final List<String> PUBLIC_FIELDS = List.of("name", "scopes", "legacyScope");
    private final VmGatewayService gateway;
    private final HttpPolicyContract contract;
    private final HttpPolicyValidator validator;

    public CredentialController(
            VmGatewayService gateway, HttpPolicyContract contract, HttpPolicyValidator validator) {
        this.gateway = gateway;
        this.contract = contract;
        this.validator = validator;
    }

    public record Scope(
            UUID agentProfileId,
            String host,
            List<String> paths,
            String location,
            String selector,
            List<String> legacyMethods) {}

    public record Save(String name, String secret, List<Scope> scopes) {
        @Override
        public String toString() {
            return "Credential request [redacted]";
        }
    }

    private Map<String, Object> input(Save request) {
        validateName(request.name());
        var result = new LinkedHashMap<String, Object>();
        result.put("name", request.name());
        if (request.secret() != null) {
            result.put("secret", request.secret());
        }
        if (request.scopes() != null) {
            if (request.scopes().size() > MAX_SCOPES) {
                throw new IllegalArgumentException("Use at most 100 credential scopes");
            }
            List<Map<String, Object>> scopes = new ArrayList<>();
            for (Scope scope : request.scopes()) {
                scopes.add(scopeMetadata(request.name(), scope));
            }
            result.put("scopes", scopes);
        }
        return result;
    }

    private Map<String, Object> scopeMetadata(String name, Scope scope) {
        if (scope == null
                || scope.agentProfileId() == null
                || scope.host() == null
                || scope.paths() == null
                || scope.location() == null
                || scope.selector() == null) {
            throw new IllegalArgumentException("Complete each credential scope");
        }
        String host = validator.host(scope.host());
        validator.pathPatterns(scope.paths());
        contract.credentials(
                List.of(
                        Map.of(
                                "placeholder",
                                name,
                                "location",
                                scope.location(),
                                "selector",
                                scope.selector())));
        var entry = new LinkedHashMap<String, Object>();
        entry.put("agentProfileId", scope.agentProfileId().toString());
        entry.put("host", host);
        entry.put("paths", scope.paths());
        entry.put("location", scope.location());
        entry.put("selector", scope.selector());
        if (scope.legacyMethods() != null && !scope.legacyMethods().isEmpty()) {
            entry.put("legacyMethods", legacyMethods(scope.legacyMethods()));
        }
        return entry;
    }

    private List<String> legacyMethods(List<String> input) {
        if (input.stream().anyMatch(Objects::isNull)) {
            throw new IllegalArgumentException("Invalid previous method limit");
        }
        var methods = input.stream().map(method -> method.toLowerCase(Locale.ROOT)).toList();
        validator.ruleMethods(methods);
        return input.stream().map(method -> method.toUpperCase(Locale.ROOT)).toList();
    }

    private static Map<String, JsonNode> publicEntry(JsonNode value) {
        Map<String, JsonNode> result = new LinkedHashMap<>();
        for (String key : PUBLIC_FIELDS) {
            if (value.has(key)) {
                result.put(key, value.get(key));
            }
        }
        return result;
    }

    @GetMapping
    public List<Map<String, JsonNode>> list() throws IOException {
        JsonNode result = gateway.command(Map.of("command", "credential-list"));
        if (!result.isArray()) {
            throw new IOException("Invalid credential metadata");
        }
        List<Map<String, JsonNode>> entries = new ArrayList<>();
        result.forEach(value -> entries.add(publicEntry(value)));
        return entries;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public Map<String, JsonNode> create(@RequestBody Save value) throws IOException {
        return publicEntry(
                gateway.command(
                        Map.of("command", "credential-create", "credential", input(value))));
    }

    @PutMapping("/{name}")
    public Map<String, JsonNode> update(@PathVariable String name, @RequestBody Save value)
            throws IOException {
        validateName(name);
        if (!name.equals(value.name())) {
            throw new IllegalArgumentException(
                    "The variable name cannot change; create a new credential to use another name");
        }
        return publicEntry(
                gateway.command(
                        Map.of("command", "credential-update", "credential", input(value))));
    }

    @DeleteMapping("/{name}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable String name) throws IOException {
        validateName(name);
        gateway.command(Map.of("command", "credential-delete", "name", name));
    }

    private static void validateName(String value) {
        if (!HttpCredential.validManagedName(value)) {
            throw new IllegalArgumentException(
                    "Use an uppercase variable name, digits and underscores; the internal VM"
                            + " credential prefix is reserved");
        }
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> invalid(IllegalArgumentException error) {
        return ResponseEntity.badRequest().body(Map.of("message", error.getMessage()));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, String>> unreadable() {
        return ResponseEntity.badRequest().body(Map.of("message", "Invalid credential fields"));
    }

    @ExceptionHandler(IOException.class)
    public ResponseEntity<Map<String, String>> unavailable() {
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(
                        Map.of(
                                "message",
                                "Credential storage is unavailable. Check that the local gateway is"
                                        + " running."));
    }
}
