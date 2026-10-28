package com.automantle.api.controller;

import com.automantle.api.service.VmGatewayService;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import tools.jackson.databind.JsonNode;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/vms")
public class VmController {
    private static final int MAX_NAME_LENGTH = 80;
    private static final int MIN_MEMORY_MIB = 128;
    private static final int MAX_MEMORY_MIB = 65_536;
    private static final int MAX_VCPU_COUNT = 64;
    private static final int MAX_TERMINAL_INPUT_BYTES = 4096;
    private static final int MAX_BYTE_VALUE = 255;
    private final VmGatewayService gateway;

    public VmController(VmGatewayService gateway) {
        this.gateway = gateway;
    }

    public record Settings(
            String name, UUID agentProfileId, int memoryMib, int vcpuCount, boolean setup,
            String isoPath) {}

    public record CopyVm(String name) {}

    public record Input(List<Integer> data) {}

    public record Browse(String directory) {}

    @PostMapping("/iso-files")
    public Map<String, Object> browse(@RequestBody Browse request) throws IOException {
        Path directory = Path.of(request.directory() == null || request.directory().isBlank()
                ? System.getProperty("user.home") : request.directory()).toRealPath();
        if (!Files.isDirectory(directory)) {
            throw new IllegalArgumentException("Choose a directory on this machine");
        }
        try (var entries = Files.list(directory)) {
            var files = entries.filter(path -> Files.isReadable(path)
                            && (Files.isDirectory(path) || path.getFileName().toString().toLowerCase(java.util.Locale.ROOT).endsWith(".iso")))
                    .sorted(Comparator.<Path, Boolean>comparing(path -> !Files.isDirectory(path))
                            .thenComparing(path -> path.getFileName().toString(), String.CASE_INSENSITIVE_ORDER))
                    .limit(1000)
                    .map(path -> Map.<String, Object>of("name", path.getFileName().toString(),
                            "path", path.toString(), "directory", Files.isDirectory(path)))
                    .toList();
            return Map.of("directory", directory.toString(), "parent",
                    directory.getParent() == null ? directory.toString() : directory.getParent().toString(), "entries", files);
        }
    }

    @GetMapping
    public JsonNode list() throws IOException {
        return gateway.command(Map.of("command", "list-machines"));
    }

    @PostMapping
    public JsonNode create(@RequestBody Settings request) throws IOException {
        if (request.isoPath() == null || request.isoPath().isBlank()) {
            throw new IllegalArgumentException("Select a local OS ISO file for this VM");
        }
        return gateway.command(
                Map.of(
                        "command", "create-machine",
                        "settings", settings(request),
                        "isoPath", request.isoPath().trim()));
    }

    @PutMapping("/{id}")
    public JsonNode update(@PathVariable String id, @RequestBody Settings request)
            throws IOException {
        return gateway.command(
                Map.of(
                        "command",
                        "update-machine",
                        "id",
                        machineId(id),
                        "settings",
                        settings(request)));
    }

    @PostMapping("/{id}/copy")
    public JsonNode copy(@PathVariable String id, @RequestBody CopyVm request) throws IOException {
        validateName(request.name());
        return gateway.command(
                Map.of(
                        "command",
                        "copy-machine",
                        "id",
                        machineId(id),
                        "name",
                        request.name().trim()));
    }

    @DeleteMapping("/{id}")
    public JsonNode delete(@PathVariable String id) throws IOException {
        return gateway.command(Map.of("command", "delete-machine", "id", machineId(id)));
    }

    @PostMapping("/{id}/start")
    public JsonNode start(@PathVariable String id) throws IOException {
        return gateway.command(Map.of("command", "start-machine", "id", machineId(id)));
    }

    @PostMapping("/{id}/reinstall")
    public JsonNode reinstall(@PathVariable String id) throws IOException {
        return gateway.command(Map.of("command", "reinstall-machine", "id", machineId(id)));
    }

    @PostMapping("/{id}/complete-installation")
    public JsonNode completeInstallation(@PathVariable String id) throws IOException {
        return gateway.command(Map.of("command", "complete-installation", "id", machineId(id)));
    }

    @PostMapping("/{id}/stop")
    public JsonNode stop(@PathVariable String id) throws IOException {
        return gateway.command(Map.of("command", "shutdown-machine", "id", machineId(id)));
    }

    @PostMapping("/{id}/force-stop")
    public JsonNode forceStop(@PathVariable String id) throws IOException {
        return gateway.command(Map.of("command", "force-stop-machine", "id", machineId(id)));
    }

    @GetMapping("/{id}/terminal")
    public JsonNode output(@PathVariable String id, @RequestParam(defaultValue = "0") long offset)
            throws IOException {
        if (offset < 0) {
            throw new IllegalArgumentException("Invalid terminal offset");
        }
        return gateway.command(
                Map.of("command", "terminal-read", "id", runId(id), "offset", offset));
    }

    @PostMapping("/{id}/terminal/input")
    public JsonNode input(@PathVariable String id, @RequestBody Input request) throws IOException {
        if (request.data() == null
                || request.data().isEmpty()
                || request.data().size() > MAX_TERMINAL_INPUT_BYTES
                || request.data().stream()
                        .anyMatch(b -> b == null || b < 0 || b > MAX_BYTE_VALUE)) {
            throw new IllegalArgumentException("Terminal input must contain 1-4096 bytes");
        }
        return gateway.command(
                Map.of("command", "terminal-write", "id", runId(id), "data", request.data()));
    }

    @PostMapping("/{id}/terminal/external")
    public Map<String, Long> external(@PathVariable String id) throws IOException {
        return Map.of("pid", gateway.openExternalTerminal(runId(id)));
    }

    private static Map<String, Object> settings(Settings value) {
        validateName(value.name());
        if (value.agentProfileId() == null) {
            throw new IllegalArgumentException("Choose an existing Agent Profile");
        }
        if (value.memoryMib() < MIN_MEMORY_MIB
                || value.memoryMib() > MAX_MEMORY_MIB
                || value.vcpuCount() < 1
                || value.vcpuCount() > MAX_VCPU_COUNT) {
            throw new IllegalArgumentException(
                    "Memory must be 128-65536 MiB and CPUs must be 1-64");
        }
        return Map.of(
                "name",
                value.name().trim(),
                "agentProfileId",
                value.agentProfileId().toString(),
                "memoryMib",
                value.memoryMib(),
                "vcpuCount",
                value.vcpuCount(),
                "setup",
                value.setup());
    }

    private static void validateName(String value) {
        if (value == null
                || value.isBlank()
                || value.codePointCount(0, value.length()) > MAX_NAME_LENGTH
                || value.codePoints().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException(
                    "VM name must contain 1-80 characters without control characters");
        }
    }

    private static String machineId(String value) {
        if (!value.matches("[A-Za-z0-9_-]{1,64}")) {
            throw new IllegalArgumentException("Invalid VM ID");
        }
        return value;
    }

    private static String runId(String value) {
        if (!value.matches("automantle-vm-[0-9a-fA-F]{32}")) {
            throw new IllegalArgumentException("Invalid VM run ID");
        }
        return value;
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> invalid(IllegalArgumentException error) {
        return ResponseEntity.badRequest().body(Map.of("message", error.getMessage()));
    }

    @ExceptionHandler(IOException.class)
    public ResponseEntity<Map<String, String>> unavailable(IOException error) {
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(
                        Map.of(
                                "message",
                                "Cannot reach the local gateway or terminal program. Check that the"
                                        + " gateway is running."));
    }
}
