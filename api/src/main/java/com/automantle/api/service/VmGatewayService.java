package com.automantle.api.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

@Service
public class VmGatewayService {
    private static final int REQUEST_LIMIT_BYTES = 64 * 1024;
    private static final int RESPONSE_LIMIT_BYTES = 2 * 1024 * 1024;
    private static final int READ_BUFFER_BYTES = 8192;
    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(15);
    private static final Duration MACHINE_CREATION_TIMEOUT = Duration.ofSeconds(120);
    private static final Set<String> MACHINE_CREATION_COMMANDS =
            Set.of("create-disk", "create-machine", "copy-machine");
    private static final long TERMINAL_STARTUP_MILLIS = 300;
    private static final List<String> XTERM_ARGUMENTS =
            List.of(
                    "-T",
                    "AutoMantle VM terminal",
                    "-fa",
                    "DejaVu Sans Mono",
                    "-fs",
                    "13",
                    "-geometry",
                    "100x30+80+80");

    private final JsonMapper mapper = JsonMapper.builder().build();
    private final String socket;
    private final String binary;
    private final String terminal;

    public VmGatewayService(
            @Value("${app.gateway.socket}") String socket,
            @Value("${app.gateway.binary}") String binary,
            @Value("${app.gateway.external-terminal}") String terminal) {
        this.socket = socket;
        this.binary = binary;
        this.terminal = terminal;
    }

    public JsonNode command(Map<String, ?> command) throws IOException {
        Duration timeout =
                MACHINE_CREATION_COMMANDS.contains(command.get("command"))
                        ? MACHINE_CREATION_TIMEOUT
                        : DEFAULT_TIMEOUT;
        return exchange(command, timeout);
    }

    JsonNode exchange(Map<String, ?> command, Duration timeout) throws IOException {
        byte[] payload =
                (mapper.writeValueAsString(command) + "\n").getBytes(StandardCharsets.UTF_8);
        if (payload.length > REQUEST_LIMIT_BYTES) {
            throw new IllegalArgumentException("VM request is too large");
        }
        long deadline = System.nanoTime() + timeout.toNanos();
        try (SocketChannel channel = SocketChannel.open(StandardProtocolFamily.UNIX);
                Selector selector = Selector.open()) {
            channel.configureBlocking(false);
            boolean connected = channel.connect(UnixDomainSocketAddress.of(socket));
            SelectionKey key =
                    channel.register(
                            selector, connected ? SelectionKey.OP_WRITE : SelectionKey.OP_CONNECT);
            ByteBuffer outgoing = ByteBuffer.wrap(payload);
            ByteBuffer incoming = ByteBuffer.allocate(READ_BUFFER_BYTES);
            ByteArrayOutputStream response = new ByteArrayOutputStream();
            while (true) {
                awaitReady(selector, deadline);
                if (key.isConnectable() && channel.finishConnect()) {
                    key.interestOps(SelectionKey.OP_WRITE);
                }
                if (key.isWritable()) {
                    channel.write(outgoing);
                    if (!outgoing.hasRemaining()) {
                        key.interestOps(SelectionKey.OP_READ);
                    }
                }
                if (key.isReadable()) {
                    JsonNode result = readResponse(channel, incoming, response);
                    if (result != null) {
                        return result;
                    }
                }
            }
        } catch (UnsupportedOperationException exception) {
            throw new IOException(
                    "VM controls require the app and gateway on the same Linux/WSL host",
                    exception);
        }
    }

    private void awaitReady(Selector selector, long deadline) throws IOException {
        long remaining = deadline - System.nanoTime();
        if (remaining <= 0) {
            throw new IOException("Gateway request timed out");
        }
        selector.select(Math.max(1, TimeUnit.NANOSECONDS.toMillis(remaining)));
        if (Thread.currentThread().isInterrupted()) {
            throw new IOException("Gateway request interrupted");
        }
        selector.selectedKeys().clear();
    }

    private JsonNode readResponse(
            SocketChannel channel, ByteBuffer incoming, ByteArrayOutputStream response)
            throws IOException {
        if (channel.read(incoming) < 0) {
            throw new IOException("Gateway returned an incomplete response");
        }
        incoming.flip();
        while (incoming.hasRemaining()) {
            byte value = incoming.get();
            if (value == '\n') {
                return parseResponse(response);
            }
            if (response.size() >= RESPONSE_LIMIT_BYTES) {
                throw new IOException("Gateway response is too large");
            }
            response.write(value);
        }
        incoming.clear();
        return null;
    }

    private JsonNode parseResponse(ByteArrayOutputStream response) throws IOException {
        JsonNode reply = mapper.readTree(response.toString(StandardCharsets.UTF_8));
        if (reply.has("error")) {
            throw new IllegalArgumentException(reply.get("error").asText());
        }
        if (!reply.has("result")) {
            throw new IOException("Invalid gateway response");
        }
        return reply.get("result");
    }

    public long openExternalTerminal(String id) throws IOException {
        JsonNode status = command(Map.of("command", "terminal-read", "id", id, "offset", 0));
        if (!status.path("ready").asBoolean()) {
            throw new IllegalArgumentException("VM terminal is not ready");
        }
        var process =
                new ProcessBuilder(terminalArguments(id))
                        .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                        .redirectError(ProcessBuilder.Redirect.INHERIT)
                        .start();
        verifyTerminalStartup(process);
        return process.pid();
    }

    private List<String> terminalArguments(String id) throws IOException {
        var arguments = new ArrayList<String>();
        arguments.add(terminal);
        if (Path.of(terminal).toRealPath().getFileName().toString().equals("xterm")) {
            arguments.addAll(XTERM_ARGUMENTS);
        }
        arguments.addAll(List.of("-e", binary, "terminal", id, "--socket", socket));
        return arguments;
    }

    private void verifyTerminalStartup(Process process) throws IOException {
        try {
            if (process.waitFor(TERMINAL_STARTUP_MILLIS, TimeUnit.MILLISECONDS)
                    && process.exitValue() != 0) {
                throw new IllegalArgumentException(
                        "External terminal exited during startup. Check the app log and desktop"
                                + " display settings.");
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new IOException("External terminal startup interrupted", exception);
        }
    }
}
