package com.automantle.api.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import tools.jackson.databind.json.JsonMapper;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.Executors;
import static org.junit.jupiter.api.Assertions.*;

class VmGatewayServiceTest {
    @TempDir Path directory;
    @Test void unixTransportPreservesOffsetsAndRawTerminalBytes() throws Exception {
        Path socket = directory.resolve("control.sock");
        try (var server = ServerSocketChannel.open(StandardProtocolFamily.UNIX); var workers = Executors.newVirtualThreadPerTaskExecutor()) {
            server.bind(UnixDomainSocketAddress.of(socket));
            var received = workers.submit(() -> {
                try (var channel = server.accept()) {
                    StringBuilder request = new StringBuilder();
                    ByteBuffer byteBuffer = ByteBuffer.allocate(1);
                    while (true) {
                        if (channel.read(byteBuffer) < 0) throw new IOException("truncated request");
                        byteBuffer.flip(); char value = (char)byteBuffer.get(); byteBuffer.clear();
                        if (value == '\n') break;
                        request.append(value);
                    }
                    byte[] reply = "{\"result\":{\"next\":12,\"data\":[27,195,169,13]}}\n".getBytes(StandardCharsets.UTF_8);
                    for (byte value : reply) channel.write(ByteBuffer.wrap(new byte[]{value}));
                    return JsonMapper.builder().build().readTree(request.toString());
                }
            });
            var service = new VmGatewayService(socket.toString(), "/gateway", "/terminal");
            var response = service.exchange(Map.of("command", "terminal-read", "id", "run", "offset", 8), Duration.ofSeconds(2));
            assertEquals(12, response.get("next").asInt());
            assertEquals(195, response.get("data").get(1).asInt());
            assertEquals(8, received.get().get("offset").asInt());
        }
    }
    @Test void stalledGatewayHasABoundedDeadline() throws Exception {
        Path socket = directory.resolve("stalled.sock");
        try (var server = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
            server.bind(UnixDomainSocketAddress.of(socket));
            var service = new VmGatewayService(socket.toString(), "/gateway", "/terminal");
            assertThrows(IOException.class, () -> service.exchange(Map.of("command", "list"), Duration.ofMillis(100)));
        }
    }
}
