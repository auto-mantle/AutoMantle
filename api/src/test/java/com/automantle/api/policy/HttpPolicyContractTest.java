package com.automantle.api.policy;

import static org.junit.jupiter.api.Assertions.*;

import com.automantle.api.config.HttpPolicyProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.util.unit.DataSize;

import java.util.*;

class HttpPolicyContractTest {
    private final HttpPolicyContract contract = HttpPolicyFixtures.contract();

    @Test
    void configuredLimitsApplyToActionsRulesAndCredentials() {
        var limits = new HttpPolicyProperties(
                DataSize.ofBytes(2), 1, 1, 3, 4, 16, 5);
        var configured = new HttpPolicyContract(limits, new HttpPolicyValidator(limits));

        assertDoesNotThrow(() -> configured.action(writeAction(body())));
        assertThrows(IllegalArgumentException.class,
                () -> configured.action(action("api.example.com", "/longer")));
        var twoMethods = new HashMap<>(match("/api"));
        twoMethods.put("action", List.of("get", "post"));
        assertThrows(IllegalArgumentException.class, () -> configured.match(twoMethods));
        var query = Map.of("placeholder", "TOKEN", "location", "query", "selector", "abcd");
        assertThrows(IllegalArgumentException.class,
                () -> configured.credentials(List.of(query)));
        assertDoesNotThrow(() -> configured.credentials(List.of(
                Map.of("placeholder", "TOKEN", "location", "query", "selector", "abc"))));
    }
    static Map<String, Object> action(String host, String path) {
        return Map.of("resource_type", "http", "method", "GET", "host", host, "path", path);
    }

    static Map<String, Object> match(String pattern) {
        return Map.of(
                "resource_type",
                "http",
                "action",
                List.of("get"),
                "hosts",
                List.of("API.Example.com"),
                "resource",
                List.of(pattern));
    }

    @Test
    void normalizesHostsAndMethodsButPreservesPathCase() {
        var parsed = contract.action(action("API.EXAMPLE.COM", "/Users"));
        assertEquals("get", parsed.method());
        assertEquals("api.example.com", parsed.host());
        assertEquals("/Users", parsed.path());
        assertTrue(contract.match(match("/Users")).matches(parsed));
        assertFalse(contract.match(match("/users")).matches(parsed));
    }

    @Test
    void respectsHostAndMethodAndPathTogether() {
        var match = contract.match(match("/api/*"));
        assertTrue(
                match.matches(
                        contract.action(action("api.example.com", "/api/users/42"))));
        assertFalse(
                match.matches(
                        contract.action(action("other.example.com", "/api/users"))));
        assertFalse(match.matches(new HttpAction("post", "api.example.com", "/api/users")));
        assertFalse(match.matches(contract.action(action("api.example.com", "/api"))));
        assertFalse(
                match.matches(
                        contract.action(action("api.example.com", "/api-other/users"))));
        assertTrue(
                contract.match(match("/*"))
                        .matches(contract.action(action("api.example.com", "/"))));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "api/*",
                "/api/**",
                "/api/*/users",
                "/api?x=1",
                "/api#x",
                "/api/%2fusers",
                "/api/../users",
                "/api/./users",
                "/api//users",
                "/api/ users",
                "/api/\u00e9"
            })
    void rejectsAmbiguousPatterns(String pattern) {
        assertThrows(
                IllegalArgumentException.class, () -> contract.match(match(pattern)));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "*.example.com",
                "https://api.example.com",
                "api.example.com:443",
                "api.example.com.",
                "127.0.0.1",
                "[::1]",
                "-api.example.com",
                "api..example.com",
                "api.example.com "
            })
    void rejectsAmbiguousHosts(String host) {
        assertThrows(
                IllegalArgumentException.class, () -> contract.action(action(host, "/")));
    }

    @Test
    void preservesCanonicalUnicodePathsAndRejectsEncodedAsciiOrMalformedUtf8() {
        for (String path : List.of("/api/%C3%A9", "/api/%F0%9F%98%80")) {
            var parsed = contract.action(action("api.example.com", path));
            assertEquals(path, parsed.path());
            assertEquals(path, parsed.metadata().get("path"));
            assertTrue(contract.match(match(path)).matches(parsed));
        }
        for (String path :
                List.of(
                        "/api/%2F",
                        "/api/%2E",
                        "/api/%41",
                        "/api/%c3%a9",
                        "/api/%C3",
                        "/api/%FF",
                        "/api/%",
                        "/api/%GG")) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> contract.action(action("api.example.com", path)),
                    path);
            assertThrows(
                    IllegalArgumentException.class,
                    () -> contract.match(match(path)),
                    path);
        }
    }

    @Test
    void keepsRuleListLimitsAndRejectsHostsThatCollideAfterNormalization() {
        var rule = new HashMap<>(match("/api"));
        rule.put(
                "action",
                java.util.stream.IntStream.range(0, 100).mapToObj(i -> "x-" + i).toList());
        rule.put(
                "hosts",
                java.util.stream.IntStream.range(0, 100)
                        .mapToObj(i -> "h" + i + ".example.com")
                        .toList());
        rule.put(
                "resource",
                java.util.stream.IntStream.range(0, 100).mapToObj(i -> "/api/" + i).toList());
        var parsed = contract.match(rule);
        assertEquals(100, parsed.methods().size());
        assertEquals(100, parsed.hosts().size());
        assertEquals(100, parsed.paths().size());
        for (String field : List.of("action", "hosts", "resource")) {
            var oversized = new HashMap<>(rule);
            oversized.put(field, Collections.nCopies(101, "unused"));
            assertThrows(
                    IllegalArgumentException.class,
                    () -> contract.match(oversized),
                    field);
        }
        rule.put("hosts", List.of("api.example.com", "API.EXAMPLE.COM"));
        assertThrows(IllegalArgumentException.class, () -> contract.match(rule));
    }

    @Test
    void rejectsLegacyEmptyDuplicateAndUnknownConditions() {
        var legacy = new HashMap<>(match("/"));
        legacy.remove("hosts");
        assertThrows(IllegalArgumentException.class, () -> contract.match(legacy));
        var empty = new HashMap<>(match("/"));
        empty.put("action", List.of());
        assertThrows(IllegalArgumentException.class, () -> contract.match(empty));
        empty.put("action", List.of("get", "get"));
        assertThrows(IllegalArgumentException.class, () -> contract.match(empty));
        var extra = new HashMap<>(action("api.example.com", "/"));
        extra.put("unexpected", "value");
        assertThrows(IllegalArgumentException.class, () -> contract.action(extra));
        assertThrows(
                IllegalArgumentException.class,
                () -> contract.action(action("api.example.com", "/api/*")));
    }

    @Test
    void customMethodsAndReadBodiesReachPolicyMatching() {
        for (String method : List.of("OPTIONS", "PROPFIND", "REPORT", "M-SEARCH")) {
            var request = new HashMap<>(writeAction(body()));
            request.put("method", method);
            var rule = new HashMap<>(match("/api"));
            rule.put("action", List.of(method.toLowerCase(Locale.ROOT)));
            assertTrue(contract.match(rule).matches(contract.action(request)));
        }
        for (String invalid : List.of("BAD METHOD", "GET\r\nInjected", "GET/POST")) {
            var request = new HashMap<>(action("api.example.com", "/"));
            request.put("method", invalid);
            assertThrows(IllegalArgumentException.class, () -> contract.action(request));
        }
    }

    static Map<String, Object> writeAction(Map<String, Object> body) {
        var value = new HashMap<>(action("api.example.com", "/api"));
        value.put("method", "POST");
        value.put("body", body);
        return value;
    }

    static Map<String, Object> body() {
        return Map.of(
                "content_type", "application/json", "size_bytes", 7L, "sha256", "a".repeat(64));
    }

    @Test
    void bodyFingerprintsAcceptLargeTransfersWithoutTruncatingTheirSize() {
        for (long size : List.of(9L * 1024 * 1024, 129L * 1024 * 1024, 5L * 1024 * 1024 * 1024)) {
            var metadata = new HashMap<>(body());
            metadata.put("size_bytes", size);
            var action = contract.action(writeAction(metadata));
            assertEquals(metadata, action.metadata().get("body"));
            assertEquals(action, contract.action(action.metadata()));
        }
        var integerSize = new HashMap<>(body());
        integerSize.put("size_bytes", 7);
        assertDoesNotThrow(() -> contract.action(writeAction(integerSize)));
    }

    @Test
    void retainsBodyFingerprintInCanonicalApprovalMetadata() {
        var parsed = contract.action(writeAction(body()));
        assertEquals("post", parsed.method());
        assertEquals(body(), parsed.metadata().get("body"));
        assertEquals(parsed, contract.action(parsed.metadata()));
        var rule = new HashMap<>(match("/api"));
        rule.put("action", List.of("post"));
        assertTrue(contract.match(rule).matches(parsed));
        assertThrows(
                UnsupportedOperationException.class, () -> parsed.metadata().put("body", Map.of()));
    }

    @Test
    void validatesBodyFingerprintWithoutAcceptingRawPayload() {
        for (var change :
                List.of(
                        Map.<String, Object>of("size_bytes", -1),
                        Map.<String, Object>of("size_bytes", 7.0),
                        Map.<String, Object>of("sha256", "bad"),
                        Map.<String, Object>of("content_type", "invalid"),
                        Map.<String, Object>of("raw", "payload"),
                        Map.<String, Object>of("content_type", "text/plain\r\nInjected: yes"))) {
            var changed = new HashMap<>(body());
            changed.putAll(change);
            assertThrows(
                    IllegalArgumentException.class,
                    () -> contract.action(writeAction(changed)));
        }
        var zero = new HashMap<>(body());
        zero.put("size_bytes", 0);
        assertThrows(
                IllegalArgumentException.class, () -> contract.action(writeAction(zero)));
        zero.put("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        zero.put("content_type", "");
        assertEquals(0, contract.action(writeAction(zero)).body().sizeBytes());
        var read = writeAction(body());
        read.put("method", "GET");
        assertEquals("get", contract.action(read).method());
        var missing = new HashMap<>(body());
        missing.remove("sha256");
        assertThrows(
                IllegalArgumentException.class,
                () -> contract.action(writeAction(missing)));
    }

    @Test
    void retainsFullRequestFingerprintAndAcceptsOpaqueBodyDescriptors() {
        var opaque = new HashMap<>(body());
        opaque.put("content_type", "multipart/form-data; boundary=synthetic");
        opaque.put("preview", Map.of("omitted", true));
        var request = writeAction(opaque);
        request.put("request_sha256", "b".repeat(64));
        request.put("path", "/api/%C3%A9");
        var parsed = contract.action(request);
        assertEquals(parsed, contract.action(parsed.metadata()));
        assertEquals("b".repeat(64), parsed.metadata().get("request_sha256"));
        request.put("request_sha256", "raw-private-query");
        assertThrows(IllegalArgumentException.class, () -> contract.action(request));
        opaque.put("preview", Map.of("json", "{}", "redacted", false));
        assertThrows(
                IllegalArgumentException.class,
                () -> contract.action(writeAction(opaque)));
    }

    @Test
    void acceptsBoundedFormFingerprintsButNeverFormPreviews() {
        for (String type :
                List.of(
                        "application/x-www-form-urlencoded",
                        "application/x-www-form-urlencoded; charset=utf-8")) {
            var form = new HashMap<>(body());
            form.put("content_type", type);
            form.put("preview", Map.of("omitted", true));
            var parsed = contract.action(writeAction(form));
            assertEquals(parsed, contract.action(parsed.metadata()));
            assertTrue(parsed.body().preview().omitted());
            form.put("preview", Map.of("json", "{\"code\":\"synthetic\"}", "redacted", true));
            assertThrows(
                    IllegalArgumentException.class,
                    () -> contract.action(writeAction(form)));
            form.remove("preview");
            assertNull(contract.action(writeAction(form)).body().preview());
            form.put("content_type", "application/x-www-form-urlencoded; charset=latin1");
            assertNull(contract.action(writeAction(form)).body().preview());
        }
    }

    @Test
    void jsonPreviewRequiresSupportedMediaTypeAndUtf8() {
        var body = new HashMap<>(body());
        body.put("preview", Map.of("json", "{}", "redacted", false));
        body.put("content_type", "application/json; charset=utf-8");
        assertDoesNotThrow(() -> contract.action(writeAction(body)));

        body.put("content_type", "application/json; charset=latin1");
        assertThrows(IllegalArgumentException.class, () -> contract.action(writeAction(body)));
        body.put("content_type", "application/json; charset=utf-8; charset=utf-8");
        assertThrows(IllegalArgumentException.class, () -> contract.action(writeAction(body)));
    }

    @Test
    void acceptsPlainVariableNamesInPolicyAndReviewMetadata() {
        var value = new HashMap<>(action("api.example.com", "/api"));
        value.put(
                "credentials",
                List.of(Map.of("placeholder", "GITHUB_TOKEN", "header", "authorization")));
        var parsed = contract.action(value);
        assertEquals("GITHUB_TOKEN", parsed.credentials().getFirst().placeholder());
        assertEquals(parsed, contract.action(parsed.metadata()));
    }

    @Test
    void validatesStructuredCredentialPlacementsWithoutAcceptingFramingOrInvalidPointers() {
        for (var placement :
                List.of(
                        Map.of(
                                "placeholder",
                                "SERVICE_TOKEN",
                                "location",
                                "header",
                                "selector",
                                "authorization"),
                        Map.of(
                                "placeholder",
                                "SERVICE_TOKEN",
                                "location",
                                "json",
                                "selector",
                                "/auth/a~1b~0c/0/token"),
                        Map.of(
                                "placeholder",
                                "SERVICE_TOKEN",
                                "location",
                                "query",
                                "selector",
                                "api_key"))) {
            var input = new HashMap<>(action("api.example.com", "/api"));
            input.put("credentials", List.of(placement));
            var parsed = contract.action(input);
            assertEquals(parsed, contract.action(parsed.metadata()));
        }
        for (var placement :
                List.of(
                        Map.of(
                                "placeholder",
                                "SERVICE_TOKEN",
                                "location",
                                "header",
                                "selector",
                                "host",
                                "format",
                                "raw"),
                        Map.of(
                                "placeholder",
                                "SERVICE_TOKEN",
                                "location",
                                "header",
                                "selector",
                                "content-length",
                                "format",
                                "raw"),
                        Map.of(
                                "placeholder",
                                "SERVICE_TOKEN",
                                "location",
                                "json",
                                "selector",
                                "auth.token",
                                "format",
                                "raw"),
                        Map.of(
                                "placeholder",
                                "SERVICE_TOKEN",
                                "location",
                                "json",
                                "selector",
                                "/auth/~2token",
                                "format",
                                "raw"),
                        Map.of(
                                "placeholder",
                                "SERVICE_TOKEN",
                                "location",
                                "query",
                                "selector",
                                "api_key",
                                "format",
                                "unknown"),
                        Map.of(
                                "placeholder",
                                "SERVICE_TOKEN",
                                "location",
                                "body",
                                "selector",
                                "*",
                                "format",
                                "raw"))) {
            var input = new HashMap<>(action("api.example.com", "/api"));
            input.put("credentials", List.of(placement));
            assertThrows(IllegalArgumentException.class, () -> contract.action(input));
        }
    }

    @Test
    void rejectsObsoleteCredentialFormat() {
        var plain =
                Map.of(
                        "placeholder",
                        "SERVICE_TOKEN",
                        "location",
                        "header",
                        "selector",
                        "authorization");
        var oldBearer = new HashMap<String, Object>(plain);
        oldBearer.put("format", "bearer");
        var oldRaw = new HashMap<String, Object>(plain);
        oldRaw.put("format", "raw");
        assertThrows(IllegalArgumentException.class,
                () -> contract.credentials(List.of(oldBearer)));
        assertThrows(IllegalArgumentException.class,
                () -> contract.credentials(List.of(oldRaw)));
        assertEquals(1, contract.credentials(List.of(plain)).size());
    }

    @Test
    void preservesCredentialIdentityAndSanitizedPreviewInApprovalSnapshot() {
        var body = new HashMap<>(body());
        body.put(
                "preview",
                Map.of("json", "{\"amount\":42,\"password\":\"[REDACTED]\"}", "redacted", true));
        var action = new HashMap<>(writeAction(body));
        action.put(
                "credentials",
                List.of(
                        Map.of(
                                "placeholder",
                                "AUTOMANTLE_SERVICE_TOKEN",
                                "header",
                                "authorization")));
        var parsed = contract.action(action);
        assertEquals("AUTOMANTLE_SERVICE_TOKEN", parsed.credentials().getFirst().placeholder());
        assertTrue(parsed.body().preview().redacted());
        assertEquals(parsed, contract.action(parsed.metadata()));
        assertEquals(body, parsed.metadata().get("body"));
        assertFalse(parsed.metadata().toString().contains("secret="));
    }

    @Test
    void rejectsMalformedOrOversizedReviewWithoutEchoingPayloadErrors() {
        for (Object preview :
                List.of(
                        Map.of("json", "{\"x\":1,\"x\":2}", "redacted", false),
                        Map.of("json", "{} {}", "redacted", false),
                        Map.of("json", "private-invalid-payload", "redacted", true),
                        Map.of("json", "\"" + "x".repeat(17000) + "\"", "redacted", false),
                        Map.of("json", "{}", "redacted", "false"),
                        Map.of("omitted", false),
                        Map.of(
                                "json",
                                "{}",
                                "redacted",
                                true,
                                "secret",
                                "private-invalid-payload"))) {
            var body = new HashMap<>(body());
            body.put("preview", preview);
            var error =
                    assertThrows(
                            IllegalArgumentException.class,
                            () -> contract.action(writeAction(body)));
            assertFalse(error.getMessage().contains("private-invalid-payload"));
        }
        var body = new HashMap<>(body());
        body.put("preview", Map.of("omitted", true));
        assertTrue(contract.action(writeAction(body)).body().preview().omitted());
        for (Object credentials :
                List.of(
                        List.of(),
                        List.of(Map.of("placeholder", "real-secret", "header", "authorization")),
                        List.of(Map.of("placeholder", "AUTOMANTLE_TOKEN", "header", "cookie")),
                        List.of(
                                Map.of(
                                        "placeholder",
                                        "AUTOMANTLE_TOKEN",
                                        "header",
                                        "authorization",
                                        "secret",
                                        "real-secret")),
                        List.of(
                                Map.of(
                                        "placeholder",
                                        "AUTOMANTLE_TOKEN",
                                        "header",
                                        "authorization"),
                                Map.of(
                                        "placeholder",
                                        "AUTOMANTLE_OTHER",
                                        "header",
                                        "authorization")))) {
            var action = new HashMap<>(action("api.example.com", "/api"));
            action.put("credentials", credentials);
            assertThrows(IllegalArgumentException.class, () -> contract.action(action));
        }
    }
}
