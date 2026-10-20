package com.automantle.api.controller;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import com.automantle.api.service.VmGatewayService;
import com.automantle.api.policy.HttpPolicyFixtures;

import org.junit.jupiter.api.Test;

import tools.jackson.databind.json.JsonMapper;

import java.util.*;

class CredentialControllerTest {
    private static final UUID PROFILE = UUID.fromString("10000000-0000-0000-0000-000000000001");

    private static CredentialController.Save request(String secret) {
        return new CredentialController.Save("GITHUB_TOKEN", secret, null);
    }

    @Test
    void responsesNeverReturnSecretEvenIfGatewayAddsOne() throws Exception {
        var gateway = mock(VmGatewayService.class);
        var controller = new CredentialController(
                gateway, HttpPolicyFixtures.contract(), HttpPolicyFixtures.validator());
        var mapper = JsonMapper.builder().build();
        var metadata =
                mapper.readTree(
                        "{\"name\":\"GITHUB_TOKEN\",\"secret\":\"synthetic-secret-value-12345\",\"header\":\"authorization\",\"agentProfileId\":\""
                                + PROFILE
                                + "\",\"host\":\"api.example.com\",\"methods\":[\"GET\"],\"paths\":[\"/api\"]}");
        when(gateway.command(anyMap())).thenReturn(metadata);
        var response = controller.create(request("synthetic-secret-value-12345"));
        assertEquals("GITHUB_TOKEN", response.get("name").asText());
        assertFalse(response.containsKey("secret"));
        assertFalse(response.toString().contains("synthetic-secret"));
        assertEquals(Set.of("name"), response.keySet());
        var array = mapper.createArrayNode();
        array.add(metadata);
        when(gateway.command(Map.of("command", "credential-list"))).thenReturn(array);
        assertFalse(controller.list().toString().contains("synthetic-secret"));
        assertFalse(
                request("synthetic-secret-value-12345").toString().contains("synthetic-secret"));
    }

    @Test
    void updatesKeepOmittedSecretAndNamesCannotChange() throws Exception {
        var gateway = mock(VmGatewayService.class);
        var controller = new CredentialController(
                gateway, HttpPolicyFixtures.contract(), HttpPolicyFixtures.validator());
        when(gateway.command(anyMap()))
                .thenReturn(JsonMapper.builder().build().readTree("{\"name\":\"GITHUB_TOKEN\"}"));
        controller.update("GITHUB_TOKEN", request(null));
        @SuppressWarnings("unchecked")
        var capture = org.mockito.ArgumentCaptor.forClass(Map.class);
        verify(gateway).command(capture.capture());
        var input = (Map<?, ?>) capture.getValue().get("credential");
        assertFalse(input.containsKey("secret"));
        assertEquals(Set.of("name"), input.keySet());
        assertThrows(
                IllegalArgumentException.class,
                () -> controller.update("OTHER_TOKEN", request(null)));
        assertThrows(IllegalArgumentException.class, () -> controller.delete("../secret"));
        controller.delete("GITHUB_TOKEN");
        verify(gateway).command(Map.of("command", "credential-delete", "name", "GITHUB_TOKEN"));
    }

    @Test
    void scopesAreValidatedAndForwardedWithoutReadingSecrets() throws Exception {
        var gateway = mock(VmGatewayService.class);
        var controller = new CredentialController(
                gateway, HttpPolicyFixtures.contract(), HttpPolicyFixtures.validator());
        when(gateway.command(anyMap()))
                .thenReturn(
                        JsonMapper.builder()
                                .build()
                                .readTree("{\"name\":\"GITHUB_TOKEN\",\"scopes\":[]}"));
        var scope =
                new CredentialController.Scope(
                        PROFILE,
                        "API.EXAMPLE.COM",
                        List.of("/api/*", "/api/%C3%A9"),
                        "json",
                        "/auth/token",
                        List.of("GET"));
        var response =
                controller.update(
                        "GITHUB_TOKEN",
                        new CredentialController.Save("GITHUB_TOKEN", null, List.of(scope)));
        assertTrue(response.containsKey("scopes"));
        @SuppressWarnings("unchecked")
        var capture = org.mockito.ArgumentCaptor.forClass(Map.class);
        verify(gateway).command(capture.capture());
        var credential = (Map<?, ?>) capture.getValue().get("credential");
        assertFalse(credential.containsKey("secret"));
        var saved = (Map<?, ?>) ((List<?>) credential.get("scopes")).getFirst();
        assertEquals("api.example.com", saved.get("host"));
        assertEquals(scope.paths(), saved.get("paths"));
        assertEquals(List.of("GET"), saved.get("legacyMethods"));
        for (var invalid :
                List.of(
                        new CredentialController.Scope(
                                PROFILE,
                                "*.example.com",
                                List.of("/*"),
                                "header",
                                "authorization",
                                null),
                        new CredentialController.Scope(
                                PROFILE, "api.example.com", List.of("/*"), "json", "token", null),
                        new CredentialController.Scope(
                                PROFILE,
                                "api.example.com",
                                List.of("/*"),
                                "header",
                                "host",
                                null))) {
            assertThrows(
                    IllegalArgumentException.class,
                    () ->
                            controller.update(
                                    "GITHUB_TOKEN",
                                    new CredentialController.Save(
                                            "GITHUB_TOKEN", null, List.of(invalid))));
        }
    }

    @Test
    void invalidScopePathsAndMethodLimitsNeverReachCredentialStorage() {
        var gateway = mock(VmGatewayService.class);
        var controller = new CredentialController(
                gateway, HttpPolicyFixtures.contract(), HttpPolicyFixtures.validator());
        List<List<String>> invalidPaths =
                List.of(
                        List.of(),
                        List.of("/api", "/api"),
                        List.of("/api/../private"),
                        List.of("/api/%2F"),
                        Arrays.asList("/api", null),
                        Collections.nCopies(101, "/api"));
        for (var paths : invalidPaths) {
            var scope =
                    new CredentialController.Scope(
                            PROFILE, "api.example.com", paths, "header", "authorization", null);
            assertThrows(
                    IllegalArgumentException.class,
                    () ->
                            controller.update(
                                    "GITHUB_TOKEN",
                                    new CredentialController.Save(
                                            "GITHUB_TOKEN", null, List.of(scope))));
        }
        List<List<String>> invalidMethods =
                List.of(
                        List.of("GET", "get"), List.of("BAD METHOD"),
                        Arrays.asList("GET", null), Collections.nCopies(101, "GET"));
        for (var methods : invalidMethods) {
            var scope =
                    new CredentialController.Scope(
                            PROFILE,
                            "api.example.com",
                            List.of("/api/*"),
                            "header",
                            "authorization",
                            methods);
            assertThrows(
                    IllegalArgumentException.class,
                    () ->
                            controller.update(
                                    "GITHUB_TOKEN",
                                    new CredentialController.Save(
                                            "GITHUB_TOKEN", null, List.of(scope))));
        }
        verifyNoInteractions(gateway);
    }
}
