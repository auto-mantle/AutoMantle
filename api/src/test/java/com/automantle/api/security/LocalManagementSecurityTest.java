package com.automantle.api.security;

import static org.mockito.Mockito.mock;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.automantle.api.config.GatewaySecurityConfig;
import com.automantle.api.config.SecurityConfig;
import com.automantle.api.controller.CsrfController;
import com.automantle.api.controller.DashboardController;
import com.automantle.api.controller.GatewayController;
import com.automantle.api.service.ApprovalRequestService;
import com.automantle.api.service.PolicyEvaluationService;

import org.junit.jupiter.api.*;
import org.springframework.context.annotation.*;
import org.springframework.core.env.MapPropertySource;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.test.web.servlet.*;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import java.util.Map;

class LocalManagementSecurityTest {
    private AnnotationConfigWebApplicationContext context;
    private MockMvc mvc;

    @Configuration
    @EnableWebMvc
    @EnableWebSecurity
    @Import({
        SecurityConfig.class,
        GatewaySecurityConfig.class,
        CsrfController.class,
        GatewayController.class,
        com.automantle.api.controller.SetupController.class,
        DashboardController.class,
        com.automantle.api.controller.RequestHistoryController.class,
        com.automantle.api.controller.CredentialController.class,
        com.automantle.api.policy.HttpPolicyContract.class,
        com.automantle.api.policy.HttpPolicyValidator.class,
        com.automantle.api.controller.VmController.class,
        com.automantle.api.controller.NetworkHistoryController.class,
        Probe.class
    })
    static class TestConfig {
        @Bean
        com.automantle.api.config.HttpPolicyProperties httpPolicyProperties() {
            return com.automantle.api.policy.HttpPolicyFixtures.limits();
        }

        @Bean
        com.automantle.api.service.SetupService setupService() {
            return mock(com.automantle.api.service.SetupService.class);
        }

        @Bean
        com.automantle.api.service.AgentProfileFacadeService profiles() {
            return mock(com.automantle.api.service.AgentProfileFacadeService.class);
        }

        @Bean
        PolicyEvaluationService evaluation() {
            return mock(PolicyEvaluationService.class);
        }

        @Bean
        ApprovalRequestService approvals() {
            return mock(ApprovalRequestService.class);
        }

        @Bean
        com.automantle.api.service.RequestHistoryService history() {
            return mock(com.automantle.api.service.RequestHistoryService.class);
        }

        @Bean
        com.automantle.api.service.VmGatewayService vmGateway() {
            return mock(com.automantle.api.service.VmGatewayService.class);
        }
    }

    @RestController
    static class Probe {
        @GetMapping("/probe")
        String read() {
            return "local";
        }

        @PostMapping("/probe")
        String write() {
            return "changed";
        }
    }

    @BeforeEach
    void setup() {
        context = new AnnotationConfigWebApplicationContext();
        context.setServletContext(new MockServletContext());
        context.getEnvironment()
                .getPropertySources()
                .addFirst(
                        new MapPropertySource(
                                "local",
                                Map.of("app.security.frontend-url", "http://localhost:3000")));
        context.register(TestConfig.class);
        context.refresh();
        mvc =
                MockMvcBuilders.webAppContextSetup(context)
                        .addFilters(context.getBean(FilterChainProxy.class))
                        .build();
    }

    @AfterEach
    void cleanup() {
        if (context != null) context.close();
    }

    private MockHttpServletRequestBuilder local(MockHttpServletRequestBuilder request) {
        return request.with(
                r -> {
                    r.setRemoteAddr("127.0.0.1");
                    r.setServerName("localhost");
                    r.setServerPort(8081);
                    return r;
                });
    }

    @Test
    void approvalExpirationIsNativeOnlyAndValidatesLifecycleReasons() throws Exception {
        var id = java.util.UUID.randomUUID();
        var profile = java.util.UUID.randomUUID();
        String path = "/gateway/approval-requests/" + id + "/expire";
        String body = "{\"agentProfileId\":\"" + profile + "\",\"reason\":\"CLIENT_CLOSED\"}";
        mvc.perform(local(post(path)).contentType("application/json").content(body))
                .andExpect(status().isForbidden());
        mvc.perform(
                        local(post(path))
                                .header("X-Automantle-Gateway", "local")
                                .header("Origin", "http://localhost:8081")
                                .contentType("application/json")
                                .content(body))
                .andExpect(status().isForbidden());
        mvc.perform(
                        local(post(path))
                                .header("X-Automantle-Gateway", "local")
                                .contentType("application/json")
                                .content(body))
                .andExpect(status().isNoContent());
        org.mockito.Mockito.verify(context.getBean(ApprovalRequestService.class))
                .expireUnexecutedRequest(
                        id,
                        profile,
                        com.automantle.api.entity.ApprovalExpirationReason.CLIENT_CLOSED);
        mvc.perform(
                        local(post(path))
                                .header("X-Automantle-Gateway", "local")
                                .contentType("application/json")
                                .content(body.replace("CLIENT_CLOSED", "HTTP_TIMEOUT_GUESSED")))
                .andExpect(status().isBadRequest());
    }

    @Test
    void credentialsRejectMissingCsrfAndHostileOrigins() throws Exception {
        mvc.perform(local(post("/credentials")).contentType("application/json").content("{}"))
                .andExpect(status().isForbidden());
        mvc.perform(local(get("/credentials")).header("Origin", "https://attacker.example"))
                .andExpect(status().isForbidden());
        mvc.perform(local(delete("/credentials/GITHUB_TOKEN"))).andExpect(status().isForbidden());
        var gateway = context.getBean(com.automantle.api.service.VmGatewayService.class);
        org.mockito.Mockito.verifyNoInteractions(gateway);
    }

    @Test
    void packetAuditIsNativeOnlyAndValidatesCounts() throws Exception {
        String event =
                "[{\"requestId\":\"10000000-0000-0000-0000-000000000001\",\"agentProfileId\":\"10000000-0000-0000-0000-000000000002\",\"runId\":\"automantle-vm-"
                        + "a".repeat(32)
                        + "\",\"protocol\":\"UDP\",\"etherType\":2048,\"packetCount\":2,\"byteCount\":84,\"reason\":\"UNSUPPORTED_NETWORK\"}]";
        mvc.perform(
                        local(post("/gateway/network-history"))
                                .contentType("application/json")
                                .content(event))
                .andExpect(status().isForbidden());
        mvc.perform(
                        local(post("/gateway/network-history"))
                                .header("X-Automantle-Gateway", "local")
                                .header("Origin", "http://localhost:8082")
                                .contentType("application/json")
                                .content(event))
                .andExpect(status().isForbidden());
        mvc.perform(
                        local(post("/gateway/network-history"))
                                .header("X-Automantle-Gateway", "local")
                                .contentType("application/json")
                                .content(event))
                .andExpect(status().isNoContent());
        mvc.perform(
                        local(post("/gateway/network-history"))
                                .header("X-Automantle-Gateway", "local")
                                .contentType("application/json")
                                .content(event.replace("\"packetCount\":2", "\"packetCount\":0")))
                .andExpect(status().isBadRequest());
    }

    @Test
    void dashboardNeedsNoLoginAndHasNoLoginEndpoints() throws Exception {
        mvc.perform(local(get("/probe")))
                .andExpect(status().isOk())
                .andExpect(content().string("local"));
        for (String path :
                new String[] {
                    "/auth/me",
                    "/auth/login",
                    "/auth/register",
                    "/oauth2/authorization/keycloak",
                    "/organizations",
                    "/projects",
                    "/environments"
                }) {
            mvc.perform(local(get(path))).andExpect(status().isNotFound());
        }
    }

    @Test
    void servesDashboardRoutesWithoutSwallowingUnknownApiOrAssetPaths() throws Exception {
        mvc.perform(local(get("/")))
                .andExpect(status().isOk())
                .andExpect(forwardedUrl("/index.html"));
        mvc.perform(local(get("/profiles/00000000-0000-0000-0000-000000000002")))
                .andExpect(status().isOk())
                .andExpect(forwardedUrl("/index.html"));
        for (String path :
                new String[] {"/agents/unknown", "/assets/missing.js", "/gateway/unknown"}) {
            var request = local(get(path));
            if (path.startsWith("/gateway/")) request.header("X-Automantle-Gateway", "local");
            mvc.perform(request).andExpect(status().isNotFound());
        }
    }

    @Test
    void packagedDashboardCanMutateOnItsOwnOriginWithCsrf() throws Exception {
        var result =
                mvc.perform(local(get("/csrf")).header("Origin", "http://localhost:8081"))
                        .andExpect(status().isOk())
                        .andReturn();
        CsrfToken token = (CsrfToken) result.getRequest().getAttribute(CsrfToken.class.getName());
        var session = (MockHttpSession) result.getRequest().getSession(false);
        mvc.perform(
                        local(post("/probe"))
                                .session(session)
                                .header(token.getHeaderName(), token.getToken())
                                .header("Origin", "http://localhost:8081"))
                .andExpect(status().isOk())
                .andExpect(content().string("changed"));
    }

    @Test
    void rejectsVmAndLanPeersEvenWithSpoofedForwardingHeaders() throws Exception {
        for (String peer : new String[] {"172.30.0.2", "192.168.1.10"}) {
            mvc.perform(
                            local(get("/probe"))
                                    .with(
                                            r -> {
                                                r.setRemoteAddr(peer);
                                                return r;
                                            })
                                    .header("X-Forwarded-For", "127.0.0.1"))
                    .andExpect(status().isForbidden());
        }
    }

    @Test
    void rejectsDnsRebindingAndUntrustedBrowserOrigins() throws Exception {
        mvc.perform(
                        local(get("/probe"))
                                .with(
                                        r -> {
                                            r.setServerName("attacker.example");
                                            return r;
                                        }))
                .andExpect(status().isForbidden());
        mvc.perform(local(get("/csrf")).header("Origin", "https://attacker.example"))
                .andExpect(status().isForbidden());
        mvc.perform(local(get("/csrf")).header("Sec-Fetch-Site", "cross-site"))
                .andExpect(status().isForbidden());
        mvc.perform(local(get("/csrf")).header("Origin", "null")).andExpect(status().isForbidden());
    }

    @Test
    void localMutationsStillRequireCsrfAndRejectHostileOriginsWithAValidToken() throws Exception {
        mvc.perform(local(post("/probe"))).andExpect(status().isForbidden());
        var result =
                mvc.perform(local(get("/csrf")).header("Origin", "http://localhost:3000"))
                        .andExpect(status().isOk())
                        .andReturn();
        CsrfToken token = (CsrfToken) result.getRequest().getAttribute(CsrfToken.class.getName());
        var session = (MockHttpSession) result.getRequest().getSession(false);
        mvc.perform(
                        local(post("/probe"))
                                .session(session)
                                .header(token.getHeaderName(), token.getToken())
                                .header("Origin", "http://localhost:3000"))
                .andExpect(status().isOk())
                .andExpect(content().string("changed"));
        mvc.perform(
                        local(post("/probe"))
                                .session(session)
                                .header(token.getHeaderName(), token.getToken())
                                .header("Origin", "https://attacker.example"))
                .andExpect(status().isForbidden());
    }

    @Test
    void nativeGatewayRequestsNeedNoAccountTokenOrCsrf() throws Exception {
        mvc.perform(local(get("/gateway/health")).header("X-Automantle-Gateway", "local"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ready"));
        org.mockito.Mockito.when(
                        context.getBean(PolicyEvaluationService.class)
                                .evaluateAction(org.mockito.ArgumentMatchers.any()))
                .thenReturn(
                        new com.automantle.api.dto.GatewayEvaluateResponse(
                                "DENY", "No rule", null, java.util.List.of()));
        mvc.perform(
                        local(post("/gateway/evaluate"))
                                .header("X-Automantle-Gateway", "local")
                                .contentType("application/json")
                                .content(
                                        "{\"agentProfileId\":\"00000000-0000-0000-0000-000000000001\",\"action\":{\"resource_type\":\"http\",\"method\":\"get\",\"host\":\"example.com\",\"path\":\"/\"}}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("DENY"));
        mvc.perform(local(get("/gateway/auth/login")).header("X-Automantle-Gateway", "local"))
                .andExpect(status().isNotFound());
        mvc.perform(local(get("/gateways"))).andExpect(status().isNotFound());
    }

    @Test
    void vmTerminalInputRequiresCsrfAndRejectsRemotePeers() throws Exception {
        String path = "/vms/automantle-vm-" + "a".repeat(32) + "/terminal/input";
        mvc.perform(local(post(path)).contentType("application/json").content("{\"data\":[3]}"))
                .andExpect(status().isForbidden());
        mvc.perform(
                        local(get("/vms"))
                                .with(
                                        r -> {
                                            r.setRemoteAddr("172.30.0.2");
                                            return r;
                                        }))
                .andExpect(status().isForbidden());
        var result = mvc.perform(local(get("/csrf"))).andReturn();
        var token = (CsrfToken) result.getRequest().getAttribute(CsrfToken.class.getName());
        var session = (MockHttpSession) result.getRequest().getSession(false);
        mvc.perform(
                        local(post(path))
                                .session(session)
                                .header(token.getHeaderName(), token.getToken())
                                .header("Origin", "https://attacker.example")
                                .contentType("application/json")
                                .content("{\"data\":[3]}"))
                .andExpect(status().isForbidden());
        org.mockito.Mockito.verifyNoInteractions(
                context.getBean(com.automantle.api.service.VmGatewayService.class));
        mvc.perform(
                        local(post(path))
                                .session(session)
                                .header(token.getHeaderName(), token.getToken())
                                .contentType("application/json")
                                .content("{\"data\":[3]}"))
                .andExpect(status().isOk());
    }

    @Test
    void gatewayValidatesProfilesThroughTheLocalNativeBarrier() throws Exception {
        var id = java.util.UUID.fromString("10000000-0000-0000-0000-000000000001");
        var profiles = context.getBean(com.automantle.api.service.AgentProfileFacadeService.class);
        org.mockito.Mockito.when(profiles.getProfile(id))
                .thenReturn(new com.automantle.api.dto.AgentProfileResponse(id, "Agent", null));
        String path = "/gateway/agent-profiles/" + id;
        mvc.perform(local(get(path)).header("X-Automantle-Gateway", "local"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(id.toString()));
        mvc.perform(local(get(path))).andExpect(status().isForbidden());
        mvc.perform(
                        local(get(path))
                                .header("X-Automantle-Gateway", "local")
                                .header("Origin", "http://localhost:8081"))
                .andExpect(status().isForbidden());
        mvc.perform(
                        local(get(path))
                                .header("X-Automantle-Gateway", "local")
                                .with(
                                        r -> {
                                            r.setRemoteAddr("172.30.0.2");
                                            return r;
                                        }))
                .andExpect(status().isForbidden());
    }

    @Test
    void requestHistoryIsLocalAndClearRequiresCsrf() throws Exception {
        mvc.perform(local(delete("/request-history"))).andExpect(status().isForbidden());
        var result = mvc.perform(local(get("/csrf"))).andReturn();
        var token = (CsrfToken) result.getRequest().getAttribute(CsrfToken.class.getName());
        var session = (MockHttpSession) result.getRequest().getSession(false);
        mvc.perform(
                        local(delete("/request-history"))
                                .session(session)
                                .header(token.getHeaderName(), token.getToken()))
                .andExpect(status().isNoContent());
        org.mockito.Mockito.verify(
                        context.getBean(com.automantle.api.service.RequestHistoryService.class))
                .clear();
        mvc.perform(
                        local(get("/request-history"))
                                .with(
                                        r -> {
                                            r.setRemoteAddr("192.168.1.20");
                                            return r;
                                        }))
                .andExpect(status().isForbidden());
        String event =
                "{\"requestId\":\"00000000-0000-0000-0000-000000000002\",\"agentProfileId\":\"00000000-0000-0000-0000-000000000001\",\"host\":\"api.example.com\",\"port\":443,\"method\":\"CONNECT\",\"reason\":\"HTTPS_DISABLED\"}";
        mvc.perform(
                        local(post("/gateway/request-history"))
                                .contentType("application/json")
                                .content(event))
                .andExpect(status().isForbidden());
        mvc.perform(
                        local(post("/gateway/request-history"))
                                .header("X-Automantle-Gateway", "local")
                                .contentType("application/json")
                                .content(event))
                .andExpect(status().isNoContent());
        mvc.perform(
                        local(post("/gateway/request-history"))
                                .header("X-Automantle-Gateway", "local")
                                .header("Origin", "http://localhost:8081")
                                .contentType("application/json")
                                .content(event))
                .andExpect(status().isForbidden());
    }

    @Test
    void gatewayRejectsBrowserRequestsEvenFromTheDashboardOrigin() throws Exception {
        mvc.perform(local(get("/gateway/health"))).andExpect(status().isForbidden());
        for (String origin :
                new String[] {"http://localhost:3000", "https://attacker.example", "null"}) {
            mvc.perform(
                            local(get("/gateway/health"))
                                    .header("X-Automantle-Gateway", "local")
                                    .header("Origin", origin))
                    .andExpect(status().isForbidden());
        }
        mvc.perform(
                        local(get("/gateway/health"))
                                .header("X-Automantle-Gateway", "local")
                                .header("Sec-Fetch-Site", "same-origin"))
                .andExpect(status().isForbidden());
    }

    @Test
    void setupStartIsNativeOnlyAndFinishNeedsBrowserCsrf() throws Exception {
        String profile = "10000000-0000-0000-0000-000000000001";
        String body = "{\"agentProfileId\":\"" + profile + "\",\"lifetimeSeconds\":300}";
        mvc.perform(local(post("/gateway/setup")).contentType("application/json").content(body))
                .andExpect(status().isForbidden());
        mvc.perform(
                        local(post("/gateway/setup"))
                                .header("X-Automantle-Gateway", "local")
                                .header("Origin", "http://localhost:8081")
                                .contentType("application/json")
                                .content(body))
                .andExpect(status().isForbidden());
        mvc.perform(
                        local(post("/gateway/setup"))
                                .header("X-Automantle-Gateway", "local")
                                .contentType("application/json")
                                .content(body))
                .andExpect(status().isCreated());
        mvc.perform(local(post("/agents/profiles/" + profile + "/setup/finish")))
                .andExpect(status().isForbidden());
        var result = mvc.perform(local(get("/csrf"))).andReturn();
        var token = (CsrfToken) result.getRequest().getAttribute(CsrfToken.class.getName());
        var session = (MockHttpSession) result.getRequest().getSession(false);
        mvc.perform(
                        local(post("/agents/profiles/" + profile + "/setup/finish"))
                                .session(session)
                                .header(token.getHeaderName(), token.getToken()))
                .andExpect(status().isNoContent());
        org.mockito.Mockito.verify(context.getBean(com.automantle.api.service.SetupService.class))
                .finish(java.util.UUID.fromString(profile), null);
        mvc.perform(local(get("/agents/policies"))).andExpect(status().isNotFound());
    }

    @Test
    void gatewayRejectsVmLanAndRebindingRequests() throws Exception {
        for (String peer : new String[] {"172.30.0.2", "192.168.1.10"}) {
            mvc.perform(
                            local(get("/gateway/health"))
                                    .header("X-Automantle-Gateway", "local")
                                    .with(
                                            r -> {
                                                r.setRemoteAddr(peer);
                                                return r;
                                            })
                                    .header("X-Forwarded-For", "127.0.0.1"))
                    .andExpect(status().isForbidden());
        }
        mvc.perform(
                        local(get("/gateway/health"))
                                .header("X-Automantle-Gateway", "local")
                                .with(
                                        r -> {
                                            r.setServerName("attacker.example");
                                            return r;
                                        }))
                .andExpect(status().isForbidden());
    }
}
