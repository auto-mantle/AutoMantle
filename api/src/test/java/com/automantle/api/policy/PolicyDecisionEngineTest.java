package com.automantle.api.policy;

import static org.junit.jupiter.api.Assertions.*;

import com.automantle.api.entity.RuleEffect;
import com.automantle.api.policy.PolicyDecisionEngine.Rule;

import org.junit.jupiter.api.Test;

import java.util.*;

class PolicyDecisionEngineTest {
    private final PolicyDecisionEngine engine = HttpPolicyFixtures.engine();

    private Map<String, Object> action() {
        return HttpPolicyContractTest.action("api.example.com", "/api/users");
    }

    private Rule rule(RuleEffect effect) {
        return new Rule(UUID.randomUUID(), effect, HttpPolicyContractTest.match("/api/*"));
    }

    @Test
    void combinesEveryPairOfEffectsWithoutOrderDependence() {
        for (RuleEffect first : RuleEffect.values())
            for (RuleEffect second : RuleEffect.values()) {
                Rule a = rule(first), b = rule(second);
                RuleEffect expected =
                        first == RuleEffect.DENY || second == RuleEffect.DENY
                                ? RuleEffect.DENY
                                : first == RuleEffect.REQUIRE_APPROVAL
                                                || second == RuleEffect.REQUIRE_APPROVAL
                                        ? RuleEffect.REQUIRE_APPROVAL
                                        : RuleEffect.ALLOW;
                var forward = engine.evaluate(action(), List.of(a, b));
                assertEquals(expected, forward.effect());
                assertEquals(forward, engine.evaluate(action(), List.of(b, a)));
                assertEquals(2, forward.matchedRules().size());
            }
    }

    @Test
    void defaultsToDenyAndIgnoresNonmatchingRestrictions() {
        assertEquals(RuleEffect.DENY, engine.evaluate(action(), List.of()).effect());
        Rule allow = rule(RuleEffect.ALLOW);
        Rule unrelated =
                new Rule(
                        UUID.randomUUID(),
                        RuleEffect.DENY,
                        HttpPolicyContractTest.match("/other/*"));
        var result = engine.evaluate(action(), List.of(allow, unrelated));
        assertEquals(RuleEffect.ALLOW, result.effect());
        assertEquals(
                List.of(allow.ruleId()),
                result.matchedRules().stream()
                        .map(PolicyDecisionEngine.MatchedRule::ruleId)
                        .toList());
    }

    @Test
    void failsClosedOnMalformedActionsOrApplicableRules() {
        Rule allow = rule(RuleEffect.ALLOW);
        assertEquals(RuleEffect.DENY, engine.evaluate(Map.of(), List.of(allow)).effect());
        assertEquals(RuleEffect.DENY, engine.evaluate(null, List.of(allow)).effect());
        var legacy = new HashMap<>(allow.match());
        legacy.remove("hosts");
        Rule invalid = new Rule(UUID.randomUUID(), RuleEffect.ALLOW, legacy);
        assertEquals(RuleEffect.DENY, engine.evaluate(action(), List.of(allow, invalid)).effect());
        Rule missingEffect = new Rule(UUID.randomUUID(), null, allow.match());
        assertEquals(
                RuleEffect.DENY, engine.evaluate(action(), List.of(allow, missingEffect)).effect());
    }

    private Map<String, Object> placement(String location, String selector) {
        return Map.of("placeholder", "SERVICE_TOKEN", "location", location, "selector", selector);
    }

    @Test
    void credentialScopeIsCheckedSeparatelyByGateway() {
        var input = new HashMap<>(action());
        input.put("credentials", List.of(placement("header", "authorization")));
        var result = engine.evaluate(input, List.of(rule(RuleEffect.ALLOW)));
        assertEquals(RuleEffect.ALLOW, result.effect());
        assertEquals(RuleEffect.DENY, engine.evaluate(input, List.of()).effect());
    }

    @Test
    void requestPoliciesContinueToRestrictDestinationMethodAndPath() {
        var allowed = placement("json", "/auth/token");
        var match = new HashMap<>(HttpPolicyContractTest.match("/api/*"));
        match.put("credentials", List.of(allowed));
        Rule grant = new Rule(UUID.randomUUID(), RuleEffect.ALLOW, match);
        var input = new HashMap<>(action());
        input.put("credentials", List.of(allowed));
        assertEquals(RuleEffect.ALLOW, engine.evaluate(input, List.of(grant)).effect());
        for (var wrong :
                List.of(
                        placement("json", "/description"),
                        placement("query", "token"),
                        placement("header", "authorization"),
                        Map.<String, Object>of(
                                "placeholder",
                                "OTHER_TOKEN",
                                "location",
                                "json",
                                "selector",
                                "/auth/token"))) {
            input.put("credentials", List.of(wrong));
            assertEquals(
                    RuleEffect.ALLOW,
                    engine.evaluate(input, List.of(grant, rule(RuleEffect.ALLOW))).effect());
        }
        input.put("credentials", List.of(allowed));
        input.put("host", "other.example.com");
        assertEquals(RuleEffect.DENY, engine.evaluate(input, List.of(grant)).effect());
        input.put("host", "api.example.com");
        input.put("method", "post");
        assertEquals(RuleEffect.DENY, engine.evaluate(input, List.of(grant)).effect());
        input.put("method", "get");
        input.put("path", "/other");
        assertEquals(RuleEffect.DENY, engine.evaluate(input, List.of(grant)).effect());
    }

    @Test
    void approvalAndDenyStillTakePrecedenceWithCredentialMetadata() {
        var allowed = placement("query", "api_key");
        var match = new HashMap<>(HttpPolicyContractTest.match("/api/*"));
        match.put("credentials", List.of(allowed));
        Rule grant = new Rule(UUID.randomUUID(), RuleEffect.REQUIRE_APPROVAL, match);
        var input = new HashMap<>(action());
        input.put("credentials", List.of(allowed));
        assertEquals(
                RuleEffect.REQUIRE_APPROVAL,
                engine.evaluate(input, List.of(grant, rule(RuleEffect.ALLOW))).effect());
        assertEquals(
                RuleEffect.DENY,
                engine.evaluate(input, List.of(grant, rule(RuleEffect.DENY))).effect());
        input.put("credentials", List.of(allowed, placement("json", "/note")));
        assertEquals(RuleEffect.REQUIRE_APPROVAL, engine.evaluate(input, List.of(grant)).effect());
    }
}
