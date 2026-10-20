package com.automantle.api.policy;

import com.automantle.api.entity.RuleEffect;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Component
public final class PolicyDecisionEngine {
    public static final String NO_MATCHING_RULE_REASON = "No applicable rule allows this action";

    public record Rule(UUID ruleId, RuleEffect effect, Map<String, Object> match) {}

    public record MatchedRule(UUID ruleId, RuleEffect effect) {}

    public record Decision(
            RuleEffect effect, String reason, HttpAction action, List<MatchedRule> matchedRules) {
        public boolean isUnmatchedAction() {
            return action != null
                    && matchedRules.isEmpty()
                    && reason.equals(NO_MATCHING_RULE_REASON);
        }
    }

    private final HttpPolicyContract contract;

    public PolicyDecisionEngine(HttpPolicyContract contract) {
        this.contract = contract;
    }

    public Decision evaluate(Map<String, Object> input, List<Rule> rules) {
        HttpAction action;
        try {
            action = contract.action(input);
        } catch (IllegalArgumentException error) {
            return new Decision(
                    RuleEffect.DENY,
                    "Invalid or unsupported action: " + error.getMessage(),
                    null,
                    List.of());
        }
        List<MatchedRule> matched = new ArrayList<>();
        for (Rule rule : rules.stream().sorted(Comparator.comparing(Rule::ruleId)).toList()) {
            try {
                HttpRuleMatch match = contract.match(rule.match());
                if (rule.effect() == null) {
                    throw new IllegalArgumentException("Rule effect is required");
                }
                if (match.matches(action)) {
                    matched.add(new MatchedRule(rule.ruleId(), rule.effect()));
                }
            } catch (IllegalArgumentException error) {
                return new Decision(
                        RuleEffect.DENY,
                        "Invalid applicable rule " + rule.ruleId() + ": " + error.getMessage(),
                        action,
                        List.of());
            }
        }
        List<MatchedRule> immutable = List.copyOf(matched);
        if (matched.stream().anyMatch(rule -> rule.effect() == RuleEffect.DENY)) {
            return new Decision(
                    RuleEffect.DENY,
                    "A matching rule explicitly denies this action",
                    action,
                    immutable);
        }
        if (matched.stream().anyMatch(rule -> rule.effect() == RuleEffect.REQUIRE_APPROVAL)) {
            return new Decision(
                    RuleEffect.REQUIRE_APPROVAL,
                    "A matching rule requires human approval",
                    action,
                    immutable);
        }
        if (!matched.isEmpty()) {
            return new Decision(
                    RuleEffect.ALLOW, "Matching rules allow this action", action, immutable);
        }
        return new Decision(RuleEffect.DENY, NO_MATCHING_RULE_REASON, action, immutable);
    }
}
