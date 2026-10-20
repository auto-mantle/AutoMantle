package com.automantle.api.policy;

import com.automantle.api.config.HttpPolicyProperties;
import org.springframework.util.unit.DataSize;

public final class HttpPolicyFixtures {
    private HttpPolicyFixtures() {}

    public static HttpPolicyProperties limits() {
        return new HttpPolicyProperties(
                DataSize.ofMegabytes(8), DataSize.ofKilobytes(16), 100, 32, 128, 1024, 1024, 2048);
    }

    public static HttpPolicyValidator validator() {
        return new HttpPolicyValidator(limits());
    }

    public static HttpPolicyContract contract() {
        HttpPolicyProperties limits = limits();
        return new HttpPolicyContract(limits, new HttpPolicyValidator(limits));
    }

    public static PolicyDecisionEngine engine() {
        return new PolicyDecisionEngine(contract());
    }
}
