package com.automantle.api.dto;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

import java.util.UUID;

public record ReportNetworkHistory(
        @NotNull UUID requestId,
        @NotNull UUID agentProfileId,
        @NotNull @Pattern(regexp = "automantle-vm-[0-9a-f]{32}") String runId,
        @Min(0) @Max(65535) Integer etherType,
        @NotNull @Pattern(regexp = "UNKNOWN|ARP|IPV4|TCP|UDP|ICMP|IPV4_OTHER|IPV6|VLAN")
                String protocol,
        @Pattern(regexp = "[0-9a-fA-F:.]{1,45}") String sourceIp,
        @Pattern(regexp = "[0-9a-fA-F:.]{1,45}") String destinationIp,
        @Min(0) @Max(65535) Integer sourcePort,
        @Min(0) @Max(65535) Integer destinationPort,
        @Min(1) long packetCount,
        @Min(0) long byteCount,
        @NotNull Reason reason) {
    public enum Reason {
        INSPECTION_TRANSPORT,
        LINK_CONTROL,
        UNSUPPORTED_NETWORK,
        MALFORMED_NETWORK,
        SOURCE_BINDING_DENIED
    }
}
