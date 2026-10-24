# How AutoMantle works

```text
Browser on Linux host ──> local dashboard/API ──> SQLite
                               ^                    profiles, rules,
                               |                    approvals, history
                         policy evaluation
                               |
Guest VM ──> isolated network ──> gateway proxy ──> permitted destination
    |                              |
    +── Linux and agent harness    +── credential insertion, audit
```

The API manages policy and the dashboard. The gateway runs VMs and intercepts supported outbound HTTP traffic. The privileged helper performs narrowly scoped host setup for the gateway. Each VM is associated with exactly one agent profile, and the gateway asks the API to evaluate requests against that profile.

## Request decisions

For an HTTP action, a rule matches its method, exact host, and path. The decision order is:

1. A matching `DENY` rule denies the request.
2. Otherwise, a matching `REQUIRE_APPROVAL` rule waits for a human decision.
3. Otherwise, a matching `ALLOW` rule permits the request.
4. With no matching rule, the request is denied.

Invalid or unsupported actions are denied. During an active setup session, an otherwise unmatched **supported** request becomes a setup prompt instead of an immediate denial. An explicit deny still applies. See [profiles and policies](policies.md).

## Guest and host boundaries

The guest VM runs your workload. The gateway has its own Unix control socket and a separate root helper socket. The dashboard talks to the local gateway through the API; the dashboard is intended for a local browser session. Managed credential values are stored by the gateway on the host and are not returned by the dashboard's credential listing.

The gateway's proxy supports inspected HTTP and, after local CA setup, HTTPS. It blocks private and special-use upstream destinations and IPv6-only destinations. Unsupported forwarding and protocols can fail closed. AutoMantle is a request control layer for the supported traffic path; prepare the guest and workload to use that path, and check [Request History](approvals.md#request-history) for the observed result.

## Persistence

Profiles, rules, approvals, and request history are in the API's SQLite database. Managed credentials and VM disks are in gateway-owned storage. Dashboard VMs use saved disks so Linux files and installed tools can persist after a clean stop. A copied VM receives its own disk and settings. Deleting a VM deletes its saved files. Console tails and run records held by the gateway are temporary.

These stores are separate: back up both the API data directory and gateway storage if you need to preserve a complete installation. See [operations](operations.md#data-and-backups).
