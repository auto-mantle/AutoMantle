# How AutoMantle works

```text
Local browser -> API/dashboard -> profiles, rules, approvals, history in SQLite
                    |
                    v
             user-owned gateway -> policy proxy -> permitted destination
                    ^
                    | explicit proxy forwarding
             restricted guest network -> workload in a VM
```

The API manages policy and the dashboard. Each VM belongs to one agent profile, and the gateway asks the API to evaluate requests against it. The CLI starts the API and gateway as user services. ISO VMs run as QEMU user services; advanced direct kernel launches use Cloud Hypervisor. No AutoMantle host process runs as root.

## Request decisions

For an HTTP action, a rule matches its method, exact host, and path. A matching `DENY` rule takes precedence; otherwise a `REQUIRE_APPROVAL` rule waits for a human decision, an `ALLOW` rule permits the request, and an unmatched request is denied. During a setup session, an otherwise unmatched supported request can become a prompt. See [profiles and policies](policies.md).

## Guest and host boundaries

ISO VMs use a restricted QEMU user network with an explicit forward from `10.0.2.100:3128` to that VM's private host policy proxy. Direct traffic to the host and internet is disabled. Advanced Cloud Hypervisor launches retain their guest VSOCK bridge. The gateway's control socket and storage belong to the login account. QEMU runs as a systemd user service with memory and CPU limits.

The proxy supports HTTP and, after CA preparation, inspected HTTPS. It blocks private and special-use upstream destinations and IPv6-only destinations. Request History records decisions seen by the proxy. Traffic that cannot reach the proxy is not represented as a packet count in new rootless VM runs.

## Persistence

Profiles, rules, approvals, and request history are in the API SQLite database. Managed credentials and VM disks are in user-owned gateway storage. Dashboard VMs use saved disks so installed tools can persist after a clean stop. Console tails and run records held by the gateway are temporary. See [operations](operations.md#data-and-backups).
