# How AutoMantle works

```text
Local browser -> API/dashboard -> profiles, rules, approvals, history in SQLite
                    |
                    v
             user-owned gateway -> policy proxy -> permitted destination
                    ^
                    | private VSOCK connection
             guest loopback proxy -> workload in a VM without a network card
```

The API manages policy and the dashboard. The gateway runs VMs and inspects supported outbound HTTP traffic. Each VM belongs to one agent profile, and the gateway asks the API to evaluate requests against that profile. The CLI starts the API and gateway as user services; each VM is a separate Cloud Hypervisor user service. No AutoMantle host process runs as root.

## Request decisions

For an HTTP action, a rule matches its method, exact host, and path. A matching `DENY` rule takes precedence; otherwise a `REQUIRE_APPROVAL` rule waits for a human decision, an `ALLOW` rule permits the request, and an unmatched request is denied. During a setup session, an otherwise unmatched supported request can become a prompt. See [profiles and policies](policies.md).

## Guest and host boundaries

The guest VM runs your workload. It has no virtio network interface. A small guest process listens on `127.0.0.1:3128` and forwards HTTP proxy connections over VSOCK to that VM's private host policy proxy. Unsupported direct TCP, UDP, and ICMP traffic has no guest network route. The gateway's control socket and storage belong to the login account. Cloud Hypervisor's user service hides the account's home directory except for that VM's disk directory and executable; seccomp and Landlock remain enabled.

The proxy supports HTTP and, after CA preparation, inspected HTTPS. It blocks private and special-use upstream destinations and IPv6-only destinations. Request History records decisions seen by the proxy. Traffic that cannot reach the proxy is not represented as a packet count in new rootless VM runs.

## Persistence

Profiles, rules, approvals, and request history are in the API SQLite database. Managed credentials and VM disks are in user-owned gateway storage. Dashboard VMs use saved disks so installed tools can persist after a clean stop. Console tails and run records held by the gateway are temporary. See [operations](operations.md#data-and-backups).
