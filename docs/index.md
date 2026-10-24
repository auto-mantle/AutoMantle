# AutoMantle documentation

AutoMantle provides a local management dashboard for Linux VMs that run agent workloads. Each VM belongs to an **agent profile**. The gateway inspects supported outbound HTTP requests and asks the API to apply that profile's rules. You can allow a request, deny it, or require a human decision.

The project currently has three parts:

- **Dashboard and API** — a Spring Boot application on the host. It stores profiles, rules, approvals, and request history in SQLite.
- **Gateway and helper** — Rust services that manage VMs, networking, the inspection proxy, and host operations.
- **Guest VM** — a Linux environment where you install and run your own agent harness. VM files and installed tools can persist between starts.

Start with [installation and first run](getting-started.md). Then read [how it works](concepts.md) and [profile policies](policies.md) before connecting a workload.

## Common tasks

| Task | Guide |
| --- | --- |
| Build and install on a Linux host | [Getting started](getting-started.md) |
| Create a profile and choose outbound access | [Agent profiles and policies](policies.md) |
| Create, start, stop, or copy a VM | [Virtual machines](virtual-machines.md) |
| Review a connection prompt | [Approvals and request history](approvals.md) |
| Keep API keys outside the VM | [Credentials](credentials.md) |
| Diagnose services or back up data | [Operations and troubleshooting](operations.md) |

## Current scope

The dashboard manages local VMs on one Linux host. AutoMantle does not install an agent harness or sign in to an AI provider for you. A VM image must be prepared with Linux, the tools you need, and, for inspected HTTPS, trust in the gateway's local CA. The [getting started guide](getting-started.md) identifies which assets the installer supplies and which you must supply.
