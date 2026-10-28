# AutoMantle documentation

AutoMantle provides a local dashboard for Linux VMs that run agent workloads. Each VM belongs to an **agent profile**. The gateway inspects supported outbound HTTP requests and applies that profile's rules.

AutoMantle has three parts:

- **Dashboard and API** — a Spring Boot application that stores profiles, rules, approvals, and request history in SQLite.
- **Gateway and CLI** — Rust executables that start and stop the app, run VMs as user services, and enforce outbound request rules.
- **Guest VM** — a user-supplied Linux installation. Its tools and harness depend on the image selected when the VM is created.

Start with [installation and first run](getting-started.md). Then read [how it works](concepts.md) and [profile policies](policies.md).

## Common tasks

| Task | Guide |
| --- | --- |
| Start and stop a compiled release | [Getting started](getting-started.md) |
| Create a profile and choose outbound access | [Agent profiles and policies](policies.md) |
| Create, start, stop, or copy a VM | [Virtual machines](virtual-machines.md) |
| Review a connection prompt | [Approvals and request history](approvals.md) |
| Keep API keys outside the VM | [Credentials](credentials.md) |
| Diagnose services or back up data | [Operations and troubleshooting](operations.md) |

The dashboard manages local VMs on one Linux host. AutoMantle does not sign in to an AI provider or install an agent harness at runtime. The user's guest installation must contain those tools and the public CA if inspected HTTPS is needed.
