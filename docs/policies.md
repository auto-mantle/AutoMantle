# Agent profiles and policies

An agent profile owns the network rules used by its VMs. Create one profile per workload or trust boundary. You can create a profile in **Agent Profiles**, open it, and add rules there. Each VM selects one existing profile.

## Rule fields

Every HTTP rule has an **effect**, one or more **methods**, one or more **exact hosts**, and one or more **paths**. The dashboard offers `ALLOW`, `DENY`, and `REQUIRE_APPROVAL` effects.

| Field | Example | Meaning |
| --- | --- | --- |
| Effect | `ALLOW` | Permit matching supported requests. |
| Methods | `get`, `post` | HTTP methods, matched after normalization to lower case. |
| Hosts | `api.example.com` | Exact destination hostnames; no wildcard host matching. |
| Paths | `/v1/messages` | Exact, case-sensitive path. |
| Path prefix | `/v1/*` | Matches descendants such as `/v1/messages`, but not `/v1` itself. |

A rule containing several hosts or paths applies to **every combination** of its listed methods, hosts, and paths. Create separate rules when you need different permissions for different destinations.

For example, this rule allows `POST https://api.example.com/v1/messages` and no other method, host, or path:

```json
{
  "effect": "ALLOW",
  "match": {
    "resource_type": "http",
    "action": ["post"],
    "hosts": ["api.example.com"],
    "resource": ["/v1/messages"]
  }
}
```

The JSON shape is also accepted by the local API at `POST /agents/profiles/{profileId}/rules`. The dashboard provides a form for the same fields.

## Decision precedence

When multiple rules match, `DENY` wins, then `REQUIRE_APPROVAL`, then `ALLOW`. With no match, AutoMantle denies the request. A broad allow therefore cannot override a narrower explicit deny. A request that requires approval pauses until you approve or reject it in the dashboard; [approvals](approvals.md) covers the workflow.

Start with exact hosts and paths. Add a path prefix only when the workload really needs a whole subtree. Review [Request History](approvals.md#request-history) after running the workload to see the effect of your rules.

## Setup mode

Setup mode helps you learn which supported connections a harness makes while you configure it.

1. Create a VM with **Setup Mode** selected, or edit a stopped VM to turn it on.
2. Start the VM and run the harness connection or login flow in the guest.
3. For each unknown supported request, inspect the host, method, and path shown in the dashboard.
4. Choose **Allow and save to this profile** to permit that attempt and save an exact `ALLOW` rule, or **Deny** to reject that attempt without saving a rule.
5. Select **Finish setup** on the profile when done. Turn off Setup Mode on the VM for later normal runs.

Setup mode is time limited to at most 24 hours per session. It does not bypass explicit `DENY` rules or create permissions for unsupported traffic. An approval can expire before the request executes; retry the request if needed. Saved rules remain after setup ends.

The prompted destination has **not** been verified as an AI provider. Check it against your own expected destination list before allowing it.
