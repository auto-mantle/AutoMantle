# Approvals and request history

The **Approvals** tab lists pending and past human decisions. A request appears when a matching profile rule has the `REQUIRE_APPROVAL` effect or when an unknown supported connection is encountered in active Setup Mode.

## Review a request

Read the profile, destination host, HTTP method, path, and any available request details before deciding. The dashboard may show credential identity and a sanitized JSON preview; a preview may be omitted, and it is not a guarantee that you have seen the entire request body.

- **Approve** permits the pending request governed by a `REQUIRE_APPROVAL` rule.
- **Reject** denies it.
- **Allow and save to this profile** is the setup decision. It permits the attempt and creates an exact allow rule for its method, host, and path.
- **Deny** in setup rejects the attempt without adding a rule.

An approval can become **expired** if its setup session ends, its VM stops, or it cannot be executed in time. In that case, retry the action after reviewing the current rules. Resolving a nonpending request returns a conflict rather than applying a late decision.

## Request history

The **Request History** tab records policy outcomes from requests handled by the gateway proxy. It can show the profile, host, method, path, outcome, reason, matched rule IDs, and related approval where those fields are available. Use it to diagnose a blocked connection or confirm that a permitted request reached the policy layer.

The API retains at most 10,000 history records for up to 30 days and pages through them. The dashboard has a clear history action. Request history is an audit aid, not a replacement for the workload's own logs or a proof that its task succeeded.
