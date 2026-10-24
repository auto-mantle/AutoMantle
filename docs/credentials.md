# Credentials

Use the **Credentials** tab to keep managed API keys on the host. A credential has an uppercase variable name, a secret value, and one or more scopes. The dashboard never displays a saved secret again; editing without a new value keeps the existing one.

## Create a scoped credential

1. Create the [agent profile](policies.md) that will use the credential.
2. Select **Add credential** and choose a name such as `EXAMPLE_API_KEY`.
3. Enter the secret and add a scope with the profile, exact HTTPS host, allowed path or path prefix, insertion location, and field name.
4. Add a separate `ALLOW` or `REQUIRE_APPROVAL` profile rule for the request's method, host, and path.

Scopes can place the value in a request header, JSON body field, or query parameter. A JSON selector uses a path such as `/auth/token`; a header selector can be `Authorization` or `X-API-Key`. A credential with no scopes cannot be used. Its scope and the profile's request policy must both permit the request. Managed credential insertion is for inspected HTTPS requests.

The gateway stores managed credentials under its private VM storage directory and inserts values into permitted outbound requests. Put the variable name, such as `EXAMPLE_API_KEY`, where the value would otherwise appear in the guest's request. The gateway replaces that name only at a matching scoped location; surrounding text such as `Bearer ` remains intact. The actual secret stays on the host. Do not put the raw secret into the guest request: the proxy rejects protected secret values it sees in the request.

Credential values and the gateway's CA private key are sensitive host data. Include them only in protected backups and do not publish them with the documentation or guest image. See [data and backups](operations.md#data-and-backups).
