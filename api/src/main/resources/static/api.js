const unsafeMethods = new Set(["POST", "PUT", "PATCH", "DELETE"]);

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

export async function apiRequest(path, options = {}) {
  const method = (options.method ?? "GET").toUpperCase();
  const headers = new Headers(options.headers);
  headers.set("Accept", "application/json");
  if (unsafeMethods.has(method)) {
    const response = await fetch("/csrf", { credentials: "same-origin", headers: { Accept: "application/json" }, signal: options.signal });
    if (!response.ok) throw new ApiError(response.status, "Could not obtain the browser security token. Please retry.");
    const csrf = await response.json().catch(() => null);
    if (!csrf || typeof csrf.token !== "string" || !csrf.token || typeof csrf.headerName !== "string" || csrf.headerName.toUpperCase() !== "X-CSRF-TOKEN") {
      throw new ApiError(500, "The server returned an invalid browser security token.");
    }
    headers.set(csrf.headerName, csrf.token);
  }
  const response = await fetch(path, { ...options, method, headers, credentials: "same-origin" });
  if (!response.ok) {
    const data = await response.json().catch(() => null);
    const message = response.status === 409 && path.startsWith("/approval-requests/")
      ? (typeof data?.message === "string" ? data.message : "This request is no longer pending. Refresh the list.")
      : typeof data?.message === "string" ? data.message : `Request failed (${response.status}). Please retry.`;
    throw new ApiError(response.status, message);
  }
  return response.status === 204 ? null : response.json();
}

export function jsonRequest(method, value) {
  return { method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(value) };
}

export function ruleRequest(form) {
  const methods = [...new Set([...form.getAll("method"), ...String(form.get("customMethods") ?? "").split(",").map(value => value.trim().toLowerCase()).filter(Boolean)])];
  if (methods.some(value => !/^[a-z0-9!#$%&'*+.^_`|~\-]+$/.test(value))) throw new Error("HTTP methods must be valid method tokens.");
  const hosts = String(form.get("hosts") ?? "").split(",").map(value => value.trim().toLowerCase()).filter(Boolean);
  const paths = String(form.get("paths") ?? "").split(",").map(value => value.trim()).filter(Boolean);
  if (!methods.length || !hosts.length || !paths.length) throw new Error("Choose a method and enter destination hosts and resource paths.");
  const effect = form.get("effect");
  if (!["ALLOW", "DENY", "REQUIRE_APPROVAL"].includes(effect)) throw new Error("Choose a valid rule effect.");
  const match = { resource_type: "http", action: methods, hosts, resource: paths };
  return { effect, match };
}

export function credentialRequest(form) {
  const split = value => String(value ?? "").split(",").map(part => part.trim()).filter(Boolean);
  const request = { name: String(form.get("name") ?? ""), scopes: [] };
  const secret = form.get("secret");
  if (secret) request.secret = secret;

  const profiles = form.getAll("scopeProfile");
  const hosts = form.getAll("scopeHost");
  const paths = form.getAll("scopePaths");
  const locations = form.getAll("scopeLocation");
  const selectors = form.getAll("scopeSelector");
  const methods = form.getAll("scopeLegacyMethods");
  request.scopes = profiles.map((agentProfileId, index) => {
    const scope = {
      agentProfileId,
      host: String(hosts[index] ?? "").trim().toLowerCase(),
      paths: split(paths[index]),
      location: locations[index],
      selector: String(selectors[index] ?? "").trim()
    };
    if (!agentProfileId || !scope.host || !scope.paths.length || !["header", "query", "json"].includes(scope.location) || !scope.selector)
      throw new Error("Complete each credential scope.");
    if (scope.location === "header") scope.selector = scope.selector.toLowerCase();
    if (scope.location === "json" && !scope.selector.startsWith("/"))
      throw new Error("JSON field paths start with /, for example /auth/token.");
    const legacyMethods = split(methods[index]);
    if (legacyMethods.length) scope.legacyMethods = legacyMethods;
    return scope;
  });
  return request;
}

export function approvalReview(action) {
  if (!action || typeof action !== "object" || Array.isArray(action)) return null;
  const credentials = Array.isArray(action.credentials) ? action.credentials.filter(entry =>
    entry && typeof entry.placeholder === "string" && /^[A-Z_][A-Z0-9_]{0,127}$/.test(entry.placeholder) &&
    (["authorization", "x-api-key"].includes(entry.header) ||
      (["header", "json", "query"].includes(entry.location) && typeof entry.selector === "string"))) : [];
  const body = action.body && typeof action.body === "object" && !Array.isArray(action.body) ? action.body : null;
  const preview = body?.preview;
  let json = null;
  if (typeof preview?.json === "string" && preview.json.length <= 16 * 1024) {
    try { json = JSON.stringify(JSON.parse(preview.json), null, 2); } catch { }
  }
  return {
    credentials, body, json, redacted: preview?.redacted === true,
    bodyMessage: body?.size_bytes === 0 ? "Empty request body." : preview?.omitted === true
      ? "Payload preview was omitted because it could not be safely displayed within the size limit."
      : "Payload preview is unavailable for this request."
  };
}

export function sortApprovals(requests) {
  return [...requests].sort((a, b) => Number(b.status === "PENDING") - Number(a.status === "PENDING") || new Date(b.createdAt) - new Date(a.createdAt));
}
