import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
const source = await readFile(new URL("../../main/resources/static/api.js", import.meta.url), "utf8");
const { apiRequest, jsonRequest, ruleRequest, credentialRequest, approvalReview, sortApprovals, ApiError } = await import(`data:text/javascript;base64,${Buffer.from(source).toString("base64")}`);

test("read requests stay on the app origin without authentication or a CSRF round trip", async t => {
  const calls = [];
  t.mock.method(globalThis, "fetch", async (url, options) => { calls.push({ url, options }); return Response.json([]); });
  assert.deepEqual(await apiRequest("/agents/profiles"), []);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "/agents/profiles");
  assert.equal(calls[0].options.credentials, "same-origin");
  assert.equal(calls[0].options.headers.has("Authorization"), false);
});

test("mutations obtain CSRF before preserving the request body", async t => {
  const calls = [];
  t.mock.method(globalThis, "fetch", async (url, options) => {
    calls.push({ url, options });
    return calls.length === 1 ? Response.json({ token: "local-csrf", headerName: "X-CSRF-TOKEN" }) : Response.json({ id: "profile" });
  });
  const request = jsonRequest("POST", { name: "<script>untrusted profile</script>" });
  await apiRequest("/agents/profiles", request);
  assert.deepEqual(calls.map(call => call.url), ["/csrf", "/agents/profiles"]);
  assert.equal(calls[1].options.body, request.body);
  assert.equal(calls[1].options.headers.get("X-CSRF-TOKEN"), "local-csrf");
  assert.equal(calls[1].options.headers.get("Content-Type"), "application/json");
  assert.equal(calls[1].options.credentials, "same-origin");
});

test("failed, malformed, and invalid-header CSRF responses prevent mutation", async t => {
  for (const response of [new Response("unavailable", { status: 503 }), Response.json({}), Response.json({ token: "token", headerName: "Authorization" }), new Response("bad JSON")]) {
    const calls = [];
    const mock = t.mock.method(globalThis, "fetch", async url => { calls.push(url); return response; });
    await assert.rejects(apiRequest("/agents/profiles/a", { method: "DELETE" }), ApiError);
    assert.deepEqual(calls, ["/csrf"]);
    mock.mock.restore();
  }
});

test("successful deletion accepts an empty 204 response", async t => {
  t.mock.method(globalThis, "fetch", async url => url === "/csrf"
    ? Response.json({ token: "token", headerName: "X-CSRF-TOKEN" }) : new Response(null, { status: 204 }));
  assert.equal(await apiRequest("/agents/profiles/a", { method: "DELETE" }), null);
});

test("rule validation errors and approval conflicts are shown clearly", async t => {
  t.mock.method(globalThis, "fetch", async url => url === "/csrf" ? Response.json({ token: "token", headerName: "X-CSRF-TOKEN" })
    : Response.json({ message: "Destination hosts are required" }, { status: 400 }));
  await assert.rejects(apiRequest("/agents/profiles/a/rules", jsonRequest("POST", {})), /Destination hosts are required/);
  t.mock.method(globalThis, "fetch", async url => url === "/csrf" ? Response.json({ token: "token", headerName: "X-CSRF-TOKEN" })
    : Response.json({}, { status: 409 }));
  await assert.rejects(apiRequest("/approval-requests/a/resolve", jsonRequest("POST", { decision: "APPROVED" })), /no longer pending/);
});

function form(values = {}) {
  const data = new FormData();
  for (const [key, value] of Object.entries({ effect: "ALLOW", hosts: "API.EXAMPLE.COM, other.example.com", paths: "/API/*, /Exact", ...values })) data.set(key, value);
  data.append("method", "get"); data.append("method", "post");
  return data;
}

test("rule forms preserve exact paths and send hosts and methods without body predicates", () => {
  assert.deepEqual(ruleRequest(form()), { effect: "ALLOW", match: { resource_type: "http", action: ["get", "post"],
    hosts: ["api.example.com", "other.example.com"], resource: ["/API/*", "/Exact"] } });
  assert.deepEqual(Object.keys(ruleRequest(form({ effect: "REQUIRE_APPROVAL" }))).sort(), ["effect", "match"]);
});

test("incomplete rules and invalid effects cannot be submitted", () => {
  const missingMethods = form(); missingMethods.delete("method");
  for (const data of [missingMethods, form({ hosts: " , " }), form({ paths: "" }), form({ effect: "UNKNOWN" })]) assert.throws(() => ruleRequest(data));
});

test("approval review retains redacted JSON as text and validates credential labels", () => {
  const payload = { amount: 42, password: "[REDACTED]", note: "<img src=x onerror=alert(1)>" };
  const review = approvalReview({ credentials: [{ placeholder: "AUTOMANTLE_SERVICE_TOKEN", header: "authorization" },
    { placeholder: "real-secret", header: "authorization" }, { placeholder: "AUTOMANTLE_OTHER", header: "cookie" }],
    body: { size_bytes: 64, preview: { json: JSON.stringify(payload), redacted: true } } });
  assert.equal(review.credentials.length, 1);
  assert.equal(review.credentials[0].placeholder, "AUTOMANTLE_SERVICE_TOKEN");
  assert.deepEqual(JSON.parse(review.json), payload);
  assert.equal(review.redacted, true);
});

test("legacy, omitted, oversized, and invalid previews degrade safely", () => {
  assert.equal(approvalReview(null), null);
  assert.equal(approvalReview([]), null);
  assert.match(approvalReview({ body: { size_bytes: 0 } }).bodyMessage, /Empty request body/);
  assert.match(approvalReview({ body: { preview: { omitted: true } } }).bodyMessage, /preview was omitted/);
  for (const json of ["not JSON", '"' + "x".repeat(16384) + '"']) assert.equal(approvalReview({ body: { preview: { json } } }).json, null);
});

test("approvals show pending first then newest, without mutating fetched data", () => {
  const requests = [{ id: "old", status: "APPROVED", createdAt: "2026-01-01" },
    { id: "new", status: "REJECTED", createdAt: "2026-03-01" }, { id: "pending", status: "PENDING", createdAt: "2026-02-01" }];
  assert.deepEqual(sortApprovals(requests).map(item => item.id), ["pending", "new", "old"]);
  assert.equal(requests[0].id, "old");
});

test("setup approval conflicts retain the specific server explanation", async t => {
  t.mock.method(globalThis, "fetch", async url => url === "/csrf"
    ? Response.json({ token: "token", headerName: "X-CSRF-TOKEN" })
    : Response.json({ message: "A current rule blocks this setup connection" }, { status: 409 }));
  await assert.rejects(apiRequest("/approval-requests/setup/resolve", jsonRequest("POST", { decision: "APPROVED", saveRule: true })), /current rule blocks/);
});
test("custom methods are normalized, deduplicated, and validated", () => {
  assert.deepEqual(ruleRequest(form({ customMethods: "PROPFIND, report, GET" })).match.action, ["get", "post", "propfind", "report"]);
  for (const customMethods of ["BAD METHOD", "GET/POST", "GET\r\nInjected"]) assert.throws(() => ruleRequest(form({ customMethods })));
});

test("approval review accepts named credentials without the Automantle prefix", () => {
  const review=approvalReview({credentials:[{placeholder:"GITHUB_TOKEN",header:"authorization"},{placeholder:"STRIPE_KEY",header:"x-api-key"}]});
  assert.deepEqual(review.credentials.map(c=>c.placeholder),["GITHUB_TOKEN","STRIPE_KEY"]);
});

test("credential scopes belong to credentials while rules contain only request conditions", () => {
  const data = new FormData();data.set("name","SERVICE_TOKEN");data.set("secret","");
  for (const [location,selector] of [["header","Authorization"],["json","/auth/token"],["query","api_key"]]) {
    data.append("scopeProfile","10000000-0000-0000-0000-000000000001");data.append("scopeHost","API.EXAMPLE.COM");
    data.append("scopePaths","/api/*, /login");data.append("scopeLocation",location);data.append("scopeSelector",selector);data.append("scopeLegacyMethods","");
  }
  const request=credentialRequest(data);
  assert.equal(request.name,"SERVICE_TOKEN");assert.equal("secret" in request,false);
  assert.deepEqual(request.scopes.map(s=>[s.location,s.selector]),[["header","authorization"],["json","/auth/token"],["query","api_key"]]);
  assert.equal(request.scopes[0].host,"api.example.com");assert.deepEqual(request.scopes[0].paths,["/api/*","/login"]);
  assert.equal("credentials" in ruleRequest(form()).match,false);
});

test("credential forms reject incomplete scopes and preserve migration method limits", () => {
  const data=new FormData();data.set("name","SERVICE_TOKEN");
  data.set("scopeProfile","10000000-0000-0000-0000-000000000001");data.set("scopeHost","api.example.com");
  data.set("scopePaths","/api/*");data.set("scopeLocation","header");data.set("scopeSelector","authorization");
  data.set("scopeLegacyMethods","GET, POST");
  assert.deepEqual(credentialRequest(data).scopes[0].legacyMethods,["GET","POST"]);
  for (const [key,value] of [["scopeHost",""],["scopePaths",""],["scopeProfile",""],["scopeLocation","body"],["scopeSelector",""]]) {
    const invalid=new FormData();for(const [k,v] of data) invalid.append(k,v);invalid.set(key,value);
    assert.throws(()=>credentialRequest(invalid));
  }
  data.set("scopeLocation","json");data.set("scopeSelector","auth.token");assert.throws(()=>credentialRequest(data),/start with/);
  const empty=new FormData();empty.set("name","SERVICE_TOKEN");assert.deepEqual(credentialRequest(empty).scopes,[]);
});

test("approval review includes exact body and query insertion locations", () => {
  const credentials = [{ placeholder: "SERVICE_TOKEN", location: "json", selector: "/auth/token" },
    { placeholder: "SERVICE_TOKEN", location: "query", selector: "api_key" }];
  assert.deepEqual(approvalReview({ credentials }).credentials, credentials);
});
