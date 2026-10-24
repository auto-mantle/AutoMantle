import assert from "node:assert/strict";
import test from "node:test";
import {
  profilesView, profileView
} from "../../main/resources/static/views/profiles.js";
import { approvalsView } from "../../main/resources/static/views/approvals.js";
import { historyView } from "../../main/resources/static/views/history.js";
import { credentialsView } from "../../main/resources/static/views/credentials.js";
import { vmsView } from "../../main/resources/static/views/vms.js";

class FakeNode {
  constructor(tag) {
    this.tag = tag;
    this.children = [];
    this.attributes = {};
    this.classList = { add() {}, remove() {} };
  }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  addEventListener() {}
  before() {}
}
const visibleText = node => [node.textContent ?? "", ...node.children.map(visibleText)].join(" ");

test("every dashboard view renders with the shared UI helpers", async t => {
  const previous = {
    Node: globalThis.Node, document: globalThis.document, fetch: globalThis.fetch,
    window: globalThis.window, location: globalThis.location, history: globalThis.history,
    setInterval: globalThis.setInterval
  };
  t.after(() => Object.assign(globalThis, previous));
  globalThis.Node = FakeNode;
  globalThis.document = {
    hidden: false,
    createElement: tag => new FakeNode(tag),
    createTextNode: text => Object.assign(new FakeNode("#text"), { textContent: text })
  };

  const profile = { id: "p1", name: "Example agent", setupExpiresAt: null };
  const responses = new Map([
    ["/agents/profiles", [profile]],
    ["/agents/profiles/p1/rules", [{ id: "r1", effect: "ALLOW", match: { resource_type: "http", action: ["get"], hosts: ["example.com"], resource: ["/api/*"] } }]],
    ["/credentials", [{ name: "EXAMPLE_TOKEN", scopes: [] }]],
    ["/vms", [{ id: "vm1", name: "Example VM", state: "stopped", agentProfileId: "p1", vcpuCount: 2, memoryMib: 2048 }]],
    ["/request-history", { items: [], nextBefore: null }],
    ["/approval-requests", [{ id: "a1", status: "APPROVED", createdAt: "2026-01-01T00:00:00Z", actionSummary: "Example request", agentProfileId: "p1", actionMetadata: { type: "HTTP", action: { credentials: [] } } }]]
  ]);
  globalThis.fetch = async url => {
    const path = String(url).split("?")[0];
    assert.ok(responses.has(path), `Unexpected request: ${url}`);
    return Response.json(responses.get(path));
  };
  const context = {
    isCurrent: () => true,
    setPoll: timer => clearInterval(timer),
    setCleanup: () => {},
    reload: async () => {}
  };
  for (const [name, expected, render] of [
    ["profiles", "Example agent", container => profilesView(container, context)],
    ["profile detail", "example.com", container => profileView(container, profile, context)],
    ["approvals", "Example request", container => approvalsView(container, context)],
    ["history", "No requests recorded", container => historyView(container, context)],
    ["credentials", "EXAMPLE_TOKEN", container => credentialsView(container, context)],
    ["VMs", "Example VM", container => vmsView(container, context)]
  ]) {
    const container = new FakeNode("section");
    await render(container);
    assert.match(visibleText(container), new RegExp(expected), `${name} rendered no content`);
  }

  const main = new FakeNode("main");
  globalThis.document.querySelector = () => main;
  globalThis.window = { addEventListener() {} };
  globalThis.location = { pathname: "/", search: "" };
  globalThis.history = { pushState() {}, replaceState() {} };
  globalThis.setInterval = () => 0;
  await import("../../main/resources/static/app.js");
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(main.children[0].className, "dashboard-layout");
  assert.equal(main.children[0].children[0].tag, "nav");
  assert.match(visibleText(main), /Agent Profiles.*Example agent/);
  assert.doesNotMatch(visibleText(main), /CONTROL PLANE|Manage agent access/);
});
