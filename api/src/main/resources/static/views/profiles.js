import { apiRequest, jsonRequest, ruleRequest } from "../api.js";
import { node, button, heading, empty, notice, makeForm, removeRecord, badge, field, profileLink, rulePath, date } from "../ui.js";

export async function profilesView(container, context) {
  const errors = node("div");
  const editor = node("div");
  const list = node("div", {}, empty("Loading profiles…"));
  const refresh = async () => {
    try {
      const profiles = await apiRequest("/agents/profiles");
      if (!context.isCurrent()) return;
      errors.replaceChildren();
      if (!profiles.length) { list.replaceChildren(empty("No agent profiles found.")); return; }
      const body = node("tbody");
      for (const profile of profiles) {
        const deleteButton = button("Delete", () => removeRecord(`/agents/profiles/${encodeURIComponent(profile.id)}`, `profile "${profile.name}"`, refresh, errors, deleteButton), "button danger");
        body.append(node("tr", {},
          node("td", {}, node("a", { href: profileLink(profile.name), className: "profile-name" }, profile.name)),
          node("td", {}, deleteButton)));
      }
      list.replaceChildren(node("div", { className: "table-wrap" }, node("table", {},
        node("thead", {}, node("tr", {}, ["Name", "Actions"].map(label => node("th", { scope: "col" }, label)))), body)));
    } catch (error) { if (context.isCurrent()) { list.replaceChildren(); notice(errors, error, refresh); } }
  };
  const create = button("Create Profile", () => {
    editor.replaceChildren(makeForm("Create Agent Profile", [field("Name", "name", "", { required: true, maxlength: 255, placeholder: "code-reviewer-bot" })], async data => {
      await apiRequest("/agents/profiles", jsonRequest("POST", { name: data.get("name") }));
      editor.replaceChildren(); await refresh();
    }, "Create Profile", () => editor.replaceChildren()));
    editor.querySelector("input").focus();
  }, "button primary");
  container.replaceChildren(node("div", { className: "actions page-actions" }, create), errors, editor, list);
  await refresh();
}

export async function profileView(container, profile, context) {
  const setup = node("section", { className: "card" }, node("h2", {}, "Harness connection setup"));
  const rules = node("section");
  const errors = node("div");
  const status = node("p");
  setup.append(status);
  setup.append(node("p", { className: "help" }, "Only connections you allow are saved as exact host, method, and path rules. Explicit denies still apply. Harness installation and provider login need a prepared VM image."));
  const finish = button("Finish setup", async () => {
      finish.disabled = true;
      try { await apiRequest(`/agents/profiles/${encodeURIComponent(profile.id)}/setup/finish`, { method: "POST" }); await context.reload(); }
      catch (error) { notice(errors, error); finish.disabled = false; }
  });
  setup.append(finish);
  function showSetup(current) {
    const active = current.setupExpiresAt && Date.now() < new Date(current.setupExpiresAt).getTime();
    status.textContent = active ? `Setup mode is active until ${date(current.setupExpiresAt)}. Unknown supported connections wait for your decision.`
      : "Launch this profile's VM with --mode setup to configure the harness connection. Connection prompts appear here and on every dashboard page.";
    finish.hidden = !active;
  }
  showSetup(profile);
  container.replaceChildren(setup, errors, rules);
  await rulesView(rules, profile.id, context);
  let refreshing = false;
  if (context.isCurrent()) context.setPoll(setInterval(async () => {
    if (document.hidden || refreshing) return;
    refreshing = true;
    try { const current = await apiRequest(`/agents/profiles/${encodeURIComponent(profile.id)}`); if (context.isCurrent()) showSetup(current); }
    catch (error) { if (context.isCurrent()) notice(errors, error); }
    finally { refreshing = false; }
  }, 2000));
}

function ruleEditor(rule, save, cancel) {
  const effect = node("select", { name: "effect", className: "form-input" }, ["ALLOW", "DENY", "REQUIRE_APPROVAL"].map(value => node("option", { value }, value.replaceAll("_", " "))));
  effect.value = rule?.effect ?? "ALLOW";
  const methods = node("fieldset", {}, node("legend", {}, "HTTP methods"), node("div", { className: "methods" },
    ["get", "post", "put", "patch", "delete", "head", "options"].map(method => node("label", {},
      node("input", { type: "checkbox", name: "method", value: method, checked: (rule?.match?.action ?? ["get"]).includes(method) }), method.toUpperCase()))));
  return makeForm(rule ? "Edit Rule" : "Add Rule", [node("label", { className: "field" }, node("span", {}, "Effect"), effect), methods,
    field("Other HTTP methods (comma separated)", "customMethods", (rule?.match?.action ?? []).filter(method => !["get", "post", "put", "patch", "delete", "head", "options"].includes(method)).join(", "), { placeholder: "PROPFIND, REPORT" }),
    field("Destination hosts (comma separated)", "hosts", rule?.match?.hosts?.join(", ") ?? "", { required: true, placeholder: "api.example.com", help: "Exact host names. Every listed host and path combination uses this rule." }),
    field("Resource paths (comma separated)", "paths", rule?.match?.resource?.join(", ") ?? "/api/*", { required: true, help: "Paths are case-sensitive. /api/* matches descendants of /api/, but not /api itself." })],
    data => save(ruleRequest(data)), rule ? "Update Rule" : "Save Rule", cancel);
}

async function rulesView(container, profileId, context) {
  const errors = node("div");
  const editor = node("div");
  const list = node("div", { className: "stack rule-list" }, empty("Loading rules…"));
  const edit = rule => {
    editor.replaceChildren(ruleEditor(rule, async request => {
      await apiRequest(rulePath(profileId, rule?.id), jsonRequest(rule ? "PATCH" : "POST", request));
      editor.replaceChildren(); await refresh();
    }, () => editor.replaceChildren()));
  };
  const refresh = async () => {
    try {
      const rules = await apiRequest(rulePath(profileId));
      if (!context.isCurrent()) return;
      errors.replaceChildren();
      list.replaceChildren(...(rules.length ? rules.map(rule => {
        const match = rule.match;
        const summary = match?.resource_type === "http" ? node("div", { className: "match mono" },
          node("div", {}, "Methods: ", match.action?.join(", ").toUpperCase() ?? ""),
          node("div", {}, "Hosts: ", match.hosts?.join(", ") || "Requires review: add destination hosts"),
          node("div", {}, "Paths: ", match.resource?.join(", ") ?? "")) : node("pre", {}, JSON.stringify(match, null, 2));
        const deleteButton = button("Delete", () => removeRecord(rulePath(profileId, rule.id), "rule", refresh, errors, deleteButton), "text-button danger");
        return node("article", { className: "card" }, node("div", { className: "row between" },
          node("div", { className: "row" }, badge(rule.effect)),
          node("div", { className: "actions" }, button("Edit", () => edit(rule), "text-button"), deleteButton)), summary);
      }) : [empty("No rules found.")]));
    } catch (error) { if (context.isCurrent()) { list.replaceChildren(); notice(errors, error, refresh); } }
  };
  container.replaceChildren(heading("Rules", button("Add Rule", () => edit(null), "button primary")), errors, editor, list);
  await refresh();
}
