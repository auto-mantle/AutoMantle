import { apiRequest, jsonRequest, credentialRequest } from "../api.js";
import { node, button, empty, heading, field, makeForm, notice, removeRecord } from "../ui.js";

export async function credentialsView(container, context) {
  const errors = node("div");
  const editor = node("div");
  const list = node("div", { className: "stack" });
  let profiles = [];

  function editCredential(credential = null) {
    const scopes = node("div", { className: "stack" });

    function addScope(scope = {}) {
      const profile = node("select", { name: "scopeProfile", className: "form-input", required: true },
        node("option", { value: "" }, "Choose agent profile"),
        profiles.map(entry => node("option", { value: entry.id }, entry.name)));
      if (scope.agentProfileId && !profiles.some(entry => entry.id === scope.agentProfileId)) {
        profile.append(node("option", { value: scope.agentProfileId }, "Deleted profile (choose another)"));
      }
      profile.value = scope.agentProfileId ?? "";
      const location = node("select", { name: "scopeLocation", className: "form-input" },
        node("option", { value: "header" }, "Header"),
        node("option", { value: "json" }, "JSON body field"),
        node("option", { value: "query" }, "Query parameter"));
      location.value = scope.location ?? "header";
      const selector = field("Field or header name", "scopeSelector", scope.selector ?? "authorization", { required: true, maxlength: 1024 });
      const help = node("p", { className: "help" });
      const updateHelp = () => {
        help.textContent = location.value === "json" ? "JSON field path, for example /auth/token."
          : location.value === "query" ? "Parameter name, for example api_key."
          : "Header name, for example Authorization or X-API-Key.";
      };
      location.addEventListener("change", updateHelp);
      updateHelp();

      const row = node("div", { className: "card stack" },
        node("label", { className: "field" }, node("span", {}, "Agent profile"), profile),
        field("Allowed host", "scopeHost", scope.host ?? "", { required: true, placeholder: "api.example.com", help: "Exact host name. HTTPS only." }),
        field("Allowed paths (comma separated)", "scopePaths", scope.paths?.join(", ") ?? "/*", { required: true, help: "Use an exact path or a prefix such as /api/*." }),
        node("label", { className: "field" }, node("span", {}, "Where to insert"), location),
        selector,
        help,
        node("input", { type: "hidden", name: "scopeLegacyMethods", value: scope.legacyMethods?.join(",") ?? "" }),
        scope.legacyMethods?.length
          ? node("p", { className: "help" }, `Previous method limit preserved: ${scope.legacyMethods.join(", ")}. Remove this scope and add a new one to let request policies alone control methods.`)
          : null,
        button("Remove scope", () => row.remove(), "text-button danger"));
      scopes.append(row);
    }
    for (const scope of credential?.scopes ?? []) addScope(scope);
    if (!credential) addScope();

    const scopeFields = node("fieldset", {}, node("legend", {}, "Credential scope"),
      node("p", { className: "help" }, "This credential can be inserted only at these destinations and locations. Request policies must also allow the request. No scopes means no access."),
      scopes,
      button("Add scope", () => addScope(), "text-button"));
    editor.replaceChildren(makeForm(credential ? "Edit credential" : "Add credential", [
      field("Variable name", "name", credential?.name ?? "", {
        required: true, readOnly: Boolean(credential), maxlength: 128,
        pattern: "[A-Z_][A-Z0-9_]{0,127}", placeholder: "GITHUB_TOKEN"
      }),
      field("Secret value", "secret", "", {
        type: "password", required: !credential, minlength: 16, maxlength: 4096,
        autocomplete: "new-password", spellcheck: "false",
        help: credential ? "Leave empty to keep the saved value. Saved secrets are never shown again."
          : "Paste the real token or API key (16–4096 characters). It stays outside the VM."
      }),
      scopeFields
    ], async form => {
      const request = credentialRequest(form);
      const path = credential ? `/credentials/${encodeURIComponent(credential.name)}` : "/credentials";
      await apiRequest(path, jsonRequest(credential ? "PUT" : "POST", request));
      if (!context.isCurrent()) return;
      editor.replaceChildren();
      await refresh();
    }, credential ? "Save changes" : "Save credential", () => editor.replaceChildren()));
    editor.querySelector("input")?.focus();
  }
  async function refresh() {
    try {
      const [entries, allProfiles] = await Promise.all([apiRequest("/credentials"), apiRequest("/agents/profiles")]);
      if (!context.isCurrent()) return;
      profiles = allProfiles;
      errors.replaceChildren();
      list.replaceChildren(...(entries.length ? entries.map(credential => {
        const remove = button("Delete", () => removeRecord(
          `/credentials/${encodeURIComponent(credential.name)}`, `credential "${credential.name}"`, refresh, errors, remove), "button danger");
        const legacy = credential.legacyScope && !credential.scopes?.length
          ? node("div", {},
            node("p", { className: "help" }, "This credential has no active scope. Edit it to configure allowed destinations and locations. Previous settings:"),
            node("pre", {}, JSON.stringify(credential.legacyScope, null, 2)))
          : null;
        const scopeList = credential.scopes?.length
          ? node("ul", {}, credential.scopes.map(scope => node("li", {},
            `${profiles.find(entry => entry.id === scope.agentProfileId)?.name ?? "Deleted profile"}: ${scope.host}${scope.paths.join(", ")} — ${scope.location} ${scope.selector}`,
            scope.legacyMethods?.length ? ` (previous method limit: ${scope.legacyMethods.join(", ")})` : "")))
          : node("p", { className: "small muted" }, "No scopes configured. Credential use is blocked.");
        return node("article", { className: "card" },
          heading(credential.name, button("Edit", () => editCredential(credential)), remove), legacy, scopeList);
      }) : [empty("No credentials saved yet.")]));
    } catch (error) { if (context.isCurrent()) notice(errors, error); }
  }
  container.replaceChildren(node("div", { className: "actions page-actions" },
    button("Add credential", () => editCredential(), "button primary"),
    button("Refresh", () => refresh())),
    node("p", { className: "muted small" }, "Configure secrets and their scope here. Profile rules control requests. Both checks must allow credential use. Only the credential name is replaced; surrounding text stays as sent. Saved secrets stay outside the VM and are never shown again."),
    errors, editor, list);
  await refresh();
}
