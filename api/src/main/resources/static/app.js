import { apiRequest, jsonRequest } from "./api.js";
import { node, button, empty, notice, profileLink } from "./ui.js";
import { profilesView, profileView } from "./views/profiles.js";
import { approvalsView } from "./views/approvals.js";
import { historyView } from "./views/history.js";
import { credentialsView } from "./views/credentials.js";
import { vmsView } from "./views/vms.js";

const main = document.querySelector("#app");
let revision = 0;
let poll = null;
let viewCleanup = () => {};

async function loadView() {
  viewCleanup(); viewCleanup = () => {};
  const currentRevision = ++revision;
  const context = {
    isCurrent: () => currentRevision === revision,
    setPoll: timer => { poll = timer; },
    setCleanup: cleanup => { viewCleanup = cleanup; },
    reload: loadView
  };
  clearInterval(poll);
  poll = null;
  main.setAttribute("aria-busy", "true");
  const path = location.pathname.match(/^\/profiles\/([^/]+)$/);
  const errors = node("div");
  const content = node("section");
  try {
    if (path) {
      main.replaceChildren(node("a", { href: "/", className: "back-link" }, "← Dashboard"), errors, empty("Loading profile…"));
      const name = decodeURIComponent(path[1]);
      const profiles = await apiRequest("/agents/profiles");
      let profile = profiles.find(p => p.name === name);
      if (!profile) profile = profiles.find(p => p.id === name);
      if (!profile) throw new Error("Agent Profile not found.");
      history.replaceState(null, "", profileLink(profile.name));
      if (currentRevision !== revision) return;
      main.replaceChildren(node("a", { href: "/", className: "back-link" }, "← Dashboard"), node("h1", {}, profile.name),
        errors, content);
      await profileView(content, profile, context);
    } else {
      const active = new URLSearchParams(location.search).get("tab") ?? "profiles";
      const sections = [["profiles", "Agent Profiles"], ["vms", "Virtual Machines"], ["credentials", "Credentials"], ["approvals", "Approvals"], ["history", "Request History"]];
      const selectedTab = sections.some(([tab]) => tab === active) ? active : "profiles";
      const tabs = node("nav", { className: "tabs-nav", "aria-label": "Dashboard sections" });
      for (const [tab, title] of sections) {
        const selected = tab === selectedTab;
        const tabButton = button(title, () => { history.pushState(null, "", tab === "profiles" ? "/" : `/?tab=${tab}`); void loadView(); }, `tab-button${selected ? " active" : ""}`);
        if (selected) tabButton.setAttribute("aria-current", "page");
        tabs.append(tabButton);
      }
      main.replaceChildren(node("div", { className: "dashboard-layout" },
        tabs, node("div", { className: "dashboard-panel" }, errors, content)));
      if (selectedTab === "vms") await vmsView(content, context);
      else if (selectedTab === "credentials") await credentialsView(content, context);
      else if (selectedTab === "approvals") await approvalsView(content, context);
      else if (selectedTab === "history") await historyView(content, context);
      else await profilesView(content, context);
    }
  } catch (error) { if (currentRevision === revision) notice(errors, error, loadView); }
  finally { if (currentRevision === revision) main.setAttribute("aria-busy", "false"); }
}
const setupPrompts = node("section", { className: "stack setup-prompts", "aria-label": "Harness connection setup", "aria-live": "polite", hidden: true });
main.before(setupPrompts);
let setupTimer = null, setupBusy = false, setupLoading = false, setupFingerprint = "";
async function refreshAfterSetupDecision() {
  if (new URLSearchParams(location.search).get("tab") !== "vms") await loadView();
}
async function refreshSetupPrompts() {
  if (setupLoading || setupBusy) return;
  setupLoading = true;
  try {
    const [pending, profiles] = await Promise.all([apiRequest("/approval-requests?pending=true&setupOnly=true&limit=100"), apiRequest("/agents/profiles")]);
    const profileNames = new Map(profiles.map(p => [p.id, p.name]));
    const requests = pending.filter(r => r.actionMetadata?.type === "SETUP" && r.status === "PENDING");
    const fingerprint = JSON.stringify(requests);
    if (fingerprint === setupFingerprint) return;
    setupFingerprint = fingerprint;
    setupPrompts.hidden = requests.length === 0;
    setupPrompts.replaceChildren(...requests.map(request => {
      const action = request.actionMetadata.action;
      const errors = node("div");
      const controls = node("div", { className: "actions" });
      const resolve = async decision => {
        if (setupBusy) return;
        setupBusy = true;
        setupPrompts.querySelectorAll("button").forEach(b => { b.disabled = true; });
        let failure = null;
        try { await apiRequest(`/approval-requests/${encodeURIComponent(request.id)}/resolve`, jsonRequest("POST", { decision, saveRule: decision === "APPROVED" })); await refreshAfterSetupDecision(); }
        catch (error) { failure = error; }
        finally { setupBusy = false; setupFingerprint = ""; await refreshSetupPrompts(); }
        if (failure) setupPrompts.prepend(node("p", { className: "notice" }, failure.message));
      };
      controls.append(button("Allow and save to this profile", () => resolve("APPROVED"), "button approve"),
        button("Deny", () => resolve("REJECTED"), "button danger"),
        button("Finish setup", async () => {
          if (setupBusy) return;
          setupBusy = true;
          try { await apiRequest(`/agents/profiles/${encodeURIComponent(request.agentProfileId)}/setup/finish`, { method: "POST" }); await refreshAfterSetupDecision(); }
          catch (error) { notice(errors, error); }
          finally { setupBusy = false; setupFingerprint = ""; await refreshSetupPrompts(); }
        }));
      return node("article", { className: "card" }, node("h2", {}, "Harness wants to connect"),
        node("h3", { className: "mono" }, action.host), node("p", { className: "mono" }, `${action.method.toUpperCase()} ${action.path}`),
        node("p", { className: "small muted" }, `Profile: ${profileNames.get(request.agentProfileId) ?? "Profile unavailable"}`),
        node("p", {}, "Allowing saves this exact host, method, and path to the profile. This destination has not been verified as an LLM provider."),
        node("p", { className: "help" }, "Deny rejects this attempt without saving a rule."),
        profileNames.has(request.agentProfileId) ? node("a", { href: profileLink(profileNames.get(request.agentProfileId)) }, `Open profile: ${profileNames.get(request.agentProfileId)}`) : node("p", { className: "muted" }, "Profile unavailable"),
        node("p", { className: "small muted" }, "If the harness times out, retry after saving the rule."), errors, controls);
    }));
    if (requests.length === 100) setupPrompts.append(node("a", { href: "/?tab=approvals" }, "More pending requests — open Approval Requests"));
  } catch (error) { setupFingerprint = ""; setupPrompts.hidden = false; notice(setupPrompts, error, refreshSetupPrompts); }
  finally { setupLoading = false; }
}
function startSetupPolling() {
  clearInterval(setupTimer);
  void refreshSetupPrompts();
  setupTimer = setInterval(() => { if (!document.hidden) void refreshSetupPrompts(); }, 2000);
}
window.addEventListener("popstate", () => { void loadView(); });
window.addEventListener("pagehide", () => { revision++; viewCleanup(); clearInterval(poll); clearInterval(setupTimer); });
window.addEventListener("pageshow", event => { if (event.persisted) { void loadView(); startSetupPolling(); } });
startSetupPolling();
void loadView();
