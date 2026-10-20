import { apiRequest, jsonRequest, approvalReview, sortApprovals } from "../api.js";
import { node, button, empty, badge, notice, date } from "../ui.js";

function review(action) {
  const data = approvalReview(action);
  if (!data) return node("p", {}, "Request details are unavailable.");
  const section = node("section", { className: "review", "aria-label": "Request review" }, node("h4", {}, "Credentials"));
  section.append(data.credentials.length ? node("ul", {}, data.credentials.map(entry => node("li", {}, node("code", {}, /^AUTOMANTLE_VM_BEARER_[0-9A-F]{64}$/.test(entry.placeholder) ? "VM login credential (hidden; fingerprint recorded)" : entry.placeholder),
    ` via ${entry.location ? `${entry.location} ${entry.selector}` : entry.header === "authorization" ? "Authorization" : "X-API-Key"}`))) : node("p", { className: "muted" }, "No credential identity was provided."));
  if (data.body) section.append(node("h4", {}, "JSON payload"),
    typeof data.body.size_bytes === "number" ? node("p", { className: "muted small" }, `${data.body.size_bytes} bytes`) : node("span"),
    data.json !== null ? node("div", {}, data.redacted ? node("p", { className: "muted" }, "Sensitive values are hidden.") : null,
      node("pre", {}, data.json)) : node("p", { className: "muted" }, data.bodyMessage));
  return section;
}

export async function approvalsView(container, context) {
  const errors = node("div");
  const list = node("div", { className: "stack" }, empty("Loading approval requests…"));
  let busy = false;
  let loading = false;
  let page = 0;
  const pendingOnly = node("input", { type: "checkbox", checked: true });
  const pageLabel = node("span", { className: "small muted" });
  const previous = button("Previous", async () => { if (page > 0 && !loading && !busy) { page--; await refresh(); } });
  const next = button("Next", async () => { if (!loading && !busy) { page++; await refresh(); } });
  pendingOnly.addEventListener("change", () => { page = 0; void refresh(); });
  const refresh = async () => {
    if (loading || busy || !context.isCurrent()) return;
    loading = true;
    try {
      const [approvalPage, profiles] = await Promise.all([
        apiRequest(`/approval-requests?page=${page}&limit=50&pending=${pendingOnly.checked}`), apiRequest("/agents/profiles")]);
      const requests = sortApprovals(approvalPage);
      const profileNames = new Map(profiles.map(p => [p.id, p.name]));
      if (!context.isCurrent()) return;
      errors.replaceChildren();
      pageLabel.textContent = `Page ${page + 1}`;
      previous.disabled = page === 0;
      next.disabled = requests.length < 50;
      list.replaceChildren(...(requests.length ? requests.map(request => {
        const pending = request.status === "PENDING";
        const actions = node("div", { className: "actions" });
        if (pending) for (const [decision, label, style] of [["APPROVED", request.actionMetadata?.type === "SETUP" ? "Allow and save to this profile" : "Approve", "button approve"], ["REJECTED", "Reject", "button danger"]]) {
          const control = button(label, async () => {
            if (busy) return;
            if (!confirm(`${label} this request?`)) return;
            busy = true;
            const controls = [...list.querySelectorAll("button")];
            controls.forEach(item => { item.disabled = true; });
            let resolutionError = null;
            try { await apiRequest(`/approval-requests/${encodeURIComponent(request.id)}/resolve`, jsonRequest("POST", { decision, saveRule: decision === "APPROVED" && request.actionMetadata?.type === "SETUP" })); }
            catch (error) { resolutionError = error; }
            finally {
              busy = false;
              await refresh();
              controls.forEach(item => { if (item.isConnected) item.disabled = false; });
              if (resolutionError) notice(errors, resolutionError, refresh);
            }
          }, style);
          actions.append(control);
        }
        return node("article", { className: "card" }, node("div", { className: "row between" },
          node("div", { className: "row" }, badge(request.status), node("span", { className: "small muted" }, `Requested: ${date(request.createdAt)}`)), actions),
          node("h3", {}, request.actionSummary),
          request.status === "EXPIRED" ? node("p", { className: "notice" }, request.expirationMessage ?? "Request expired before execution") : null,
          review(request.actionMetadata?.action),
          node("details", {}, node("summary", {}, "Rule and request details"), node("pre", {}, JSON.stringify({ type: request.actionMetadata?.type, action: request.actionMetadata?.action,
            matchedRules: request.actionMetadata?.matchedRules?.map(rule => ({ effect: rule.effect })) }, null, 2))),
          node("p", { className: "small muted" }, `Profile: ${profileNames.get(request.agentProfileId) ?? "Deleted or unavailable profile"}`));
      }) : [empty("No approval requests found.")]));
    } catch (error) { if (context.isCurrent()) notice(errors, error, refresh); }
    finally { loading = false; }
  };
  container.replaceChildren(node("div", { className: "actions page-actions" }, button("Refresh", refresh)),
    node("div", { className: "actions" }, node("label", {}, pendingOnly, " Pending only"), previous, pageLabel, next), errors, list);
  await refresh();
  if (context.isCurrent()) context.setPoll(setInterval(() => { if (!document.hidden) void refresh(); }, 2000));
}
