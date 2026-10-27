import { apiRequest } from "../api.js";
import { node, button, empty, badge, notice, date, displayMessage } from "../ui.js";

export async function historyView(container, context) {
  const errors = node("div");
  const list = node("div", { className: "stack" }, empty("Loading request history…"));
  const profile = node("select", { className: "form-input", "aria-label": "Filter by agent profile" }, node("option", { value: "" }, "All agent profiles"));
  const help = node("p", { className: "muted small" }, "Updates every 2 seconds. Keeps up to 10,000 requests for 30 days. Headers, queries, and payloads are not recorded. Paths may contain application identifiers.");
  let loading = false, clearing = false, nextBefore = null, rows = [], older = false, generation = 0;
  const more = button("Load older requests", () => refresh(true));
  more.hidden = true;
  function render() {
    list.replaceChildren(...(rows.length ? rows.map(event => node("article", { className: "card" },
      node("div", { className: "row between" }, badge(event.result), node("span", { className: "small muted" }, date(event.time))),
      node("h3", { className: "mono" }, event.host ? `${event.host}${event.port ? `:${event.port}` : ""}` : event.destinationIp ? `${event.destinationIp}${event.port !== null ? `:${event.port}` : ""}` : "Destination unavailable"),
      node("p", { className: "mono small" }, event.protocol ? `${event.protocol}${event.etherType !== null ? ` · EtherType 0x${event.etherType.toString(16).padStart(4, "0")}` : ""}` : [event.method, event.path].filter(Boolean).join(" ") || "Request details unavailable"),
      node("p", {}, displayMessage(event.reason)),
      event.packetCount !== null && event.packetCount !== undefined ? node("p", { className: "small muted" }, `${event.packetCount} packets · ${event.byteCount} bytes · Source: ${event.sourceIp ?? "unknown"}${event.sourcePort !== null ? `:${event.sourcePort}` : ""}`) : null,
      node("p", { className: "small muted" }, `Profile: ${event.agentName || "Deleted or unavailable profile"}`),
      event.approvalId ? node("a", { href: "/?tab=approvals", className: "small" }, "View approvals") : null
    )) : [empty("No requests recorded for this selection.")]));
    more.hidden = nextBefore === null;
  }
  async function refresh(append = false) {
    if (loading || clearing || !context.isCurrent()) return;
    loading = true;
    const expected = generation;
    more.disabled = true;
    try {
      const query = new URLSearchParams();
      if (profile.value) query.set("agentProfileId", profile.value);
      if (append && nextBefore !== null) query.set("before", String(nextBefore));
      const page = await apiRequest(`/request-history?${query}`);
      if (!context.isCurrent() || expected !== generation) return;
      errors.replaceChildren();
      rows = append ? [...rows, ...page.items] : page.items;
      older = append;
      nextBefore = page.nextBefore;
      render();
    } catch (error) { if (context.isCurrent() && expected === generation) notice(errors, error, () => refresh()); }
    finally { loading = false; more.disabled = false; }
  }
  profile.addEventListener("change", () => {
    generation++; older = false; rows = []; nextBefore = null;
    render();
    if (!loading) void refresh();
  });
  const clear = button("Clear history", async () => {
    if (!confirm("Clear all local request history? Profiles, rules, and approval history will remain. New requests will continue to be recorded.")) return;
    clear.disabled = true;
    clearing = true;
    generation++;
    try {
      await apiRequest("/request-history", { method: "DELETE" });
      rows = []; nextBefore = null; older = false; render(); errors.replaceChildren();
    } catch (error) { notice(errors, error); }
    finally { clearing = false; clear.disabled = false; }
    if (!loading && context.isCurrent()) await refresh();
  }, "button danger");
  container.replaceChildren(node("div", { className: "actions page-actions" }, clear),
    help, node("label", { className: "field" }, "Agent profile", profile), errors, list, more);
  try {
    const profiles = await apiRequest("/agents/profiles");
    if (!context.isCurrent()) return;
    profiles.forEach(p => profile.append(node("option", { value: p.id }, p.name)));
  } catch (error) { if (context.isCurrent()) notice(errors, error); }
  await refresh();
  if (context.isCurrent()) context.setPoll(setInterval(() => { if (!document.hidden && !older) void refresh(); }, 2000));
}
