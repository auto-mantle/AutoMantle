import { apiRequest } from "./api.js";

export const date = value => new Date(value).toLocaleString();
export const profileLink = name => `/profiles/${encodeURIComponent(name)}`;
export const displayMessage = value => String(value).replace(/automantle-vm-[0-9a-f]{32}|vm-[0-9a-f]{32}/gi, "VM")
  .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, "internal reference");
export const rulePath = (profileId, id) => `/agents/profiles/${encodeURIComponent(profileId)}/rules${id ? `/${encodeURIComponent(id)}` : ""}`;

export function node(tag, attributes = {}, ...children) {
  const element = document.createElement(tag);
  for (const [key, value] of Object.entries(attributes)) {
    if (key.startsWith("on")) element.addEventListener(key.slice(2), value);
    else if (key === "className") element.className = value;
    else if (["hidden", "disabled", "checked", "required", "readOnly"].includes(key)) element[key] = value;
    else element.setAttribute(key, value);
  }
  for (const child of children.flat(Infinity)) {
    if (child !== null && child !== undefined) element.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return element;
}
export const button = (label, action, style = "button") => node("button", { type: "button", className: style, onclick: action }, label);
export const heading = (title, ...actions) => node("div", { className: "row between" }, node("h2", {}, title), node("div", { className: "actions" }, ...actions));
export const empty = label => node("p", { className: "card muted" }, label);
export function confirmAction(message) {
  return new Promise(resolve => {
    let settled = false;
    const dialog = node("dialog", { className: "confirm-dialog", "aria-label": "Confirm deletion" });
    const finish = confirmed => {
      if (settled) return;
      settled = true; dialog.close(); dialog.remove(); resolve(confirmed);
    };
    const cancel = button("Cancel", () => finish(false));
    dialog.append(node("h3", {}, "Confirm deletion"), node("p", {}, message),
      node("div", { className: "actions" }, button("Yes", () => finish(true), "button danger"), cancel));
    dialog.addEventListener("cancel", event => { event.preventDefault(); finish(false); });
    dialog.addEventListener("close", () => finish(false));
    document.body.append(dialog);
    dialog.showModal();
    cancel.focus();
  });
}
export function badge(value) {
  const style = value === "STOPPED" ? "stopped" : ["RUNNING", "ALLOW", "ALLOWED", "APPROVED"].includes(value) ? "allow" : ["DENY", "DENIED", "FAILED", "CANCELLED", "REJECTED", "EXPIRED"].includes(value) ? "deny" : "pending";
  return node("span", { className: `badge badge-${style}` }, String(value).replaceAll("_", " "));
}
export function field(label, name, value = "", { type = "text", required = false, help = null, ...extra } = {}) {
  const input = node("input", { type, name, value, required, className: "form-input", ...extra });
  return node("label", { className: "field" }, node("span", {}, label), input, help ? node("span", { className: "help" }, help) : null);
}
export function notice(container, error, retry) {
  container.replaceChildren(node("div", { className: "notice", role: "alert" }, displayMessage(error instanceof Error ? error.message : error),
    retry ? button("Retry", retry, "text-button") : null));
}
export function makeForm(title, fields, save, label = "Save", onCancel = null) {
  const errors = node("div");
  const submit = node("button", { type: "submit", className: "button primary" }, label);
  const form = node("form", { className: "card" }, node("h3", {}, title), ...fields, errors,
    node("div", { className: "actions" }, submit, onCancel ? button("Cancel", onCancel) : null));
  form.addEventListener("submit", async event => {
    event.preventDefault();
    if (submit.disabled) return;
    submit.disabled = true;
    errors.replaceChildren();
    try { await save(new FormData(form)); } catch (error) { notice(errors, error); }
    finally { submit.disabled = false; }
  });
  return form;
}
export async function removeRecord(path, label, refresh, errors, control) {
  if (!await confirmAction(`Do you want to delete this ${label}?`)) return;
  control.disabled = true;
  try { await apiRequest(path, { method: "DELETE" }); await refresh(); }
  catch (error) { notice(errors, error); }
  finally { control.disabled = false; }
}
