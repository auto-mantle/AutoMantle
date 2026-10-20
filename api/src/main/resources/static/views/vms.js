import { apiRequest, jsonRequest } from "../api.js";
import { node, button, heading, empty, notice, field, makeForm, confirmAction, displayMessage, badge } from "../ui.js";

export async function vmsView(container, context) {
  container.classList.add("vm-view");
  const errors = node("div"), runs = node("div", { className: "stack" }), terminalPanel = node("section", { className: "card vm-terminal-panel", hidden: true });
  let profileNames = new Map(), setupExpiry = new Map(), terminal = null, terminalTimer = null, attachedId = null, disposed = false;
  let terminalLoading = false, offset = 0, sending = false, queue = [], attachment = 0;
  const closeTerminal = () => {
    attachment++; clearTimeout(terminalTimer); terminalTimer = null; attachedId = null; queue = []; sending = false;
    terminal?.dispose(); terminal = null; terminalPanel.hidden = true;
  };
  context.setCleanup(() => { disposed = true; closeTerminal(); container.classList.remove("vm-view"); });
  const inputErrors = node("div");
  async function sendInput(bytes, version) {
    if (!attachedId || disposed || version !== attachment) return;
    if (queue.length + bytes.length > 65536) { notice(inputErrors, "Paste is too large. Send smaller pieces."); return; }
    queue.push(...bytes);
    if (sending) return;
    sending = true;
    try {
      while (queue.length && attachedId && !disposed && version === attachment) {
        const chunk = queue.slice(0, 4096);
        const reply = await apiRequest(`/vms/${attachedId}/terminal/input`, jsonRequest("POST", { data: chunk }));
        if (version !== attachment) return;
        if (!Number.isInteger(reply.written) || reply.written < 1 || reply.written > chunk.length) throw new Error("VM could not accept terminal input.");
        queue.splice(0, reply.written);
      }
    } catch (error) { if (version === attachment) { queue = []; notice(inputErrors, error); } }
    finally { if (version === attachment) sending = false; }
  }
  async function attach(run) {
    closeTerminal(); offset = 0; terminalLoading = false;
    attachedId = run.id;
    const version = attachment;
    terminal = new window.Terminal({ cols: 80, rows: 24, scrollback: 5000, fontSize: 13, cursorBlink: true, disableStdin: true });
    const connectedTerminal = terminal;
    terminal.attachCustomKeyEventHandler(event => {
      if (!(event.ctrlKey || event.metaKey) || event.altKey) return true;
      const key = event.key.toLowerCase();
      return key !== "v" && !(key === "c" && (event.shiftKey || connectedTerminal.hasSelection()));
    });
    const screen = node("div", { className: "vm-terminal", "aria-label": `Terminal inside VM: ${run.name ?? "VM"}` });
    connectedTerminal.attachCustomWheelEventHandler(event => {
      if (event.ctrlKey || event.metaKey) return false;
      if (connectedTerminal.buffer.active.type !== "normal" || !event.deltaY) return true;
      const lines = event.deltaMode === 1 ? event.deltaY : event.deltaMode === 2
        ? event.deltaY * connectedTerminal.rows : event.deltaY / (connectedTerminal.options.fontSize * 1.2);
      connectedTerminal.scrollLines(Math.sign(lines) * Math.max(1, Math.round(Math.abs(lines))));
      event.preventDefault(); event.stopPropagation();
      return false;
    });
    const networkMode = node("p", { className: "small muted" });
    const updateNetworkMode = () => { networkMode.textContent = `Network: ${run.setup && new Date(setupExpiry.get(run.agentProfileId) ?? 0).getTime() > Date.now() ? "Setup Mode" : "Normal enforcement"}`; };
    updateNetworkMode();
    terminalPanel.replaceChildren(heading(`Terminal inside VM: ${run.name ?? "VM"}`,
      button("Close terminal", closeTerminal)),
      node("p", {}, `Profile: ${profileNames.get(run.agentProfileId) ?? "Profile unavailable"} · Files and installed tools are saved`),
      networkMode, inputErrors, screen);
    terminalPanel.hidden = false; inputErrors.replaceChildren(); terminal.open(screen); terminal.focus();
    terminal.onData(data => { void sendInput(Array.from(new TextEncoder().encode(data)), version); });
    const read = async () => {
      if (disposed || version !== attachment || terminalLoading) return;
      terminalLoading = true;
      try {
        const reply = await apiRequest(`/vms/${run.id}/terminal?offset=${offset}`);
        if (disposed || version !== attachment) return;
        updateNetworkMode();
        if (reply.gap) terminal.write("\r\n[Older console output expired]\r\n");
        terminal.write(new Uint8Array(reply.data)); offset = reply.next;
        terminal.options.disableStdin = !reply.ready || reply.state !== "running";
        if (["stopped", "failed"].includes(reply.state)) { terminal.write(`\r\n[VM ${reply.state}]\r\n`); return; }
        terminalTimer = setTimeout(read, 150);
      } catch (error) { if (version === attachment && !disposed) { notice(inputErrors, error); terminalTimer = setTimeout(read, 1500); } }
      finally { if (version === attachment) terminalLoading = false; }
    };
    void read();
  }
  let allProfiles = [];
  const editor = node("div");
  function settingsForm(vm = null) {
    const profiles = node("select", { name: "agentProfileId", required: true, className: "form-input" },
      node("option", { value: "" }, "Choose Agent Profile"),
      ...allProfiles.map(p => node("option", { value: p.id }, p.name)));
    profiles.value = vm?.agentProfileId ?? "";
    const setup = node("input", { type: "checkbox", name: "setup", checked: vm?.setup ?? false });
    return makeForm(vm ? "Edit VM" : "Create VM", [
      field("Name", "name", vm?.name ?? "", { required: true, maxlength: 80 }),
      node("p", { className: "small muted" }, "Linux · Files and installed tools remain when this VM stops."),
      node("label", { className: "field" }, node("span", {}, "Agent Profile"), profiles),
      field("Memory (MiB)", "memoryMib", String(vm?.memoryMib ?? 2048), { type: "number", min: 128, max: 65536, required: true }),
      field("CPUs", "vcpuCount", String(vm?.vcpuCount ?? 2), { type: "number", min: 1, max: 64, required: true }),
      node("label", {}, setup, " Setup Mode: prompt for unknown supported connections")
    ], async form => {
      const request = Object.fromEntries(form.entries());
      request.memoryMib = Number(request.memoryMib); request.vcpuCount = Number(request.vcpuCount); request.setup = setup.checked;
      await apiRequest(vm ? `/vms/${vm.id}` : "/vms", jsonRequest(vm ? "PUT" : "POST", request));
      if (disposed) return;
      editor.replaceChildren(); await refresh();
    }, vm ? "Save changes" : "Create VM", () => editor.replaceChildren());
  }
  function copyForm(vm) {
    editor.replaceChildren(makeForm("Copy VM", [
      field("Name", "name", `${vm.name} copy`.slice(0, 80), { required: true, maxlength: 80 }),
      node("p", { className: "small muted" }, "Copies Linux, files, installed tools, saved logins and VM settings into an independent VM.")
    ], async form => {
      await apiRequest(`/vms/${vm.id}/copy`, jsonRequest("POST", Object.fromEntries(form.entries())));
      if (disposed) return;
      editor.replaceChildren(); await refresh();
    }, "Copy VM", () => editor.replaceChildren()));
    editor.scrollIntoView({ block: "nearest" });
  }
  async function act(vm, action) {
    try {
      const reply = await apiRequest(`/vms/${vm.id}/${action}`, { method: "POST" });
      errors.replaceChildren();
      await refresh();
      if (action === "start" && !disposed) await attach({ ...reply, id: reply.runId });
    } catch (error) { notice(errors, error); }
  }
  async function refresh() {
    const [profiles, machines] = await Promise.all([apiRequest("/agents/profiles"), apiRequest("/vms")]);
    if (disposed || !context.isCurrent()) return;
    allProfiles = profiles;
    profileNames = new Map(profiles.map(p => [p.id, p.name]));
    setupExpiry = new Map(profiles.map(p => [p.id, p.setupExpiresAt]));
    runs.replaceChildren(...(machines.length ? machines.map(vm => {
      const active = !["stopped", "failed"].includes(vm.state);
      const controls = node("div", { className: "actions" });
      if (!active) {
        controls.append(button("Start", () => act(vm, "start"), "button approve"),
          button("Edit", () => editor.replaceChildren(settingsForm(vm))),
          button("Copy", () => copyForm(vm)),
          button("Delete", async () => {
            if (!await confirmAction(`Do you want to delete VM "${vm.name}" and all its files?`)) return;
            try { await apiRequest(`/vms/${vm.id}`, { method: "DELETE" }); if (attachedId === vm.runId) closeTerminal(); await refresh(); }
            catch (error) { notice(errors, error); }
          }, "button danger"));
      } else {
        if (vm.state === "running") controls.append(button("Stop", () => act(vm, "stop"), "button danger"));
        if (vm.terminalReady) controls.append(button("Open terminal", () => attach({ ...vm, id: vm.runId })),
          button("Open in external terminal", async () => {
            try { await apiRequest(`/vms/${vm.runId}/terminal/external`, { method: "POST" }); }
            catch (error) { notice(errors, error); }
          }));
        if (vm.state !== "running") controls.append(button("Force stop", () => {
          if (confirm("Force stop this VM? Unsaved work and unflushed changes may be lost.")) void act(vm, "force-stop");
        }, "button danger"));
      }
      return node("article", { className: "card" }, heading(vm.name, badge(vm.state.toUpperCase())),
        node("p", {}, `Linux · ${vm.vcpuCount} CPU${vm.vcpuCount === 1 ? "" : "s"} · ${vm.memoryMib} MiB RAM · Profile: ${profileNames.get(vm.agentProfileId) ?? "Profile unavailable"}`),
        vm.error ? node("p", { className: "notice" }, displayMessage(vm.error)) : null, controls);
    }) : [empty("No VMs yet. Create one with Linux included.")]));
  }
  container.replaceChildren(node("div", { className: "actions page-actions" },
    button("Create VM", () => editor.replaceChildren(settingsForm()), "button primary"),
    button("Refresh", () => { void refresh().catch(error => notice(errors, error)); })),
    errors, editor, terminalPanel, runs);
  let refreshing = false;
  const reload = async () => { if (refreshing || disposed) return; refreshing = true; try { await refresh(); } catch (error) { notice(errors, error); } finally { refreshing = false; } };
  await reload();
  if (!disposed && context.isCurrent()) context.setPoll(setInterval(() => { if (!document.hidden) void reload(); }, 2000));
}
