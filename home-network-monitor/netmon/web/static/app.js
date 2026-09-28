"use strict";

// ---------------------------------------------------------------- helpers
// All untrusted strings (hostnames, domains) are inserted as text nodes.
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else if (k === "dataset") Object.assign(el.dataset, v);
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    el.appendChild(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}
const $ = (sel) => document.querySelector(sel);
function mount(target, ...nodes) {
  const el = typeof target === "string" ? $(target) : target;
  el.replaceChildren(...nodes.flat());
}

function fmtBytes(n) {
  if (n === null || n === undefined) return "–";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = Number(n);
  while (Math.abs(v) >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v >= 100 || i === 0 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`;
}
function fmtNum(n) { return Number(n || 0).toLocaleString(); }
function timeAgo(ts) {
  if (!ts) return "–";
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 90) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}
function fmtTime(ts) { return ts ? new Date(ts * 1000).toLocaleString() : "–"; }
function localDay(d = new Date()) {
  const off = d.getTimezoneOffset() * 60000;
  return new Date(d - off).toISOString().slice(0, 10);
}
function deviceLabel(d) {
  const vendor = d.vendor && !/randomized/i.test(d.vendor) ? d.vendor : null;
  return d.alias || d.hostname || (vendor ? `${vendor} (${d.ip || d.mac})` : null) || d.ip || d.mac || d.device;
}

async function api(path, options = {}) {
  const res = await fetch(path, { headers: { "Content-Type": "application/json" }, ...options });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

const SVG_NS = "http://www.w3.org/2000/svg";
function s(tag, attrs, ...children) {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, String(v));
  for (const c of children.flat()) el.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
  return el;
}

// Grouped bar chart: download + upload per bucket.
function barChart(container, points, { labelEvery = 1 } = {}) {
  const el = typeof container === "string" ? $(container) : container;
  const width = el.clientWidth || 800;
  const height = el.clientHeight || 220;
  if (!points.length || points.every((p) => !p.down && !p.up)) {
    mount(el, h("div", { class: "empty" }, "No traffic data yet for this period."));
    return;
  }
  const pad = { l: 56, r: 8, t: 10, b: 24 };
  const max = Math.max(...points.map((p) => Math.max(p.down || 0, p.up || 0)), 1);
  const iw = width - pad.l - pad.r;
  const ih = height - pad.t - pad.b;
  const bw = iw / points.length;
  const barW = Math.max(1.5, Math.min(18, bw * 0.38));
  const svg = s("svg", { viewBox: `0 0 ${width} ${height}`, preserveAspectRatio: "none" });
  const grid = s("g", { class: "grid" });
  const axis = s("g", { class: "axis" });
  for (let i = 0; i <= 4; i++) {
    const y = pad.t + ih - (ih * i) / 4;
    grid.appendChild(s("line", { x1: pad.l, x2: width - pad.r, y1: y, y2: y }));
    axis.appendChild(s("text", { x: pad.l - 6, y: y + 3, "text-anchor": "end" }, fmtBytes((max * i) / 4)));
  }
  svg.append(grid, axis);
  points.forEach((p, i) => {
    const cx = pad.l + bw * i + bw / 2;
    const hd = (ih * (p.down || 0)) / max;
    const hu = (ih * (p.up || 0)) / max;
    const tip = `${p.title || p.label}\nDownload ${fmtBytes(p.down)}\nUpload ${fmtBytes(p.up)}`;
    svg.appendChild(s("rect", { class: "bar-down", x: cx - barW - 1, y: pad.t + ih - hd, width: barW, height: Math.max(hd, 0), rx: 2 }, s("title", {}, tip)));
    svg.appendChild(s("rect", { class: "bar-up", x: cx + 1, y: pad.t + ih - hu, width: barW, height: Math.max(hu, 0), rx: 2 }, s("title", {}, tip)));
    if (i % labelEvery === 0) {
      axis.appendChild(s("text", { x: cx, y: height - 6, "text-anchor": "middle" }, p.label));
    }
  });
  mount(el, svg);
}

function table(columns, rows, { onRowClick, empty = "Nothing here yet." } = {}) {
  if (!rows.length) return h("div", { class: "empty" }, empty);
  let sortKey = null;
  let sortDir = -1;
  const tbody = h("tbody");
  const render = () => {
    const sorted = sortKey ? [...rows].sort((a, b) => {
      const col = columns.find((c) => c.key === sortKey);
      const va = col.sort ? col.sort(a) : a[sortKey];
      const vb = col.sort ? col.sort(b) : b[sortKey];
      return (va > vb ? 1 : va < vb ? -1 : 0) * sortDir;
    }) : rows;
    tbody.replaceChildren(...sorted.map((r) => h("tr", { class: onRowClick ? "clickable" : null, onclick: onRowClick ? () => onRowClick(r) : null },
      columns.map((c) => h("td", { class: c.num ? "num" : null }, c.render ? c.render(r) : (r[c.key] ?? "–"))))));
  };
  const head = h("tr", {}, columns.map((c) => h("th", {
    class: [c.num ? "num" : "", c.key ? "sortable" : ""].join(" ").trim() || null,
    onclick: c.key ? () => { sortDir = sortKey === c.key ? -sortDir : -1; sortKey = c.key; render(); } : null,
  }, c.title)));
  render();
  return h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, head), tbody));
}

const sevRank = { high: 3, medium: 2, low: 1, info: 0 };
function alertItem(a, { onAck } = {}) {
  return h("div", { class: `alert-item${a.acknowledged ? " acked" : ""}` },
    h("span", { class: `sev ${a.severity}` }, a.severity),
    h("div", {},
      h("div", { class: "title" }, a.title),
      h("div", { class: "detail" }, a.detail || ""),
      h("div", { class: "meta" }, `${fmtTime(a.ts)} · ${a.category.replace(/_/g, " ")}${a.label ? " · " + a.label : ""}`)),
    a.acknowledged ? h("span", { class: "pill" }, "acknowledged")
      : h("button", { class: "btn small", onclick: async (e) => { e.stopPropagation(); await api(`/api/alerts/${a.id}/ack`, { method: "POST" }); onAck && onAck(); } }, "Acknowledge"));
}

// ---------------------------------------------------------------- state
const state = { day: localDay(), tab: "overview", devices: [] };
const dayInput = $("#day");
dayInput.value = state.day;
dayInput.max = state.day;
dayInput.addEventListener("change", () => { state.day = dayInput.value || localDay(); refresh(); });

document.querySelectorAll("#tabs button").forEach((btn) => btn.addEventListener("click", () => showTab(btn.dataset.tab)));
document.querySelectorAll("[data-goto]").forEach((btn) => btn.addEventListener("click", () => showTab(btn.dataset.goto)));
function showTab(tab) {
  state.tab = tab;
  document.querySelectorAll("#tabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.id === `tab-${tab}`));
  history.replaceState(null, "", `#${tab}`);
  refresh();
}

// ---------------------------------------------------------------- overview
async function loadOverview() {
  const [sum, openAlertRows] = await Promise.all([api(`/api/summary?day=${state.day}`), api("/api/alerts?status=open&limit=100")]);
  const alerts = openAlertRows.sort((a, b) => (sevRank[b.severity] - sevRank[a.severity]) || (b.ts - a.ts)).slice(0, 6);
  const t = sum.traffic;
  const total = t.wan || t.devices;
  const srcNote = t.source === "gateway" ? "whole home (gateway counters)" : t.source === "devices" ? "sum of monitored devices" : "no traffic source yet";
  const openAlerts = Object.values(sum.alerts).reduce((a, b) => a + b, 0);
  const serious = (sum.alerts.high || 0) + (sum.alerts.medium || 0);
  mount("#kpis",
    kpi("Download", fmtBytes(total.bytes_down), srcNote, "down"),
    kpi("Upload", fmtBytes(total.bytes_up), t.wan && t.devices.bytes_up ? `per-device sum ${fmtBytes(t.devices.bytes_up)}` : srcNote, "up"),
    kpi("Devices online", `${sum.devices.online} / ${sum.devices.total}`, sum.devices.new ? `${sum.devices.new} new this day` : "no new devices"),
    kpi("DNS lookups", fmtNum(sum.dns.queries), `${fmtNum(sum.dns.domains)} unique hosts`),
    kpi("Open alerts", fmtNum(openAlerts), serious ? `${serious} medium/high` : "nothing serious", openAlerts ? "alert" : ""));

  const [y, m, d] = state.day.split("-").map(Number);
  const start = new Date(y, m - 1, d).getTime() / 1000;
  const byHour = Object.fromEntries(sum.hourly.map((r) => [r.hour_ts, r]));
  const points = [];
  for (let i = 0; i < 24; i++) {
    const ts = start + i * 3600;
    const key = Object.keys(byHour).find((k) => Math.abs(k - ts) < 1800);
    const r = key ? byHour[key] : {};
    points.push({ label: `${i}`, title: `${i}:00–${i + 1}:00`, down: r.bytes_down || 0, up: r.bytes_up || 0 });
  }
  barChart("#hourly-chart", points, { labelEvery: 2 });

  const maxT = Math.max(...sum.top_talkers.map((r) => r.bytes_up + r.bytes_down), 1);
  mount("#top-talkers", table([
    { title: "Device", render: (r) => r.label },
    { title: "Type", render: (r) => h("span", { class: "pill" }, r.device_type || "unknown") },
    { title: "Down", num: true, render: (r) => fmtBytes(r.bytes_down) },
    { title: "Up", num: true, render: (r) => fmtBytes(r.bytes_up) },
    { title: "", render: (r) => { const b = h("div", { class: "bar-inline" }, h("span")); b.firstChild.style.width = `${(100 * (r.bytes_up + r.bytes_down)) / maxT}%`; return b; } },
  ], sum.top_talkers, { onRowClick: (r) => openDevice(r.device), empty: "No per-device traffic yet (needs sniffer or NetFlow; see README)." }));

  mount("#top-domains", table([
    { title: "Site", render: (r) => h("span", { class: "mono" }, r.domain) },
    { title: "Lookups", num: true, render: (r) => fmtNum(r.queries) },
    { title: "Devices", num: true, render: (r) => r.devices },
  ], sum.top_domains, { empty: "No DNS data yet (enable the DNS proxy, Pi-hole or AdGuard import)." }));

  mount("#recent-alerts", alerts.length ? alerts.map((a) => alertItem(a, { onAck: refresh })) : h("div", { class: "empty" }, "No open alerts."));
  updateAlertBadge(sum.alerts);
}
function kpi(label, value, sub, cls = "") {
  return h("div", { class: `kpi ${cls}` }, h("div", { class: "label" }, label), h("div", { class: "value" }, value), h("div", { class: "sub" }, sub));
}
function updateAlertBadge(counts) {
  const n = (counts.high || 0) + (counts.medium || 0);
  const badge = $("#alert-badge");
  badge.hidden = !n;
  badge.textContent = n;
}

// ---------------------------------------------------------------- devices
async function loadDevices() {
  state.devices = await api(`/api/devices?day=${state.day}`);
  renderDevices();
  fillDeviceSelects();
}
function renderDevices() {
  const q = $("#device-filter").value.trim().toLowerCase();
  const onlineOnly = $("#device-online-only").checked;
  const rows = state.devices.filter((d) => (!onlineOnly || d.online) &&
    (!q || [d.alias, d.hostname, d.vendor, d.ip, d.mac, d.device_type].some((v) => (v || "").toLowerCase().includes(q))));
  const online = state.devices.filter((d) => d.online).length;
  $("#device-count").textContent = `${online} online · ${state.devices.length} known`;
  mount("#devices-table", table([
    { title: "", render: (r) => h("span", { class: `dot${r.online ? " on" : ""}`, title: r.online ? "online" : "offline" }) },
    { title: "Name", key: "label", sort: deviceLabel, render: (r) => h("div", {}, deviceLabel(r), r.trusted ? h("span", { class: "pill", title: "marked as trusted" }, "trusted") : null, r.unidentified ? h("span", { class: "pill warn" }, "no MAC yet") : null) },
    { title: "Type", key: "device_type", render: (r) => h("span", { class: "pill" }, r.device_type || "unknown") },
    { title: "Vendor", key: "vendor", render: (r) => r.vendor || "–" },
    { title: "IP", key: "ip", render: (r) => h("span", { class: "mono" }, r.ip || "–") },
    { title: "MAC", key: "mac", render: (r) => h("span", { class: "mono" }, r.unidentified ? "–" : r.mac) },
    { title: "Down", key: "bytes_down", num: true, render: (r) => fmtBytes(r.bytes_down) },
    { title: "Up", key: "bytes_up", num: true, render: (r) => fmtBytes(r.bytes_up) },
    { title: "Lookups", key: "queries", num: true, render: (r) => fmtNum(r.queries) },
    { title: "Last seen", key: "last_seen", num: true, render: (r) => timeAgo(r.last_seen) },
    { title: "Alerts", key: "open_alerts", num: true, render: (r) => r.open_alerts ? h("span", { class: "sev medium" }, r.open_alerts) : "" },
  ], rows, { onRowClick: (r) => openDevice(r.mac), empty: "No devices discovered yet." }));
}
$("#device-filter").addEventListener("input", renderDevices);
$("#device-online-only").addEventListener("change", renderDevices);

function fillDeviceSelects() {
  for (const sel of [$("#domain-device"), $("#query-device")]) {
    const current = sel.value;
    const opts = [h("option", { value: "" }, "All devices")].concat(
      [...state.devices].filter((d) => !d.unidentified).sort((a, b) => deviceLabel(a).localeCompare(deviceLabel(b)))
        .map((d) => h("option", { value: d.mac }, deviceLabel(d))));
    sel.replaceChildren(...opts);
    sel.value = current;
  }
}

const DEVICE_TYPES = ["phone", "tablet", "laptop", "computer", "tv/streaming", "game console", "smart speaker", "camera/doorbell", "printer", "iot", "server", "network", "apple device", "phone/tablet/laptop", "unknown"];

async function openDevice(mac) {
  const data = await api(`/api/devices/${encodeURIComponent(mac)}?days=30`);
  const d = data.device;
  const alias = h("input", { type: "text", value: d.alias || "", placeholder: "Friendly name (e.g. Kid's iPad)", maxlength: 64 });
  const type = h("select", {}, DEVICE_TYPES.map((t) => h("option", { value: t, selected: t === d.device_type }, t)));
  const trusted = h("input", { type: "checkbox", checked: !!d.trusted });
  const save = h("button", { class: "btn", onclick: async () => {
    await api(`/api/devices/${encodeURIComponent(mac)}`, { method: "PATCH", body: JSON.stringify({ alias: alias.value, device_type: type.value, trusted: trusted.checked }) });
    save.textContent = "Saved";
    setTimeout(() => { save.textContent = "Save"; }, 1500);
    loadDevices();
  } }, "Save");
  const chart = h("div", { class: "chart" });
  const totals = data.history.reduce((acc, r) => ({ up: acc.up + r.bytes_up, down: acc.down + r.bytes_down, q: acc.q + r.queries }), { up: 0, down: 0, q: 0 });
  mount("#drawer-body",
    h("h1", {}, deviceLabel(d)),
    h("div", { class: "muted" }, [d.device_type, d.vendor].filter(Boolean).join(" · ")),
    h("div", { class: "facts" },
      fact("IP address", d.ip), fact("MAC address", d.mac), fact("Hostname", d.hostname),
      fact("First seen", fmtTime(d.first_seen)), fact("Last seen", timeAgo(d.last_seen)),
      fact("Seen via", d.sources), fact("Services", d.services),
      fact("30-day download", fmtBytes(totals.down)), fact("30-day upload", fmtBytes(totals.up)), fact("30-day DNS lookups", fmtNum(totals.q))),
    d.mac && !d.mac.startsWith("ip:") ? h("div", { class: "edit-row" }, alias, type, h("label", { class: "check" }, trusted, "Trusted"), save) : null,
    h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Last 30 days")), chart),
    data.alerts.length ? h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Alerts")), data.alerts.map((a) => alertItem(a, { onAck: () => openDevice(mac) }))) : null,
    h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Domains (last 7 days)")),
      table([
        { title: "Domain", key: "domain", render: (r) => h("span", { class: "mono" }, r.domain) },
        { title: "Lookups", key: "queries", num: true, render: (r) => fmtNum(r.queries) },
        { title: "Last", key: "last_ts", num: true, render: (r) => timeAgo(r.last_ts) },
      ], data.top_domains, { empty: "No DNS lookups recorded for this device." })),
    h("div", { class: "card" }, h("div", { class: "card-head" }, h("h2", {}, "Remote hosts by traffic (last 7 days)")),
      table([
        { title: "Host", render: (r) => h("span", { class: "mono" }, r.remote_host || r.remote_ip) },
        { title: "IP", render: (r) => h("span", { class: "mono" }, r.remote_ip) },
        { title: "Port", num: true, render: (r) => `${r.remote_port}/${r.proto}` },
        { title: "Down", key: "bytes_down", num: true, render: (r) => fmtBytes(r.bytes_down) },
        { title: "Up", key: "bytes_up", num: true, render: (r) => fmtBytes(r.bytes_up) },
      ], data.top_hosts, { empty: "No flow data for this device (needs sniffer or NetFlow)." })));
  $("#drawer").hidden = false;
  barChart(chart, data.history.map((r) => ({ label: r.day.slice(5), title: r.day, down: r.bytes_down, up: r.bytes_up })), { labelEvery: 5 });
}
function fact(label, value) { return h("div", {}, h("span", {}, label), value || "–"); }
$("#drawer-close").addEventListener("click", () => { $("#drawer").hidden = true; });
$("#drawer").addEventListener("click", (e) => { if (e.target.id === "drawer") $("#drawer").hidden = true; });
document.addEventListener("keydown", (e) => { if (e.key === "Escape") $("#drawer").hidden = true; });

// ---------------------------------------------------------------- domains
let domainTimer;
async function loadDomains() {
  if (!state.devices.length) { state.devices = await api(`/api/devices?day=${state.day}`); fillDeviceSelects(); }
  const params = new URLSearchParams({ day: state.day, days: $("#domain-days").value, group: $("#domain-group").checked, limit: 500 });
  const search = $("#domain-search").value.trim();
  if (search) params.set("search", search);
  if ($("#domain-device").value) params.set("device", $("#domain-device").value);
  const rows = await api(`/api/domains?${params}`);
  const [y, m, d] = state.day.split("-").map(Number);
  const periodStart = new Date(y, m - 1, d).getTime() / 1000 - (Number($("#domain-days").value) - 1) * 86400;
  mount("#domains-table", table([
    { title: $("#domain-group").checked ? "Site" : "Host", key: "domain", render: (r) => h("span", {}, h("span", { class: "mono" }, r.domain), " ", r.first_seen_ever && r.first_seen_ever >= periodStart ? h("span", { class: "pill new", title: "first time this host was seen on your network" }, "new") : null) },
    { title: "Lookups", key: "queries", num: true, render: (r) => fmtNum(r.queries) },
    { title: "Blocked", key: "blocked", num: true, render: (r) => r.blocked ? fmtNum(r.blocked) : "" },
    { title: "Devices", key: "devices", num: true, render: (r) => h("span", { title: r.device_labels || "" }, r.devices) },
    { title: "Who", render: (r) => h("span", { class: "muted small" }, (r.device_labels || "").split(",").slice(0, 3).join(", ") + ((r.devices > 3) ? "…" : "")) },
    { title: "Last seen", key: "last_ts", num: true, render: (r) => timeAgo(r.last_ts) },
  ], rows, { empty: "No domains recorded for this period." }));
}
$("#domain-search").addEventListener("input", () => { clearTimeout(domainTimer); domainTimer = setTimeout(loadDomains, 300); });
["#domain-days", "#domain-device", "#domain-group"].forEach((id) => $(id).addEventListener("change", loadDomains));

// ---------------------------------------------------------------- traffic
async function loadTraffic() {
  const days = Number($("#traffic-days").value);
  const rows = await api(`/api/traffic/daily?days=${days}`);
  const hasWan = rows.some((r) => r.wan_down !== null);
  $("#traffic-source").textContent = hasWan ? "Totals from the AT&T gateway's WAN counters (whole home)." : "Totals are the sum of per-device traffic seen by the sniffer / NetFlow.";
  barChart("#daily-chart", rows.map((r) => ({
    label: r.day.slice(5), title: r.day,
    down: hasWan ? r.wan_down || 0 : r.devices_down, up: hasWan ? r.wan_up || 0 : r.devices_up,
  })), { labelEvery: Math.max(1, Math.ceil(days / 15)) });
  const byDev = await api(`/api/traffic/by-device?start=${rows[0].day}&end=${rows[rows.length - 1].day}`);
  mount("#traffic-devices", table([
    { title: "Device", key: "label", render: (r) => r.label },
    { title: "Download", key: "bytes_down", num: true, render: (r) => fmtBytes(r.bytes_down) },
    { title: "Upload", key: "bytes_up", num: true, render: (r) => fmtBytes(r.bytes_up) },
    { title: "Upload share", num: true, render: (r) => `${Math.round((100 * r.bytes_up) / Math.max(1, r.bytes_up + r.bytes_down))}%` },
  ], byDev, { onRowClick: (r) => openDevice(r.device), empty: "No per-device traffic recorded." }));
}
$("#traffic-days").addEventListener("change", loadTraffic);

// ---------------------------------------------------------------- alerts
async function loadAlerts() {
  const rows = await api(`/api/alerts?status=${$("#alert-status").value}&limit=500`);
  rows.sort((a, b) => (a.acknowledged - b.acknowledged) || (sevRank[b.severity] - sevRank[a.severity]) || (b.ts - a.ts));
  mount("#alerts-list", rows.length ? rows.map((a) => alertItem(a, { onAck: loadAlerts })) : h("div", { class: "empty" }, "No alerts."));
}
$("#alert-status").addEventListener("change", loadAlerts);
$("#ack-all").addEventListener("click", async () => { await api("/api/alerts/ack-all", { method: "POST" }); loadAlerts(); });

// ---------------------------------------------------------------- live dns
async function loadQueries() {
  if (!state.devices.length) { state.devices = await api(`/api/devices?day=${state.day}`); fillDeviceSelects(); }
  const params = new URLSearchParams({ limit: 300 });
  const search = $("#query-search").value.trim();
  if (search) params.set("search", search);
  if ($("#query-device").value) params.set("device", $("#query-device").value);
  const rows = await api(`/api/queries?${params}`);
  mount("#queries-table", table([
    { title: "Time", render: (r) => new Date(r.ts * 1000).toLocaleTimeString() },
    { title: "Device", render: (r) => r.label },
    { title: "Domain", render: (r) => h("span", { class: "mono" }, r.domain) },
    { title: "Type", render: (r) => r.qtype || "" },
    { title: "Result", render: (r) => h("span", { class: r.rcode === "NXDOMAIN" || r.rcode === "BLOCKED" ? "pill warn" : "pill" }, r.rcode || "") },
    { title: "Source", render: (r) => h("span", { class: "muted small" }, r.source) },
  ], rows, { empty: "No DNS lookups recorded yet." }));
}
let queryTimer;
$("#query-search").addEventListener("input", () => { clearTimeout(queryTimer); queryTimer = setTimeout(loadQueries, 300); });
$("#query-device").addEventListener("change", loadQueries);

// ---------------------------------------------------------------- data
const EXPORTS = [
  ["devices", "Devices"], ["traffic_daily", "Daily traffic per device"], ["wan_daily", "Daily whole-home traffic"],
  ["domain_stats", "Domains per device per day"], ["dns_queries", "Raw DNS query log"], ["host_traffic", "Remote hosts per device"],
  ["traffic_hourly", "Hourly traffic per device"], ["alerts", "Alerts"],
];
function renderExports() {
  const start = $("#export-start").value;
  const end = $("#export-end").value;
  const qs = new URLSearchParams();
  if (start) qs.set("start", start);
  if (end) qs.set("end", end);
  mount("#export-links", EXPORTS.map(([t, label]) => h("li", {}, h("a", { href: `/api/export/${t}.csv?${qs}` }, label))));
}
async function loadData() {
  renderExports();
  const health = await api("/api/health");
  const entries = Object.entries(health.collectors);
  mount("#collectors", entries.length ? entries.map(([name, st]) => h("div", { class: "collector" },
    h("div", {}, h("span", { class: `dot${st.ok ? " on" : ""}` }), h("strong", {}, name)),
    h("div", { class: "muted" }, `${st.message || ""} · ${timeAgo(st.updated)}`))) : h("div", { class: "empty" }, "No collectors running (demo or read-only mode)."));
}
$("#export-start").addEventListener("change", renderExports);
$("#export-end").addEventListener("change", renderExports);
$("#export-end").value = localDay();
$("#export-start").value = localDay(new Date(Date.now() - 29 * 86400000));

// ---------------------------------------------------------------- refresh
const loaders = { overview: loadOverview, devices: loadDevices, domains: loadDomains, traffic: loadTraffic, alerts: loadAlerts, queries: loadQueries, data: loadData };
async function refresh() {
  try {
    await loaders[state.tab]();
  } catch (err) {
    console.error(err);
  }
}
setInterval(() => {
  if (document.hidden || !$("#drawer").hidden) return;
  if (state.tab === "queries" && !$("#query-live").checked) return;
  if (["overview", "devices", "queries", "alerts"].includes(state.tab)) refresh();
}, 15000);
window.addEventListener("resize", () => { if (state.tab === "overview" || state.tab === "traffic") refresh(); });

window.addEventListener("hashchange", () => {
  const tab = location.hash.slice(1);
  if (loaders[tab] && tab !== state.tab) showTab(tab);
});
const initial = location.hash.slice(1);
showTab(loaders[initial] ? initial : "overview");
