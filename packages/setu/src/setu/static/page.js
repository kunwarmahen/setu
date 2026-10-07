// Setu's page: draws what /api says, and nothing else. Every value from the
// API goes in as text (textContent), never as markup: a connection's name is
// shown, it is never run. The key arrives after "#" in the address, is kept
// in this browser, and leaves the address bar at once.
"use strict";

const KEY = "setu.page.token";
const EVERY = 15000;

function keep(token) {
  try { localStorage.setItem(KEY, token); } catch (_) { /* private window */ }
}
function kept() {
  try { return localStorage.getItem(KEY) || ""; } catch (_) { return ""; }
}

function takeToken() {
  const hash = new URLSearchParams(location.hash.slice(1));
  const fresh = hash.get("token");
  if (fresh) {
    keep(fresh);
    history.replaceState(null, "", location.pathname + location.search);
    return fresh;
  }
  return kept();
}

let token = takeToken();

// h("div.card", {title: "x"}, child, "text") -- a small, text-only builder
function h(spec, attrs, ...kids) {
  const [tag, ...classes] = spec.split(".");
  const el = document.createElement(tag || "div");
  if (classes.length) el.className = classes.join(" ");
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v !== undefined && v !== null && v !== false) el.setAttribute(k, v);
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

class Unauthorized extends Error {}

async function api(path) {
  const res = await fetch(path, { headers: { Authorization: `Bearer ${token}` },
                                  cache: "no-store" });
  if (res.status === 401) throw new Unauthorized();
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.detail || `${res.status}`);
  return body;
}

function ago(iso) {
  if (!iso) return "never";
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return iso;
  const s = Math.max(0, (Date.now() - then) / 1000);
  if (s < 90) return "just now";
  if (s < 5400) return `${Math.round(s / 60)} minutes ago`;
  if (s < 129600) return `${Math.round(s / 3600)} hours ago`;
  if (s < 86400 * 45) return `${Math.round(s / 86400)} days ago`;
  return new Date(then).toLocaleDateString();
}

// -- the header ----------------------------------------------------------------

function drawStatus(st) {
  const facts = document.getElementById("facts");
  const lock = st.lock || {};
  const badge = lock.locked
    ? h("span.badge." + (lock.open ? "open" : "locked"), {},
        lock.open ? "locked · key held" : "locked")
    : h("span.badge", {}, "not locked");
  if (lock.locked && !lock.open) {
    badge.title = "Its sign-ins are sealed. Open it in a terminal with: setu lock unlock";
  }
  const catalog = st.catalog
    ? h("span", {}, `catalog from ${st.catalog.source}` +
        (st.catalog.issued ? `, issued ${st.catalog.issued.slice(0, 10)}` : ""))
    : h("span", {}, "no catalog kept");
  facts.replaceChildren(badge, h("span.folder", { title: "Setu's folder" }, st.folder),
                        catalog, h("span", {}, `setu ${st.version}`));

  const box = document.getElementById("problems");
  if (st.problems && st.problems.length) {
    box.replaceChildren(h("ul", {}, st.problems.map((p) => h("li", {}, p))));
    box.hidden = false;
  } else {
    box.hidden = true;
  }
}

// -- connections -----------------------------------------------------------------

function drawConnections(rows, names) {
  const box = document.getElementById("connections");
  document.getElementById("n-connections").textContent = rows.length ? `${rows.length}` : "";
  if (!rows.length) {
    box.replaceChildren(h("p.empty", {}, "None yet. Pick one below to connect."));
    return;
  }
  const open = new Set([...box.querySelectorAll("details.log[open]")]
    .map((d) => d.dataset.ref));
  box.replaceChildren(...rows.map((row) => connectionCard(row, names, open.has(row.ref))));
}

function connectionCard(row, names, logOpen) {
  const name = names[row.connector] || row.connector;
  const card = h("article.card" + (row.locked ? ".is-locked" : ""), {},
    h("div.card-head", {},
      h("h3", {}, `${name} · ${row.account}`),
      h("span.chip", { title: "what agents may do with it" }, row.level_label || row.level)),
    row.email ? h("div.who", {}, row.email) : null,
    h("div.meta", {}, `last used ${ago(row.last_used)}`,
      row.road === "browser" ? " · signed in through a browser window" : ""),
    row.health_line ? h("div.trouble", {}, row.health_line) : null,
    row.locked ? h("div.warn", {}, "Sealed: it can't be used until the folder is " +
                   "opened (setu lock unlock).") : null,
    row.installed ? null : h("div.warn", {}, `Its connector (${row.connector}) is not ` +
                             "installed here any more."),
    h("span.ref", {}, row.ref));
  const log = h("details.log", { "data-ref": row.ref },
                h("summary", {}, "What it did"), h("div.log-body", {}));
  log.addEventListener("toggle", () => { if (log.open) drawLog(row.ref, log); });
  if (logOpen) { log.open = true; }
  card.append(log);
  return card;
}

async function drawLog(ref, details) {
  const body = details.querySelector(".log-body");
  try {
    const data = await api(`/api/log?ref=${encodeURIComponent(ref)}&limit=200`);
    if (!data.entries.length) {
      body.replaceChildren(h("p.empty", {}, "No requests made for it yet."));
      return;
    }
    body.replaceChildren(...data.entries.map((e) => {
      const refused = /^(refused|failed)|^[45]\d\d$/.test(e.outcome);
      return h("div.log-row", {},
        h("span.when", { title: e.at }, e.at.replace("T", " ").slice(5, 16)),
        h("span.verb", {}, e.method),
        h("span.path", {}, e.path),
        h("span.outcome" + (refused ? ".refused" : ""), {}, e.outcome));
    }));
    if (data.total > data.entries.length) {
      body.append(h("p.empty", {}, `The newest ${data.entries.length} of ${data.total}. ` +
                    `All of them: setu log ${ref} -n ${data.total}`));
    }
  } catch (err) {
    body.replaceChildren(h("p.warn", {}, `Couldn't read it: ${err.message}`));
  }
}

// -- available -------------------------------------------------------------------

function drawAvailable(connectors) {
  const free = connectors.filter((c) => !c.connected);
  const box = document.getElementById("available");
  document.getElementById("n-available").textContent = free.length ? `${free.length}` : "";
  if (!free.length) {
    box.replaceChildren(h("p.empty", {}, connectors.length
      ? "Every installed connector is connected. Another account: setu connect ID --as NAME."
      : "No connectors installed. Try: uv pip install setu-gmail"));
    return;
  }
  box.replaceChildren(...free.map(availableCard));
}

function availableCard(c) {
  return h("article.card", {},
    h("div.card-head", {}, h("h3", {}, c.name),
      c.label ? h("span.chip", { title: "what the catalog says of it" }, c.label) : null),
    h("div.who", {}, c.summary),
    h("ul.levels", {}, c.levels.map((lv) => h("li", {},
      h("b", {}, lv.label),
      lv.name === c.default_level ? h("span.default", {}, "default") : null,
      lv.description ? ` — ${lv.description}` : ""))),
    c.yanked ? h("div.warn", {}, `Withdrawn: ${c.yanked}`) : null,
    c.contained ? h("div.contained", {}, c.contained) : null,
    c.ready ? null : h("div.warn", {}, `First it ${c.not_ready}.`),
    h("div.cmd", { title: "run this in a terminal" }, `setu connect ${c.id}`));
}

// -- the loop --------------------------------------------------------------------

async function refresh() {
  const gate = document.getElementById("gate");
  if (!token) { gate.hidden = false; return; }
  try {
    const [st, conns, ctors] = await Promise.all([
      api("/api/status"), api("/api/connections"), api("/api/connectors")]);
    gate.hidden = true;
    const names = Object.fromEntries(ctors.connectors.map((c) => [c.id, c.name]));
    drawStatus(st);
    drawConnections(conns.connections, names);
    drawAvailable(ctors.connectors);
    document.getElementById("updated").textContent =
      `Updated ${new Date().toLocaleTimeString()}`;
  } catch (err) {
    if (err instanceof Unauthorized) { gate.hidden = false; return; }
    document.getElementById("updated").textContent = `Couldn't reach Setu: ${err.message}`;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  if (window.top !== window.self) document.body.classList.add("embedded");
  refresh();
  setInterval(() => { if (!document.hidden) refresh(); }, EVERY);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); });
});
