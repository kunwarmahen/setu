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

async function api(path, payload) {
  let res;
  const init = { headers: { Authorization: `Bearer ${token}` }, cache: "no-store" };
  if (payload !== undefined) {
    init.method = "POST";
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(payload);
  }
  try {
    res = await fetch(path, init);
  } catch (_) {
    // the request never left: Setu stopped, or something in the browser
    // (an ad or privacy blocker) refused it
    throw new Error("the browser couldn't reach Setu. Is setu serve still running? " +
                    "An ad blocker can also stop this page's requests.");
  }
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

// Cards are redrawn only when what they show changed: a name half typed,
// a level half picked, must survive the next refresh.
const drawn = {};
function changed(what, data) {
  const key = JSON.stringify(data);
  if (drawn[what] === key) return false;
  drawn[what] = key;
  return true;
}

function levelPicker(c, current) {
  return h("select", { "aria-label": `${c.name}'s access level` },
    c.levels.map((lv) => {
      const opt = h("option", { value: lv.name }, lv.label);
      if (lv.name === current) opt.selected = true;
      return opt;
    }));
}

function drawConnections(rows, names, cards) {
  if (!changed("connections", [rows, Object.keys(cards)])) return;
  const box = document.getElementById("connections");
  document.getElementById("n-connections").textContent = rows.length ? `${rows.length}` : "";
  if (!rows.length) {
    box.replaceChildren(h("p.empty", {}, "None yet. Pick one below to connect."));
    return;
  }
  const open = new Set([...box.querySelectorAll("details.log[open]")]
    .map((d) => d.dataset.ref));
  box.replaceChildren(...rows.map((row) => connectionCard(row, names, open.has(row.ref),
                                                          cards[row.connector])));
}

function connectionCard(row, names, logOpen, c) {
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
  if (c) card.append(changeLevel(row, c));
  card.append(disconnectButton(row, names[row.connector] || row.connector));
  const log = h("details.log", { "data-ref": row.ref },
                h("summary", {}, "What it did"), h("div.log-body", {}));
  log.addEventListener("toggle", () => { if (log.open) drawLog(row.ref, log); });
  if (logOpen) { log.open = true; }
  card.append(log);
  return card;
}

function changeLevel(row, c) {
  const pick = levelPicker(c, row.level);
  const go = h("button.btn", { type: "button" }, "Change level");
  go.addEventListener("click", () => {
    if (pick.value === row.level) return;
    const label = c.levels.find((lv) => lv.name === pick.value).label;
    if (!confirm(`Sign in to ${c.name} again, at "${label}"? Agents get the new level ` +
                 "as soon as you finish.")) return;
    startSignIn("/api/connect", { connector: row.connector, account: row.account,
                                  level: pick.value });
  });
  return h("div.actions", {}, pick, go);
}

function disconnectButton(row, name) {
  const go = h("button.btn.danger", { type: "button" }, "Disconnect");
  go.addEventListener("click", async () => {
    const what = row.road === "browser"
      ? "This deletes its sign-in (the browser profile) here"
      : "This revokes the key at the site and deletes it here";
    if (!confirm(`Disconnect ${name} · ${row.account}? ${what}; agents lose it ` +
                 "at once.")) return;
    go.disabled = true;
    try {
      await api("/api/disconnect", { ref: row.ref });
      say(`Disconnected ${row.ref}.`);
      refresh();
    } catch (err) {
      say(`Couldn't disconnect: ${err.message}`, true);
      go.disabled = false;
    }
  });
  return go;
}

async function drawLog(ref, details) {
  const body = details.querySelector(".log-body");
  try {
    const data = await api(`/api/requests?ref=${encodeURIComponent(ref)}&limit=200`);
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
  if (!changed("available", connectors)) return;
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
    c.ready ? connectForm(c) : null);
}

function connectForm(c) {
  const account = h("input.field", { type: "text", value: "personal", maxlength: "40",
                                     "aria-label": "your name for this account" });
  const pick = levelPicker(c, c.default_level);
  const go = h("button.btn.go", { type: "button" }, "Connect");
  go.addEventListener("click", () => startSignIn("/api/connect", {
    connector: c.id, account: account.value.trim() || "personal", level: pick.value }));
  return h("div.actions", {}, h("label.small", {}, "as ", account), pick, go);
}

// -- add a site -------------------------------------------------------------------

function wireAddSite() {
  const site = document.getElementById("site-address");
  const account = document.getElementById("site-account");
  const level = document.getElementById("site-level");
  document.getElementById("site-go").addEventListener("click", () => {
    if (!site.value.trim()) { say("Type the site's address first.", true); return; }
    startSignIn("/api/add-site", { site: site.value.trim(),
                                   account: account.value.trim() || "personal",
                                   level: level.value });
  });
}

// -- a sign-in in progress ----------------------------------------------------------

let watching = null;

function say(text, bad) {
  const box = document.getElementById("signin");
  box.hidden = false;
  box.classList.toggle("bad", Boolean(bad));
  box.replaceChildren(h("p", {}, text));
}

async function startSignIn(path, payload) {
  try {
    await api(path, payload);
  } catch (err) {
    say(`Couldn't start: ${err.message}`, true);
    return;
  }
  window.scrollTo({ top: 0, behavior: "smooth" });
  watchSignIn();
}

function watchSignIn() {
  if (watching) return;
  const tick = async () => {
    let st;
    try { st = await api("/api/signin"); } catch (_) { return; }
    drawSignIn(st);
    if (!st.running && st.events.some((e) => e.event === "done")) {
      clearInterval(watching);
      watching = null;
      refresh();
    }
  };
  watching = setInterval(tick, 1500);
  tick();
}

let shownEvents = -1;

function drawSignIn(st) {
  if (st.events.length === shownEvents && st.running) return;   // nothing new
  shownEvents = st.events.length;
  const box = document.getElementById("signin");
  box.hidden = false;
  box.classList.remove("bad");
  const rows = [h("h3", {}, `Signing in: ${st.ref}`)];
  for (const e of st.events) {
    const line = describe(e, st.running);
    if (line) rows.push(line);
  }
  if (st.running) {
    const stop = h("button.btn", { type: "button" }, "Cancel");
    stop.addEventListener("click", () => api("/api/signin/cancel", {}).catch(() => {}));
    rows.push(h("div.actions", {}, stop));
  } else {
    const close = h("button.btn", { type: "button" }, "Close");
    close.addEventListener("click", () => { box.hidden = true; shownEvents = -1; });
    rows.push(h("div.actions", {}, close));
  }
  box.replaceChildren(...rows);
}

function describe(e, running) {
  switch (e.event) {
    case "started":
      return h("p.meta", {}, e.level_label ? `At "${e.level_label}".` : "Starting…");
    case "url": {
      if (!running) return null;          // a link to a sign-in that is over
      const parts = [h("a.btn.go", { href: e.url, target: "_blank",
                                     rel: "noopener noreferrer" }, "Open the sign-in page")];
      if (e.paste && running) parts.push(pasteBox());
      return h("div.actions.col", {}, parts,
        h("p.meta", {}, e.paste
          ? "Sign in there. When it ends on a page that won't load, copy that page's " +
            "address and paste it here."
          : "Sign in there; this finishes by itself when you're done."));
    }
    case "window":
      return h("p", {}, "A window opened on this computer. Sign in there, then close " +
                        "the window to finish.");
    case "link":
      if (!running) return null;
      return h("div.actions.col", {},
        h("a.btn.go", { href: e.url, target: "_blank", rel: "noopener noreferrer" },
          "Open the sign-in window"),
        h("p.meta", {}, "It works once, on the first device that opens it" +
          (e.expires_at ? `, until ${new Date(e.expires_at * 1000).toLocaleTimeString()}` : "") +
          "."));
    case "opened":
      return h("p.meta", {}, "Opened on a device.");
    case "ask":
      return running ? askBox(e.question) : null;
    case "paste_refused":
      return h("p.warn", {}, `That address didn't fit: ${e.message}`);
    case "connected":
      return h("p.ok", {}, `Connected ${e.ref}` + (e.email ? ` as ${e.email}` : "") +
                           (e.level_label ? ` — ${e.level_label}` : "") + ".");
    case "error":
      return h("p.warn", {}, e.message);
    case "cancelled":
      return h("p.meta", {}, "Cancelled. Nothing was saved.");
    default:
      return null;
  }
}

function pasteBox() {
  const field = h("input.field.wide", { type: "url", placeholder: "http://127.0.0.1:…/?code=…",
                                        "aria-label": "the address the sign-in ended on" });
  const go = h("button.btn", { type: "button" }, "Send");
  go.addEventListener("click", async () => {
    try { await api("/api/signin/paste", { address: field.value.trim() }); field.value = ""; }
    catch (err) { say(err.message, true); }
  });
  return h("div.actions", {}, field, go);
}

function askBox(question) {
  const yes = h("button.btn.go", { type: "button" }, "Yes, I signed in");
  const no = h("button.btn", { type: "button" }, "No");
  const answer = (v) => api("/api/signin/answer", { yes: v }).catch(() => {});
  yes.addEventListener("click", () => answer(true));
  no.addEventListener("click", () => answer(false));
  return h("div", {}, h("p", {}, question), h("div.actions", {}, yes, no));
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
    const cards = Object.fromEntries(ctors.connectors.map((c) => [c.id, c]));
    drawConnections(conns.connections, names, cards);
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
  wireAddSite();
  refresh();
  // a sign-in started before this page was opened (or reloaded) is shown too
  if (token) api("/api/signin").then((st) => { if (st.running) watchSignIn(); })
    .catch(() => {});
  setInterval(() => { if (!document.hidden) refresh(); }, EVERY);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); });
});
