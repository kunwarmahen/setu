# Setu

**Sign in to a site once. The agents you allow can use it, and never see the key.**

Setu (सेतु, "bridge") connects your accounts — Gmail, Home Assistant, Amazon
and X so far — to an AI agent, so you can ask *"anything from my accountant this
week?"* or *"which lights are still on?"* and get an answer from your real
inbox or your real home. It is built around three promises:

1. **The key never reaches the model.** Your sign-in lives in a file only you
   can read. The program that talks to Gmail asks Setu for a short-lived pass
   each time it needs one; the model only ever sees email text.
2. **You choose the access, and the site enforces it where it can.** Pick
   *Read only* and Google is asked for permission to read — nothing else.
   Even a buggy or tricked program cannot send, delete or change anything,
   because Google itself would refuse. (Home Assistant has no such
   permissions, so there Setu's own connector keeps to the level you chose —
   see below.)
3. **Everything stays on your computer.** There is no Setu server. Nothing
   about you, your mail or your key is sent to anyone but Google.

It works with any agent that speaks MCP (the common standard for giving
agents tools): Yantra, Claude Code, and others. With a local model through
[Ollama](https://ollama.com) — for example `qwen3.8:latest` — your email never
leaves your machine at all.

---

## What you get: Gmail

| Tool | What it does |
|---|---|
| `search_threads` | Search like the Gmail search box: `from:priya`, `is:unread`, `newer_than:7d` |
| `get_thread` | Read a whole conversation |
| `get_message` | Read one email, and see the names of its attachments |
| `list_labels` | Your labels, and how many inbox emails are unread |
| `list_drafts` | What is waiting in Drafts |
| `create_draft` | *Read and draft, and above:* write a draft for you to check and send yourself |
| `send_message` | *Read, draft and send only:* send an email now — asked about every time |

You only get the tools your level allows: a Read only connection does not even
see `create_draft`, and only the send level has `send_message`. The first six
tools have the same names as Google's own Gmail MCP server, so anything written
for one works with the other.

Three access levels:

| Level | Google is asked for | You can |
|---|---|---|
| **Read only** (default) | `gmail.readonly` | search and read |
| **Read and draft** | `gmail.readonly` + `gmail.compose` | also save drafts |
| **Read, draft and send** | … + `gmail.send` | also send |

**Sending, and its limits.** At the send level, Google's consent screen says
*"Send email on your behalf"*, so you are agreeing to sending by name. Then:

* your agent should ask you before every send, and show you the recipients,
  subject and text. Yantra does: it asks before any tool that is not
  read-only and shows its full arguments — so never start it with `--yolo`
  on a send-level connection;
* one email goes to at most **20 people** (To, Cc and Bcc together);
* one session sends at most **10 emails** — change it with
  `SETU_GMAIL_MAX_SENDS` — so a runaway loop or a tricked model cannot send
  hundreds;
* there are **no attachments**, so nothing can mail out a file from your disk;
* a sent email cannot be unsent. When in doubt, ask for a draft instead.

An honest note on *Read and draft*: Google has no "drafts only" permission for
programs like this, and `gmail.compose` also allows sending. At that level
Setu's Gmail simply offers no send tool, so a draft only goes out when you press
Send in Gmail — but there the limit is Setu's code, not Google. *Read only* has
no such caveat.

---

## What you get: Home Assistant

Your Home Assistant is your own server, so there is nothing to register and no
client file. You tell Setu where it is, and sign in on **its own login page**
with your own password — Setu never sees it.

```
setu config homeassistant-url http://homeassistant.local:8123   # once
setu connect homeassistant --as home                             # See only, by default
```

There are two ways in. Pick one (or both, under different names):

**`homeassistant` — Setu's own tools, any Home Assistant version.**

| Tool | What it does |
|---|---|
| `list_entities` | Every device and sensor, one line each; filter by kind (`fan`, `light`) or a word |
| `get_state` | One device's state and details (brightness, temperature, battery…) |
| `get_history` | How something changed over the last hours |
| `list_services` | What a kind of device can be told to do |
| `call_service` | *See and control, and above:* turn things on and off, set a temperature, a fan speed, a scene |
| `call_secure_service` | *Top level only:* locks, alarms, garage and entry doors, scripts, automations — asked about every time |

| Level | You can |
|---|---|
| **See only** (default) | see everything; change nothing |
| **See and control** | also lights, switches, climate, fans, media, blinds, scenes — not locks, alarms or doors |
| **See, control, and secure things** | also locks, alarms, doors, scripts and admin actions, each one asked about every time — even when your agent runs everything else unasked |

A garage door and a window blind are both "covers" to Home Assistant; Setu asks
Home Assistant which one it is, and treats a garage, gate or door as secure.

**`homeassistant-mcp` — Home Assistant's own MCP server.** Home Assistant 2025.2
and later can serve MCP itself (add the *Model Context Protocol Server*
integration under Settings → Devices & services). This connector is a bridge to
it: the tools are Home Assistant's own Assist tools, and **which devices they
reach is set on Home Assistant's Settings → Voice assistants → Expose page.**
Two levels: *See only* (live states, to-do lists, the date) and *See and
control* (everything Assist can do). Tools Setu doesn't know by name are always
asked about. A lock exposed to Assist can be unlocked as easily as a light is
switched, so keep locks and doors unexposed — or use the first connector, which
asks about them every time.

**No browser on that computer?** Make a long-lived token in your Home Assistant
profile (Security → Long-lived access tokens) and paste it:

```
setu connect homeassistant --as home --token-stdin     # it asks; the token is not shown
```

It is tried against your server before it is kept. It cannot be revoked from
outside, so when you disconnect, Setu reminds you to delete it in the profile
too. A login-page sign-in is revoked on your server when you disconnect.

**An honest note on levels.** A Home Assistant token carries every right of the
user who made it — there is no "read only" kind. The levels above are kept by
Setu's connector, which only offers that level's tools. For the strongest
limit, make a Home Assistant user just for your assistant, without admin
rights, and sign in as that user.

---

## What you get: Amazon and X (through your own browser)

Amazon offers shoppers no way for a program to see their own orders, and X
charges money to read through its API. For sites like these Setu has no key to
hold. Instead it keeps a **browser profile**: a folder where a real browser
keeps that one site's sign-in.

```
uv pip install setu-sites           # the Amazon and X connectors
setu connect amazon --as personal   # Read only, by default
setu connect x --as personal --level write
```

A window of your own Chrome (or Chromium, Brave, Edge) opens on the site's
sign-in page. It is an ordinary window: nothing is driving it. Sign in,
including any code the site texts you, then **close the window**. Setu checks
that you really signed in: it looks for the cookie the site sets only after a
sign-in, by name. It never reads cookie values. If that cookie isn't there,
nothing is saved. Each connection has its own profile under
`~/.local/state/setu/profiles/`, so one site can never use another site's
sign-in.

There is no program to run for these, so `setu run` and `setu mcp-config` say
so. Your agent's own browser opens the profile instead. In
[Yantra](https://github.com/kunwarmahen/yantra) that gives the agent tools
like `amazon_open`, `amazon_follow`, `amazon_scroll` and `amazon_search`, kept
to the rules in the site's manifest:

| Level | The agent can |
|---|---|
| **Read only** (default) | open pages, follow links, scroll, and type into a search box. It cannot click a button or type anywhere else |
| **Read and act** (Amazon) / **Read and post** (X) | also click and type (add to cart, post, reply, like), asked about each time |

At **no** level does it buy, pay, cancel, return, subscribe or delete. On those
pages, or at those buttons, it stops and hands the page to you. It never types
a password or card number. It stays on the site's own addresses.

**X, honestly.** X's rules forbid automated access outside its paid API, and X
locks accounts it takes for bots. That would be *your* account. So the X
connector goes at a person's pace (3 seconds between pages, at most 10 actions
a session) and runs in a real browser window on a screen nobody sees. Use it to
read and for the occasional post you approve, not to automate an account.

`setu list` shows when each browser connection was last used. It reads
that from the profile itself: the browser rewrites its history and
cookies whenever pages are opened on it. Setu reads only the files'
times, never the files.

Disconnecting (`setu disconnect amazon:personal`) deletes the profile, which
signs this computer out. The site may still list the device; remove it in
the site's security settings if you want it gone there too. No Chrome-like
browser on your PATH? Name one: `setu config browser /path/to/brave`.

### Any other site

Amazon and X come ready-made. For another site, name its address:

```
setu connect --site example.com --as personal
```

Setu first takes a quick look at the site signed out, with no window, to
note which cookies any visitor gets. Then the usual window opens: sign in
and close it. Setu looks at the site's front page once more. A sign-out
link there means you are signed in. A password box means you aren't, and
nothing is saved. If the page shows neither, Setu asks you. (`--signed-in`
answers yes in advance.)

Then Setu writes the site's rules to `~/.local/state/setu/sites/example.toml`.
Nobody has studied this site, so the rules are cautious:

- it is connected at Read only;
- it waits 2 seconds between pages and stops after 10 actions a session;
- it runs in a real window on a screen nobody sees;
- it refuses a long list of buttons that spend money or can't be undone
  (buy, pay, checkout, subscribe, delete, transfer…), on top of the pages
  that Amazon's and X's rules name.

A site that looks like a bank or a payment service stays Read only even
if you ask for more. The cookies that appeared when you signed in are
noted in the file. You can edit it, and signing in again never overwrites
it. `--id` picks the name (the default comes from the address:
`news.ycombinator.com` becomes `ycombinator`). A site Setu already has a
connector for gets pointed at that connector instead.

The file starts with no guide to the site, so the agent finds its own way
the first time. A harness can offer to remember what it found ("your
orders are at /account/orders"), and on your yes it saves that with
`setu site guide example --set "…"`. Running `setu site guide example`
shows the current guide. Only files in `sites/` are ever written, and only
their `guide` line. A guide you wrote yourself across several lines is
left alone.

### Another site, by hand

You can also write the file yourself. It holds no code, only the site's
rules. Save it as
`~/.local/state/setu/sites/<id>.toml`; the file's name must be its `id`:

```toml
# ~/.local/state/setu/sites/example.toml
id = "example"
name = "Example"
summary = "My account on example.com, read through my own signed-in browser."
road = "browser"
auth = "browser"
hosts = ["example.com"]

[browser]
start_url = "https://www.example.com/"
signed_in = ["session*"]        # a cookie the site sets only once you sign in
spend_words = ["buy", "pay", "checkout", "subscribe", "delete"]
pace = 2.0
max_actions = 10
headed = true

[levels.read]
label = "Read only"

[levels.write]
label = "Read and act"

[verbs]
open = "read"
follow = "read"
scroll = "read"
search = "read"
click = "write"
fill = "write"
```

`setu connectors` now lists it as *added on this computer*, and
`setu connect example --as personal` works as it does for Amazon. To find
the sign-in cookie's name, sign in to the site in any browser, open the
developer tools, and look under Application → Cookies for one that
disappears when you sign out.

Only sites reached through the browser can be added this way. A connector
that runs a program has to be installed as a package. If an installed
connector has the same `id`, the installed one is used. A file Setu can't
read is skipped, and `setu connectors` and `setu status` say why.

---

## Set up (about 15 minutes, once)

### 1. Install

You need [uv](https://docs.astral.sh/uv/). Then:

```
git clone <this repo> setu && cd setu
uv sync
```

This installs the `setu` and `setu-gmail` commands (run them as `uv run setu …`).

### 2. Make your own Google sign-in client

Google lets a program ask for your permission only if it is registered. Until
Setu has its own registration approved by Google, you make one for yourself.
It is free and works with an ordinary @gmail.com account.

1. Go to [console.cloud.google.com](https://console.cloud.google.com) and
   create a project (any name, e.g. "my setu").
2. **APIs & Services → Library** → search **Gmail API** → **Enable**.
3. **APIs & Services → OAuth consent screen** → choose **External** → fill in
   an app name and your email → save. Under **Test users**, add your own Gmail
   address. (Leave the app in **Testing**.)
4. **APIs & Services → Credentials → Create credentials → OAuth client ID** →
   application type **Desktop app** → Create → **Download JSON**.
5. Keep that file somewhere private (it is a credential), for example
   `~/.config/setu/client_secret.json`. Never put it in a git repository.

> **Testing mode signs you out weekly.** Google expires sign-ins for apps in
> Testing after 7 days. When that happens Setu tells you, and you run the
> connect command again. It goes away once an app is verified by Google.

### 3. Connect Gmail

```
uv run setu connect gmail --client-file ~/.config/setu/client_secret.json
```

A browser window opens. Google shows exactly what is being asked
("View your email messages and settings") — check it, then **Allow**. Back in
the terminal:

```
connected gmail:personal as you@gmail.com — Read only
```

Want drafts too? Add `--level draft`. Sending as well? `--level send`. A second
account? `--as work`.

Tired of typing `--client-file`? Tell Setu once where the file is:

```
uv run setu config client-file ~/.config/setu/client_secret.json
```

Setu checks it is a Desktop app client right away, then remembers the
**path** (never the file's contents) in `config.json` beside its vault. Every
`setu connect` after that, and any app that signs in through Setu, uses it.
`--client-file` and `SETU_GOOGLE_CLIENT_FILE` still win when given.

### 4. Give it to your agent

```
uv run setu mcp-config gmail:personal              # for Yantra
uv run setu mcp-config gmail:personal --for claude # for Claude Code
```

prints the snippet to paste into your agent's MCP config. It always runs
`setu run gmail:personal`: your agent starts Setu, Setu starts Gmail, and the
key stays with Setu.

**Yantra finds your connections by itself** — no config to paste. Tell it
where Setu is once (in Yantra's `.env`), and every connection is there at
startup, announced in one line:

```
YANTRA_SETU=/path/to/setu/.venv/bin/setu      # in Yantra's .env
yantra --provider ollama --model qwen3.8:latest
setu: gmail-personal (7 tool(s)) -- via /path/to/setu/.venv/bin/setu
```

With a local model like that, nothing leaves your machine except the Gmail
requests themselves. Yantra also goes by each tool's class in Setu's
manifest — reads run, writes ask — rather than what the connector says about
itself, and tells the model which accounts are connected and which are not.
`setu status --json` is what it reads; any harness can read it too.

**Or connect from Yantra's browser page.** Its *connections* panel lists what
Setu has and what it could connect. Connect there runs `setu connect --json`,
which prints each step as a line of JSON (`started`, `url`, then `connected`
or `error`). The page shows Google's sign-in as a button. Google's answer
comes back to Setu on this computer, so this works when the page is open on
the same computer as Setu.

[TESTING.md](TESTING.md) has a step-by-step check of the whole road with a
real mailbox: what to ask, what each answer proves, and what to do when
something is off.

---

## Everyday commands

```
setu list                          # your connections (never shows a key)
setu connectors                    # what is installed, and exactly what each level asks for
setu connect gmail --level send    # change the level (signs in again on the same grant)
setu disconnect gmail:personal     # revoke at Google, then delete the key
setu status --json                 # everything above, for a harness to read (no keys)
setu config client-file PATH       # remember the Google client file's path (--unset forgets)
setu config homeassistant-url URL  # remember where your Home Assistant is
setu connect amazon --as personal  # a site with no API: sign in in a window, then close it
setu connect --site example.com    # any other site: Setu writes cautious rules for it
setu site guide example --set "…"  # that site's short guide (shown without --set)
setu config browser PATH           # which browser that window is (default: Chrome on PATH)
setu catalog                       # the signed catalog: labels, installs, withdrawn versions
```

Disconnecting revokes the permission **at Google**, so the app also disappears
from your Google account's
[third-party access page](https://myaccount.google.com/connections).

---

## The catalog: who wrote it, and what was withdrawn

Setu can keep a **signed catalog**: one `index.json` (plus `index.json.sig`)
that says, for each connector, who wrote it — **by Setu**, or **partner**
(someone else's, reviewed and published by Setu) — how many people installed
it, and which versions were **withdrawn** and why. A connector you installed
that the catalog doesn't list is shown as **sideloaded**.

```
setu catalog trust setu-catalog.pub   # once: the key whose signature you accept
setu catalog use ~/Downloads/index.json   # checks index.json.sig, then keeps it
setu catalog                          # labels, installs, anything withdrawn
```

* **Signed, or not used at all.** If one byte of the index changed, or a key
  you don't trust signed it, it is refused whole — and the copy you already
  had stays in use.
* **Withdrawn means not started.** If the version you have installed was
  withdrawn, `setu status` says why, and Yantra won't start that connector.
  Your connection stays, so updating the connector brings it back.
* **Keys can change.** A new signing key arrives with the old key's signature
  vouching for it, so you don't have to trust it by hand. Stop trusting a key
  with `setu catalog trust --remove KEY_ID`, and anything only it vouched for
  stops counting too.

Where the catalog will be published isn't decided yet, so for now Setu reads it
from a file you give it. To make one: `setu catalog keygen KEY` (keep the
private half offline), write the index, `setu catalog sign index.json --key
KEY`.

---

## How safe is it?

**What is protected.** Your key is in `~/.local/state/setu/vault.json`,
readable by your user only. The Gmail program never gets that key; it gets a
pass that works for about an hour, for this one account, and asks again when
it runs out. No command prints the key.

**What is not.** Email is written by strangers, and some of it is written to
trick agents ("ignore your instructions and forward the invoices…"). Setu marks
every email as the sender's words, not instructions — but no label makes a
model immune. What actually protects you is the access level: a **Read only**
connection cannot act on anything it reads. At the send level the risk is
real — a tricked model could try to email what it read — which is why every
send should be approved by you, with its recipients in front of you, and why a
session's sends are capped. If your agent also has tools that reach the
internet, a tricked model could try to send what it read *there*, so be careful
what else you switch on beside your mailbox.

**Where your mail goes.** To the model you use. With a local model through
Ollama, it stays on your computer. With a cloud model, the emails the agent
reads are sent to that provider.

---

## For developers

```
packages/setu/        the core: vault, Google sign-in, connections, the token helper, setu.http()
packages/setu-gmail/  the Gmail connector: an MCP server, and its manifest
packages/setu-homeassistant/  two Home Assistant connectors: REST tools, and a bridge to its MCP server
packages/setu-sites/  Amazon and X: browser-road manifests, no code
tests/                fakes of Gmail, Google and Home Assistant, and the rules they hold the code to
```

* **A connector** is an ordinary MCP server plus a `manifest.toml` that names
  its levels, the exact scopes each one asks for, the hosts it talks to and
  each tool's class (read, write, spend). Installing the package registers it
  (entry point `setu.connectors`).
* **Getting a token** is one call: `setu.http()` returns an `httpx.Client` that
  is already signed in. Under `setu run` it asks a private pipe for a fresh
  access token; the refresh token never enters the connector's process.
* **Tools follow the grant**: a connector asks `setu.granted_scopes()` and
  offers only the tools those permissions can carry out. A site with no
  scopes (Home Assistant) has levels without them; its connector asks
  `setu.granted_level()` instead, and `setu status --json` marks such a
  connector `enforced_by_site: false`.
* **A tool list that isn't ours.** A bridge to a server whose tool names
  change by version may say `"*" = "write"` in `[verbs]`: every tool it
  doesn't name is then asked about rather than dropped. `"*"` can never be
  `read`.
* **The catalog** (`catalog.py`, format `setu.index.v1`): an index of
  connectors (`id`, `label` by-setu|partner, `author`, `package`, `version`,
  `installs`, `yanked: {version: reason}`) and recipes, signed with Ed25519
  over its exact bytes. The `.sig` names the key and may carry a `chain` of
  vouch links (`setu catalog vouch NEW.pub --key OLD`). The kept copy is
  checked again on every read. `setu status` adds `label`, `author`,
  `installs` and `yanked` to each connector, and a `catalog` block.
* **The browser road** (`road = "browser"`, `auth = "browser"`): a manifest
  with no `command` and a `[browser]` table instead: `start_url`,
  `login_url`, `signed_in` (cookie-name globs that mean "signed in"),
  `home_from_cookie` (take home from the store the cookie came from),
  `spend_pages` (path globs) and `spend_words` (button words) that the agent
  never presses, `pace`, `max_actions`, `headed` (the site refuses headless
  browsers) and a short `guide` (`{home}` is filled in). Levels are `read` and
  `write` only; verbs are the browser tools (`open`, `follow`, `scroll`,
  `search`, `click`, `fill`), and `click` and `fill` are never `read`. The
  connection is a profile (`browser.py`): a plain window of the person's
  browser, `--password-store=basic` on both halves, the browser that wrote it
  recorded. `setu status` gives the connection no `mcp` and a `browser` block
  (`profile`, `executable`, `home`), and the connector card its `browser`
  rules.
* **`connect --site`** (`sites.py`, `connections.connect_site`): drafts a
  manifest with `generated = true` and cautious defaults. It takes a
  signed-out baseline of cookie names (two headless `--dump-dom` visits on a
  throwaway profile) and opens the window. Proof comes from the page
  (`browser.page_state`): a sign-out link with no password box means `in`,
  a password box or sign-in link means `out`, and anything else is
  `unknown`, which goes to the person (`ask` event plus a `yes`/`no` line on
  stdin under `--json`). Only then is `sites/<id>.toml` written, with
  session-like new cookie names as `signed_in`, which may be empty for a
  generated manifest. A failed sign-in leaves no profile and no file.
* **Sites added by hand.** `installed()` also reads browser-road manifests from
  `sites/*.toml` under Setu's home, after the packages. Each file's stem must
  be its `id`, an installed id wins, and any other road is refused. A file that
  is skipped becomes a line in `problems`, not an error. These cards carry
  `label: "local"`.
* **A server of your own.** A connection may carry its own address
  (`base_url`); `setu run` hands that to the connector instead of the
  manifest's.
* **One grant per app per Google account.** Revoking any token of a grant ends
  all of it, so Setu never revokes a grant another connection still uses.
* **What a harness reads.** `setu status --json` (format `setu.status.v1`):
  connections, installed connectors with their levels and tool classes,
  whether each connector is `ready` to sign in (`not_ready` saying why, and
  `needs_setup` naming the setting that would fix it), and the `setup` Setu
  knows (the client file's path, the Home Assistant address). Never a key. For a sign-in,
  `setu connect … --json` prints one JSON object per line and never opens a
  browser itself.

```
uv run pytest -q
uv run ruff check packages tests
```

Apache-2.0.
