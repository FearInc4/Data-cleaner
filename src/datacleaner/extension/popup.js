// Popup for the Data Cleaner extension.
//
// There is no background script: everything happens while the popup is open.
// The pairing (your Data Cleaner address + a revocable pairing code) is kept in
// extension storage. Personal details are fetched for one form at a time, go
// straight into that page, and are never stored by the extension.

import { fillPage } from "./fill.js";

const $ = (selector) => document.querySelector(selector);
const store = chrome.storage.local;
const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

class ApiError extends Error {
  constructor(message, { unpaired = false } = {}) {
    super(message);
    this.unpaired = unpaired;
  }
}

export function hostMatches(host, domains) {
  host = (host || "").toLowerCase();
  return domains.some((d) => host === d || host.endsWith("." + d));
}

export function normaliseBase(text) {
  let value = (text || "").trim();
  if (!/^https?:\/\//i.test(value)) value = "https://" + value;
  const url = new URL(value);
  return { base: url.origin, insecure: url.protocol !== "https:" && !LOCAL_HOSTS.has(url.hostname) };
}

// Permission patterns match any port, so "http://localhost/*" covers http://localhost:25326.
const originPattern = (base) => {
  const url = new URL(base);
  return `${url.protocol}//${url.hostname}/*`;
};

async function getPairing() {
  const { base, token } = await store.get(["base", "token"]);
  return base && token ? { base, token } : null;
}

async function api(path, { method = "GET", body } = {}) {
  const pairing = await getPairing();
  if (!pairing) throw new ApiError("Not paired yet.", { unpaired: true });
  let resp;
  try {
    resp = await fetch(pairing.base + path, {
      method,
      credentials: "omit", // the pairing code is the only credential; never the app's cookies
      cache: "no-store",
      headers: {
        Authorization: `Bearer ${pairing.token}`,
        Accept: "application/json",
        ...(body ? { "Content-Type": "application/json" } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new ApiError(`Can't reach ${pairing.base}. Is Data Cleaner running?`);
  }
  let data = null;
  try {
    data = await resp.json();
  } catch {
    // not JSON (e.g. a proxy error page)
  }
  if (resp.status === 401) throw new ApiError((data && data.detail) || "Pair the extension again.", { unpaired: true });
  if (!resp.ok) throw new ApiError((data && data.detail) || `Data Cleaner returned HTTP ${resp.status}.`);
  return data;
}

function say(text, kind = "") {
  const el = $("#message");
  el.textContent = text;
  el.className = "message" + (kind ? " " + kind : "");
  el.hidden = !text;
}

function show(view) {
  $("#pair-view").hidden = view !== "pair";
  $("#main-view").hidden = view !== "main";
}

async function currentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab || null;
}

// --- actions (exported for tests) ---------------------------------------------

export async function pair(baseText, token) {
  const { base, insecure } = normaliseBase(baseText);
  if (!token.startsWith("dcx_")) throw new ApiError("That doesn't look like a pairing code. They start with dcx_.");
  await store.set({ base, token });
  try {
    const who = await api("/api/ext/whoami");
    return { who, insecure };
  } catch (err) {
    await store.remove(["base", "token"]);
    throw err;
  }
}

export async function unpair() {
  const pairing = await getPairing();
  await store.remove(["base", "token"]);
  if (pairing) {
    try {
      await chrome.permissions.remove({ origins: [originPattern(pairing.base)] });
    } catch {
      // already gone
    }
  }
}

export async function fillTab(tabId, taskId) {
  const data = await api(`/api/ext/tasks/${taskId}/fill`);
  const [injection] = await chrome.scripting.executeScript({
    target: { tabId },
    func: fillPage,
    args: [data.values, data.patterns, data.domains],
  });
  return injection.result;
}

export async function markSubmitted(taskId, note) {
  return api(`/api/ext/tasks/${taskId}/submitted`, { method: "POST", body: { note: note || "" } });
}

// --- rendering ------------------------------------------------------------------

async function render() {
  const pairing = await getPairing();
  if (!pairing) {
    show("pair");
    return;
  }
  show("main");
  let data;
  try {
    data = await api("/api/ext/tasks");
  } catch (err) {
    if (err.unpaired) {
      await store.remove(["base", "token"]);
      show("pair");
    }
    say(err.message, "error");
    return;
  }
  $("#who").textContent = new URL(pairing.base).host;

  const tab = await currentTab();
  let tabHost = "";
  try {
    tabHost = tab && tab.url ? new URL(tab.url).hostname : "";
  } catch {
    tabHost = "";
  }
  const here = tabHost ? data.tasks.find((t) => hostMatches(tabHost, t.domains)) : null;
  renderHere(here, tab);

  const list = $("#tasks");
  list.replaceChildren();
  for (const task of data.tasks) {
    if (here && task.id === here.id) continue;
    const li = document.createElement("li");
    const label = document.createElement("div");
    const name = document.createElement("span");
    name.className = "name";
    name.textContent = task.broker;
    const who = document.createElement("small");
    who.textContent = task.status === "needs_user_action" ? `${task.profile} · check or resubmit` : task.profile;
    label.append(name, who);
    const open = document.createElement("button");
    open.type = "button";
    open.textContent = "Open form";
    open.addEventListener("click", async () => {
      if (!/^https?:\/\//i.test(task.url)) return;
      await chrome.tabs.create({ url: task.url });
      window.close();
    });
    li.append(label, open);
    list.append(li);
  }
  $("#empty").hidden = data.tasks.length > 0;
}

function renderHere(task, tab) {
  const box = $("#here");
  box.hidden = !task;
  if (!task) return;
  $("#here-broker").textContent = `${task.broker} opt-out`;
  $("#here-profile").textContent = `For ${task.profile}`;
  const steps = $("#here-steps");
  steps.replaceChildren(...(task.steps || []).map((s) => {
    const li = document.createElement("li");
    li.textContent = s;
    return li;
  }));
  steps.hidden = !(task.steps || []).length;

  const fill = $("#fill");
  fill.onclick = async () => {
    fill.disabled = true;
    try {
      const result = await fillTab(tab.id, task.id);
      if (result && result.ok) {
        say(result.filled
          ? `Filled ${result.filled} field${result.filled === 1 ? "" : "s"}. Check them, solve any CAPTCHA, press Submit on the page, then come back and choose "I submitted it".`
          : "No fields recognised. If the site asks you to search first, find your listing and try again.", result.filled ? "ok" : "");
      } else if (result && result.reason === "insecure") {
        say("This page isn't HTTPS, so your details weren't filled in.", "error");
      } else {
        say("This page isn't on the broker's own website, so your details weren't filled in.", "error");
      }
    } catch (err) {
      say(err.message || "Couldn't fill this page.", "error");
    } finally {
      fill.disabled = false;
    }
  };

  const done = $("#submitted");
  done.onclick = async () => {
    done.disabled = true;
    try {
      const res = await markSubmitted(task.id, $("#note").value.trim());
      const when = res.next_action_at ? new Date(res.next_action_at + "Z").toLocaleDateString() : null;
      say(when ? `Recorded. Data Cleaner will follow up from ${when} if the listing isn't gone.` : "Recorded.", "ok");
      await render();
    } catch (err) {
      say(err.message, "error");
    } finally {
      done.disabled = false;
    }
  };
}

function wire() {
  $("#pair-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    say("");
    let parsed;
    try {
      parsed = normaliseBase($("#base").value);
    } catch {
      say("Enter the address you open Data Cleaner at, e.g. http://localhost:25326", "error");
      return;
    }
    // Ask before anything else is awaited: the browser only shows the prompt straight after a click.
    const granted = await chrome.permissions.request({ origins: [originPattern(parsed.base)] });
    if (!granted) {
      say("The extension needs permission to talk to your Data Cleaner address.", "error");
      return;
    }
    try {
      const { who, insecure } = await pair($("#base").value, $("#token").value.trim());
      $("#token").value = "";
      say(`Paired as ${who.user}.` + (insecure ? " This address isn't HTTPS: only use it over a private network such as Tailscale." : ""),
        insecure ? "error" : "ok");
      await render();
    } catch (err) {
      say(err.message, "error");
    }
  });
  $("#unpair").addEventListener("click", async () => {
    await unpair();
    say("Unpaired. Remove the pairing in Data Cleaner too (Account & security).");
    show("pair");
  });
}

window.DataCleaner = { pair, unpair, fillTab, markSubmitted, render, hostMatches, normaliseBase };

wire();
render();
