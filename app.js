/* The Finance System's web page.
 *
 * In plain words: this page reads the summary the MacBook pinned up (webpage-summary.json) and the forms
 * (webpage-forms.json) from Alvin's private mailbox on GitHub, and posts what he types back to the same
 * mailbox as notes (GitHub "issues"). It never works anything out that the MacBook has not worked out
 * first; the one sum it does is the sweep, from figures the summary gives it.
 *
 * Everything typed is saved on this device first, in its outbox, and only then sent. If sending fails
 * (no signal, the key has expired) it stays in the outbox and is tried again the next time the page is
 * unlocked or comes back online. Each note carries a serial number made here, so if one is ever sent
 * twice the MacBook keeps it once.
 *
 * The lock (added 2026-09-13 at Alvin's request): a six-digit passcode opens the page. The key, the last
 * summary and the unsent entries are kept on the device only encrypted (AES-GCM, with a key derived from
 * the passcode by PBKDF2-SHA-256, 600,000 rounds), so without the passcode they cannot be read, even from
 * the browser's storage. The page locks when reloaded, and after a set time away or idle. Wrong guesses
 * bring growing waits. A forgotten passcode means erasing this device's copy and pasting the key again.
 *
 * All text from the summary is shown as text, never as HTML. The page talks to api.github.com and
 * nowhere else (the Content-Security-Policy in index.html enforces it).
 *
 * Source: webpage/ in the Finance System repository; tools/finance-system-webpage.py deploy copies it to
 * the page's own public repository, which holds code only. Written 2026-09-13 under D-2026-09-13-01;
 * redesigned the same night (layout, passcode).
 */
"use strict";

// GitHub's address. Only a test changes it, through config.json, to a stand-in on
// the same machine; the published config.json never names one.
const api = () => (CFG && CFG.api) || "https://api.github.com";
const MARKER = "finance-system-web-entry";
const P = "finance-system.";
const STALE_HOURS = 2;
const ITERATIONS = 600000;
const PIN_LEN = 6;
// What only an unlocked page may hold. Everything else (the forms, the settings) is not private.
const SECRET = new Set(["token", "snap", "outbox", "sent", "waiting", "expiry", "schema", "drafts"]);
// Where the page kept these before the lock existed, read once to move them into the vault.
const OLD = { token: "token", snap: "snapshot", outbox: "outbox", sent: "sent", waiting: "waiting", expiry: "expiry", schema: "schema" };

let CFG = null, SNAP = null, SCHEMA = null;
let NET = "unknown";          // "ok" | "offline" | "key" | "error"
let NET_MSG = "", NET_DETAIL = "";
let TAB = "today";
let VIEW = null;               // null, or { type: "form" | "settings" | "questions", ... }
let MEM = null, VKEY = null, VMETA = null;   // the unlocked vault: its contents, its key, its salt
let GEN = 0;                   // bumped by every lock, passcode change and erase: a save or a fetch begun before is dropped

/* ---------- storage ---------- */

function rawGet(k) { try { return localStorage.getItem(P + k); } catch (e) { return null; } }
function rawSet(k, v) { try { localStorage.setItem(P + k, v); } catch (e) { /* storage blocked */ } }
function rawDrop(k) { try { localStorage.removeItem(P + k); } catch (e) { /* ignore */ } }
function load(k, d) {
  if (SECRET.has(k)) return MEM && MEM[k] !== undefined ? MEM[k] : d;
  const v = rawGet(k);
  try { return v === null ? d : JSON.parse(v); } catch (e) { return d; }
}
function save(k, v) {
  if (SECRET.has(k)) { if (MEM) { MEM[k] = v; persist(); } return; }
  rawSet(k, JSON.stringify(v));
}
function token() { return load("token", ""); }

/* ---------- the lock: encryption ---------- */

const enc = new TextEncoder(), dec = new TextDecoder();
function b64(u8) { let s = ""; for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000)); return btoa(s); }
function unb64(s) { const b = atob(s), u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; }
function rand(n) { const a = new Uint8Array(n); crypto.getRandomValues(a); return a; }

async function deriveKey(pin, salt, iterations) {
  const base = await crypto.subtle.importKey("raw", enc.encode(pin), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations, hash: "SHA-256" }, base,
                                 { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
async function seal(key, meta, text) {
  const iv = rand(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(text)));
  return JSON.stringify({ v: 1, salt: meta.salt, iter: meta.iter, iv: b64(iv), ct: b64(ct) });
}
let persisting = Promise.resolve();
function persist() {
  if (!MEM || !VKEY) return;
  const key = VKEY, meta = VMETA, text = JSON.stringify(MEM), gen = GEN;
  persisting = persisting.then(() => seal(key, meta, text)).then(v => {
    if (gen !== GEN) return;                       // a passcode change or an erase came after
    try { localStorage.setItem(P + "vault", v); }
    catch (e) { toast("This device would not save. Keep the page open until what you typed has sent."); }
  }).catch(() => { /* kept in memory */ });
  return persisting;
}
async function unlockWith(pin) {
  if (!hasVault()) return false;
  const v = JSON.parse(rawGet("vault"));
  const salt = unb64(v.salt);
  const key = await deriveKey(pin, salt, v.iter);
  let text;
  try { text = dec.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(v.iv) }, key, unb64(v.ct))); }
  catch (e) { return false; }
  MEM = JSON.parse(text); VKEY = key; VMETA = { salt: v.salt, iter: v.iter };
  return true;
}
async function setPasscode(pin) {
  GEN++; await persisting;                          // nothing saved under the old passcode may land after
  const salt = rand(16);
  VKEY = await deriveKey(pin, salt, ITERATIONS);
  VMETA = { salt: b64(salt), iter: ITERATIONS };
  MEM = MEM || {};
  rawSet("vault", await seal(VKEY, VMETA, JSON.stringify(MEM)));
  for (const k of Object.values(OLD)) rawDrop(k);   // nothing private left in the clear
}
function hasVault() { return !!rawGet("vault"); }
function eraseDevice() {
  GEN++;
  MEM = null; VKEY = null; VMETA = null; SNAP = null; SCHEMA = null;
  persisting.then(() => dropAll());
  dropAll();
}
// Everything this page ever kept on the device, including the names used before 2026-09-13's renames.
function dropAll() {
  try {
    for (const k of Object.keys(localStorage)) if (k.startsWith(P) || k.startsWith("desk.") || k.startsWith("finance-desk.")) localStorage.removeItem(k);
  } catch (e) { /* ignore */ }
}
// A tab left open on the old page, or its copy kept for offline use, can write the old names in the clear
// again. At every start and every unlock, fold anything unsent into the vault and remove the old names.
function sweepOld() {
  let found = false;
  try {
    const oldOut = JSON.parse(rawGet(OLD.outbox) || "null");
    if (MEM && Array.isArray(oldOut) && oldOut.length) {
      const have = new Set((MEM.outbox || []).map(e => e.id));
      MEM.outbox = (MEM.outbox || []).concat(oldOut.filter(e => e && e.id && !have.has(e.id)));
      persist();
    }
    for (const k of Object.values(OLD)) if (rawGet(k) !== null) { rawDrop(k); found = true; }
    for (const k of Object.keys(localStorage)) if (k.startsWith("desk.") || k.startsWith("finance-desk.")) { localStorage.removeItem(k); found = true; }
  } catch (e) { /* ignore */ }
  return found;
}

/* Wrong guesses: four are free, then 30 seconds, doubling, at most 15 minutes. */
function lockout() { return load("lockout", { fails: 0, until: 0 }); }
function failWait(fails) { return fails < 5 ? 0 : Math.min(15 * 60, 30 * Math.pow(2, fails - 5)) * 1000; }

/* ---------- small helpers ---------- */

function h(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [a, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (a === "class") e.className = v;
    else if (a === "text") e.textContent = v;
    else if (a.startsWith("on")) e.addEventListener(a.slice(2), v);
    else if (v === true) e.setAttribute(a, "");
    else e.setAttribute(a, String(v));
  }
  for (const k of kids.flat()) {
    if (k === null || k === undefined || k === false) continue;
    e.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
  return e;
}
function clear(e) { while (e.firstChild) e.removeChild(e.firstChild); return e; }

/* Icons, drawn as lines in the manner of Apple's symbols. */
const ICONS = {
  today: [["rect", { x: 3.5, y: 5, width: 17, height: 15.5, rx: 3.5 }], ["path", { d: "M3.5 10h17M8 3v4M16 3v4" }], ["circle", { cx: 12, cy: 15, r: 1.4, fill: "currentColor", stroke: "none" }]],
  plus: [["path", { d: "M12 5v14M5 12h14", "stroke-width": 2.4 }]],
  plusc: [["circle", { cx: 12, cy: 12, r: 10, fill: "currentColor", stroke: "none" }], ["path", { d: "M12 7.5v9M7.5 12h9", stroke: "#fff", "stroke-width": 2.2 }]],
  numbers: [["path", { d: "M5 20V13M10 20V8M15 20v-9M20 20V4" , "stroke-width": 2.2 }]],
  gear: [["path", { d: "M18.96 10.15 L21.46 10.38 L21.46 13.62 L18.96 13.85 L18.23 15.61 L19.84 17.54 L17.54 19.84 L15.61 18.23 L13.85 18.96 L13.62 21.46 L10.38 21.46 L10.15 18.96 L8.39 18.23 L6.46 19.84 L4.16 17.54 L5.77 15.61 L5.04 13.85 L2.54 13.62 L2.54 10.38 L5.04 10.15 L5.77 8.39 L4.16 6.46 L6.46 4.16 L8.39 5.77 L10.15 5.04 L10.38 2.54 L13.62 2.54 L13.85 5.04 L15.61 5.77 L17.54 4.16 L19.84 6.46 L18.23 8.39Z" }], ["circle", { cx: 12, cy: 12, r: 3 }]],
  chevR: [["path", { d: "M9 5l7 7-7 7", "stroke-width": 2.2 }]],
  chevL: [["path", { d: "M15 5l-7 7 7 7", "stroke-width": 2.4 }]],
  check: [["path", { d: "M5 12.5l4.5 4.5L19 7.5", "stroke-width": 2.8 }]],
  lock: [["rect", { x: 5, y: 10.5, width: 14, height: 10, rx: 2.5 }], ["path", { d: "M8 10.5V8a4 4 0 0 1 8 0v2.5" }]],
  work: [["rect", { x: 3.5, y: 7.5, width: 17, height: 12, rx: 3 }], ["path", { d: "M9 7.5V6a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v1.5M3.5 13h17" }]],
  card: [["rect", { x: 3, y: 5.5, width: 18, height: 13, rx: 3 }], ["path", { d: "M3 10h18M7 15h4" }]],
  bank: [["path", { d: "M3.5 9.5L12 4.5l8.5 5M5 20h14M6.5 11v6.5M10.2 11v6.5M13.8 11v6.5M17.5 11v6.5" }]],
  bubble: [["path", { d: "M4.5 6.5a2.5 2.5 0 0 1 2.5-2.5h10a2.5 2.5 0 0 1 2.5 2.5v7a2.5 2.5 0 0 1-2.5 2.5H11l-4.5 3.5V16H7a2.5 2.5 0 0 1-2.5-2.5z" }]],
  pencil: [["path", { d: "M5 19l1-4.2L15.8 5a1.8 1.8 0 0 1 2.6 0l.6.6a1.8 1.8 0 0 1 0 2.6L9.2 18l-4.2 1zM13.5 7.3l3.2 3.2" }]],
  warn: [["path", { d: "M12 4.5l8.5 15h-17z" }], ["path", { d: "M12 10v4.2", "stroke-width": 2.2 }], ["circle", { cx: 12, cy: 17, r: 1.1, fill: "currentColor", stroke: "none" }]],
  tray: [["path", { d: "M4 13.5l2.2-7.2A2 2 0 0 1 8.1 5h7.8a2 2 0 0 1 1.9 1.3L20 13.5V18a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2zM4 13.5h4.5l1 2h5l1-2H20" }]],
  moon: [["path", { d: "M19.5 14.5A7.5 7.5 0 0 1 9.5 4.5a7.5 7.5 0 1 0 10 10z" }]],
  del: [["path", { d: "M9 6h10a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H9l-6-6z" }], ["path", { d: "M12 9.5l5 5M17 9.5l-5 5" }]],
  receipt: [["path", { d: "M6 3.5h12v17l-2.2-1.4-2 1.4-1.8-1.4-1.8 1.4-2-1.4L6 20.5z" }], ["path", { d: "M9 8h6M9 11.5h6M9 15h3.5" }]],
  income: [["path", { d: "M12 4v10M7.5 9.5L12 14l4.5-4.5" , "stroke-width": 2 }], ["path", { d: "M4.5 15v2.5a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2V15" }]],
  vault: [["rect", { x: 3.5, y: 5, width: 17, height: 14, rx: 3 }], ["circle", { cx: 12, cy: 12, r: 3.2 }], ["path", { d: "M12 8.8v1M12 14.2v1M8.8 12h1M14.2 12h1" }]],
  gauge: [["path", { d: "M4.5 16a7.5 7.5 0 1 1 15 0" }], ["path", { d: "M12 16l3.5-4.5", "stroke-width": 2.2 }], ["circle", { cx: 12, cy: 16, r: 1.2, fill: "currentColor", stroke: "none" }]],
  heart: [["path", { d: "M12 19.5s-7-4.3-7-9.6A3.9 3.9 0 0 1 12 7.6a3.9 3.9 0 0 1 7 2.3c0 5.3-7 9.6-7 9.6z" }]],
  search: [["circle", { cx: 10.5, cy: 10.5, r: 6 }], ["path", { d: "M15 15l4.5 4.5", "stroke-width": 2.2 }]],
  trend: [["path", { d: "M4 17l5-5 3.5 3.5L20 8" , "stroke-width": 2.2 }], ["path", { d: "M15 8h5v5" , "stroke-width": 2.2 }]],
  updown: [["path", { d: "M8.5 9.5L12 6l3.5 3.5M8.5 14.5L12 18l3.5-3.5", "stroke-width": 2 }]],
};
function icon(name) {
  const NS = "http://www.w3.org/2000/svg";
  const s = document.createElementNS(NS, "svg");
  s.setAttribute("viewBox", "0 0 24 24"); s.setAttribute("fill", "none"); s.setAttribute("stroke", "currentColor");
  s.setAttribute("stroke-width", "1.8"); s.setAttribute("stroke-linecap", "round"); s.setAttribute("stroke-linejoin", "round");
  s.setAttribute("aria-hidden", "true");
  for (const [tag, attrs] of ICONS[name] || []) {
    const e = document.createElementNS(NS, tag);
    for (const [a, v] of Object.entries(attrs)) e.setAttribute(a, String(v));
    s.append(e);
  }
  return s;
}

function money(v) {
  const n = Number(String(v).replace(/[$,\s]/g, ""));
  return Number.isFinite(n) ? n : null;
}
function fmt$(v) {
  const n = money(v);
  return n === null ? "" : (n < 0 ? "−$" : "$") + Math.abs(n).toLocaleString("en-CA", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}
function fmtWhole$(v) { const f = fmt$(v); return f.replace(/\.00$/, ""); }
function pad(n) { return String(n).padStart(2, "0"); }
function isoOf(d) { return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`; }
function todayISO() { return isoOf(new Date()); }
function typedAt() {
  const d = new Date(), off = -d.getTimezoneOffset(), s = off >= 0 ? "+" : "-", a = Math.abs(off);
  return `${todayISO()}T${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}${s}${pad(Math.floor(a / 60))}:${pad(a % 60)}`;
}
function dateOf(iso) {
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(iso || "");
  return m ? new Date(+m[1], +m[2] - 1, +m[3]) : null;
}
function dayName(iso, opts) { const d = dateOf(iso); return d ? d.toLocaleDateString("en-CA", opts) : (iso || ""); }
function shortDate(iso) {
  const d = dateOf(iso);
  const opts = { weekday: "short", day: "numeric", month: "short" };
  if (d && d.getFullYear() !== new Date().getFullYear()) { delete opts.weekday; opts.year = "numeric"; }
  return dayName(iso, opts).replace(/^(\w+),/, "$1");
}
// A date inside a sentence reads as "Jan 1, 2026"; in a list it is "Thu Jan 1".
function prettyDates(text) { return String(text || "").replace(/\b(\d{4}-\d{2}-\d{2})\b/g, (m, iso) => dayName(iso, { day: "numeric", month: "short", year: "numeric" })); }
function daysFrom(iso) {
  const d = dateOf(iso); if (!d) return null;
  const t = new Date(); t.setHours(0, 0, 0, 0);
  return Math.round((d - t) / 864e5);
}
function rel(iso) {
  const n = daysFrom(iso);
  if (n === null) return "";
  if (n === 0) return "today";
  if (n === 1) return "tomorrow";
  if (n === -1) return "yesterday";
  return n > 0 ? `in ${n} days` : `${-n} days ago`;
}
function ago(iso, short) {
  if (!iso) return "never";
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return iso;
  const m = Math.round((Date.now() - t) / 60000);
  if (m < 1) return "just now";
  if (m < 60) return short ? `${m} min ago` : `${m} minute${m === 1 ? "" : "s"} ago`;
  const hrs = Math.round(m / 60);
  if (hrs < 36) return short ? `${hrs} h ago` : `${hrs} hour${hrs === 1 ? "" : "s"} ago`;
  const d = Math.round(hrs / 24);
  return short ? `${d} d ago` : `${d} day${d === 1 ? "" : "s"} ago`;
}
function when(iso) {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return iso || "";
  return new Date(t).toLocaleString("en-CA", { weekday: "short", month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }).replace(/,/g, "");
}
function newId() {
  const abc = "abcdefghjkmnpqrstuvwxyz23456789", a = rand(14);
  return Array.from(a, x => abc[x % abc.length]).join("");
}
function device() { return /iPhone|iPad|iPod/.test(navigator.userAgent) ? "iPhone" : "MacBook"; }
function toast(msg) {
  const t = document.getElementById("toast");
  t.textContent = msg; t.hidden = false;
  t.classList.remove("show"); void t.offsetWidth; t.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { t.hidden = true; }, 3200);
}
function hoursSince(iso) { const t = Date.parse(iso || ""); return Number.isFinite(t) ? (Date.now() - t) / 3.6e6 : 999; }
function plural(n, one, many) { return `${n} ${n === 1 ? one : (many || one + "s")}`; }

/* A sheet rising from the bottom: a question with its answers, in place of the browser's own boxes. */
function sheet(title, msg, actions, closeLabel) {
  const scrim = h("div", { class: "scrim", role: "dialog", "aria-modal": "true", "aria-label": title });
  const close = () => {
    document.removeEventListener("keydown", onKey);
    if (!motionOK()) { scrim.remove(); return; }
    scrim.classList.add("leaving"); setTimeout(() => scrim.remove(), 200);
  };
  const onKey = ev => { if (ev.key === "Escape") close(); };
  const box = h("div", { class: "sheet" }, h("div", { class: "grab" }), h("h3", { text: title }), msg ? h("p", { class: "msg", text: msg }) : null);
  const acts = h("div", { class: "acts" });
  for (const a of actions) acts.append(h("button", { class: "btn wide " + (a.kind || "gray"), type: "button", onclick: () => { close(); if (a.run) a.run(); } }, a.label));
  acts.append(h("button", { class: "btn wide gray", type: "button", onclick: close }, closeLabel || "Cancel"));
  box.append(acts);
  scrim.append(box);
  scrim.addEventListener("click", ev => { if (ev.target === scrim) close(); });
  document.addEventListener("keydown", onKey);
  document.body.append(scrim);
  const first = acts.querySelector("button"); if (first) first.focus();
  box.close = close;
  return box;
}

/* ---------- talking to GitHub ---------- */

class PageError extends Error { constructor(kind, msg, detail) { super(msg); this.kind = kind; this.detail = detail || ""; } }

async function gh(path, opts = {}) {
  if (!token()) throw new PageError("key", "No key on this device yet. Add it in Settings.");
  if (!CFG || !CFG.github_owner || !CFG.mailbox_repository) throw new PageError("error", "The page does not know which mailbox to use.");
  let r;
  try {
    r = await fetch(api() + path, {
      method: opts.method || "GET", cache: "no-store", body: opts.body,
      headers: Object.assign({ "Authorization": "Bearer " + token(), "X-GitHub-Api-Version": "2022-11-28",
                               "Accept": opts.accept || "application/vnd.github+json" },
                             opts.body ? { "Content-Type": "application/json" } : {})
    });
  } catch (e) {
    throw new PageError("offline", "No connection. Your entries are saved on this device and will send later.");
  }
  const exp = r.headers.get("github-authentication-token-expiration");
  if (exp) save("expiry", exp);
  if (r.status === 401) throw new PageError("key", "GitHub did not accept this device's key. It may have been deleted or pasted wrongly: make a new one and paste it in Settings.");
  if (r.status === 403 || r.status === 404) throw new PageError("key", "This device's key cannot open your mailbox. It may be missing a permission.",
    "When the key was made, it needed two permissions on your mailbox: to read its files, and to read and write its entries. The web page's instructions on your MacBook show where.");
  if (!r.ok) throw new PageError("error", "GitHub is not answering just now. Try again in a few minutes.");
  return r;
}
const repo = () => `/repos/${encodeURIComponent(CFG.github_owner)}/${encodeURIComponent(CFG.mailbox_repository)}`;

async function refresh() {
  const gen = GEN;
  try {
    const raw = "application/vnd.github.raw+json";
    const [s, f] = await Promise.all([
      gh(repo() + "/contents/webpage-summary.json", { accept: raw }).then(r => r.json()),
      gh(repo() + "/contents/webpage-forms.json", { accept: raw }).then(r => r.json()).catch(() => SCHEMA)
    ]);
    const issues = await gh(repo() + "/issues?state=open&per_page=100").then(r => r.json());
    if (gen !== GEN || !MEM) return;                // locked while the answer was on its way
    if (s && s.format === "finance-system-webpage-summary") { SNAP = s; save("snap", s); }
    if (f && f.forms) { SCHEMA = f; save("schema", f); }
    const waiting = issues.filter(i => !i.pull_request && typeof i.body === "string" && i.body.indexOf(MARKER) >= 0).length;
    save("waiting", waiting);
    NET = "ok"; NET_MSG = "";
  } catch (e) {
    if (gen !== GEN) return;
    NET = e.kind || "error"; NET_MSG = e.message; NET_DETAIL = e.detail || "";
  }
  if (MEM) render();
}

let flushing = false;
async function flush() {
  if (flushing || !MEM) return;
  flushing = true;
  try {
    let box = load("outbox", []);
    while (box.length && MEM) {
      const entry = box[0];
      try {
        const r = await gh(repo() + "/issues", { method: "POST", body: JSON.stringify({ title: "Finance System web entry, waiting for the MacBook to collect it", body: JSON.stringify(entry) }) });
        const j = await r.json();
        const sent = load("sent", []);
        sent.unshift({ entry, number: j.number, sent_at: new Date().toISOString() });
        save("sent", sent.slice(0, 60));
        box = load("outbox", []).filter(x => x.id !== entry.id);
        save("outbox", box);
        save("waiting", load("waiting", 0) + 1);
      } catch (e) {
        NET = e.kind || "error"; NET_MSG = e.message; NET_DETAIL = e.detail || ""; NET_DETAIL = e.detail || "";
        break;
      }
    }
  } finally {
    flushing = false;
    if (MEM) render();
  }
}

function submit(kind, fields, corrects) {
  const entry = { format: MARKER, id: newId(), kind, typed_at: typedAt(), device: device(), fields };
  if (corrects) entry.corrects = corrects;
  const box = load("outbox", []);
  box.push(entry);
  save("outbox", box);
  toast(navigator.onLine ? "Saved. Sending…" : "Saved on this device. It sends when you are back online.");
  flush();
  return entry;
}

/* ---------- what each kind of entry is called, and looks like ---------- */

// How often each kind is used decides where it sits on Add: the everyday ones as tiles, the rest in lists.
const KINDS = {
  shift: { name: "Shift", desc: "A shift, a list, a stipend", icon: "work", color: "blue", group: "often",
           help: "Fill in what you know. Hours left blank are taken from what your phone measured." },
  expense: { name: "Paid it myself", desc: "Cash, your own card, a split bill", icon: "receipt", color: "green", group: "often" },
  income: { name: "Income received", desc: "Pay, OHIP, a stipend, a refund", icon: "income", color: "purple", group: "often" },
  bankvisit: { name: "Month-end banking", desc: "Pay yourself, CRA and the cards online", icon: "bank", color: "orange", group: "often",
               help: "Once a month, in online banking: pay yourself, CRA and the cards. Tick each payment as you make it, type the chequing balance you then see, and a suggested amount to send to Questrade is worked out." },
  registered: { name: "TFSA, RRSP or FHSA", desc: "Money in or out", icon: "vault", color: "blue", group: "sometimes" },
  reading: { name: "A reading", desc: "Odometer, an account's value", icon: "gauge", color: "gray", group: "sometimes" },
  card: { name: "A credit card change", desc: "Opened, bonus, fee, closed", icon: "card", color: "gray", group: "sometimes" },
  life: { name: "A change in life or plans", desc: "A move, the wedding, insurance, salary", icon: "heart", color: "red", group: "sometimes" },
  answer: { name: "Answer a question", desc: "", icon: "bubble", color: "purple", group: "any", help: "" },
  note: { name: "Note", desc: "Anything else for the record", icon: "pencil", color: "gray", group: "any" },
};
function kindOf(k) { return KINDS[k] || { name: k, desc: "", icon: "pencil", color: "gray" }; }
function formsList() { return (SCHEMA && SCHEMA.forms) || []; }
// The expense ledger's questions are all one shape: "2026-02-03 - Uber - $18.40 has no receipt. ..."
const RECEIPT = /^(\d{4}-\d{2}-\d{2}) - (.+) - (-?\$[\d,]+(?:\.\d\d)?)(:| has no receipt)/;
function receiptOf(q) {
  const m = RECEIPT.exec(q.text || "");
  if (!m) return null;
  return { date: m[1], what: m[2], amount: m[3], problem: m[4] === ":" ? "No card or bank charge found for it" : "No receipt filed" };
}
function openQuestions() {
  return ((SNAP && SNAP.questions) || []).filter(q => !q.answered)
    .sort((a, b) => (a.due || "9999").localeCompare(b.due || "9999"));
}

/* ---------- the frame: top bar, tabs, sync ---------- */

function renderChrome() {
  const app = document.getElementById("app");
  document.body.classList.toggle("in-form", !!(VIEW && VIEW.type === "form"));
  document.body.classList.toggle("in-settings", !!(VIEW && VIEW.type === "settings"));
  const here = VIEW && VIEW.type === "settings" ? "" : VIEW && VIEW.type === "form" ? (VIEW.from === "today" ? "today" : "add") : TAB;
  // A small count on a tab: entries not yet sent on Add, things that need him on Today.
  const needs = ((SNAP && SNAP.held) || []).length + (NET === "key" ? 1 : 0), unsent = load("outbox", []).length;
  for (const b of document.querySelectorAll("#seg button, #tabbar button")) {
    const old = b.querySelector(".tab-badge"); if (old) old.remove();
    const n = b.dataset.tab === "today" ? needs : b.dataset.tab === "add" ? unsent : 0;
    if (n) b.append(h("span", { class: "tab-badge", "aria-label": `${n} waiting`, text: String(n) }));
  }
  for (const b of document.querySelectorAll("#seg button, #tabbar button")) {
    if (b.dataset.tab === here) b.setAttribute("aria-current", "page"); else b.removeAttribute("aria-current");
  }
  const left = document.getElementById("bar-left");
  const title = document.getElementById("bar-title");
  const oldBack = left.querySelector(".back"); if (oldBack) oldBack.remove();
  if (VIEW && VIEW.type !== "settings") {
    const backTo = VIEW.type === "form" ? (VIEW.from === "today" ? "Today" : "Add") : ({ today: "Today", add: "Add", numbers: "Summary" })[TAB];
    left.prepend(h("button", { class: "back", type: "button", onclick: () => closeView() }, icon("chevL"), backTo));
    title.textContent = "";
  } else {
    title.textContent = VIEW && VIEW.type === "settings" ? "Settings" : ({ today: "Today", add: "Add", numbers: "Summary" })[TAB];
  }
  const s = document.getElementById("sync"), st = document.getElementById("sync-text");
  s.className = "sync";
  const outbox = load("outbox", []).length;
  let text;
  if (NET === "key" || NET === "error") { s.classList.add("bad"); text = "Needs attention"; }
  else if (SNAP && SNAP.machine && SNAP.machine.state === "stuck") { s.classList.add("bad"); text = "Books not updating"; }
  else if (NET === "offline") { s.classList.add("stale"); text = outbox ? `Offline · ${outbox} to send` : "Offline"; }
  else if (!SNAP) { s.classList.add("stale"); text = "No summary yet"; }
  else if (hoursSince(SNAP.checked_at) > STALE_HOURS) { s.classList.add("stale"); text = `MacBook asleep · ${ago(SNAP.checked_at, true)}`; }
  else if (outbox) { s.classList.add("stale"); text = `${outbox} to send`; }
  else if (SNAP.machine && SNAP.machine.state === "busy") text = "Catching up";
  else text = `Updated ${ago(SNAP.checked_at, true)}`;
  st.textContent = text;
  s.setAttribute("aria-label", "Sync: " + text + ". Open settings.");
  app.hidden = false;
}

function head(title, sub, withStatus) {
  const hd = h("div", { class: "head" }, h("h1", { text: title }), sub ? h("div", { class: "sub", text: sub }) : null);
  if (withStatus) {
    const src = document.getElementById("sync");
    const pill = h("button", { class: src.className, type: "button", "aria-label": src.getAttribute("aria-label"), onclick: () => openView({ type: "settings" }) },
      h("span", { class: "dot" }), h("span", { text: document.getElementById("sync-text").textContent }));
    hd.append(pill);
  }
  return hd;
}

function render(animate) {
  // Never draw Alvin's figures behind the lock, except while he changes the passcode from Settings.
  if (!MEM || (!document.getElementById("lock").hidden && !LOCK.mode.startsWith("change"))) return;
  renderChrome();
  const main = clear(document.getElementById("main"));
  let page;
  if (VIEW && VIEW.type === "form") page = renderForm();
  else if (VIEW && VIEW.type === "settings") page = renderSettings();
  else if (VIEW && VIEW.type === "questions") page = renderQuestions();
  else if (VIEW && VIEW.type === "trend") page = renderTrend();
  else if (TAB === "add") page = renderAdd();
  else if (TAB === "numbers") page = renderNumbers();
  else page = renderToday();
  if (VIEW && VIEW.type !== "settings") {
    const backTo = VIEW.type === "form" ? (VIEW.from === "today" ? "Today" : "Add") : ({ today: "Today", add: "Add", numbers: "Summary" })[TAB];
    page.prepend(h("button", { class: "back pageback", type: "button", onclick: () => closeView() }, icon("chevL"), backTo));
  }
  if (animate && motionOK()) { page.classList.add("enter"); page.addEventListener("animationend", () => page.classList.remove("enter"), { once: true }); }
  main.append(page);
  onScroll();
}

function go(tab) {
  if (VIEW) { try { history.back(); } catch (e) { /* ignore */ } }
  TAB = tab; VIEW = null; save("tab", tab);
  render(true); window.scrollTo(0, 0);
}
function openView(v) {
  VIEW = v;
  try { history.pushState({ view: v.type }, ""); } catch (e) { /* ignore */ }
  render(true); window.scrollTo(0, 0);
}
function closeView(fromPop) {
  if (!VIEW) return;
  const back = VIEW.type === "form" && VIEW.from === "today" ? "today" : null;
  VIEW = null;
  if (back) TAB = back;
  if (!fromPop) { try { history.back(); } catch (e) { /* ignore */ } }
  render(true); window.scrollTo(0, 0);
}
function onScroll() { document.getElementById("bar").classList.toggle("scrolled", window.scrollY > 28); }

/* ---------- Today ---------- */

function renderToday() {
  const p = h("div", { class: "page" });
  p.append(head("Today", dayName(todayISO(), { weekday: "long", day: "numeric", month: "long" }), true));
  const alerts = attention();
  if (alerts.length) p.append(h("div", { class: "section" }, alerts));
  if (!SNAP) {
    p.append(h("div", { class: "card glass" }, h("h3", { text: "Waiting for the first summary" }),
      h("p", { class: "muted", text: "The MacBook sends one within 15 minutes of being open. If it never has, its bookkeeper may be switched off: the web page's instructions on the MacBook say how to switch it on." })));
    return p;
  }
  // What needs doing first (the visit, the questions), then the calendar. On a wide screen the
  // calendar sits beside them.
  const colA = h("div", {}), colB = h("div", {});
  colA.append(h("section", { class: "section" }, h("h2", { text: "Month-end banking" }), visitCard()));
  colA.append(questionsSection());
  colB.append(upcoming());
  p.append(h("div", { class: "cols" }, colA, colB));
  return p;
}

function attention() {
  const out = [];
  const alert = (color, ic, t, d, ...acts) => h("div", { class: "alert " + color }, h("span", { class: "ico " + color }, icon(ic)),
    h("div", { class: "t", text: t }), d ? (d instanceof Node ? d : h("div", { class: "d", text: d })) : null, acts.filter(Boolean).length ? h("div", { class: "acts" }, acts) : null);
  if (NET === "key" || NET === "error") out.push(alert("red", "warn", NET === "key" ? "The key needs you" : "GitHub did not answer",
    h("div", { class: "d" }, NET_MSG + " ", NET_DETAIL ? h("details", {}, h("summary", { text: "Details" }), h("div", { text: NET_DETAIL })) : null),
    NET === "key" ? h("button", { class: "btn small tinted", type: "button", onclick: () => openView({ type: "settings" }) }, "Open Settings") : null));
  // First, what only he can put right.
  if (SNAP && SNAP.held && SNAP.held.length) {
    for (const e of SNAP.held) {
      out.push(alert("orange", "warn", "Held back: " + prettyDates(e.summary), "It was not added to your books because " + e.reason + ".",
        e.fields ? h("button", { class: "btn small tinted", type: "button", onclick: () => startCorrect(e, "today") }, "Correct it") : null,
        h("button", { class: "btn small gray", type: "button", onclick: () => withdraw(e) }, "Delete it")));
    }
  }
  const outbox = load("outbox", []);
  if (outbox.length) out.push(alert("orange", "tray", `${plural(outbox.length, "entry", "entries")} not sent yet`, "Saved on this device. They send by themselves when there is a connection.",
    h("button", { class: "btn small tinted", type: "button", onclick: () => flush() }, "Send now")));
  // Then the MacBook, in one line: asleep, or not updating, or both.
  const m = (SNAP && SNAP.machine) || {};
  const asleep = SNAP && hoursSince(SNAP.checked_at) > STALE_HOURS;
  if (m.state === "stuck" || asleep) {
    const t = m.state === "stuck" ? "Your books are not updating" : "The MacBook is asleep";
    const d = (asleep ? `These figures are from ${ago(SNAP.checked_at)}. ` : "") + "Keep sending: nothing is lost, and it is added when the MacBook catches up.";
    out.push(alert(m.state === "stuck" ? "red" : "orange", m.state === "stuck" ? "warn" : "moon", t, d,
      h("button", { class: "btn small gray", type: "button", onclick: () => openView({ type: "settings" }) }, "Details")));
  }
  return out;   // the key, then what only he can put right, then what is unsent, then the MacBook
}

function lastBusinessDay(y, m) {
  const d = new Date(y, m + 1, 0);
  while (d.getDay() === 0 || d.getDay() === 6) d.setDate(d.getDate() - 1);
  return d;
}
function visitDate(pd) {
  const t = new Date(), lbd = lastBusinessDay(t.getFullYear(), t.getMonth());
  t.setHours(0, 0, 0, 0);
  return t <= lbd ? isoOf(lbd) : (pd.next_visit || isoOf(lastBusinessDay(t.getFullYear(), t.getMonth() + 1)));
}

function visitCard() {
  const pd = SNAP.payday;
  const c = h("section", { class: "visit glass", "aria-label": "Month-end banking" });
  if (!pd) { c.append(h("p", { class: "muted", text: "Nothing planned yet." })); return c; }
  const iso = visitDate(pd);
  const known = pd.items.filter(i => money(i.amount)), unknown = pd.items.length - known.length;
  const est = i => (i.basis || "").startsWith("estimate");
  const anyEst = known.some(est);
  const total = known.reduce((a, i) => a + money(i.amount), 0);
  c.append(h("div", { class: "top" },
    h("div", {}, h("div", { class: "when", text: dayName(iso, { weekday: "long", day: "numeric", month: "long" }) }), h("div", { class: "in", text: rel(iso) })),
    known.length ? h("div", { class: "total" },
      anyEst ? h("div", { class: "est" }, h("span", { class: "v num", text: "about " + fmtWhole$(Math.round(total)) }), h("span", { class: "chip orange", text: "estimate" }))
             : h("div", { class: "v num", text: fmt$(total) }),
      h("div", { class: "l", text: unknown ? `to pay, plus ${plural(unknown, "card balance")}` : "to pay" })) : null));
  const items = h("div", { class: "items" });
  for (const it of pd.items) {
    items.append(h("div", { class: "item" }, h("span", { class: "what" }, it.what, est(it) ? h("span", { class: "chip orange", text: "estimate" }) : null),
      it.amount ? h("span", { class: "amt", text: est(it) ? "about " + fmtWhole$(Math.round(money(it.amount))) : fmt$(it.amount) }) : h("span", { class: "onscreen", text: "full balance" })));
  }
  c.append(items);
  const why = pd.items.filter(est).map(i => i.basis.replace(/^estimate:\s*/, ""));
  if (why.length) c.append(h("p", { class: "small muted", text: `The amounts marked estimate are ${[...new Set(why)][0]}.` }));
  c.append(h("button", { class: "btn primary wide", type: "button", onclick: () => startForm("bankvisit", null, "today") }, "Log month-end banking"));
  return c;
}

function upcoming() {
  const s = h("section", { class: "section" }, h("h2", { text: "Coming up" }));
  const due = (SNAP.due || []);
  if (!due.length) { s.append(h("div", { class: "card glass" }, h("p", { class: "muted", text: "Nothing in the next six weeks." }))); return s; }
  const ul = h("div", { class: "list glass" });
  // A calendar line is "paid at the bank visit" only if a visit item has its date and, to the dollar, its amount.
  const visitItems = ((SNAP.payday && SNAP.payday.items) || []).filter(i => i.due && money(i.amount) !== null);
  const paidAtVisit = d => visitItems.some(i => i.due === d.date && money(d.amount) !== null && Math.abs(money(i.amount) - money(d.amount)) < 1);
  for (const d of due) {
    const dt = dateOf(d.date);
    const leaf = h("span", { class: "day", "aria-hidden": "true" },
      h("span", { class: "wd", text: dt ? dt.toLocaleDateString("en-CA", { weekday: "short" }) : "" }),
      h("span", { class: "dn", text: dt ? String(dt.getDate()) : "" }),
      h("span", { class: "mo", text: dt ? dt.toLocaleDateString("en-CA", { month: "short" }) : "" }));
    if (paidAtVisit(d)) continue;           // it is in the bank visit above, with its amount
    const cut = d.what.search(/[:;]|\.\s/);
    const title = cut > 0 ? d.what.slice(0, cut) : d.what;
    let rest = cut > 0 ? d.what.slice(cut + 1).trim() : "";
    // A bill paid through another charge (the tax through the Chexy charge on the 20th) reads as covered,
    // and is struck through only once that charge's day has passed.
    const via = /^(already )?paid (by|through) the Chexy charge on the (\d{1,2})(st|nd|rd|th)/i.exec(rest);
    let paid = false, viaNote = "";
    if (via) {
      const dd = dateOf(d.date), chargeDay = dd ? new Date(dd.getFullYear(), dd.getMonth(), +via[3]) : null;
      const t = new Date(); t.setHours(0, 0, 0, 0);
      paid = chargeDay && chargeDay <= t;
      viaNote = paid ? "paid through the Chexy charge" : `paid through the Chexy charge on ${chargeDay ? shortDate(isoOf(chargeDay)) : "the 20th"}`;
      rest = "";
    }
    const main = h("span", { class: "main" }, h("span", { class: "title clamp", text: title }),
      h("span", { class: "meta", text: rel(d.date).replace(/^./, c => c.toUpperCase()) + (viaNote ? " · " + viaNote : "") }),
      rest ? h("span", { class: "detail" }, icon("chevR"), h("span", { class: "clamp1", text: rest.replace(/^./, c => c.toUpperCase()).replace(/(^|[^$\d.,])(\d{1,3}(?:,\d{3})*\.\d{2})\b/g, "$1$$$2") })) : null);
    const est = (d.basis || "").startsWith("estimate") && !via;
    const amount = d.amount && Number(d.amount) ? h("span", { class: "amt" + (paid ? " paid" : via ? " covered" : ""), text: (est ? "about " : "") + "$" + Math.round(money(d.amount)).toLocaleString("en-CA") }) : h("span", {});
    const row = rest ? h("button", { class: "row", type: "button", "aria-expanded": "false" }, leaf, main, amount) : h("div", { class: "row" }, leaf, main, amount);
    if (rest) row.addEventListener("click", () => { const o = row.classList.toggle("open"); row.setAttribute("aria-expanded", String(o)); });
    ul.append(row);
  }
  s.append(ul);
  if (due.some(d => (d.basis || "").startsWith("estimate"))) s.append(h("p", { class: "foot", text: "Amounts are as planned in your calendar: estimates until paid." }));
  return s;
}

function receiptRow(q, from) {
  const r = receiptOf(q), dt = dateOf(r.date);
  return h("button", { class: "row", type: "button", onclick: () => startForm("answer", { question: q.id }, from) },
    h("span", { class: "day", "aria-hidden": "true" }, h("span", { class: "wd", text: dt.toLocaleDateString("en-CA", { weekday: "short" }) }),
      h("span", { class: "dn", text: String(dt.getDate()) }), h("span", { class: "mo", text: dt.toLocaleDateString("en-CA", { month: "short" }) })),
    h("span", { class: "main" }, h("span", { class: "title", text: r.what }), h("span", { class: "meta", text: r.problem })),
    h("span", { class: "amt", text: r.amount }));
}
function questionRow(q, from) {
  if (receiptOf(q)) return receiptRow(q, from);
  const n = daysFrom(q.due);
  return h("button", { class: "row plain", type: "button", onclick: () => startForm("answer", { question: q.id }, from) },
    h("span", { class: "main" }, h("span", { class: "title clamp", text: prettyDates(q.text) }),
      q.due ? h("span", { class: "meta" + (n !== null && n < 0 ? " overdue" : ""), text: (n !== null && n < 0 ? "Overdue · " : "Due ") + shortDate(q.due) }) : null),
    icon("chevR"));
}

function questionsSection() {
  const all = openQuestions(), qs = all.filter(q => !receiptOf(q)), receipts = all.length - qs.length;
  const s = h("section", { class: "section" });
  s.append(h("div", { class: "section-h" }, h("span", { text: "Questions for you" }),
    qs.length > 3 ? h("button", { class: "link", type: "button", onclick: () => openView({ type: "questions" }) }, `See all ${qs.length}`) : null));
  if (!all.length) { s.append(h("div", { class: "card glass" }, h("p", { class: "muted", text: "None waiting." }))); return s; }
  const ul = h("div", { class: "list glass" });
  for (const q of qs.slice(0, 3)) ul.append(questionRow(q, "today"));
  if (receipts) ul.append(h("button", { class: "row", type: "button", onclick: () => openView({ type: "questions", receipts: true }) },
    h("span", { class: "ico gray" }, icon("card")), h("span", { class: "main" }, h("span", { class: "title", text: `${plural(receipts, "receipt")} to explain` }),
      h("span", { class: "meta", text: "Expenses with no receipt, or a receipt with no charge" })), icon("chevR")));
  s.append(ul);
  return s;
}

function renderQuestions() {
  const all = openQuestions(), qs = all.filter(q => !receiptOf(q)), rs = all.filter(q => receiptOf(q));
  const p = h("div", { class: "page narrow" });
  p.append(head("Questions", "What the MacBook is waiting on you for, soonest first. Tap one to answer it."));
  const box = h("div", { class: "searchbox glass" }, icon("search"));
  const inp = h("input", { type: "search", placeholder: "Search questions and receipts", "aria-label": "Search questions and receipts", autocomplete: "off" });
  box.append(inp);
  p.append(box);
  const holder = h("div", { class: "page" });
  p.append(holder);
  const draw = () => {
    clear(holder);
    const t = inp.value.trim().toLowerCase();
    const match = q => !t || prettyDates(q.text).toLowerCase().includes(t);
    const q1 = qs.filter(match), r1 = rs.filter(match).sort((a, b) => receiptOf(a).date.localeCompare(receiptOf(b).date));
    if (q1.length) { const ul = h("div", { class: "list glass" }); for (const q of q1) ul.append(questionRow(q, "today")); holder.append(ul); }
    else if (t && r1.length) holder.append(h("p", { class: "foot", text: "No questions match; these receipts do." }));
    if (r1.length) {
      const ul = h("div", { class: "list glass" });
      for (const q of r1) ul.append(receiptRow(q, "today"));
      holder.append(h("details", { class: "fold", open: !!VIEW.receipts || !!t || !q1.length },
        h("summary", {}, h("span", { text: `Receipts to explain · ${r1.length}` }), h("span", { class: "link" }, h("span", { class: "when-closed", text: "Show" }), h("span", { class: "when-open", text: "Hide" }))),
        ul));
    }
    if (!q1.length && !r1.length) holder.append(h("p", { class: "foot", text: "Nothing matches." }));
  };
  inp.addEventListener("input", draw);
  draw();
  return p;
}

/* ---------- Add ---------- */

function startForm(kind, prefill, from) {
  const d = !prefill ? load("drafts", {})[kind] : null;
  openView({ type: "form", kind, corrects: "", prefill: prefill || d || null, restored: !!d, from: from || "add" });
}

function startCorrect(e, from) { openView({ type: "form", kind: e.kind, corrects: e.id, prefill: e.fields || {}, label: e.summary, from: from || "add" }); }
function withdraw(e) {
  sheet("Delete this entry?", prettyDates(e.summary || summaryOf(e)) + ". It comes out of your books; the record keeps a copy, marked as deleted.",
    [{ label: "Delete it", kind: "danger", run: () => { submit("withdraw", {}, e.id); render(); } }]);
}

function renderAdd() {
  const p = h("div", { class: "page" });
  p.append(head("Add", "Sent to your private mailbox. The MacBook files it within 15 minutes of being open.", true));
  const forms = formsList();
  if (!forms.length) { p.append(h("div", { class: "card glass" }, h("p", { class: "muted", text: "The forms have not arrived yet. They come with the first summary." }))); return p; }
  const all = openQuestions(), rc = all.filter(q => receiptOf(q)).length, qc = all.length - rc;
  const descOf = f => f.kind === "answer" ? (all.length ? [qc ? plural(qc, "question") : "", rc ? plural(rc, "receipt") : ""].filter(Boolean).join(" · ") : "None waiting") : (kindOf(f.kind).desc || f.title);
  const drafts = load("drafts", {});
  const draftTag = f => drafts[f.kind] ? h("span", { class: "chip blue", text: "draft" }) : null;
  const group = g => forms.filter(f => (kindOf(f.kind).group || "sometimes") === g);
  const tiles = h("div", { class: "tiles" });
  for (const f of group("often")) {
    const k = kindOf(f.kind);
    tiles.append(h("button", { class: "tile glass", type: "button", onclick: () => startForm(f.kind) },
      h("span", { class: "tile-top" }, h("span", { class: "ico " + k.color }, icon(k.icon)), draftTag(f)),
      h("span", {}, h("div", { class: "t", text: k.name }), h("div", { class: "d", text: descOf(f) }))));
  }
  p.append(tiles);
  const listOf = (title, g) => {
    const fs = group(g);
    if (!fs.length) return null;
    const ul = h("div", { class: "list glass" });
    for (const f of fs) {
      const k = kindOf(f.kind);
      ul.append(h("button", { class: "row", type: "button", onclick: () => startForm(f.kind) }, h("span", { class: "ico " + k.color }, icon(k.icon)),
        h("span", { class: "main" }, h("span", { class: "title", text: k.name }), h("span", { class: "meta", text: descOf(f) })),
        h("span", { class: "trail" }, draftTag(f), icon("chevR"))));
    }
    return h("section", { class: "section" }, h("h2", { text: title }), ul);
  };
  p.append(listOf("Now and then", "sometimes"));
  p.append(listOf("Questions and notes", "any"));
  p.append(recentSection());
  return p;
}

function recentSection() {
  const s = h("section", { class: "section" }, h("h2", { text: "Recent" }));
  const ul = h("div", { class: "list glass" });
  const seen = new Set();
  const row = (title, meta, chip, chipColor, onTap) => {
    const kids = [h("span", { class: "main" }, h("span", { class: "title", text: title }), meta ? h("span", { class: "meta", text: meta }) : null),
                  h("span", { class: "chip " + (chipColor || ""), text: chip })];
    return onTap ? h("button", { class: "row recent", type: "button", onclick: onTap }, kids[0], kids[1], icon("chevR")) : h("div", { class: "row plain" }, ...kids);
  };
  for (const e of load("outbox", [])) { seen.add(e.id); ul.append(row(summaryOf(e), "On this device", "Not sent", "orange")); }
  const collected = (SNAP && SNAP.recent) || [];
  const collectedIds = new Set(collected.map(r => r.id));
  for (const x of load("sent", []).slice(0, 10)) {
    if (seen.has(x.entry.id) || collectedIds.has(x.entry.id)) continue;
    seen.add(x.entry.id);
    ul.append(row(summaryOf(x.entry), "Sent " + ago(x.sent_at), "Waiting for MacBook", "blue"));
  }
  const LABEL = { current: ["Filed", "green"], held: ["Held", "red"], superseded: ["Corrected", ""], withdrawn: ["Deleted", ""], duplicate: ["Duplicate", ""] };
  for (const r of collected.slice(0, 15)) {
    if (seen.has(r.id)) continue;
    const [lab, col] = LABEL[r.status] || [r.status, ""];
    const canAct = (r.status === "current" || r.status === "held") && r.kind !== "withdraw";
    ul.append(row(prettyDates(r.summary), r.received_at ? "Received " + ago(r.received_at) : "", lab, col, canAct ? () => entryActions(r) : null));
  }
  if (!ul.firstChild) ul.append(h("div", { class: "row plain" }, h("span", { class: "muted", text: "Nothing yet. What you send appears here." })));
  s.append(ul);
  return s;
}

function entryActions(r) {
  const acts = [];
  if (r.fields) acts.push({ label: "Correct it", kind: "tinted", run: () => startCorrect(r) });
  acts.push({ label: "Delete it", kind: "danger", run: () => withdraw(r) });
  sheet(prettyDates(r.summary), "A correction replaces it. Deleting takes it out of your books. The record keeps a copy of both, marked.", acts);
}

function summaryOf(e) {
  const f = e.fields || {};
  switch (e.kind) {
    case "shift": return `Shift ${shortDate(f.date)}${f.description ? " · " + f.description : ""}`;
    case "expense": return `${f.what || "Paid it myself"} · ${fmt$(f.amount)}`;
    case "bankvisit": return `Month-end banking ${shortDate(f.date)}`;
    case "income": return `Income ${fmt$(f.amount)}`;
    case "registered": return `${fmt$(f.amount)} ${f.direction === "withdrawal" ? "out of" : "into"} ${(f.account || "").replace(/^qt-/, "").toUpperCase()}`;
    case "reading": return `Reading: ${f.value || ""}`;
    case "card": return "Card change";
    case "life": return "Change: " + (f.text || "").slice(0, 60);
    case "answer": { const q = ((SNAP && SNAP.questions) || []).find(x => x.id === f.question); return "Answer: " + (q ? q.text : "a question"); }
    case "note": return "Note: " + (f.text || "").slice(0, 80);
    case "withdraw": return "Deleting an entry";
    default: return e.kind;
  }
}

/* ---------- a form ---------- */

// How each form's fields are grouped. A field the MacBook adds later, and no group names, goes at the end.
const LAYOUT = {
  shift: [
    { h: "When", keys: [["date"], ["shift_start", "shift_end"]] },
    { h: "What", keys: [["type"], ["description"]] },
    { more: "Hours and patients", hint: "All optional", keys: [["hours", "travel_hours"], ["patients", "period"], ["site"]] },
    { more: "Pay", hint: "All optional", keys: [["amount"], ["pay_base", "pay_ffs"], ["ffs_billed", "shadow_pct"], ["pay_shadow", "pay_stipend"], ["pay_other", "expense_reimbursed"]] },
    { keys: [["note"]] },
  ],
  expense: [
    { keys: [["what"], ["amount", "date"]] },
    { keys: [["paid"]] },
    { keys: [["meal"], ["who_why"]] },
    { more: "Receipt", hint: "Optional", keys: [["receipt"]] },
  ],
  bankvisit: [
    { keys: [["date"]] },
    { h: "What you paid", foot: "Tick each one as you pay it.", keys: [["paid"]] },
    { h: "Then", keys: [["balance"]] },
    { sweep: true },
    { keys: [["sweep"]] },
    { keys: [["note"]] },
  ],
  answer: [{ keys: [["question"]] }, { keys: [["answer"]] }],
  income: [{ keys: [["payer"], ["amount", "date"]] }, { keys: [["month"], ["what"]] }, { keys: [["note"]] }],
  registered: [{ keys: [["account"], ["direction"]] }, { keys: [["amount", "date"]] }, { keys: [["note"]] }],
  reading: [{ keys: [["what"]] }, { keys: [["value", "date"]] }, { keys: [["note"]] }],
  card: [{ keys: [["card"], ["event"]] }, { keys: [["date", "amount"]] }, { keys: [["note"]] }],
  life: [{ keys: [["what"], ["date", "amount"]] }, { keys: [["text"]] }],
  note: [{ keys: [["text"]] }, { keys: [["date"]] }],
};
const LONG_TEXT = new Set(["text", "answer", "note", "who_why"]);
function monthsAround() {
  const out = [], d = new Date(); d.setDate(1); d.setMonth(d.getMonth() + 1);
  for (let i = 0; i < 15; i++) { out.push({ value: `${d.getFullYear()}-${pad(d.getMonth() + 1)}`, label: d.toLocaleDateString("en-CA", { month: "long", year: "numeric" }) }); d.setMonth(d.getMonth() - 1); }
  return out;
}
// Plainer names for a few of the Work tab's column names.
const LABELS = { description: "Which shift", pay_ffs: "Billing paid", ffs_billed: "Billing submitted", shadow_pct: "Shadow billing %", pay_shadow: "Shadow billing pay",
                 who_why: "Who was there, and why it was work", receipt: "Where the receipt photo is", balance: "Chequing balance you see now", sweep: "Sent to Questrade" };
function labelOf(fld) { return LABELS[fld.key] || fld.label.replace(/\s*\(.*?\)\s*$/, ""); }
function hintOf(fld) { const m = /\((.*)\)\s*$/.exec(fld.label); return m ? m[1] : ""; }

function renderForm() {
  const f = formsList().find(x => x.kind === VIEW.kind);
  const p = h("div", { class: "page narrow" });
  if (!f) { p.append(head("Not available", "This form has not arrived yet.")); return p; }
  const k = kindOf(f.kind);
  p.append(head(VIEW.corrects ? "Correct: " + k.name : k.name, k.help !== undefined ? k.help : f.help));
  if (VIEW.corrects) p.append(h("div", { class: "alert orange" }, h("span", { class: "ico orange" }, icon("pencil")),
    h("div", { class: "t", text: "Correcting " + (VIEW.label || "an entry") }), h("div", { class: "d", text: "The new version replaces it. The old one is kept, marked as corrected." })));
  p.append(buildForm(f));
  return p;
}

function buildForm(f) {
  const form = h("form", { novalidate: true });
  const pre = VIEW.prefill || {};
  const byKey = Object.fromEntries(f.fields.map(x => [x.key, x]));
  const inputs = {}, wraps = {};
  const errors = h("div", { class: "errors", role: "alert", hidden: true });
  form.append(errors);

  const initial = fld => pre[fld.key] !== undefined ? pre[fld.key] : (fld.type === "date" ? todayISO() : "");
  let inMore = false;
  const fieldEl = fld => {
    const id = `f-${f.kind}-${fld.key}`;
    const v = initial(fld);
    const label = h("label", { for: id }, labelOf(fld), fld.required || inMore || fld.key === "who_why" || fld.key === "balance" ? null : h("span", { class: "opt", text: "optional" }));
    const wrap = h("div", { class: "field" }, label);
    let inp;
    if (fld.type === "checklist") {
      inp = h("div", { id, class: "ticks" });
      const items = (SNAP && SNAP.payday && SNAP.payday.items) || [];
      for (const it of items) {
        const on = Array.isArray(v) && v.includes(it.id);
        const isEst = (it.basis || "").startsWith("estimate");
        const b = h("button", { class: "tick", type: "button", role: "checkbox", "aria-checked": String(on), "data-id": it.id },
          h("span", { class: "title" }, it.what, isEst ? h("span", { class: "chip orange tick-chip", text: "estimate" }) : null), h("span", { class: "amt num muted", text: it.amount ? (isEst ? "about " + fmtWhole$(Math.round(money(it.amount))) : fmt$(it.amount)) : "full balance" }), h("span", { class: "box" }, icon("check")));
        b.addEventListener("click", () => { b.setAttribute("aria-checked", String(b.getAttribute("aria-checked") !== "true")); updateSweep(form); });
        inp.append(b);
      }
      inputs[fld.key] = inp; wraps[fld.key] = inp;
      return inp;
    }
    if (fld.type === "choice" && fld.source === "questions") {
      const hidden = h("input", { type: "hidden", id, name: fld.key });
      hidden.value = v || "";
      const box = h("div", { class: "question-card glass" });
      const draw = () => {
        clear(box);
        const cur = ((SNAP && SNAP.questions) || []).find(x => x.id === hidden.value);
        const r = cur && receiptOf(cur);
        if (r) box.append(h("span", { class: "small muted", text: r.problem }), h("span", { class: "q", text: `${r.what}, ${r.amount}, on ${shortDate(r.date)}` }),
          h("span", { class: "small muted", text: "What was it, and how was it paid? If there is a receipt, say where it is." }));
        else if (cur) box.append(h("span", { class: "small muted", text: cur.due ? "Due " + shortDate(cur.due) : "Question" }), h("span", { class: "q", text: prettyDates(cur.text) }));
        else box.append(h("span", { class: "q muted", text: "Which question are you answering?" }));
        box.append(h("button", { class: "btn small tinted", type: "button", onclick: () => pickQuestion(hidden, draw) }, cur ? "Choose another" : "Choose a question"));
      };
      draw();
      inputs[fld.key] = hidden; wraps[fld.key] = box;
      const holder = h("div", {}, hidden, box);
      return holder;
    }
    const opts = fld.type === "choice" ? (fld.options || []) : fld.type === "month" ? monthsAround() : null;
    if (false) {
      // Longer answers: a list with a tick beside the chosen one, as in the iPhone's settings.
      const hidden = h("input", { type: "hidden", id, name: fld.key });
      hidden.value = v || "";
      const list = h("div", { class: "ticks", role: "radiogroup", "aria-label": fld.label });
      for (const o of opts) {
        const b = h("button", { class: "tick radio", type: "button", role: "radio", "aria-checked": String(o.value === hidden.value), "data-value": o.value },
          h("span", { class: "title", text: o.label }), h("span", {}), h("span", { class: "box" }, icon("check")));
        b.addEventListener("click", () => {
          hidden.value = o.value;
          for (const x of list.children) x.setAttribute("aria-checked", String(x === b));
          form.dispatchEvent(new Event("change"));
        });
        list.append(b);
      }
      const holder = h("div", {}, hidden, list);
      inputs[fld.key] = hidden; wraps[fld.key] = list;
      return holder;
    }
    if (opts && opts.length <= 2 && opts.every(o => o.label.length <= 16)) {
      const hidden = h("input", { type: "hidden", id, name: fld.key });
      hidden.value = v || "";
      const segs = h("div", { class: "segs", role: "radiogroup", "aria-label": fld.label });
      for (const o of opts) {
        const b = h("button", { type: "button", role: "radio", "aria-checked": String(o.value === hidden.value) }, o.label);
        b.addEventListener("click", () => {
          hidden.value = o.value;
          for (const x of segs.children) x.setAttribute("aria-checked", String(x === b));
          form.dispatchEvent(new Event("change"));
        });
        segs.append(b);
      }
      wrap.append(hidden, segs);
      inp = hidden;
    } else if (opts) {
      // A fixed set of answers: a menu, as on the iPhone. The chosen answer shows; the arrows say it opens.
      inp = h("select", { id, name: fld.key });
      inp.append(h("option", { value: "" }, fld.type === "month" ? "Choose the month…" : "Choose…"));
      for (const o of opts) inp.append(h("option", { value: o.value, selected: o.value === v }, o.label.replace(/^[a-z0-9-]+:\s*/, "")));
      inp.addEventListener("change", () => form.dispatchEvent(new Event("change")));
      wrap.classList.add("menu");
      wrap.append(h("span", { class: "menu-arrows", "aria-hidden": "true" }, icon("updown")), inp);
    } else if (LONG_TEXT.has(fld.key)) {
      inp = h("textarea", { id, name: fld.key, maxlength: 500, rows: 3, placeholder: fld.key === "answer" ? "What you know, or where to find it" : fld.key === "who_why" ? "" : hintOf(fld) });
      inp.value = v; wrap.append(inp);
      const grow = () => { inp.rows = 3; while (inp.scrollHeight > inp.clientHeight + 2 && inp.rows < 14) inp.rows += 1; };
      inp.addEventListener("input", grow); setTimeout(grow, 0);
    } else {
      const type = { date: "date", time: "time" }[fld.type] || "text";
      const isNum = fld.type === "money" || fld.type === "number";
      const listId = fld.suggest && fld.suggest.length ? id + "-list" : null;
      inp = h("input", { id, name: fld.key, type, maxlength: 500, inputmode: isNum ? "decimal" : null, autocomplete: "off",
                         list: listId, placeholder: type === "text" && fld.type !== "money" ? hintOf(fld) : null });
      if (listId) wrap.append(h("datalist", { id: listId }, fld.suggest.map(x => h("option", { value: x }))));
      inp.value = v;
      if (fld.type === "money") wrap.append(h("div", { class: "money" }, h("span", { text: "$", "aria-hidden": "true" }), inp));
      else if (fld.key === "shadow_pct") wrap.append(h("div", { class: "money" }, inp, h("span", { text: "%", "aria-hidden": "true" })));
      else if (fld.key !== "shadow_pct") wrap.append(inp);
      if (fld.key === "balance") inp.addEventListener("input", () => updateSweep(form));
      if (fld.type === "money") inp.addEventListener("blur", () => { const n = money(inp.value); if (inp.value.trim() && n !== null) inp.value = n.toLocaleString("en-CA", { minimumFractionDigits: 2, maximumFractionDigits: 2 }); });
    }
    if (fld.type === "money" && hintOf(fld)) wrap.append(h("span", { class: "small muted", text: hintOf(fld).replace(/^./, c => c.toUpperCase()) }));
    inputs[fld.key] = inp; wraps[fld.key] = wrap;
    return wrap;
  };
  const rowEls = keys => {
    const present = keys.filter(k => byKey[k]);
    if (!present.length) return null;
    if (present.length === 1) return fieldEl(byKey[present[0]]);
    return h("div", { class: "pair" }, present.map(k => fieldEl(byKey[k])));
  };

  const used = new Set();
  const layout = LAYOUT[f.kind] || [{ keys: f.fields.map(x => [x.key]) }];
  for (const g of layout) {
    if (g.sweep) { form.append(h("div", { class: "sweep glass", id: "sweep" })); continue; }
    g.keys.flat().forEach(k => used.add(k));
    inMore = !!g.more;
    const rows = g.keys.map(rowEls).filter(Boolean);
    if (!rows.length) continue;
    const isQuestion = g.keys.flat().some(k => byKey[k] && byKey[k].source === "questions");
    if (g.more) {
      const hasValue = g.keys.flat().some(k => pre[k] !== undefined && pre[k] !== "");
      form.append(h("details", { class: "more glass", open: hasValue },
        h("summary", {}, h("span", {}, g.more, " ", h("span", { class: "hint", text: g.hint || "" })), icon("chevR")),
        h("div", { class: "fields" }, rows)));
    } else {
      form.append(h("div", { class: "group" }, g.h ? h("div", { class: "gh", text: g.h }) : null,
        isQuestion ? rows : h("div", { class: "fields glass" }, rows), g.foot ? h("div", { class: "gf", text: g.foot }) : null));
    }
  }
  const rest = f.fields.filter(x => !used.has(x.key));
  if (rest.length) form.append(h("div", { class: "group" }, h("div", { class: "fields glass" }, rest.map(fieldEl))));

  // A draft: what was typed and not sent is kept, locked in the vault, until it is sent or cleared.
  const drafts = load("drafts", {});
  const collect = () => {
    const out = {};
    for (const fld of f.fields) {
      const inp = inputs[fld.key];
      if (!inp) continue;
      if (fld.type === "checklist") { const t = Array.from(inp.querySelectorAll('.tick[aria-checked="true"]')).map(x => x.dataset.id); if (t.length) out[fld.key] = t; continue; }
      const val = String(inp.value || "").trim();
      if (val && !(fld.type === "date" && val === todayISO())) out[fld.key] = val;
    }
    return out;
  };
  form._collect = collect;
  let draftTimer = null;
  const keepDraft = () => {
    if (VIEW && VIEW.corrects) return;
    clearTimeout(draftTimer);
    draftTimer = setTimeout(() => {
      const d = load("drafts", {}), c = collect();
      if (Object.keys(c).length) d[f.kind] = c; else delete d[f.kind];
      save("drafts", d);
    }, 400);
  };
  form.addEventListener("input", keepDraft);
  form.addEventListener("change", keepDraft);
  form.addEventListener("click", ev => { if (ev.target.closest && ev.target.closest(".tick")) keepDraft(); });
  if (VIEW.restored) {
    form.prepend(h("div", { class: "draftbar" }, h("span", { text: "Your unsent draft is back." }),
      h("button", { class: "link", type: "button", onclick: () => { const d = load("drafts", {}); delete d[f.kind]; save("drafts", d); VIEW.prefill = null; VIEW.restored = false; render(true); } }, "Start again")));
  }
  // A shift like the last one of the same kind: the site, the label and the times, in one tap.
  const byType = (SNAP && SNAP.defaults && SNAP.defaults.shift_by_type) || {};
  if (f.kind === "shift" && inputs.type && Object.keys(byType).length) {
    const same = h("button", { class: "row plain samerow", type: "button", hidden: true },
      h("span", { class: "title link", text: "Fill in like your last one" }), h("span", { class: "meta", text: "site, shift and times" }));
    same.addEventListener("click", () => {
      const last = byType[inputs.type.value] || {};
      for (const [k, v] of Object.entries(last)) if (inputs[k] && !inputs[k].value) inputs[k].value = v;
      keepDraft(); toast("Filled in as your last one of this kind.");
    });
    const showSame = () => { same.hidden = !byType[inputs.type.value]; };
    inputs.type.addEventListener("change", showSame); showSame();
    if (wraps.type) wraps.type.after(same);
  }

  // A field shown only when others have given answers (the tax year of an RRSP contribution).
  const syncShowIf = () => {
    for (const fld of f.fields) {
      if (!fld.show_if || !wraps[fld.key]) continue;
      const on = Object.entries(fld.show_if).every(([k, vals]) => inputs[k] && vals.includes(inputs[k].value));
      wraps[fld.key].hidden = !on;
    }
  };
  form.addEventListener("change", syncShowIf); setTimeout(syncShowIf, 0);
  // A reading of a value is in dollars; of the odometer, in kilometres.
  if (f.kind === "reading" && inputs.what && wraps.value) {
    const unitMark = h("span", { class: "unitmark", "aria-hidden": "true" });
    const ip = inputs.value; ip.before(unitMark);
    const syncUnit = () => { const dollars = /value$/.test(inputs.what.value); unitMark.textContent = dollars ? "$" : ""; ip.placeholder = inputs.what.value === "odometer" ? "in km" : ""; };
    inputs.what.addEventListener("change", syncUnit); syncUnit();
  }

  // A meal needs who and why: that box appears only for a meal.
  const syncMeal = () => {
    if (!wraps.who_why || !inputs.meal) return;
    wraps.who_why.hidden = inputs.meal.value !== "yes";
    void 0;
  };
  form.addEventListener("change", syncMeal); syncMeal();

  form.append(h("div", { class: "formbar" }, h("button", { class: "btn primary", type: "submit" }, VIEW.corrects ? "Send the correction" : "Send")));
  form.addEventListener("submit", ev => {
    ev.preventDefault();
    const fields = {}, problems = [];
    for (const w of Object.values(wraps)) if (w.classList) w.classList.remove("bad");
    for (const fld of f.fields) {
      const inp = inputs[fld.key];
      if (!inp) continue;
      if (fld.type === "checklist") {
        fields[fld.key] = Array.from(inp.querySelectorAll('.tick[aria-checked="true"]')).map(x => x.dataset.id);
        continue;
      }
      if (wraps[fld.key] && wraps[fld.key].hidden) continue;   // not asked, so not sent
      const val = String(inp.value || "").trim();
      let bad = false;
      if (fld.required && !val) { problems.push(labelOf(fld) + " is missing"); bad = true; }
      if (val && (fld.type === "money" || fld.type === "number") && !/^-?\d{1,7}(\.\d{1,2})?$/.test(val.replace(/[,$\s]/g, ""))) { problems.push(labelOf(fld) + ": type a number like 18.50"); bad = true; }
      if (bad && wraps[fld.key] && wraps[fld.key].classList) wraps[fld.key].classList.add("bad");
      if (val) fields[fld.key] = (fld.type === "money" || fld.type === "number") ? val.replace(/[,$\s]/g, "") : val;
    }
    if (f.kind === "expense" && fields.meal === "yes" && !fields.who_why) { problems.push("A meal needs who was there and why it was work"); if (wraps.who_why) wraps.who_why.classList.add("bad"); }
    if (problems.length) { errors.textContent = problems.join(". ") + "."; errors.hidden = false; window.scrollTo({ top: 0, behavior: "smooth" }); return; }
    const from = VIEW.from;
    const d = load("drafts", {}); delete d[f.kind]; save("drafts", d);
    submit(f.kind, fields, VIEW.corrects);
    VIEW = null;
    try { history.back(); } catch (e) { /* ignore */ }
    TAB = from === "today" ? "today" : "add";
    render(); window.scrollTo(0, 0);
  });
  if (f.kind === "bankvisit") setTimeout(() => updateSweep(form), 0);
  return form;
}

function pickQuestion(hidden, redraw) {
  const qs = openQuestions();
  const box = sheet("Which question?", null, []);
  const ul = h("div", { class: "list glass" });
  for (const q of qs) ul.append(h("button", { class: "row plain", type: "button", onclick: () => { hidden.value = q.id; box.close(); redraw(); } },
    h("span", { class: "main" }, h("span", { class: "title", text: prettyDates(receiptOf(q) ? `${receiptOf(q).what}, ${receiptOf(q).amount}, ${shortDate(receiptOf(q).date)}` : q.text) }), q.due ? h("span", { class: "meta", text: "Due " + shortDate(q.due) }) : null), icon("chevR")));
  box.insertBefore(ul, box.querySelector(".acts"));
}

function updateSweep(form) {
  const box = form.querySelector("#sweep");
  if (!box || !SNAP || !SNAP.payday) return;
  const pd = SNAP.payday;
  clear(box);
  const bal = money((form.querySelector('[name="balance"]') || {}).value || "");
  const ticked = new Set(Array.from(form.querySelectorAll('.tick[aria-checked="true"]')).map(x => x.dataset.id));
  const shortly = w => w.split(/[:;.]\s|, | about | for the /)[0].split(/[:;]/)[0];
  const lines = [];
  const isEst = it => (it.basis || "").startsWith("estimate");
  // Every estimate still in the sum, whether a payment not yet ticked or a bill kept back for.
  const estOpen = pd.items.filter(it => !ticked.has(it.id) && money(it.amount) && isEst(it)).concat((pd.reserve || []).filter(r => money(r.amount) && isEst(r)));
  const itemName = w => { const m = /^Pay [^:]+: (?:the )?(.*)$/.exec(w); return m ? m[1].replace(/^./, c => c.toUpperCase()) : shortly(w); };
  for (const it of pd.items) if (!ticked.has(it.id) && money(it.amount)) lines.push([itemName(it.what) + ", not ticked yet", money(it.amount), isEst(it)]);
  for (const r of pd.reserve || []) lines.push([shortly(r.what) + ", due " + shortDate(r.due), money(r.amount), isEst(r)]);
  lines.push(["The cushion left in chequing", money(pd.cushion) || 0, false, true]);
  // A card balance has no amount here: until it is ticked as paid, the balance above still holds it.
  const cardsOpen = pd.items.filter(it => !money(it.amount) && !ticked.has(it.id)).map(it => shortly(it.what).replace(/^Pay (the )?/i, "").replace(/ balance$/i, ""));
  const cardNames = cardsOpen.join(" and ") + (cardsOpen.length > 1 ? " balances" : " balance");
  box.append(h("h3", { text: "What to send to Questrade" }));
  if (/not yet approved/i.test(pd.rule || "")) box.append(h("p", { class: "small muted", text: "A suggestion only: the plan it follows (pay everything first, send the rest, keep a cushion) is still waiting for your yes." }));
  if (bal === null) { box.append(h("p", { class: "small muted", text: "Type the chequing balance above, and the amount to send is worked out here." })); return; }
  box.append(h("div", { class: "line" }, h("span", { text: "Chequing balance" }), h("span", { class: "amt", text: fmt$(bal) })));
  box.append(h("div", { class: "sh", text: "Kept back" }));
  let left = bal;
  const anyEstLine = lines.some(l => l[2]);
  for (const [w, a, e, round] of lines) {
    left -= a;
    box.append(h("div", { class: "line muted" }, h("span", {}, w, e ? h("span", { class: "chip orange tick-chip", text: "estimate" }) : null),
      h("span", { class: "amt", text: (e ? "about −" + fmtWhole$(Math.round(a)) : "−" + (round && anyEstLine ? fmtWhole$(Math.round(a)) : fmt$(a)).replace("−", "")) })));
  }
  if (cardsOpen.length) box.append(h("div", { class: "line muted" }, h("span", { text: cardNames.replace(/^./, c => c.toUpperCase()) + ", not paid yet" }), h("span", { class: "amt", text: "not counted" })));
  const v = left > 0 ? Math.round(left * 100) / 100 : 0;
  const wait = cardsOpen.length > 0;
  // An estimate still in the sum makes the answer approximate: whole dollars, rounded down, and labelled.
  const approx = !wait && estOpen.length > 0;
  const shown = approx ? Math.max(0, Math.floor(v)) : v;
  box.append(h("div", { class: "res" + (wait ? " wait" : "") }, h("span", { text: "Amount to send" }),
    wait ? h("span", { class: "v num rounded", text: "after the cards are paid" })
         : h("span", { class: "est-wrap" }, h("span", { class: "v num rounded" + (approx ? " approx" : ""), text: (approx ? "about " + fmtWhole$(shown) : fmt$(v)) }))));
  if (approx) {
    const unpaidEst = pd.items.filter(it => !ticked.has(it.id) && money(it.amount) && isEst(it));
    box.append(h("p", { class: "small muted", text: "Some amounts kept back are estimates, so this is approximate and rounded down." +
      (unpaidEst.length ? ` Tick ${unpaidEst.map(it => shortly(it.what).replace(/^Pay /, "the ")).join(" and ")} once paid, and it gets closer.` : "") }));
  }
  if (wait) box.append(h("p", { class: "small muted", text: `Pay the ${cardNames} first and tick ${cardsOpen.length === 1 ? "it" : "them"}, then type the balance you see. The amount to send appears then.` }));
  else if (v > 0) {
    const use = h("button", { class: "btn small tinted", type: "button" }, `Use ${approx ? fmtWhole$(shown) : fmt$(v)}`);
    use.addEventListener("click", () => { const s2 = form.querySelector('[name="sweep"]'); if (s2) { s2.value = (approx ? shown : v).toFixed(2); s2.focus(); } });
    box.append(use);
  } else box.append(h("p", { class: "small muted", text: "Nothing to send this month: the balance does not cover what is still due plus the cushion." }));
}

/* ---------- Numbers ---------- */

function renderNumbers() {
  const p = h("div", { class: "page" });
  p.append(head("Summary", "Worked out on the MacBook from your records. Tap anything to see its history and where it comes from.", true));
  const figs = (SNAP && SNAP.overview) || [];
  const S = (SNAP && SNAP.series) || {};
  if (!figs.length) { p.append(h("div", { class: "card glass" }, h("p", { class: "muted", text: "No figures yet." }))); return p; }
  const g = h("div", { class: "figs" });
  const old = o => o.as_of && dateOf(o.as_of) && daysFrom(o.as_of) < -35;
  // Lead with the newest of the first two (net worth waits for year-end values; the corporation is monthly).
  const order = figs.map((o, i) => i);
  if (figs.length > 1 && (figs[1].as_of || "") > (figs[0].as_of || "")) { order[0] = 1; order[1] = 0; }
  order.forEach((idx, i) => {
    const o = figs[idx];
    const ser = o.series && S[o.series];
    const label = old(o) ? `${o.label} · ${prettyDates(o.as_of)}` : o.label;
    const b = h("button", { class: "fig glass" + (i === 0 ? " hero" : ""), type: "button" },
      h("span", { class: "l", text: label }),
      h("span", { class: "v num rounded", text: wholeValue(o.value) }),
      ser && ser.points.length >= 4 ? h("span", { class: "spark" }, chart([sparkOf(ser, o)], { form: ser.form, unit: ser.unit, spark: true, height: i === 0 ? 56 : 34 })) : h("span", { class: "spark none" }),
      h("span", { class: "fmeta" }, h("span", { class: "basis " + o.basis, text: o.basis }), deltaOf(ser, o.series),
        o.note ? h("span", { class: "asof", text: o.note }) :
        o.series === "household" ? h("span", { class: "asof", text: "Updated once a year, at Dec 31" }) : null));
    b.addEventListener("click", () => ser ? openView({ type: "trend", fig: idx }) : whereFrom(o));
    g.append(b);
  });
  p.append(g);
  const cards = [["invest", "Investments: their value, and what they cost", ["invest_market", "invest_cost"]],
                 ["chequing", "Corporate chequing at each month's end", ["chequing"]]].filter(c => c[2].every(k => S[k]));
  if (cards.length) {
    const sec = h("section", { class: "section" }, h("h2", { text: "Trends" }));
    const grid = h("div", { class: "trend-cards" });
    for (const [id, title, keys] of cards) {
      let sub = null;
      if (id === "invest") {
        const mv = S.invest_market.points, cv = S.invest_cost.points, lm = mv[mv.length - 1], lc = cv[cv.length - 1];
        if (lm && lc && lm[0] === lc[0]) {
          const gv = lm[1] - lc[1];
          sub = h("span", { class: "tc-sub fmeta rise" }, h("span", { class: "basis derived", text: "derived" }),
            `Worth ${compact(Math.abs(gv), "$", true)} ${gv >= 0 ? "more" : "less"} than they cost, at ${keyLabel(lm[0], true)}`);
        }
      }
      if (id === "chequing") {
        const lp = S.chequing.points[S.chequing.points.length - 1];
        sub = h("span", { class: "tc-sub fmeta rise" }, h("span", { class: "basis verified", text: "verified" }), `${compact(lp[1], "$", true)} at ${keyLabel(lp[0], true)}`);
      }
      const b = h("button", { class: "card glass trendcard", type: "button", onclick: () => openView({ type: "trend", keys, title }) },
        h("span", { class: "tc-h" }, h("span", { class: "t", text: title }), icon("chevR")), sub || h("span", { class: "tc-sub" }),
        chart(keys.map(k => S[k]), { form: "line", unit: "$", height: 150, legend: keys.length > 1, axis: true, hover: false, range: 36 }),
        id === "chequing" ? null : h("span", { class: "fmeta" }, h("span", { class: "basis " + S[keys[0]].basis, text: S[keys[0]].basis + " (the value and the cost)" })));
      void id;
      grid.append(b);
    }
    sec.append(grid);
    p.append(sec);
  }
  p.append(h("details", { class: "more glass" }, h("summary", {}, h("span", { text: "What the labels mean" }), icon("chevR")),
    h("div", { class: "fields" },
      Object.entries(MEANS).map(([b, t]) => h("div", { class: "field" }, h("span", { class: "basis " + b, text: b }), h("span", { class: "small muted", text: t }))))));
  return p;
}

// A figure for this year ("so far", or named by its year) draws only this year's months in its small chart.
function sparkOf(ser, o) {
  const y = String(new Date().getFullYear());
  if (ser.form === "bars" && (/so far/.test(o.label || "") || (o.label || "").includes(y))) {
    const pts = ser.points.filter(p2 => String(p2[0]).startsWith(y));
    if (pts.length >= 2) return { ...ser, points: pts };
  }
  return ser;
}
const MEANS = { verified: "read from a document or an authoritative screen", derived: "worked out from other figures, by a stated method",
                recorded: "typed by you, not yet backed by a document", measured: "logged by an instrument, such as the phone", estimate: "rests on an assumption" };
function wholeValue(v) {
  return String(v || "").replace(/^(-?)\$([\d,]+)\.(\d\d)\b/, (m, sg, d, c) => sg + "$" + Math.round(Number(d.replace(/,/g, "")) + Number(c) / 100).toLocaleString("en-CA"));
}
function whereFrom(o) {
  sheet(o.label + ": " + o.value,
    [o.as_of ? "As of " + (dateOf(o.as_of) ? prettyDates(o.as_of) : o.as_of) + "." : "", o.source ? plainSource(o.source) + "." : "",
     o.basis ? `Labelled ${o.basis}: ${MEANS[o.basis] || ""}.` : "",
     /corporation|net worth/i.test(o.label) ? "Before the tax paid to take money out of the corporation." : ""].filter(Boolean).join(" "), [], "Done");
}
// The change over the last twelve months, for a history of balances.
function deltaOf(ser, sid) {
  // A balance's change over one year: from the point closest to a year before the newest (350 to 380
  // days back, or nothing is said), naming that date so it can be checked against the chart. In dollars
  // and plain words, no arrow or colour. On the investments it says how much of the rise was money put
  // in or distributions reinvested, so a rise is never read as earnings.
  if (!ser || ser.form !== "line" || ser.points.length < 6) return null;
  const pts = ser.points, last = pts[pts.length - 1], lastD = dateOf(last[0]);
  let prev = null, bestGap = Infinity;
  for (const q of pts) {
    const d = dateOf(q[0]); if (!d) continue;
    const days = (lastD - d) / 864e5;
    if (days >= 350 && days <= 380 && Math.abs(days - 365) < bestGap) { bestGap = Math.abs(days - 365); prev = q; }
  }
  if (!prev) return null;
  // Rounded once, to the thousand, so the parts shown always add up to the whole.
  const k1 = v => Math.round(v / 1000) * 1000;
  const ch = k1(last[1] - prev[1]);
  let text = ch === 0 ? `About the same since ${prettyDates(prev[0])}.` : `${ch > 0 ? "Up" : "Down"} ${compact(Math.abs(ch), ser.unit)} since ${prettyDates(prev[0])}.`;
  const S = (SNAP && SNAP.series) || {};
  if (sid === "invest_market" && S.invest_cost) {
    // The rise, split honestly in every kind of year: what was added at cost, and what prices did.
    const c = S.invest_cost.points, c0 = c.find(q => q[0] === prev[0]), c1 = c.find(q => q[0] === last[0]);
    if (c0 && c1 && c1[1] - c0[1] > 0) {
      const put = k1(c1[1] - c0[1]), moved = ch - put;
      text += ` ${compact(put, "$")} was money put in or distributions reinvested; ` + (moved === 0 ? "prices made little difference." : `prices ${moved > 0 ? "added" : "took away"} ${compact(Math.abs(moved), "$")}.`);
    } else if (c0 && c1 && c1[1] - c0[1] < 0) text += " Money was also taken out, so this is not what prices did.";
  }
  return h("span", { class: "delta", text });
}

/* ---------- a trend, full page ---------- */

function renderTrend() {
  const S = (SNAP && SNAP.series) || {};
  const p = h("div", { class: "page narrow" });
  let keys, title, fig = null;
  if (VIEW.fig !== undefined) { fig = ((SNAP && SNAP.overview) || [])[VIEW.fig]; keys = fig && fig.series ? [fig.series] : []; title = fig ? fig.label : ""; }
  else { keys = VIEW.keys || []; title = VIEW.title || ""; }
  const sers = keys.map(k => S[k]).filter(Boolean);
  if (!sers.length) { p.append(head("Not available", "This history has not arrived yet.")); return p; }
  const main = sers[0], last = main.points[main.points.length - 1];
  p.append(head(title, fig ? "" : ""));
  // The figure's own page gives it to the cent, so it can be matched to the workbook; its card rounds it.
  let lead = fig ? String(fig.value).replace(/\.00$/, "") : compact(last[1], main.unit, true), leadNote = null;
  if (!fig && keys[0] === "invest_market" && S.invest_cost) {
    const lc = S.invest_cost.points[S.invest_cost.points.length - 1];
    if (lc && lc[0] === last[0]) {
      lead = compact(last[1], "$", true);
      const gapV = last[1] - lc[1];
      leadNote = h("div", { class: "fmeta rise" }, h("span", { class: "basis derived", text: "derived" }),
        `Worth ${compact(Math.abs(gapV), "$", true)} ${gapV >= 0 ? "more" : "less"} than the ${compact(lc[1], "$", true)} they cost, at ${keyLabel(last[0], true)}. The cost counts the money put in and the distributions reinvested.`);
    }
  }
  const big = h("div", { class: "trend-top" },
    h("div", { class: "v num rounded", text: lead }),
    h("div", { class: "fmeta" }, h("span", { class: "basis " + (fig ? fig.basis : main.basis), text: fig ? fig.basis : main.basis }),
      h("span", { class: "asof", text: "as of " + (fig && fig.as_of ? prettyDates(fig.as_of) : keyLabel(last[0], true)) })));
  if (fig && fig.note) big.append(h("div", { class: "fmeta" }, h("span", { class: "asof", text: fig.note + "." })));
  if (leadNote) big.append(leadNote);
  const rise = deltaOf(main, keys[0]);
  if (rise) big.append(h("div", { class: "fmeta rise" }, main.basis !== "derived" ? h("span", { class: "basis derived", text: "derived" }) : null, rise));
  // A value the corporation holds is before the tax paid to take it out.
  if (/corp_market|household/.test(keys[0])) big.append(h("div", { class: "fmeta" }, h("span", { class: "asof", text: "Before the tax paid to take money out of the corporation." })));
  p.append(big);
  const ranges = main.points.length > 14 ? [[12, "1 year"], [36, "3 years"], [0, "All"]] : [];
  const holder = h("div", { class: "card glass chartcard" });
  const draw = n => { clear(holder); holder.append(chart(sers, { form: main.form, unit: main.unit, height: 240, legend: sers.length > 1, axis: true, hover: true, range: n })); };
  if (ranges.length) {
    const rs = VIEW.range !== undefined ? VIEW.range : 36;
    const segs = h("div", { class: "segs range", role: "radiogroup", "aria-label": "How far back" });
    for (const [n, lab] of ranges) {
      const b = h("button", { type: "button", role: "radio", "aria-checked": String(n === rs) }, lab);
      b.addEventListener("click", () => { VIEW.range = n; for (const x of segs.children) x.setAttribute("aria-checked", String(x === b)); draw(n); });
      segs.append(b);
    }
    p.append(segs);
    draw(rs);
  } else draw(0);
  p.append(holder);
  // The same numbers as a list, for reading exactly.
  const tbl = h("div", { class: "list glass", hidden: true });
  const rows = [];
  if (sers.length > 1) rows.push(h("div", { class: "row plain listhead" }, h("span", { text: "Month" }), h("span", { class: "amt" }, sers.map((s2, j) => h("span", { class: "tv" + j, text: s2.label })))));
  main.points.slice().reverse().forEach((pt, i) => {
    rows.push(h("div", { class: "row plain" }, h("span", { class: "title", text: keyLabel(pt[0], true) }),
      h("span", { class: "amt num" }, sers.map((s2, j) => { const q = s2.points.find(x => x[0] === pt[0]); return h("span", { class: "tv" + j, text: q ? compact(q[1], s2.unit, true) : "" }); }))));
    void i;
  });
  tbl.append(...rows);
  const toggle = h("button", { class: "btn small gray", type: "button" }, "Show as a list");
  toggle.addEventListener("click", () => { tbl.hidden = !tbl.hidden; toggle.textContent = tbl.hidden ? "Show as a list" : "Hide the list"; });
  p.append(h("div", { class: "trend-actions" }, toggle), tbl);
  const stepsD = main.points.slice(1).map((pt, i) => (dateOf(pt[0]) - dateOf(main.points[i][0])) / 864e5).sort((a1, b1) => a1 - b1);
  const usualD = stepsD.length ? stepsD[Math.floor(stepsD.length / 2)] : 0;
  const gap = main.form === "line" && stepsD.some(d => d > Math.max(40, usualD * 1.6));
  p.append(h("p", { class: "foot", text: [gap ? "A break in the line marks months whose bank statement is not filed yet." : "", plainSource(main.source) + ".", `Labelled ${main.basis}: ${MEANS[main.basis] || ""}.`,
    main.form === "bars" && /^\d{4}-\d{2}$/.test(last[0]) ? "The month in progress is left out until it is over." : ""].filter(Boolean).join(" ") }));
  return p;
}

/* ---------- charts: drawn as SVG, no library ---------- */

const SVGNS = "http://www.w3.org/2000/svg";
function sv(tag, attrs, ...kids) {
  const e = document.createElementNS(SVGNS, tag);
  for (const [a, v] of Object.entries(attrs || {})) if (v !== null && v !== undefined && v !== false) e.setAttribute(a, String(v));
  for (const k of kids) if (k) e.append(k);
  return e;
}
function keyLabel(k, long) {
  if (/^\d{4}$/.test(k)) return k;
  if (/^\d{4}-\d{2}$/.test(k)) { const d = new Date(+k.slice(0, 4), +k.slice(5, 7) - 1, 1); return d.toLocaleDateString("en-CA", long ? { month: "long", year: "numeric" } : { month: "short" }); }
  const d = dateOf(k);
  return d ? d.toLocaleDateString("en-CA", long ? { day: "numeric", month: "short", year: "numeric" } : { month: "short", year: "2-digit" }) : k;
}
function compact(v, unit, full) {
  if (v === null || v === undefined) return "";
  if (unit === "h") return `${Math.round(v).toLocaleString("en-CA")} h`;
  const a = Math.abs(v), sg = v < 0 ? "−" : "";
  if (full) return sg + "$" + Math.round(a).toLocaleString("en-CA");
  if (a >= 1e6) return `${sg}$${(a / 1e6).toFixed(a >= 1e7 ? 0 : 1)}M`;
  if (a >= 1e3) return `${sg}$${(a / 1e3).toFixed(a >= 1e5 ? 0 : a >= 1e4 ? 0 : 1)}K`;
  return `${sg}$${Math.round(a)}`;
}
function niceTicks(lo, hi, n) {
  if (hi === lo) hi = lo + 1;
  const raw = (hi - lo) / n, mag = Math.pow(10, Math.floor(Math.log10(raw))), f = raw / mag;
  const step = (f < 1.5 ? 1 : f < 3 ? 2 : f < 7 ? 5 : 10) * mag;
  const out = [];
  for (let v = Math.floor(lo / step) * step; v <= hi + step * .01; v += step) out.push(v);
  if (out[out.length - 1] < hi) out.push(out[out.length - 1] + step);
  return out;
}
function motionOK() { return !(window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches); }

// One chart: a line (balances) or columns (amounts by month or year). Redrawn to its width.
function chart(sers, o) {
  const box = h("div", { class: "chart" + (o.spark ? " spark-chart" : "") });
  const tip = h("div", { class: "tip", hidden: true });
  if (!o.spark) box.append(tip);
  if (o.legend) box.append(h("div", { class: "legend" }, sers.map((s2, j) => h("span", { class: "lk" }, h("span", { class: "sw s" + j }), s2.label))));
  const tOf = k => /^\d{4}$/.test(k) ? new Date(+k, 6, 1).getTime() : /^\d{4}-\d{2}$/.test(k) ? new Date(+k.slice(0, 4), +k.slice(5, 7) - 1, 15).getTime() : (dateOf(k) || new Date(0)).getTime();
  let lastW = 0, first = true;
  const draw = () => {
    const W = Math.round(box.clientWidth || 300), H = o.height || 160;
    if (!W || W === lastW) return;
    lastW = W;
    const old = box.querySelector("svg"); if (old) old.remove();
    const bars = o.form === "bars";
    // A range keeps the last so many months by date, not by count.
    const lastT = Math.max(...sers.map(s2 => tOf(s2.points[s2.points.length - 1][0])));
    const fromT = o.range ? lastT - o.range * 30.44 * 864e5 - 15 * 864e5 : -Infinity;
    const S2 = sers.map(s2 => ({ ...s2, points: s2.points.filter(p2 => tOf(p2[0]) >= fromT) })).filter(s2 => s2.points.length);
    if (!S2.length) return;
    const keys = S2[0].points.map(p2 => p2[0]);
    const vals = S2.flatMap(s2 => s2.points.map(p2 => p2[1]));
    let lo = bars ? 0 : Math.min(...vals), hi = Math.max(...vals);
    if (!bars) { const pad2 = (hi - lo) * .08 || Math.abs(hi) * .05 || 1; lo -= pad2; hi += pad2; }
    const ticks = o.axis ? niceTicks(Math.min(lo, bars ? 0 : lo), hi, 3) : [lo, hi];
    if (o.axis) { lo = bars ? 0 : ticks[0]; hi = ticks[ticks.length - 1]; }
    const L = o.axis ? 46 : 2, R = o.axis ? 10 : 2, T = o.spark ? 3 : 8, B = o.axis ? 22 : 3;
    const iw = Math.max(10, W - L - R), ih = H - T - B, n = keys.length;
    const band = iw / Math.max(1, n);
    const t0 = Math.min(...S2.map(s2 => tOf(s2.points[0][0]))), t1 = Math.max(...S2.map(s2 => tOf(s2.points[s2.points.length - 1][0])));
    const xt = t => L + (t1 === t0 ? iw / 2 : (t - t0) / (t1 - t0) * iw);
    const x = (i, k) => bars ? L + band * (i + .5) : xt(tOf(k));
    const y = v => T + ih - (v - lo) / (hi - lo || 1) * ih;
    const svg = sv("svg", { viewBox: `0 0 ${W} ${H}`, width: W, height: H, role: "img", "aria-label": S2.map(s2 => s2.label).join(" and ") + ", " + keyLabel(keys[0], true) + " to " + keyLabel(keys[n - 1], true) });
    if (o.axis) {
      for (const t of ticks) {
        svg.append(sv("line", { class: "grid", x1: L, x2: W - R, y1: y(t), y2: y(t) }));
        svg.append(sv("text", { class: "ax", x: L - 6, y: y(t) + 4, "text-anchor": "end" }, document.createTextNode(compact(t, S2[0].unit))));
      }
      // The time axis: each January named by its year; within a single year, every other month.
      const monthly = keys.every(k => /^\d{4}-\d{2}$/.test(k)), yearly = keys.every(k => /^\d{4}$/.test(k));
      const span = (t1 - t0) / (30.44 * 864e5);
      const labs = [];
      if (yearly) keys.forEach((k, i) => labs.push([x(i, k), k]));
      else if (span <= 14) {
        const d = new Date(t0); d.setDate(1);
        for (; d.getTime() <= t1 + 20 * 864e5; d.setMonth(d.getMonth() + 1)) {
          const m = d.getMonth(), k = `${d.getFullYear()}-${pad(m + 1)}`;
          if ((m % 2) && m !== 0) continue;
          const xi = bars ? (keys.indexOf(k) >= 0 ? x(keys.indexOf(k), k) : null) : xt(new Date(d.getFullYear(), m, 15).getTime());
          if (xi !== null && xi >= L - 1 && xi <= W - R + 1) labs.push([xi, m === 0 ? String(d.getFullYear()) : d.toLocaleDateString("en-CA", { month: "short" })]);
        }
      } else {
        for (let yr = new Date(t0).getFullYear(); yr <= new Date(t1).getFullYear() + 1; yr++) {
          const k = `${yr}-01`, xi = bars ? (keys.indexOf(k) >= 0 ? x(keys.indexOf(k), k) : null) : xt(new Date(yr, 0, 1).getTime());
          if (xi !== null && xi >= L - 1 && xi <= W - R + 1) labs.push([xi, String(yr)]);
        }
      }
      if (!yearly && span > 14 && !labs.some(([xi]) => xi - L < 44)) {
        const start = new Date(t0).toLocaleDateString("en-CA", { month: "short", year: "numeric" });
        for (let q = labs.length - 1; q >= 0; q--) if (labs[q][0] - L < start.length * 6 + 24) labs.splice(q, 1);
        labs.unshift([L, start]);
      }
      for (const [xi, lab] of labs) svg.append(sv("text", { class: "ax", x: xi, y: H - 6, "text-anchor": xi <= L + 1 ? "start" : "middle" }, document.createTextNode(lab)));
      void monthly;
    }
    const anim = first && motionOK() && !o.spark;
    S2.forEach((s2, j) => {
      if (bars) {
        const bw = Math.max(2, Math.min(24, band - 2));
        s2.points.forEach((p2, i) => {
          const x0 = x(i, p2[0]) - bw / 2, y0 = y(Math.max(0, p2[1])), hh = Math.max(0, y(0) - y0), r = Math.min(4, bw / 2, hh);
          if (hh <= 0) { if (!o.spark || true) svg.append(sv("line", { class: "zero", x1: x0 + 1, x2: x0 + bw - 1, y1: y(0) - .5, y2: y(0) - .5 })); return; }
          const d = `M${x0},${y(0)} V${y0 + r} Q${x0},${y0} ${x0 + r},${y0} H${x0 + bw - r} Q${x0 + bw},${y0} ${x0 + bw},${y0 + r} V${y(0)} Z`;
          const bar = sv("path", { class: "bar s" + j + (anim ? " grow" : ""), d });
          if (anim) bar.style.setProperty("--d", `${Math.min(i * 12, 400)}ms`);
          svg.append(bar);
        });
      } else {
        // A gap of more than forty days in a monthly history is a break in the line, not a straight step.
        // A gap is judged against the history's own spacing: months for a monthly one, a year for a yearly one.
        const steps = s2.points.slice(1).map((p2, i) => tOf(p2[0]) - tOf(s2.points[i][0])).sort((a1, b1) => a1 - b1);
        const usual = steps.length ? steps[Math.floor(steps.length / 2)] : 0;
        const segs = [[]];
        s2.points.forEach((p2, i) => {
          if (i && (!o.spark || W > 400) && tOf(p2[0]) - tOf(s2.points[i - 1][0]) > Math.max(40 * 864e5, usual * 1.6)) segs.push([]);
          segs[segs.length - 1].push([x(i, p2[0]), y(p2[1])]);
        });
        const dOf = seg => seg.map((q, i) => (i ? "L" : "M") + q[0].toFixed(1) + "," + q[1].toFixed(1)).join(" ");
        if (S2.length === 1) for (const seg of segs) if (seg.length > 1) svg.append(sv("path", { class: "area s" + j + (anim ? " fade" : ""), d: dOf(seg) + ` L${seg[seg.length - 1][0].toFixed(1)},${T + ih} L${seg[0][0].toFixed(1)},${T + ih} Z` }));
        for (const seg of segs) {
          if (seg.length === 1) { svg.append(sv("circle", { class: "end s" + j, cx: seg[0][0], cy: seg[0][1], r: 2 })); continue; }
          svg.append(sv("path", { class: "line s" + j + (anim ? " draw" : ""), d: dOf(seg) }));
        }
        const all = segs[segs.length - 1], e = all[all.length - 1];
        if (!o.spark || j === 0) svg.append(sv("circle", { class: "end s" + j, cx: e[0], cy: e[1], r: o.spark ? 2.6 : 4 }));
      }
    });
    box.prepend(svg);
    if (anim) for (const pth of svg.querySelectorAll(".line.draw")) pth.style.setProperty("--len", String(Math.ceil(pth.getTotalLength())));
    first = false;
    if (o.hover !== false && !o.spark) {
      const cross = sv("line", { class: "cross", y1: T, y2: T + ih, hidden: true });
      const dots = S2.map((s2, j) => sv("circle", { class: "hdot s" + j, r: 4.5, hidden: true }));
      svg.append(cross, ...dots);
      const hit = sv("rect", { class: "hit", x: L, y: 0, width: iw, height: H });
      svg.append(hit);
      const xs = keys.map((k, i) => x(i, k));
      const show = ev => {
        const r0 = svg.getBoundingClientRect(), px = (ev.clientX - r0.left) * (W / r0.width);
        let i = 0, best = Infinity;
        xs.forEach((xx, j) => { const d = Math.abs(xx - px); if (d < best) { best = d; i = j; } });
        cross.removeAttribute("hidden"); cross.setAttribute("x1", xs[i]); cross.setAttribute("x2", xs[i]);
        S2.forEach((s2, j) => { const pt = s2.points.find(q => q[0] === keys[i]); if (!pt) { dots[j].setAttribute("hidden", ""); return; } dots[j].removeAttribute("hidden"); dots[j].setAttribute("cx", xs[i]); dots[j].setAttribute("cy", y(pt[1])); });
        clear(tip);
        tip.append(h("div", { class: "tk", text: keyLabel(keys[i], true) }), ...S2.map((s2, j) => { const pt = s2.points.find(q => q[0] === keys[i]); return h("div", { class: "tr" }, S2.length > 1 ? h("span", { class: "sw s" + j }) : null, h("span", { text: (S2.length > 1 ? s2.label + ": " : "") + compact(pt ? pt[1] : null, s2.unit, true) })); }));
        tip.hidden = false;
        // On the side away from the pointer, so it never covers the point being read.
        const tx = xs[i] / W * box.clientWidth, tw = tip.offsetWidth, cw = box.clientWidth;
        tip.style.left = (tx > cw / 2 ? Math.max(0, tx - tw - 14) : Math.min(cw - tw, tx + 14)) + "px";
      };
      const hide = () => { cross.setAttribute("hidden", ""); dots.forEach(d => d.setAttribute("hidden", "")); tip.hidden = true; };
      hit.addEventListener("pointermove", show); hit.addEventListener("pointerdown", show);
      hit.addEventListener("pointerleave", hide); hit.addEventListener("pointercancel", hide);
    }
  };
  if (window.ResizeObserver) new ResizeObserver(draw).observe(box);
  setTimeout(draw, 0);
  return box;
}

// Where a figure comes from, in words: the workings or the record it was read from.
function plainSource(src) {
  const m = /^(models|ledger)\/([^/]+?)(?:\/|\.csv)/.exec(src || "");
  if (!m) return "From " + String(src || "").replace(/\s*\([^)]*\)\s*$/, "");
  const name = m[2].replace(/-/g, " ").replace(/\bqt\b/, "Questrade").replace(/\bcorp\b/, "corporate");
  return m[1] === "models" ? `Worked out in the ${name} workings` : `Read from the ${name} record`;
}

/* ---------- Settings ---------- */

function renderSettings() {
  const p = h("div", { class: "page narrow" });
  p.append(head("Settings"));
  const row = (title, value, onTap, cls) => onTap
    ? h("button", { class: "row plain" + (cls ? " " + cls : ""), type: "button", onclick: onTap }, h("span", { class: "title", text: title }), value !== null ? h("span", { class: "muted", text: value }) : icon("chevR"))
    : h("div", { class: "row plain" }, h("span", { class: "title", text: title }), h("span", { class: "muted", text: value }));
  const outbox = load("outbox", []).length, waiting = load("waiting", 0), m = (SNAP && SNAP.machine) || {};
  p.append(h("section", { class: "section" }, h("h2", { text: "Sync" }), h("div", { class: "list glass" },
    row("Figures last changed", SNAP ? ago(SNAP.written_at) : "not yet"),
    row("MacBook last checked in", SNAP ? ago(SNAP.checked_at) : "not yet"),
    row("Books", ({ ok: "up to date", busy: "catching up", stuck: "not updating" })[m.state] || "unknown"),
    row("On this device, not sent", String(outbox)),
    row("Waiting for the MacBook", String(waiting)),
    h("button", { class: "row plain", type: "button", onclick: async () => { toast("Checking…"); await flush(); await refresh(); toast(NET === "ok" ? "Up to date." : NET_MSG); } }, h("span", { class: "title link", text: "Check now" }), h("span", {})))));
  if (m.state === "busy") p.append(h("p", { class: "foot", text: "Catching up: the MacBook is saving other work first. What you send is received, and added to your books shortly. Nothing is lost." }));
  if (m.state === "stuck" && m.reason) p.append(h("p", { class: "foot", text: `Not updating since ${when(m.since)}. For whoever looks at it: ${m.reason}.` }));

  const mins = load("autolock", 5);
  const segs = h("div", { class: "segs", role: "radiogroup", "aria-label": "Lock after" });
  for (const n of [0, 1, 5, 15]) {
    const b = h("button", { type: "button", role: "radio", "aria-checked": String(n === mins) }, n ? `${n} min` : "At once");
    b.addEventListener("click", () => { save("autolock", n); for (const x of segs.children) x.setAttribute("aria-checked", String(x === b)); });
    segs.append(b);
  }
  p.append(h("section", { class: "section" }, h("h2", { text: "Passcode" }), h("div", { class: "list glass" },
    h("div", { class: "field" }, h("span", { class: "lab", text: "Lock after this long away or idle" }), segs),
    row("Change passcode", null, () => lockScreen("change-old")),
    h("button", { class: "row plain", type: "button", onclick: () => lockNow() }, h("span", { class: "title link", text: "Lock now" }), h("span", {})))));

  const exp = load("expiry", "");
  let expText = "Never expires";
  if (exp) {
    const days = Math.round((Date.parse(exp.replace(" UTC", "Z").replace(" ", "T")) - Date.now()) / 864e5);
    expText = Number.isFinite(days) ? (days < 30 ? `Expires in ${days} days: make a new one soon` : `Expires in ${days} days`) : "Expires " + exp;
  }
  const inp = h("input", { id: "token", type: "text", class: "masked", autocomplete: "off", autocapitalize: "off", spellcheck: "false", placeholder: "Paste a new key to replace it" });
  p.append(h("section", { class: "section" }, h("h2", { text: "This device's key" }), h("div", { class: "list glass" },
    row("Key", token() ? "Saved, locked by the passcode" : "None"),
    row("Expiry", expText),
    h("details", { class: "more" }, h("summary", {}, h("span", { text: "Replace the key" }), icon("chevR")),
      h("div", { class: "fields" }, h("div", { class: "field" }, h("label", { for: "token", text: "New key" }), inp),
        h("button", { class: "row plain", type: "button", onclick: () => replaceKey(inp) }, h("span", { class: "title link", text: "Save the new key" }), h("span", {}))))),
    h("p", { class: "foot", text: "The key lets this page read your private mailbox on GitHub and post what you send to it, nothing else. One key per device: if a device is lost, delete its key on GitHub." }),
    h("p", { class: "foot", text: "Only what you send from Add leaves this device. The MacBook collects it within 15 minutes of being open, and blacks out anything shaped like a card, account or SIN number before it is written down. Never type a password here." }),
  ));

  p.append(h("button", { class: "btn danger wide", type: "button", onclick: () => sheet("Erase this device's copy?",
    "The key, the saved summary and anything not yet sent are removed from this device. You will need the key again to use the page here.",
    [{ label: "Erase", kind: "danger", run: () => { eraseDevice(); lockScreen("setup-key"); } }]) }, "Erase this device's copy"));
  return p;
}

async function replaceKey(inp) {
  const v = inp.value.trim();
  if (!looksLikeKey(v)) { toast("That does not look like a GitHub key. Copy it again from github.com."); return; }
  save("token", v); inp.value = "";
  toast("Key saved. Checking it…");
  await refresh(); await flush();
  toast(NET === "ok" ? "The key works." : NET_MSG);
}
function looksLikeKey(v) {
  // A fine-grained GitHub key begins "github", "pat", joined by underscores. The prefix is built
  // here rather than written out, so the repository's credential check never mistakes this line for a key.
  const prefix = ["github", "pat", ""].join("_");
  return v.startsWith(prefix) && /^[A-Za-z0-9_]{30,}$/.test(v);
}

/* ---------- the lock screen ---------- */

let LOCK = { mode: "unlock", pin: "", first: "", msg: "", bad: false, busy: false, migrating: false };

function lockScreen(mode, extra) {
  LOCK = Object.assign({ mode, pin: "", first: "", msg: "", bad: false, busy: false, migrating: LOCK.migrating }, extra || {});
  const el = document.getElementById("lock");
  el.hidden = false;
  if (mode !== "change-old" && mode !== "change-new" && mode !== "change-confirm") {
    document.getElementById("app").hidden = true;
    clear(document.getElementById("main"));
  }
  drawLock();
}
function closeLock() { document.getElementById("lock").hidden = true; }

function drawLock() {
  const el = clear(document.getElementById("lock"));
  const inner = h("div", { class: "lock-inner" });
  el.append(inner);
  inner.append(h("div", { class: "badge" }, icon("lock")));
  if (LOCK.mode === "setup-key") {
    inner.append(h("h1", { text: "Finance System" }));
    inner.append(h("p", { class: "sub", text: "Paste the key you made for this device on GitHub." }));
    const inp = h("input", { type: "text", class: "masked", autocomplete: "off", autocapitalize: "off", spellcheck: "false", placeholder: "Paste the key", "aria-label": "Key" });
    const err = h("p", { class: "sub bad", text: LOCK.msg || "" });
    const go2 = async () => {
      const v = inp.value.trim();
      if (!looksLikeKey(v)) { LOCK.msg = "That does not look like a GitHub key. Copy it again from github.com."; err.textContent = LOCK.msg; return; }
      MEM = { token: v };
      err.textContent = ""; btn.disabled = true; btn.textContent = "Checking the key…";
      await refresh();
      if (NET === "key") { MEM = null; btn.disabled = false; btn.textContent = "Continue"; err.textContent = NET_MSG; return; }
      lockScreen("setup-new");
    };
    const btn = h("button", { class: "btn primary wide", type: "button", onclick: go2 }, "Continue");
    inp.addEventListener("keydown", ev => { if (ev.key === "Enter") go2(); });
    inner.append(h("div", { class: "keybox" }, inp, btn, err, h("p", { class: "help", text: "Step-by-step instructions for making a key are on your MacBook, in the Finance System folder, in the web page's instructions." })));
    setTimeout(() => inp.focus(), 50);
    return;
  }
  const titles = {
    "unlock": ["Enter your passcode", ""],
    "setup-new": ["Choose a passcode", LOCK.migrating ? "Six digits. From now on the page opens with it, and what it keeps on this device is locked with it." : "Six digits. The page opens with it, and what it keeps on this device is locked with it."],
    "setup-confirm": ["Enter it again", ""],
    "change-old": ["Enter your current passcode", ""],
    "change-new": ["Choose a new passcode", "Six digits."],
    "change-confirm": ["Enter it again", ""],
  };
  const [t, s] = titles[LOCK.mode] || ["", ""];
  inner.append(h("h1", { text: t }));
  const lo = lockout();
  const waitMs = LOCK.mode === "unlock" || LOCK.mode === "change-old" ? lo.until - Date.now() : 0;
  const sub = h("p", { class: "sub" + (LOCK.bad ? " bad" : ""), text: waitMs > 0 ? `Too many tries. Try again in ${Math.ceil(waitMs / 1000)} seconds.` : (LOCK.msg || s) });
  inner.append(sub);
  const dots = h("div", { class: "dots" + (LOCK.bad ? " shake" : ""), "aria-hidden": "true" });
  for (let i = 0; i < PIN_LEN; i++) dots.append(h("span", { class: i < LOCK.pin.length ? "on" : "" }));
  inner.append(dots, h("p", { class: "sr", "aria-live": "polite", text: `${LOCK.pin.length} of ${PIN_LEN} digits` }));
  const pad = h("div", { class: "pad" });
  const letters = ["", "ABC", "DEF", "GHI", "JKL", "MNO", "PQRS", "TUV", "WXYZ"];
  for (let d = 1; d <= 9; d++) pad.append(h("button", { type: "button", onclick: () => press(String(d)), disabled: waitMs > 0 || LOCK.busy, "aria-label": String(d) }, h("span", {}, String(d), letters[d - 1] ? h("span", { class: "sub2", text: letters[d - 1] }) : h("span", { class: "sub2", text: "\u00a0" }))));
  const cancelable = LOCK.mode.startsWith("change");
  pad.append(cancelable ? h("button", { class: "txt", type: "button", onclick: () => { closeLock(); render(); } }, "Cancel") : h("span", { class: "blank" }));
  pad.append(h("button", { type: "button", onclick: () => press("0"), disabled: waitMs > 0 || LOCK.busy, "aria-label": "0" }, "0"));
  pad.append(LOCK.pin.length ? h("button", { class: "txt", type: "button", onclick: () => press("del") }, "Delete") : h("span", { class: "blank" }));
  inner.append(pad);
  if (window.matchMedia && matchMedia("(pointer: fine)").matches) inner.append(h("p", { class: "hint2", text: "You can also type the digits." }));
  if (LOCK.mode === "unlock") inner.append(h("button", { class: "link", type: "button", onclick: forgot }, "Forgot your passcode?"));
  if (waitMs > 0) { clearTimeout(drawLock.t); drawLock.t = setTimeout(drawLock, 1000); }
  if (LOCK.bad) setTimeout(() => { LOCK.bad = false; dots.classList.remove("shake"); }, 450);
}

function forgot() {
  sheet("Forgot your passcode?", "The only way back is to erase this device's copy and paste the key again. If you no longer have the key, make a new one on GitHub, as the instructions on your MacBook describe. Nothing in your records is lost: they live on the MacBook.",
    [{ label: "Erase and start again", kind: "danger", run: () => { eraseDevice(); lockScreen("setup-key"); } }]);
}

function press(k) {
  if (LOCK.busy) return;
  if (k === "del") { LOCK.pin = LOCK.pin.slice(0, -1); drawLock(); return; }
  if (LOCK.pin.length >= PIN_LEN) return;
  LOCK.pin += k;
  drawLock();
  if (LOCK.pin.length === PIN_LEN) setTimeout(complete, 120);
}

async function complete() {
  const pin = LOCK.pin, first = LOCK.first;
  LOCK.pin = ""; LOCK.first = "";
  const m = LOCK.mode;
  if (m === "setup-new" || m === "change-new") { lockScreen(m === "setup-new" ? "setup-confirm" : "change-confirm", { first: pin }); return; }
  if (m === "setup-confirm" || m === "change-confirm") {
    if (pin !== first) { lockScreen(m === "setup-confirm" ? "setup-new" : "change-new", { msg: "The passcodes did not match. Choose one again.", bad: true }); return; }
    LOCK.busy = true; LOCK.msg = "Locking your data…"; drawLock();
    await setPasscode(pin);
    save("lockout", { fails: 0, until: 0 });
    LOCK.migrating = false;
    closeLock();
    toast(m === "setup-confirm" ? "Passcode set." : "Passcode changed.");
    afterUnlock(m === "setup-confirm");
    return;
  }
  // unlock, or the first step of changing it
  const lo = lockout();
  if (lo.until > Date.now()) { LOCK.pin = ""; drawLock(); return; }
  LOCK.busy = true; LOCK.msg = "Checking…"; drawLock();
  const ok = await unlockWith(pin).catch(() => false);
  LOCK.busy = false;
  if (!ok) {
    const fails = lo.fails + 1;
    save("lockout", { fails, until: Date.now() + failWait(fails) });
    LOCK.pin = ""; LOCK.bad = true; LOCK.msg = fails >= 4 ? `Wrong passcode. ${fails >= 5 ? "Wait, then try again." : "One more try before a wait."}` : "Wrong passcode. Try again.";
    drawLock();
    return;
  }
  save("lockout", { fails: 0, until: 0 });
  if (m === "change-old") { lockScreen("change-new"); return; }
  closeLock();
  afterUnlock(false);
}

function afterUnlock(fresh) {
  if (PENDING_OLD.length) {
    const have = new Set((MEM.outbox || []).map(e => e.id));
    MEM.outbox = (MEM.outbox || []).concat(PENDING_OLD.filter(e => e && e.id && !have.has(e.id)));
    PENDING_OLD = []; persist();
  }
  sweepOld();
  SNAP = load("snap", SNAP);
  SCHEMA = load("schema", SCHEMA);
  TAB = load("tab", "today");
  VIEW = null;
  touch();
  render();
  if (!fresh || NET !== "ok") refresh().then(flush); else flush();
}

function lockNow() {
  persist();
  GEN++;
  MEM = null; VKEY = null; VMETA = null; SNAP = null; SCHEMA = null; VIEW = null;
  for (const s of document.querySelectorAll(".scrim")) s.remove();
  lockScreen(hasVault() ? "unlock" : "setup-key");
}

/* Auto-lock: after the chosen minutes away from the page, or idle on it. */
let LAST = Date.now(), HIDDEN_AT = 0;
function touch() { LAST = Date.now(); }
function autolockMs() { return load("autolock", 5) * 60000; }
function lockShowing() { return !document.getElementById("lock").hidden; }
// Idle on the page: "At once" means on leaving it, so idleness still waits a minute.
function checkIdle() { if (MEM && !lockShowing() && Date.now() - LAST > Math.max(autolockMs(), 60000)) lockNow(); }
function awayCheck() {
  document.body.classList.remove("veiled");
  if (MEM && !lockShowing() && HIDDEN_AT && Date.now() - HIDDEN_AT >= autolockMs()) { lockNow(); return true; }
  return false;
}

/* ---------- start ---------- */

// Locked, there is no vault key to fold old entries in with, so they are kept aside in memory until the
// unlock, and the old names are removed from storage at once.
let PENDING_OLD = [];
function sweepOldAtStart() {
  try { const o = JSON.parse(rawGet(OLD.outbox) || "null"); if (Array.isArray(o)) PENDING_OLD = o; } catch (e) { /* ignore */ }
  sweepOld();
}

async function boot() {
  const wire = sel => { for (const b of document.querySelectorAll(sel)) b.addEventListener("click", () => go(b.dataset.tab)); };
  wire("#seg button"); wire("#tabbar button");
  const tb = document.querySelectorAll("#tabbar button");
  tb[0].append(icon("today"), h("span", { text: "Today" }));
  tb[1].append(icon("plusc"), h("span", { text: "Add" }));
  tb[2].append(icon("numbers"), h("span", { text: "Summary" }));
  document.getElementById("gear").append(icon("gear"));
  document.getElementById("gear").addEventListener("click", () => openView({ type: "settings" }));
  document.getElementById("bar-done").addEventListener("click", () => closeView());
  document.getElementById("sync").addEventListener("click", () => openView({ type: "settings" }));
  window.addEventListener("scroll", onScroll, { passive: true });
  window.addEventListener("popstate", () => { if (VIEW) closeView(true); });   // go() has already cleared VIEW when a tab was chosen
  for (const ev of ["pointerdown", "keydown", "scroll", "touchstart"]) window.addEventListener(ev, touch, { passive: true });
  setInterval(checkIdle, 20000);
  document.addEventListener("keydown", ev => {
    if (document.getElementById("lock").hidden || document.querySelector(".scrim") || LOCK.mode === "setup-key") return;
    if (ev.target && /^(INPUT|TEXTAREA|SELECT)$/.test(ev.target.tagName)) return;
    if (/^[0-9]$/.test(ev.key)) press(ev.key);
    else if (ev.key === "Backspace") press("del");
  });
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) { HIDDEN_AT = Date.now(); document.body.classList.add("veiled"); return; }
    if (awayCheck()) return;
    touch();
    if (MEM) { flush(); refresh(); }
  });
  window.addEventListener("pagehide", () => { HIDDEN_AT = Date.now(); document.body.classList.add("veiled"); });
  window.addEventListener("pageshow", () => { awayCheck(); });
  window.addEventListener("online", () => { if (MEM) { flush(); refresh(); } });

  try { CFG = await fetch("config.json", { cache: "no-store" }).then(r => r.json()); save("cfg", CFG); }
  catch (e) { CFG = load("cfg", null); }
  if ("serviceWorker" in navigator) navigator.serviceWorker.register("sw.js").catch(() => { /* the page works without it, only not offline */ });

  if (hasVault()) { sweepOldAtStart(); lockScreen("unlock"); return; }
  // Before the lock existed, the key and the rest sat in the clear. Move them into a vault now.
  const oldToken = (() => { try { return JSON.parse(rawGet(OLD.token) || "null"); } catch (e) { return null; } })();
  if (oldToken) {
    MEM = {};
    for (const [k, old] of Object.entries(OLD)) { const v = rawGet(old); if (v !== null) { try { MEM[k] = JSON.parse(v); } catch (e) { /* skip */ } } }
    LOCK.migrating = true;
    lockScreen("setup-new");
    return;
  }
  lockScreen("setup-key");
}

boot();
