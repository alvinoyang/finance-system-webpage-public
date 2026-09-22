"use strict";

const api = () => (CFG && CFG.api) || "https://api.github.com";
const MARKER = "finance-system-web-entry";
const P = "finance-system.";
const STALE_HOURS = 2;
const ITERATIONS = 600000;
const PIN_LEN = 6;
const SECRET = new Set(["token", "snap", "outbox", "sent", "waiting", "expiry", "schema", "drafts"]);
const OLD = { token: "token", snap: "snapshot", outbox: "outbox", sent: "sent", waiting: "waiting", expiry: "expiry", schema: "schema" };

let CFG = null, SNAP = null, SCHEMA = null;
let NET = "unknown";          // "ok" | "offline" | "key" | "error"
let NET_MSG = "", NET_DETAIL = "";
let TAB = "today";
let VIEW = null;               // null, or { type: "form" | "settings" | "questions", ... }
let MEM = null, VKEY = null, VMETA = null;   // the unlocked vault: its contents, its key, its salt
let GEN = 0;                   // bumped by every lock, passcode change and erase: a fetch begun before is dropped
let VGEN = 0;                  // bumped by a passcode change and an erase only: a save begun before is dropped


function rawGet(k) { try { return localStorage.getItem(P + k); } catch (e) { return null; } }
function rawSet(k, v) { try { localStorage.setItem(P + k, v); } catch (e) { /* storage blocked */ } }
function rawDrop(k) { try { localStorage.removeItem(P + k); } catch (e) { /* ignore */ } }
function load(k, d) {
  if (ASIDE && Object.prototype.hasOwnProperty.call(ASIDE.store, k)) return ASIDE.store[k];
  if (SECRET.has(k)) return MEM && MEM[k] !== undefined ? MEM[k] : d;
  const v = rawGet(k);
  try { return v === null ? d : JSON.parse(v); } catch (e) { return d; }
}
function save(k, v) {
  if (ASIDE) { ASIDE.store[k] = v; return; }        // a neighbour drawn aside changes nothing (the swipe)
  if (SECRET.has(k)) { if (MEM) { MEM[k] = v; persist(); } return; }
  rawSet(k, JSON.stringify(v));
}
function token() { return load("token", ""); }


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
let persisting = Promise.resolve(), SEAL_NEXT = null;
function persist() {
  if (!MEM || !VKEY) return persisting;
  const queued = !!SEAL_NEXT;
  SEAL_NEXT = { key: VKEY, meta: VMETA, text: JSON.stringify(MEM), vgen: VGEN };
  if (queued) return persisting;
  persisting = persisting.then(() => {
    const job = SEAL_NEXT; SEAL_NEXT = null;
    return seal(job.key, job.meta, job.text).then(v => {
      if (job.vgen !== VGEN) return;                // a passcode change or an erase came after
      try { localStorage.setItem(P + "vault", v); }
      catch (e) { toast("This device would not save. Keep the page open until what you typed has sent."); }
    });
  }).catch(() => { /* kept in memory */ });
  return persisting;
}
async function unlockWith(pin) {
  if (!hasVault()) return false;
  const gen = VGEN;
  const v = JSON.parse(rawGet("vault"));
  const salt = unb64(v.salt);
  const key = await deriveKey(pin, salt, v.iter);
  if (gen !== VGEN) return false;      // erased, or the passcode changed, while the key was being made
  let text;
  try { text = dec.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(v.iv) }, key, unb64(v.ct))); }
  catch (e) { return false; }
  MEM = JSON.parse(text); VKEY = key; VMETA = { salt: v.salt, iter: v.iter };
  return true;
}
async function setPasscode(pin) {
  GEN++; VGEN++; SEAL_NEXT = null; await persisting;   // nothing saved under the old passcode may land after
  const gen = VGEN;
  const salt = rand(16);
  const key = await deriveKey(pin, salt, ITERATIONS);
  if (gen !== VGEN || !MEM) return false;              // the page locked or was erased while the key was being made
  const meta = { salt: b64(salt), iter: ITERATIONS };
  const sealed = await seal(key, meta, JSON.stringify(MEM));
  try { localStorage.setItem(P + "vault", sealed); } catch (e) {
    toast("This device would not let the page save anything, so your passcode has not changed. Private browsing, or no room left?");
    return false;
  }
  VKEY = key; VMETA = meta;                            // only once it is written down
  for (const k of Object.values(OLD)) rawDrop(k);   // nothing private left in the clear
  return true;
}
function hasVault() { return !!rawGet("vault"); }
function eraseDevice() {
  GEN++; VGEN++; SEAL_NEXT = null;
  if (typeof dropNeighbours === "function") dropNeighbours();
  MEM = null; VKEY = null; VMETA = null; SNAP = null; SCHEMA = null;
  persisting.then(() => dropAll());
  dropAll();
}
function dropAll() {
  try {
    for (const k of Object.keys(localStorage)) if (k.startsWith(P) || k.startsWith("desk.") || k.startsWith("finance-desk.")) localStorage.removeItem(k);
  } catch (e) { /* ignore */ }
}
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

function lockout() { return load("lockout", { fails: 0, until: 0 }); }
function failWait(fails) { return fails < 5 ? 0 : Math.min(15 * 60, 30 * Math.pow(2, fails - 5)) * 1000; }


function h(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [a, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (a === "class") e.className = v;
    else if (a === "text") e.textContent = v;
    else if (a === "style") for (const d of String(v).split(";")) { const i = d.indexOf(":"); if (i > 0) e.style.setProperty(d.slice(0, i).trim(), d.slice(i + 1).trim()); }
    else if (a.startsWith("on")) e.addEventListener(a.slice(2), v);
    else if (v === true) e.setAttribute(a, "");
    else e.setAttribute(a, String(v));
  }
  for (const k of kids.flat(Infinity)) {
    if (k === null || k === undefined || k === false) continue;
    e.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
  return e;
}
function clear(e) { while (e.firstChild) e.removeChild(e.firstChild); return e; }

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
  refresh: [["path", { d: "M19 12a7 7 0 1 1-2.05-4.95", "stroke-width": 2.2 }], ["path", { d: "M19.5 4.5v4h-4", "stroke-width": 2.2 }]],
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
function prettyDates(text) { return String(text || "").replace(/\b(\d{4}-\d{2}-\d{2})\b/g, (m, iso) => dayName(iso, { day: "numeric", month: "short", year: "numeric" })); }
function daysFrom(iso) {
  const d = dateOf(iso); if (!d) return null;
  const t = new Date(); t.setHours(0, 0, 0, 0);
  return Math.round((d - t) / 864e5);
}
function monthDay(iso) {
  const d = dateOf(iso);
  if (!d) return iso || "";
  const opts = { month: "short", day: "numeric" };
  if (d.getFullYear() !== new Date().getFullYear()) opts.year = "numeric";
  return d.toLocaleDateString("en-CA", opts).replace(/ (\d)/g, "\u00a0$1");    // never "Sep" on one line and "5" on the next
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
  const abc = "abcdefghjkmnpqrstuvwxyz", a = rand(14);
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

function quietRender() {
  if (SIDE_ANIM || (GS && GS.side)) { setTimeout(quietRender, 400); return; }   // never under a finger mid-swipe
  if (VIEW && ["form", "settings", "questions"].includes(VIEW.type)) {
    renderChrome();
    const open = document.querySelector("#main form");
    if (open && open.querySelector("#sweep")) updateSweep(open);
  } else render();
}

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
    const was = { snap: SNAP, schema: SCHEMA, waiting: load("waiting", 0), net: NET };
    const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
    const bare = x => x ? Object.assign({}, x, { checked_at: "" }) : x;
    let redraw = false;
    const staleOf = x => !!(x && hoursSince(x.checked_at) > STALE_HOURS);
    if (s && s.format === "finance-system-webpage-summary" && !same(s, SNAP)) { redraw = !same(bare(s), bare(SNAP)) || staleOf(s) !== staleOf(SNAP); SNAP = s; save("snap", s); }
    if (f && f.forms && !same(f, SCHEMA)) { SCHEMA = f; save("schema", f); redraw = true; }
    const waiting = issues.filter(i => !i.pull_request && typeof i.body === "string" && i.body.indexOf(MARKER) >= 0).length;
    if (waiting !== was.waiting) { save("waiting", waiting); redraw = true; }
    NET = "ok"; NET_MSG = "";
    if (was.net !== "ok" && was.net !== "unknown") redraw = true;   // a warning about the connection goes
    if (MEM) { if (redraw) quietRender(); else renderChrome(); }
    return;
  } catch (e) {
    if (gen !== GEN) return;
    NET = e.kind || "error"; NET_MSG = e.message; NET_DETAIL = e.detail || "";
  }
  if (MEM) quietRender();
}

let flushing = false;
async function flush() {
  if (flushing || !MEM) return;
  flushing = true;
  let box = load("outbox", []);
  const had = box.length;
  try {
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
        NET = e.kind || "error"; NET_MSG = e.message; NET_DETAIL = e.detail || "";
        break;
      }
    }
  } finally {
    flushing = false;
    if (MEM && had) quietRender();                  // an empty outbox changes nothing on the page
  }
}

const LOOKS_PRIVATE = [/\b\d{3}[ -]?\d{3}[ -]?\d{3}\b/, /\b(?:\d[ -]?){12,18}\d\b/, /\d{7,}/, /\(?\b\d{3}\)?[ .-]\d{3}[ .-]\d{4}\b/];
function privateIn(fields, formFields) {
  const numeric = new Set((formFields || []).filter(f => ["money", "number", "date", "month", "time"].includes(f.type)).map(f => f.key));
  for (const [k, v] of Object.entries(fields || {})) {
    if (numeric.has(k) || typeof v !== "string") continue;
    if (LOOKS_PRIVATE.some(re => re.test(v))) return k;
  }
  return "";
}
const PRIVATE_MSG = "Something typed looks like a SIN, a card, an account or a phone number. Take it out before sending: the last four digits are enough to name an account";
function submit(kind, fields, corrects, said) {
  const entry = { format: MARKER, id: newId(), kind, typed_at: typedAt(), device: device(), fields };
  if (corrects) entry.corrects = corrects;
  const box = load("outbox", []);
  box.push(entry);
  save("outbox", box);
  toast(navigator.onLine ? (said || "Saved. Sending…") : "Saved on this device. It sends when you are back online.");
  flush();
  return entry;
}


const KINDS = {
  shift: { name: "Shift", desc: "MGH, EDLP, Bochner, Endoscopy, ABP", icon: "work", color: "blue", group: "often",
           help: "Where, and which shift, is all it needs. Everything else can wait: add it any time from Your shifts." },
  expense: { name: "Paid it myself", desc: "Cash, your own card, a split bill", icon: "receipt", color: "green", group: "often" },
  income: { name: "Income received", desc: "Pay, OHIP, a stipend, a refund", icon: "income", color: "purple", group: "often" },
  bankvisit: { name: "Monthly banking", desc: "Download, pay yourself and CRA, sweep", icon: "bank", color: "orange", group: "often",
               help: "Step 4 of your one day a month. Tick the two payments once the money has left chequing, type what each card still owes and the chequing balance you see, and the amount to send to Questrade is worked out below. Steps 1 to 3 are on Today." },
  registered: { name: "TFSA, RRSP or FHSA", desc: "Money in or out", icon: "vault", color: "blue", group: "sometimes" },
  reading: { name: "A reading", desc: "Odometer, an account's value", icon: "gauge", color: "gray", group: "sometimes" },
  card: { name: "A credit card change", desc: "Opened, bonus, fee, closed", icon: "card", color: "gray", group: "sometimes" },
  life: { name: "A change in life or plans", desc: "A move, the wedding, insurance, salary", icon: "heart", color: "red", group: "sometimes" },
  answer: { name: "Answer a question", desc: "", icon: "bubble", color: "purple", group: "any", help: "" },
  note: { name: "Note", desc: "Anything else for the record", icon: "pencil", color: "gray", group: "any" },
};
function kindOf(k) {
  const o = KINDS[k] || { name: k, desc: "", icon: "pencil", color: "gray" };
  return o;
}
function ordinal(n) { const v = n % 100; return n + (v >= 11 && v <= 13 ? "th" : ({ 1: "st", 2: "nd", 3: "rd" })[n % 10] || "th"); }
function sittingDay() { return (SNAP && SNAP.payday && Number(SNAP.payday.sitting_day)) || 22; }
function sittingName() { return `The ${ordinal(sittingDay())}`; }
function formsList() { return (SCHEMA && SCHEMA.forms) || []; }
const RECEIPT = /^(\d{4}-\d{2}-\d{2}) - (.+) - (-?\$[\d,]+(?:\.\d\d)?)(:| has no receipt)/;
function receiptOf(q) {
  if (/^meal-/.test(String(q.id || ""))) return null;
  const m = RECEIPT.exec(q.text || "");
  if (!m) return null;
  return { date: m[1], what: m[2], amount: m[3], problem: m[4] === ":" ? "No card or bank charge found for it" : "No receipt filed" };
}
function openQuestions() {
  const mine = answeredHere();
  return ((SNAP && SNAP.questions) || []).filter(q => !q.answered && !mine.has(q.id))
    .sort((a, b) => (a.due || "9999").localeCompare(b.due || "9999"));
}
function answeredHere() {
  const local = load("outbox", []).concat(load("sent", []).map(x => x.entry)).filter(Boolean);
  const gone = new Set(local.filter(e => e.kind === "withdraw").map(e => e.corrects));
  for (const r of (SNAP && SNAP.recent) || []) if (r.status === "held") gone.add(r.id);
  const out = new Map();
  for (const e of local) if (e.kind === "answer" && e.fields && e.fields.question && !gone.has(e.id)) out.set(e.fields.question, e);
  return out;
}

const NO_RECEIPT = "no-receipt";
function canKeepWithout(q) {
  const f = formsList().find(x => x.kind === "answer");
  return !!(q && /^receipt-/.test(q.id) && f && f.fields.some(x => x.key === "resolution"));
}
function keepWithout(q) {
  return submit("answer", { question: q.id, answer: "There is no receipt. Keep the expense on the statement alone.", resolution: NO_RECEIPT }, "",
                "Kept without a receipt.");
}


function renderChrome() {
  const app = document.getElementById("app");
  document.body.classList.toggle("in-form", !!(VIEW && VIEW.type === "form"));
  document.body.classList.toggle("in-settings", !!(VIEW && VIEW.type === "settings"));
  const here = VIEW && VIEW.type === "settings" ? "" : VIEW && VIEW.type === "form" && VIEW.from === "today" && !STACK.length ? "today" : TAB;
  const needs = ((SNAP && SNAP.held) || []).length + (NET === "key" ? 1 : 0), unsent = load("outbox", []).length;
  for (const b of document.querySelectorAll("#seg button, #tabbar button")) {
    const old = b.querySelector(".tab-badge"); if (old) old.remove();
    const wp = (SNAP && SNAP.work_pay) || {};
    const n = b.dataset.tab === "today" ? needs : b.dataset.tab === "add" ? unsent : b.dataset.tab === "work" ? ((wp.chase || 0) + (wp.ask || 0)) : 0;
    if (n) b.append(h("span", { class: "tab-badge", "aria-label": `${n} waiting`, text: String(n) }));
  }
  for (const b of document.querySelectorAll("#seg button, #tabbar button")) {
    if (b.dataset.tab === here) b.setAttribute("aria-current", "page"); else b.removeAttribute("aria-current");
  }
  const left = document.getElementById("bar-left");
  const title = document.getElementById("bar-title");
  const oldBack = left.querySelector(".back"); if (oldBack) oldBack.remove();
  if (VIEW && VIEW.type !== "settings") {
    left.prepend(h("button", { class: "back", type: "button", onclick: () => closeView() }, icon("chevL"), parentName()));
    title.textContent = "";
  } else {
    title.textContent = VIEW && VIEW.type === "settings" ? "Settings" : TAB_NAME[TAB];
  }
  document.body.classList.toggle("toplevel", !VIEW);
  const s = document.getElementById("sync"), st = document.getElementById("sync-text");
  s.className = "sync";
  const outbox = load("outbox", []).length;
  let text, short;
  if (NET === "key" || NET === "error") { s.classList.add("bad"); text = short = "Needs attention"; }
  else if (SNAP && SNAP.machine && SNAP.machine.state === "stuck") { s.classList.add("bad"); text = "Books not updating"; short = "Not updating"; }
  else if (NET === "offline") { s.classList.add("stale"); text = outbox ? `Offline · ${outbox} to send` : "Offline"; short = "Offline"; }
  else if (!SNAP) { s.classList.add("stale"); text = short = "No summary yet"; }
  else if (hoursSince(SNAP.checked_at) > STALE_HOURS) { s.classList.add("stale"); text = `MacBook asleep · ${ago(SNAP.checked_at, true)}`; short = `Asleep · ${ago(SNAP.checked_at, true)}`; }
  else if (outbox) { s.classList.add("stale"); text = short = `${outbox} to send`; }
  else if (SNAP.machine && SNAP.machine.state === "busy") text = short = "Catching up";
  else { text = `Updated ${ago(SNAP.checked_at, true)}`; short = ago(SNAP.checked_at, true).replace(/^just now$/, "Just now"); }
  st.textContent = text;
  SYNC_SHORT = short;
  s.setAttribute("aria-label", "Sync: " + text + ". Open settings.");
  for (const p of document.querySelectorAll(".head-sync")) {
    p.className = s.className + " head-sync";
    p.setAttribute("aria-label", s.getAttribute("aria-label"));
    const t = p.querySelector(".sync-t"); if (t) t.textContent = short;
  }
  app.hidden = false;
}
let SYNC_SHORT = "";

function head(title, sub, withStatus) {
  const hd = h("div", { class: "head" + (withStatus ? " with-status" : "") }, h("h1", { text: title }));
  if (withStatus) {
    const src = document.getElementById("sync");
    const pill = h("button", { class: src.className + " head-sync", type: "button", "aria-label": src.getAttribute("aria-label"), onclick: () => openView({ type: "settings" }) },
      h("span", { class: "dot" }), h("span", { class: "sync-t", text: SYNC_SHORT || document.getElementById("sync-text").textContent }));
    const gear = h("button", { class: "icon-btn head-gear", type: "button", "aria-label": "Settings", onclick: () => openView({ type: "settings" }) }, icon("gear"));
    hd.append(h("div", { class: "head-right" }, pill, gear));
  }
  if (sub) hd.append(h("div", { class: "sub", text: sub }));
  return hd;
}

function render(animate) {
  if (ASIDE) { SWIPE = null; const pg = pageFor(); ASIDE.out = { page: pg, swipe: SWIPE }; return; }
  closePop();
  if (!MEM || (!document.getElementById("lock").hidden && !OPENING && !LOCK.mode.startsWith("change"))) return;
  renderChrome();
  const main = clear(document.getElementById("main"));
  SWIPE = null;                 // each page says what a sideways swipe does on it, as it is drawn
  const page = pageFor();
  const cls = ENTER === "none" ? "" : ENTER ? "enter-" + ENTER : "enter";
  ENTER = "";
  if (animate && cls && motionOK()) { page.classList.add(cls); page.addEventListener("animationend", () => page.classList.remove(cls), { once: true }); }
  main.append(page);
  onScroll();
  neighboursStale();
}
function pageFor() {
  let page;
  if (VIEW && VIEW.type === "form") page = renderForm();
  else if (VIEW && VIEW.type === "settings") page = renderSettings();
  else if (VIEW && VIEW.type === "questions") page = renderQuestions();
  else if (VIEW && VIEW.type === "trend") page = renderTrend();
  else if (VIEW && VIEW.type === "shifts") page = renderShifts();
  else if (VIEW && VIEW.type === "income") page = renderIncome();
  else if (VIEW && VIEW.type === "work") page = renderWork();
  else if (VIEW && VIEW.type === "account") page = renderAccount();
  else if (VIEW && VIEW.type === "sitting") page = renderSitting();
  else if (VIEW && VIEW.type === "saving") page = renderSaving();
  else if (VIEW && VIEW.type === "returns") page = renderReturns();
  else if (VIEW && VIEW.type === "spending") page = renderSpending();
  else if (VIEW && VIEW.type === "vehicle") page = renderVehicle();
  else if (VIEW && VIEW.type === "card") page = renderCard();
  else if (VIEW && VIEW.type === "workunit") page = renderWorkUnit();
  else if (TAB === "add") page = renderAdd();
  else if (TAB === "work") page = renderWorkTab();
  else if (TAB === "numbers") page = renderSummary();
  else page = renderToday();
  if (VIEW && VIEW.type !== "settings") {
    page.prepend(h("button", { class: "back pageback", type: "button", onclick: () => closeView() }, icon("chevL"), parentName()));
  }
  if (!SWIPE) SWIPE = VIEW ? (["form", "settings"].includes(VIEW.type) ? null : { el: page, prev: () => BACK(), next: null })
                           : { el: page, prev: () => tabStep(-1), next: () => tabStep(1) };
  return page;
}

let STACK = [], OWN_BACKS = 0;
function historyBack(n) {
  if (!n || ASIDE) return;
  OWN_BACKS += 1;
  try { history.go(-n); } catch (e) { OWN_BACKS -= 1; }
}
const TABS = ["numbers", "work", "today", "add"];
const TAB_NAME = { today: "Today", add: "Add", work: "Work", numbers: "Summary" };  // what each tab is called, in one place
let ENTER = "";                // "l" or "r": the side the next page drawn slides in from
function go(tab) {
  saveDraftNow();                               // a tab tapped while a form is open keeps what was typed (r5-page-01)
  const depth = STACK.length + (VIEW ? 1 : 0);
  if (!depth && tab !== TAB && !ENTER) ENTER = TABS.indexOf(tab) > TABS.indexOf(TAB) ? "r" : "l";
  STACK = []; VIEW = null;
  historyBack(depth);
  TAB = tab; save("tab", tab);
  render(true); window.scrollTo(0, 0);
}
function openView(v) {
  if (VIEW) { VIEW.scroll = window.scrollY; STACK.push(VIEW); }
  VIEW = v;
  if (!ASIDE) try { history.pushState({ view: v.type }, ""); } catch (e) { /* ignore */ }
  render(true); window.scrollTo(0, 0);
}
function closeView(fromPop) {
  if (!VIEW) return;
  saveDraftNow();                               // before render detaches the form (since 2026-09-16, r5-page-01)
  const back = VIEW.type === "form" && VIEW.from === "today" && !STACK.length ? "today" : null;
  VIEW = STACK.pop() || null;
  if (back) TAB = back;
  if (!fromPop) historyBack(1);
  render(true); window.scrollTo(0, VIEW && VIEW.scroll ? VIEW.scroll : 0);
}
function parentName() {
  const under = STACK[STACK.length - 1];
  if (under) return viewTitle(under);
  if (VIEW && VIEW.type === "form" && VIEW.from === "today") return "Today";
  return TAB_NAME[TAB];
}
function viewTitle(v) {
  if (!v) return TAB_NAME[TAB];
  return ({ form: kindOf(v.kind).name, settings: "Settings", questions: "Questions", shifts: "Your shifts", income: "Income",
            work: v.metric === "rate" ? "Pay per hour" : "Hours", workunit: v.title || "A shift", account: ({ "qt-tfsa": "TFSA", "qt-rrsp": "RRSP", "qt-fhsa": "FHSA" })[v.account] || "Account",
            card: v.title || "Card", trend: v.title || "History", sitting: "Monthly banking",
            saving: "What you invest", returns: "What it is worth", spending: "What you spend", vehicle: (SNAP && SNAP.vehicle && SNAP.vehicle.name) || "Your car" })[v.type] || "Back";
}
function onScroll() { document.getElementById("bar").classList.toggle("scrolled", window.scrollY > (document.body.classList.contains("toplevel") ? 48 : 28)); }
function measureBar() {
  const b = document.getElementById("bar");
  if (b && b.offsetHeight) document.documentElement.style.setProperty("--bar-h", b.offsetHeight + "px");
}

const PULL_AT = 64, PULL_MAX = 110, PULL_HOLD = 54;
let SWIPE = null;              // { el, prev, next }: prev and next give { run, whole } or null
let GS = null;                 // the touch being followed
let PULLING = false;           // a refresh begun by a pull, still running
let NO_CLICK_UNTIL = 0;        // a swipe that lands on a button must not also press it
const BACK = () => VIEW ? { whole: true, back: true, run: () => { ENTER = ENTER || "l"; closeView(); } } : null;
function tabStep(d) {
  const i = TABS.indexOf(TAB) + d;
  if (i < 0 || i >= TABS.length) return null;
  return { whole: true, run: () => { ENTER = ENTER || (d > 0 ? "r" : "l"); if (TABS[i] === "numbers") save("sumpart", "total"); go(TABS[i]); } };
}
function swipeAlong(group, el, before, after) {
  const step = d => {
    const o = Array.from(group.querySelectorAll('[role="radio"]')), i = o.findIndex(b => b.getAttribute("aria-checked") === "true");
    return o[i + d] || null;
  };
  const move = (d, beyond) => () => { const b = step(d); return b ? { run: () => { NO_CLICK_UNTIL = 0; b.click(); } } : beyond ? beyond() : null; };
  SWIPE = { el, prev: move(-1, before), next: move(1, after) };
}
function standalone() { return (window.matchMedia && matchMedia("(display-mode: standalone)").matches) || navigator.standalone === true; }
function ptrEls() { return { main: document.getElementById("main"), ptr: document.getElementById("ptr") }; }

function gStart(ev) {
  if (GS && GS.mode) gEnd({ type: "touchcancel" });     // a second finger: put back what the first had moved
  if (SIDE_ANIM) SIDE_ANIM.end();                        // a swipe still settling finishes at once
  GS = null;
  if (ev.touches.length !== 1 || !MEM || lockShowing() || document.querySelector(".scrim")) return;
  const t = ev.touches[0], tg = ev.target, a = document.activeElement;
  if (tg.closest && tg.closest("input, textarea, select, .tabbar, .formbar")) return;
  if (VIEW && VIEW.type === "form") return;
  if (a && /^(INPUT|TEXTAREA|SELECT)$/.test(a.tagName)) return;          // the keyboard is up
  const edge = t.clientX < 22 ? "l" : t.clientX > window.innerWidth - 22 ? "r" : "";
  GS = { x: t.clientX, y: t.clientY, t: Date.now(), mode: null, dx: 0, dy: 0, side: null, trail: [[ev.timeStamp || performance.now(), t.clientX]], top: window.scrollY <= 0, edge,
         noSide: !!(tg.closest && tg.closest(".chips, .chart.scrub, .bar, .pad")) || (edge && !standalone()) };
}
function sideTarget(dx) {
  if (GS && GS.edge === "l" && dx > 0 && standalone() && VIEW) return BACK();
  if (!SWIPE) return null;
  return dx > 0 ? (SWIPE.prev && SWIPE.prev()) : (SWIPE.next && SWIPE.next());
}
function gMove(ev) {
  if (!GS || ev.touches.length !== 1) return;
  const t = ev.touches[0], dx = t.clientX - GS.x, dy = t.clientY - GS.y;
  GS.dx = dx; GS.dy = dy;
  GS.trail.push([ev.timeStamp || performance.now(), t.clientX]);
  if (GS.trail.length > 12) GS.trail.shift();
  if (!GS.mode) {
    if (Math.abs(dx) < 6 && Math.abs(dy) < 6) return;
    if (!ev.cancelable) GS.mode = "none";
    else if (GS.top && !PULLING && dy > 0 && dy > Math.abs(dx) && window.scrollY <= 0) GS.mode = "pull";
    else if (!GS.noSide && Math.abs(dx) > Math.abs(dy) * 1.3 && (SWIPE || sideTarget(dx))) { GS.mode = "side"; closePop(); }
    else GS.mode = "none";
  }
  if (GS.mode === "pull") { ev.preventDefault(); pullTo(dy); }
  else if (GS.mode === "side") { ev.preventDefault(); sideTo(dx); }
}
function gEnd(ev) {
  if (!GS) return;
  const g = GS, cancel = ev && ev.type === "touchcancel";
  GS = null;
  if (g.mode === "pull") pullRelease(cancel ? 0 : g.dy);
  else if (g.mode === "side") sideRelease(g, cancel);
}

function pullOffset(dy) { return Math.max(0, Math.min(PULL_MAX, dy * 0.5)); }
let PULL_Y = 0;
let PULL_SETTLE = 0;
function pullSet(off, settle) {
  const { main, ptr } = ptrEls(), i = ptr.firstChild;
  main.classList.toggle("settle", !!settle); ptr.classList.toggle("settle", !!settle);
  clearTimeout(PULL_SETTLE);
  if (settle && !off) PULL_SETTLE = setTimeout(() => { main.classList.remove("settle"); ptr.classList.remove("settle"); }, 340);
  PULL_Y = off;
  main.style.transform = off ? `translate3d(0,${off}px,0)` : "";
  const k = Math.min(1, off / PULL_AT), y = `translate3d(0,${(off / 2 - 16).toFixed(1)}px,0)`;
  i.style.opacity = String(k);
  i.style.transform = ptr.classList.contains("busy") ? y : `${y} scale(${(.6 + .4 * k).toFixed(3)}) rotate(${Math.round(k * 300)}deg)`;
  ptr.classList.toggle("armed", off >= PULL_AT);
}
function pullTo(dy) {
  const { ptr } = ptrEls();
  if (!ptr.firstChild.firstChild) ptr.firstChild.append(icon("refresh"));
  pullSet(pullOffset(dy), false);
}
async function pullRelease(dy) {
  const { ptr } = ptrEls();
  if (pullOffset(dy) < PULL_AT || PULLING) { pullSet(0, true); return; }
  PULLING = true;
  pullSet(PULL_HOLD, true);
  ptr.classList.add("busy"); ptr.firstChild.style.transform = `translate3d(0,${PULL_HOLD / 2 - 16}px,0)`;
  const t0 = Date.now();
  try { await flush(); await refresh(); } finally {
    await new Promise(r => setTimeout(r, Math.max(0, 650 - (Date.now() - t0))));   // long enough to be seen
    ptr.classList.remove("busy");
    PULLING = false;
    pullSet(0, true);
    toast(NET === "ok" ? `Up to date. The MacBook last checked in ${ago(SNAP && SNAP.checked_at)}.` : NET_MSG);
  }
}

let ASIDE = null;              // while drawing aside: { store, out }: save() writes to store, render() draws into out
let NB = { ver: -1 };          // the neighbours drawn ahead: { ver, prev, next }
let NB_VER = 0;                // bumped by every drawing and every tap: a neighbour drawn before is stale
let NB_TIMER = 0;
let SIDE_ANIM = null;          // a finish or spring-back still running: { end() } completes it at once

function drawAside(fn) {
  const keep = { TAB, VIEW, STACK, SWIPE, ENTER, NO_CLICK_UNTIL, OWN_BACKS }, scrollTo = window.scrollTo;
  const copy = v => (v === null || v === undefined) ? v : JSON.parse(JSON.stringify(v));
  ASIDE = { store: {}, out: null };
  VIEW = copy(VIEW); STACK = copy(STACK);
  window.scrollTo = () => {};
  try { return fn(); } catch (e) { return null; }
  finally {
    window.scrollTo = scrollTo;
    ({ TAB, VIEW, STACK, SWIPE, ENTER, NO_CLICK_UNTIL, OWN_BACKS } = keep);
    ASIDE = null;
  }
}
function stillen(root) {
  const cls = ["fadein", "enter", "enter-l", "enter-r", "draw", "grow", "fade"];
  for (const el of [root, ...root.querySelectorAll(".fadein, .enter, .enter-l, .enter-r, .draw, .grow, .fade")]) el.classList.remove(...cls);
  return root;
}
function neighbour(dir, edgeBack) {
  if (!MEM || (VIEW && VIEW.type === "form") || (VIEW && VIEW.type === "settings" && !edgeBack)) return null;
  return drawAside(() => {
    let tg = edgeBack ? BACK() : SWIPE && SWIPE[dir] && SWIPE[dir]();
    if (!tg) return null;
    if (!tg.whole) {
      render();
      const now = ASIDE.out;
      tg = now && now.swipe && now.swipe[dir] && now.swipe[dir]();
      if (!tg) return null;
      ASIDE.out = null;
      tg.run();
      const got = ASIDE.out || now;       // the choice redrew the whole page, or changed the copy in place
      const part = got.swipe && got.swipe.el;
      return part ? { whole: false, page: stillen(part) } : null;
    }
    tg.run();
    const got = ASIDE.out;
    return got ? { whole: true, page: stillen(got.page), scroll: (VIEW && VIEW.scroll) || 0, top: !VIEW } : null;
  });
}
function neighboursStale() {
  NB_VER += 1;
  clearTimeout(NB_TIMER);
  NB_TIMER = setTimeout(prepNeighbours, 450);
}
function prepNeighbours() {
  if (!MEM || document.hidden || lockShowing()) return;
  if (GS) { NB_TIMER = setTimeout(prepNeighbours, 300); return; }
  if (NB.ver !== NB_VER) NB = { ver: NB_VER };
  const dir = !("prev" in NB) ? "prev" : !("next" in NB) ? "next" : null;
  if (!dir) return;
  NB[dir] = neighbour(dir, false);
  NB_TIMER = setTimeout(prepNeighbours, 60);
}
function neighbourFor(dir, edgeBack) {
  if (edgeBack) return neighbour("prev", true);
  if (NB.ver === NB_VER && dir in NB) return NB[dir];
  if (NB.ver !== NB_VER) NB = { ver: NB_VER };
  return (NB[dir] = neighbour(dir, false));
}

function sideLayer(nb, el) {
  const W = window.innerWidth;
  let layer;
  if (nb.whole) {
    layer = document.createElement("main");
    layer.className = "peek" + (nb.top ? " peek-top" : " peek-sub");
    layer.style.top = -nb.scroll + "px";
    layer.append(nb.page);
  } else {
    const r = el.getBoundingClientRect();
    layer = h("div", { class: "peek-part " + ((el.parentNode && el.parentNode.className) || "") });
    layer.style.top = r.top + "px"; layer.style.left = r.left + "px"; layer.style.width = r.width + "px";
    layer.append(nb.page);
  }
  layer.setAttribute("aria-hidden", "true");
  layer.style.transform = `translate3d(${W}px,0,0)`;
  document.body.append(layer);
  for (const row of layer.querySelectorAll(".chips")) { const on = row.querySelector('[aria-checked="true"]'); if (on && on.offsetLeft + on.offsetWidth > row.clientWidth) row.scrollLeft = on.offsetLeft - 16; }
  return layer;
}
const rubber = (dx, W) => Math.sign(dx) * (1 - 1 / (Math.abs(dx) * 0.55 / W + 1)) * W;
function sideEl(whole) { return whole ? document.getElementById("main") : (SWIPE && SWIPE.el) || document.getElementById("main"); }
function place(el, x) {
  const y = el.id === "main" ? PULL_Y : 0;
  el.style.transform = x || y ? `translate3d(${x}px,${y}px,0)` : "";
}

function sideTo(dx) {
  const S = GS.side || (GS.side = { dir: null });
  const dir = dx > 0 ? "prev" : "next";
  if (dir !== S.dir) {
    if (S.layer) S.layer.remove();
    if (S.el) place(S.el, 0);
    const edgeBack = GS.edge === "l" && dx > 0 && standalone() && !!VIEW;
    const nb = neighbourFor(dir, edgeBack);
    S.dir = dir; S.nb = nb;
    S.el = sideEl(!nb || nb.whole);
    S.el.classList.remove("settle");
    S.el.style.transition = "none";
    S.el.style.willChange = "transform";
    S.layer = nb ? sideLayer(nb, S.el) : null;
    S.W = window.innerWidth;
    document.body.classList.add("swiping");
  }
  const x = S.nb ? dx : rubber(dx, S.W);
  S.x = x;
  place(S.el, x);
  if (S.layer) S.layer.style.transform = `translate3d(${x - Math.sign(dx) * S.W}px,0,0)`;
}
function speedOf(g) {
  const s = g.trail, n = s.length;
  if (n < 2) return 0;
  let i = n - 1;
  while (i > 0 && s[n - 1][0] - s[i - 1][0] < 100) i -= 1;
  const dt = s[n - 1][0] - s[i][0];
  return dt > 0 ? (s[n - 1][1] - s[i][1]) / dt : 0;
}
function sideRelease(g, cancel) {
  const S = g.side;
  document.body.classList.remove("swiping");
  NO_CLICK_UNTIL = Date.now() + 400;
  if (!S || !S.el) return;
  const W = S.W, x = S.x || 0, sign = x > 0 ? 1 : -1, v = speedOf(g);
  const going = !cancel && S.nb && x !== 0 && (Math.abs(x) > W * 0.5 ? v * sign > -0.2 : v * sign > 0.3 && Math.abs(x) > 16);
  const to = going ? sign * W : 0;
  const finish = () => {
    SIDE_ANIM = null;
    S.el.style.transition = "none"; S.el.style.willChange = ""; place(S.el, 0);
    requestAnimationFrame(() => { S.el.style.transition = ""; });
    if (going) {
      const tg = S.dir === "prev" ? (g.edge === "l" && standalone() && VIEW ? BACK() : sideTargetOf("prev")) : sideTargetOf("next");
      if (tg) {
        if (tg.whole) { ENTER = "none"; tg.run(); stillen(document.getElementById("main")); }
        else { tg.run(); if (SWIPE && SWIPE.el) stillen(SWIPE.el); }
        NO_CLICK_UNTIL = Date.now() + 400;
      }
    }
    if (S.layer) S.layer.remove();
  };
  if (!motionOK() || Math.abs(to - x) < 1) { finish(); return; }
  const rest = Math.abs(to - x), speed = Math.abs(v);
  const ms = Math.round(Math.max(160, Math.min(360, speed > 0.05 ? rest / speed : 360)));
  const slope = speed * ms / rest, x1 = 0.2, y1 = Math.max(0.05, Math.min(1, x1 * slope));
  const ease = `transform ${ms}ms cubic-bezier(${x1}, ${y1.toFixed(3)}, 0.25, 1)`;
  S.el.style.transition = ease; place(S.el, to);
  if (S.layer) { S.layer.style.transition = ease; S.layer.style.transform = `translate3d(${to - sign * W}px,0,0)`; }
  const t = setTimeout(finish, ms + 30);
  SIDE_ANIM = { end: () => { clearTimeout(t); finish(); } };
}
function sideTargetOf(dir) { return SWIPE && SWIPE[dir] ? SWIPE[dir]() : null; }


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
  const colA = h("div", {}), colB = h("div", {});
  colA.append(h("section", { class: "section" }, h("h2", { text: "Monthly banking" }), visitCard()));
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
  const m = (SNAP && SNAP.machine) || {};
  const asleep = SNAP && hoursSince(SNAP.checked_at) > STALE_HOURS;
  if (m.state === "stuck" || asleep) {
    const t = m.state === "stuck" ? "Your books are not updating" : "The MacBook is asleep";
    const d = (asleep ? `These figures are from ${ago(SNAP.checked_at)}. ` : "") + "Keep sending: nothing is lost, and it is added when the MacBook catches up.";
    out.push(alert(m.state === "stuck" ? "red" : "orange", m.state === "stuck" ? "warn" : "moon", t, d,
      h("button", { class: "btn small gray", type: "button", onclick: () => openView({ type: "settings" }) }, "Details")));
  }
  if (m.collect_failed_since && !asleep) out.push(alert("orange", "warn", "The MacBook cannot collect your entries",
    `Since ${ago(m.collect_failed_since)}${m.collect_failed_reason ? ` (${m.collect_failed_reason})` : ""}. They wait in your mailbox, safe, until it can.`, null));
  for (const c of ((SNAP && SNAP.cards && SNAP.cards.cards) || [])) {
    for (const it of (c.items || [])) {
      if (it.status !== "ACT" && it.status !== "MISSED") continue;
      out.push(alert("orange", "warn", `${c.name}: ${cardItemName(it.item).toLowerCase()}`, it.note,
        h("button", { class: "btn small tinted", type: "button", onclick: () => { save("sumpart", "cards"); go("numbers"); } }, "Open the card")));
    }
  }
  const wp = (SNAP && SNAP.work_pay) || {};
  const nWp = (wp.chase || 0) + (wp.ask || 0);
  if (nWp) out.push(alert("orange", "warn", `${plural(nWp, "payment for work needs", "payments for work need")} you`,
    [wp.chase ? plural(wp.chase, "is overdue", "are overdue") : "", wp.ask ? `${wp.ask} to explain or place` : ""].filter(Boolean).join("; ") + ".",
    h("button", { class: "btn small tinted", type: "button", onclick: () => { save("workpart", "owed"); go("work"); } }, "Open Work")));
  return out;   // the key, then what only he can put right, then what is unsent, then the MacBook, then a card, then work pay
}

function lastBusinessDay(y, m) {
  const d = new Date(y, m + 1, 0);
  while (d.getDay() === 0 || d.getDay() === 6) d.setDate(d.getDate() - 1);
  return d;
}
function visitDate(pd) {
  if (pd.visit) return pd.visit;     // never paired with another month's date; visitCard says when it has passed (r2-page-05)
  const t = new Date(), lbd = lastBusinessDay(t.getFullYear(), t.getMonth());
  t.setHours(0, 0, 0, 0);
  return t <= lbd ? isoOf(lbd) : (pd.next_visit || isoOf(lastBusinessDay(t.getFullYear(), t.getMonth() + 1)));
}

function visitName(what) {
  let m = /^Pay yourself: (?:the )?(.+?)(?: for \w+)?$/i.exec(what);
  if (m) return "Your " + m[1];
  m = /^Pay ([^:]+): (?:the )?(.+?)(?: for \w+)?$/i.exec(what);
  if (m) return `${m[1]} ${m[2]}`;
  m = /^Pay (?:the )?(.+?) balance$/i.exec(what);
  if (m) return m[1].replace(/^./, c => c.toUpperCase());
  return what;
}
function stepState(pd, n) {
  if (!pd) return "later";
  if (n === 1) return (pd.documents || []).some(d => d.state === "todo") ? "now" : "done";
  if (n === 2) return pd.ready ? "done" : "now";
  if (pd.logged) return "done";
  return pd.ready ? "now" : "later";
}
function sittingStep(pd) {
  if (!pd) return 1;
  for (const n of [1, 2, 3]) if (stepState(pd, n) === "now") return n;
  return 5;
}
const STEP_WORDS = {
  1: "Next: step 1, download this month's documents",
  2: "Next: step 2, run CRA's calculator on the MacBook",
  3: "Next: step 3, pay yourself and CRA, then step 4, the form",
  5: "Done for this month",
};
function visitCard() {
  const pd = SNAP.payday;
  const c = h("section", { class: "visit glass", "aria-label": "Monthly banking" });
  if (!pd) { c.append(h("p", { class: "muted", text: "Nothing planned yet." })); return c; }
  const iso = visitDate(pd);
  const passed = iso < todayISO();
  const known = pd.items.filter(i => money(i.amount));
  const est = i => (i.basis || "").startsWith("estimate");
  const ring = () => h("span", { class: "bd estimate", "aria-hidden": "true" });
  const anyEst = known.some(est);
  const total = known.reduce((a, i) => a + money(i.amount), 0);
  const months = visitMonths(pd);
  const step = sittingStep(pd);
  c.append(h("div", { class: "when-line" },
    h("span", { class: "when", text: dayName(iso, { weekday: "short", day: "numeric", month: "long" }) }),
    h("span", { class: "in", text: rel(iso) }),
    h("span", { class: "chev-go", "aria-hidden": "true" }, icon("chevR"))));
  if (passed) c.append(h("p", { class: "foot warnline", text: "This visit's date has passed and the MacBook has not updated since: the next one is worked out when it does." }));
  for (const m of (pd.missed || [])) c.append(h("p", { class: "foot warnline", text: `${m}'s banking day has no payroll calculation on record: was it done? If the PDF exists, put it in the Inbox.` }));
  if (known.length) {
    const what = months.length === 1 ? `to pay for ${months[0]}` : "to pay";
    c.append(h("div", { class: "total" },
      h("span", { class: "v num" }, (anyEst ? "about " : "") + (anyEst ? fmtWhole$(Math.round(total)) : fmt$(total)), anyEst ? ring() : null),
      h("span", { class: "l", text: (pd.logged ? what.replace(/^to pay/, "paid") : what) + (pd.ready ? "" : " (last month's figures until step 2 is done)") })));
  }
  c.append(visitItemsEl(pd));
  if (pd.ready) c.append(h("p", { class: "visit-foot" }, h("span", { text: `${months[0] || "This month"}'s own calculation has been read: these are the amounts${pd.logged ? ", paid" : " to pay"}.` })));
  else c.append(h("p", { class: "visit-foot" }, ring(), h("span", { text: "Last month's figures: step 2 replaces them with this month's own." })));
  if (pd.logged) c.append(h("p", { class: "foot", text: `Logged ${dayName(pd.logged.date, { day: "numeric", month: "long" })}` + (money(pd.logged.sweep) ? `: ${fmt$(pd.logged.sweep)} sent to Questrade.` : ".")
    + (pd.next_visit ? ` Nothing more until ${dayName(pd.next_visit, { weekday: "long", day: "numeric", month: "long" })}.` : "") }));
  else c.append(h("p", { class: "foot", text: STEP_WORDS[step] + "." }));
  if ((pd.year_end || []).length) c.append(h("p", { class: "foot", text: `December: look once more before the 31st (${pd.year_end.length} thing${pd.year_end.length === 1 ? "" : "s"}, on the steps page).` }));
  c.append(h("button", { class: "btn primary wide", type: "button", onclick: () => openView({ type: "sitting" }) }, "Open the day's steps"));
  return tapArea(c, `Monthly banking, ${sittingName().toLowerCase()}: every step of the day`, () => openView({ type: "sitting" }));
}
function visitMonths(pd) {
  return [...new Set(pd.items.map(i => (/ for (January|February|March|April|May|June|July|August|September|October|November|December)$/.exec(i.what) || [])[1]).filter(Boolean))];
}
function visitItemsEl(pd) {
  const est = i => (i.basis || "").startsWith("estimate");
  const ring = () => h("span", { class: "bd estimate", "aria-hidden": "true" });
  const months = visitMonths(pd);
  const items = h("div", { class: "items" });
  for (const it of pd.items) {
    const name = months.length === 1 ? visitName(it.what) : it.what.replace(/^Pay yourself: /, "Pay yourself ");
    items.append(h("div", { class: "item", title: it.what + (it.basis ? " · " + it.basis : "") }, h("span", { class: "what", text: name }),
      it.amount ? h("span", { class: "amt num" }, est(it) ? ring() : null, h("span", { text: est(it) ? fmtWhole$(Math.round(money(it.amount))) : fmt$(it.amount) }),
                    est(it) ? h("span", { class: "sr", text: " (an estimate)" }) : null)
                : h("span", { class: "onscreen", text: "full balance" })));
  }
  return items;
}
function renderSitting() {
  const pd = SNAP && SNAP.payday;
  const p = h("div", { class: "page narrow" });
  if (!pd) { p.append(head("Monthly banking", "Your one day a month.")); p.append(h("p", { class: "muted", text: "Nothing planned yet." })); return p; }
  const iso = visitDate(pd), mon = pd.month || dayName(iso, { month: "long" });
  const now = sittingStep(pd);
  p.append(head("Monthly banking", `${dayName(iso, { weekday: "long", day: "numeric", month: "long" })}, ${rel(iso)}: ${sittingName().toLowerCase()}, or the last business day before it. Your one day a month, in this order; then nothing until the next.`));
  const asleep = SNAP && hoursSince(SNAP.checked_at) > STALE_HOURS;
  if (asleep) p.append(h("div", { class: "alert orange" }, h("span", { class: "ico orange" }, icon("moon")),
    h("div", { class: "t", text: "Open the MacBook first" }), h("div", { class: "d", text: "Steps 1 to 3 need it awake: it files what you download, runs CRA's calculator, and sends this page the amounts." })));
  const step = (n, title, state, note, body) => {
    const s = h("section", { class: "section" }, h("h2", {}, `${n}. ${title}`, state ? h("span", { class: "chip " + (state === "done" ? "green" : state === "now" ? "orange" : ""), text: state === "done" ? "done" : state === "now" ? "next" : "later" }) : null));
    if (note) s.append(h("p", { class: "foot", text: note }));
    if (body) s.append(body);
    return s;
  };
  const stateOf = n => stepState(pd, n);
  const docs = h("div", {});
  const sites = [...new Set((pd.documents || []).map(d => d.site))];
  const mark = d => d.state === "filed" ? h("span", { class: "ico green" }, icon("check")) : d.state === "inbox" ? h("span", { class: "ico orange" }, icon("tray")) : d.state === "none" ? h("span", { class: "ico gray" }, icon("moon")) : h("span", { class: "ico gray" }, icon("receipt"));
  for (const site of sites) {
    const ul = h("div", { class: "list glass" });
    for (const d of (pd.documents || []).filter(x => x.site === site)) {
      ul.append(h("div", { class: "row", title: d.what }, mark(d), h("span", { class: "main" }, h("span", { class: "title", text: d.get || d.what }),
        h("span", { class: "meta", text: (d.detail ? d.detail.replace(/^./, c => c.toUpperCase()) + " · " : "") + d.by })),
        h("span", { class: "chip " + (d.state === "filed" ? "green" : d.state === "inbox" ? "orange" : ""), text: d.state === "filed" ? "in" : d.state === "inbox" ? "arrived" : d.state === "none" ? "none yet" : "to get" })));
    }
    docs.append(h("div", { class: "section-h" }, h("span", { text: site })), ul);
  }
  for (const w of (pd.inbox || [])) docs.append(h("p", { class: "foot warnline", text: `In the Inbox, waiting for a session: ${w.what || w.name} (${w.why}).` }));
  const todo = (pd.documents || []).filter(d => d.state === "todo").length;
  p.append(step(1, "Download the documents", stateOf(1),
    `Log in to each website below in turn and save each file to iCloud Drive › Finance System Inbox (on the phone) or Finance System › Documents › Inbox (on the MacBook). The MacBook files and reads each one within 15 minutes of being open; a green tick here means it is in. ${todo ? `${todo} still to get.` : "All in."} If a tick has not come after 15 minutes with the MacBook open, the file is named below this list with the reason, or Today says the MacBook is asleep.`, docs));
  const calc = pd.calculation || {};
  const s2 = h("div", { class: "card glass" },
    h("p", { text: "On the MacBook: open the Finance System folder, then its tools folder, and double-click Monthly Banking. A black window opens and a browser window follows; watch it type this month's figures into CRA's calculator (about a minute)." }),
    h("p", { text: `It ends with "Done: the PDF is in the Inbox", then "Read" and ${mon}'s two amounts; this page shows them within a minute (pull down to refresh). If the window says "Stopped" or "did not finish", read it: it says what to do, and the figures it printed are right either way.` }));
  p.append(step(2, "CRA's payroll calculator", stateOf(2), pd.ready ? `${mon}'s calculation has been read: the two amounts under step 3 are its own.`
    : calc.state === "inbox" ? `Not read yet: ${calc.detail}. The two amounts under step 3 are last month's until it is read.`
    : `Not done yet: the two amounts under step 3 are last month's until this runs.`, s2));
  const pay = h("div", { class: "visit glass" }, visitItemsEl(pd));
  const own = `your personal chequing account${pd.net_pay_to ? ` (ending ${pd.net_pay_to})` : ""}`;
  const how = `in this order: the net pay as a transfer to ${own}, then the remittance to CRA as a Government Tax Payment of the type Federal payroll deductions (the payroll account).`;
  p.append(step(3, "Pay yourself, then CRA", stateOf(3), pd.ready
    ? `From corporate chequing, ${how} The two cards are step 4's, not this step's.`
    : `Not yet: do step 2 first. The two lines below are last month's figures, and this month's may differ. Pay only what ${mon}'s own calculation says. Then, out of corporate chequing, ${how}`, pay));
  const visa = (pd.cards || []).find(c => c.id === "visa"), amex = (pd.cards || []).find(c => c.id === "amex");
  const cardWords = (visa ? `The corporate Visa: ${visa.note}. ` : "") + (amex ? `The Amex: ${amex.note}. ` : "");
  p.append(step(4, "Log the day, send the sweep", stateOf(4), `${cardWords}Then, on the form: tick the two payments once the money has left chequing, type what each card still owes (that money is kept back in chequing) and the chequing balance you see, and the amount to send to Questrade appears: the sweep, what is left once the payments, the cards, the bills due before the next banking day and a cushion are kept back. Send that amount from corporate chequing as a bill payment to Questrade, the corporation's cash account, then type it in the last box.`,
    pd.logged ? h("p", { class: "foot", text: `Logged ${dayName(pd.logged.date, { day: "numeric", month: "long" })}` + (money(pd.logged.sweep) ? `: ${fmt$(pd.logged.sweep)} sent to Questrade.` : ".") })
              : h("button", { class: "btn primary wide", type: "button", onclick: () => startForm("bankvisit", null, "today") }, "Log monthly banking")));
  if ((pd.year_end || []).length) {
    const ye = h("div", { class: "list glass" });
    for (const r of pd.year_end) ye.append(h("div", { class: "row" },
      h("span", { class: "main" }, h("span", { class: "title", text: r.what.split(/[:;]\s|\.\s/)[0] }), h("span", { class: "meta", text: dayName(r.date, { weekday: "short", day: "numeric", month: "long" }) })),
      money(r.amount) ? h("span", { class: "amt", text: "$" + Math.round(money(r.amount)).toLocaleString("en-CA") }) : h("span", {})));
    p.append(step(5, "Before the 31st, look once more", null, "December only: what falls between this day and the year end, so that it and both pay legs clear inside the year.", ye));
  }
  return p;
}

function upcoming() {
  const s = h("section", { class: "section" }, h("h2", { text: "Coming up" }));
  const due = (SNAP.due || []);
  if (!due.length) { s.append(h("div", { class: "card glass" }, h("p", { class: "muted", text: "Nothing in the next six weeks." }))); return s; }
  const ul = h("div", { class: "list glass" });
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
    const via = d.paid_via ? true : /^(already )?paid (by|through) the Chexy charge on the (\d{1,2})(st|nd|rd|th)/i.exec(rest);
    let paid = false, viaNote = "";
    if (via) {
      const t = new Date(); t.setHours(0, 0, 0, 0);
      const chargeDay = d.paid_via ? dateOf(d.paid_via) : (dateOf(d.date) ? new Date(dateOf(d.date).getFullYear(), dateOf(d.date).getMonth(), +via[3]) : null);
      paid = !!d.paid_already;
      if (!d.paid_via) {
        const from = chargeDay ? isoOf(new Date(chargeDay.getTime() - 3 * 864e5)) : d.date;
        const cra = (SNAP.cra_tax && SNAP.cra_tax.payments) || [];
        paid = cra.some(p => p.date >= from && p.date <= d.date && Math.abs(money(p.amount) - money(d.amount)) < 1);
      }
      viaNote = paid ? "paid via Chexy" : chargeDay && chargeDay <= t ? "via Chexy, not yet confirmed" :
        `via Chexy, ${chargeDay ? monthDay(isoOf(chargeDay)) : "the 20th"}`;
      rest = "";
    }
    const est = (d.basis || "").startsWith("estimate") && !via;
    const detail = rest ? rest.replace(/^./, c => c.toUpperCase()).replace(/(^|[^$\d.,])(\d{1,3}(?:,\d{3})*\.\d{2})\b/g, "$1$$$2") : "";
    const more = !!detail || title.length > 30;
    const main = h("span", { class: "main" }, h("span", { class: "title one", text: title }),
      h("span", { class: "meta" }, h("span", { text: rel(d.date).replace(/^./, c => c.toUpperCase()) + (viaNote ? " · " + viaNote : "") }),
        more ? h("span", { class: "chev-d", "aria-hidden": "true" }, icon("chevR")) : null),
      detail ? h("span", { class: "detail", text: detail }) : null);
    const incoming = d.direction === "in";
    const amount = d.amount && Number(d.amount) ? h("span", { class: "amt" + (paid ? " paid" : via ? " covered" : "") + (incoming ? " in" : "") },
      est ? h("span", { class: "about", text: "about" }) : null, h("span", { text: (incoming ? "+" : "") + "$" + Math.round(money(d.amount)).toLocaleString("en-CA") })) : h("span", {});
    const row = more ? h("button", { class: "row due", type: "button", "aria-expanded": "false" }, leaf, main, amount) : h("div", { class: "row due" }, leaf, main, amount);
    if (more) row.addEventListener("click", () => { const o = row.classList.toggle("open"); row.setAttribute("aria-expanded", String(o)); });
    ul.append(row);
  }
  s.append(ul);
  if (due.some(d => (d.basis || "").startsWith("estimate"))) s.append(h("p", { class: "foot", text: "Amounts are as planned in your calendar: estimates until paid. Tap a line for its details." }));
  return s;
}

function receiptRow(q, from, redraw) {
  const r = receiptOf(q), dt = dateOf(r.date);
  const leaf = () => h("span", { class: "day", "aria-hidden": "true" }, h("span", { class: "wd", text: dt.toLocaleDateString("en-CA", { weekday: "short" }) }),
    h("span", { class: "dn", text: String(dt.getDate()) }), h("span", { class: "mo", text: dt.toLocaleDateString("en-CA", { month: "short" }) }));
  const keep = canKeepWithout(q) && redraw;
  const row = h("div", { class: "row" }, leaf(),
    h("span", { class: "main" }, h("span", { class: "title", text: r.what }), h("span", { class: "meta", text: r.problem }),
      keep ? h("button", { class: "btn small gray keep", type: "button", onclick: () => {
        const entry = keepWithout(q);
        row.replaceWith(h("div", { class: "row kept" }, leaf(),
          h("span", { class: "main" }, h("span", { class: "title", text: "Kept without a receipt" }), h("span", { class: "meta", text: `${r.what}, ${r.amount}` })),
          h("button", { class: "link", type: "button", onclick: () => { submit("withdraw", {}, entry.id, "Back on your list. Sending…"); redraw(); } }, "Undo")));
      } }, "Keep without a receipt") : null),
    h("span", { class: "amt", text: r.amount }));
  return tapArea(row, `${r.what}, ${r.amount}, ${shortDate(r.date)}. ${r.problem}. Answer`, () => startForm("answer", { question: q.id }, from));
}
function questionRow(q, from) {
  if (receiptOf(q)) return receiptRow(q, from);
  const n = daysFrom(q.due);
  const wp = q.workpay ? Object.assign({ id: q.id, text: q.text }, q.workpay) : null;
  return h("button", { class: "row plain", type: "button", onclick: () => q.chq ? chqAnswer(q, from) : wp ? workpayAnswer(wp) : startForm("answer", { question: q.id }, from) },
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
  let qs = [], rs = [];
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
    const all = openQuestions();          // again each time: one kept without a receipt, or put back, has moved
    qs = all.filter(q => !receiptOf(q)); rs = all.filter(q => receiptOf(q));
    const t = inp.value.trim().toLowerCase();
    const match = q => !t || prettyDates(q.text).toLowerCase().includes(t);
    const q1 = qs.filter(match), r1 = rs.filter(match).sort((a, b) => receiptOf(a).date.localeCompare(receiptOf(b).date));
    if (q1.length) { const ul = h("div", { class: "list glass" }); for (const q of q1) ul.append(questionRow(q, "today")); holder.append(ul); }
    else if (t && r1.length) holder.append(h("p", { class: "foot", text: "No questions match; these receipts do." }));
    if (r1.length) {
      const ul = h("div", { class: "list glass" });
      for (const q of r1) ul.append(receiptRow(q, "today", draw));
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


function startForm(kind, prefill, from) {
  const d = !prefill ? load("drafts", {})[kind] : null;
  openView({ type: "form", kind, corrects: "", prefill: prefill || d || null, restored: !!d, from: from || "add" });
}

const draftKeyOf = (kind, corrects) => corrects ? "fix:" + corrects : kind;
function startCorrect(e, from) {
  const d = load("drafts", {})[draftKeyOf(e.kind, e.id)];
  openView({ type: "form", kind: e.kind, corrects: e.id, prefill: d || e.fields || {}, restored: !!d, label: e.summary, from: from || "add" });
}
let DRAFT_NOW = null;
function saveDraftNow() { if (DRAFT_NOW) { const f = DRAFT_NOW; DRAFT_NOW = null; f(); } }
function withdraw(e) {
  sheet("Delete this entry?", prettyDates(e.summary || summaryOf(e)) + ". It comes out of your books; the record keeps a copy, marked as deleted.",
    [{ label: "Delete it", kind: "danger", run: () => { submit("withdraw", {}, e.id); render(); } }]);
}

function renderAdd() {
  const p = h("div", { class: "page" });
  p.append(head("Add", "The MacBook files what you send within 15 minutes of being open.", true));
  const forms = formsList();
  if (!forms.length) { p.append(h("div", { class: "card glass" }, h("p", { class: "muted", text: "The forms have not arrived yet. They come with the first summary." }))); return p; }
  const all = openQuestions(), rc = all.filter(q => receiptOf(q)).length, qc = all.length - rc;
  const descOf = f => f.kind === "answer" ? (all.length ? [qc ? plural(qc, "question") : "", rc ? plural(rc, "receipt") + " to explain" : ""].filter(Boolean).join(", ") : "None waiting") : (kindOf(f.kind).desc || f.title);
  const drafts = load("drafts", {});
  const draftTag = f => drafts[f.kind] ? h("span", { class: "chip blue", text: "draft" }) : null;
  const group = g => forms.filter(f => (kindOf(f.kind).group || "sometimes") === g);
  const tiles = h("div", { class: "tiles" });
  for (const f of group("often")) {
    const k = kindOf(f.kind);
    tiles.append(h("button", { class: "tile glass", type: "button", onclick: () => startForm(f.kind) },
      h("span", { class: "tile-top" }, h("span", { class: "ico " + k.color }, icon(k.icon)), draftTag(f)),
      h("div", { class: "t", text: k.name }), h("div", { class: "d", text: descOf(f) })));
  }
  p.append(tiles);
  if (forms.some(f => f.kind === "shift")) {
    const mine = allShifts(), needs = mine.filter(x => missingOf(x).some(m => m !== "hours")).length;
    p.append(h("div", { class: "list glass" }, h("button", { class: "row", type: "button", onclick: () => { save("workpart", "shifts"); go("work"); } },
      h("span", { class: "ico blue" }, icon("work")),
      h("span", { class: "main" }, h("span", { class: "title", text: "Your shifts" }),
        h("span", { class: "meta", text: mine.length ? `${plural(mine.length, "shift")} sent from here` + (needs ? ` · ${needs} missing pay or patients` : "") : "Add hours, patients or pay to a shift later" })),
      h("span", { class: "trail" }, needs ? h("span", { class: "chip orange", text: String(needs) }) : null, icon("chevR")))));
  }
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
    case "shift": return `${shiftTitle(f)}, ${shortDate(f.date)}`;
    case "expense": return `${f.what || "Paid it myself"} · ${fmt$(f.amount)}`;
    case "bankvisit": return `Monthly banking ${shortDate(f.date)}`;
    case "income": return `Income ${fmt$(f.amount)}`;
    case "registered": return `${fmt$(f.amount)} ${f.direction === "withdrawal" ? "out of" : "into"} ${(f.account || "").replace(/^qt-/, "").toUpperCase()}`;
    case "reading": return `Reading: ${f.value || ""}`;
    case "card": return "Card change";
    case "life": return "Change: " + (f.text || "").slice(0, 60);
    case "answer": {
      const q = ((SNAP && SNAP.questions) || []).find(x => x.id === f.question), r = q && receiptOf(q);
      if (f.resolution === NO_RECEIPT) return "Kept without a receipt: " + (r ? `${r.what}, ${r.amount}` : "an expense");
      return "Answer: " + (q ? q.text : "a question");
    }
    case "note": return "Note: " + (f.text || "").slice(0, 80);
    case "withdraw": return "Deleting an entry";
    default: return e.kind;
  }
}


function cardsFoot() {
  const cards = (SNAP && SNAP.payday && SNAP.payday.cards) || [];
  const each = cards.map(c => `${c.name}: ${c.note}.`).join(" ");
  return "Type what each card's screen says it still owes; that money is kept back in chequing. "
    + (each || "The Visa pays itself in the first days of next month, so its balance stays in chequing.");
}
const LAYOUT = {
  shift: [
    { h: "When", keys: [["date"], ["shift_start", "shift_end"]] },
    { h: "What", keys: [["type"], ["description"]] },
    { more: "Hours and patients", hint: "All optional", keys: [["hours", "travel_hours"], ["patients", "patients_private"], ["period"], ["site"]] },
    { more: "Pay", hint: "All optional", keys: [["amount"], ["pay_base", "pay_shadow"], ["ffs_billed", "shadow_pct"], ["billed_total", "pay_ffs"], ["pay_travel", "pay_stipend"], ["pay_other", "expense_reimbursed"]] },
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
    { h: "What you paid", foot: "Tick each only once the money has left chequing.", keys: [["paid"]] },
    { h: "The cards, kept back", foot: cardsFoot, keys: [["visa_owing"], ["amex_owing"]] },
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
const LABELS = { description: "Which shift", pay_ffs: "Paid, all payers", billed_total: "Submitted, all payers", ffs_billed: "Fees MGH billed", shadow_pct: "Shadow billing %", pay_shadow: "Shadow billing pay", pay_travel: "Travel time paid", patients_private: "Private patients",
                 who_why: "Who was there, and why it was work", receipt: "Where the receipt photo is", balance: "Chequing balance you see now", sweep: "Sent to Questrade (the corporation's cash account)",
                 visa_owing: "Corporate Visa: balance owing", amex_owing: "Amex Business Platinum: balance still owing" };
function labelOf(fld) { return LABELS[fld.key] || fld.label.replace(/\s*\(.*?\)\s*$/, ""); }
function hintOf(fld) { const m = /\((.*)\)\s*$/.exec(fld.label); return m ? m[1] : ""; }

function renderForm() {
  const f = formsList().find(x => x.kind === VIEW.kind);
  const p = h("div", { class: "page narrow" });
  if (!f) { p.append(head("Not available", "This form has not arrived yet.")); return p; }
  const k = kindOf(f.kind);
  const byPlace = f.kind === "shift" && f.fields.some(x => x.key === "place");   // forms of version 3 or later
  if (byPlace && VIEW.corrects) {
    const pre = VIEW.prefill || {};
    p.append(head(shiftTitle(pre), `${dayName(pre.date, { weekday: "long", day: "numeric", month: "long", year: "numeric" })}. Add or change anything; this version replaces the one you sent, and the record keeps both.`));
    p.append(buildShiftForm(f));
    return p;
  }
  p.append(head(VIEW.corrects ? "Correct: " + k.name : k.name, k.help !== undefined ? k.help : f.help));
  if (VIEW.corrects) p.append(h("div", { class: "alert orange" }, h("span", { class: "ico orange" }, icon("pencil")),
    h("div", { class: "t", text: "Correcting " + (VIEW.label || "an entry") }), h("div", { class: "d", text: "The new version replaces it. The old one is kept, marked as corrected." })));
  p.append(byPlace ? buildShiftForm(f) : buildForm(f));
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
    const label = h("label", { for: id }, labelOf(fld), fld.required || inMore || ["who_why", "balance", "visa_owing", "amex_owing"].includes(fld.key) ? null : h("span", { class: "opt", text: "optional" }));
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
        b.addEventListener("click", () => {
          const on = b.getAttribute("aria-checked") !== "true";
          b.setAttribute("aria-checked", String(on));
          if (on) { const bal = form.querySelector('[name="balance"]'); if (bal && String(bal.value || "").trim()) form.dataset.staleBalance = "1"; }
          else if (!form.querySelector('.tick[aria-checked="true"]')) delete form.dataset.staleBalance;
          updateSweep(form);
        });
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
        if (r) {
          box.append(h("span", { class: "small muted", text: r.problem }), h("span", { class: "q", text: `${r.what}, ${r.amount}, on ${shortDate(r.date)}` }),
            h("span", { class: "small muted", text: "What was it, and how was it paid? If there is a receipt, say where it is." }));
          if (canKeepWithout(cur) && !VIEW.corrects) box.append(h("button", { class: "btn tinted wide", type: "button", onclick: () => {
            const d = load("drafts", {}); delete d.answer; save("drafts", d);
            keepWithout(cur); closeView();
          } }, "Keep it without a receipt"));
        } else if (cur) box.append(h("span", { class: "small muted", text: cur.due ? "Due " + shortDate(cur.due) : "Question" }), h("span", { class: "q", text: prettyDates(cur.text) }));
        else box.append(h("span", { class: "q muted", text: "Which question are you answering?" }));
        box.append(h("button", { class: "btn small tinted", type: "button", onclick: () => pickQuestion(hidden, draw) }, cur ? "Choose another" : "Choose a question"));
      };
      draw();
      inputs[fld.key] = hidden; wraps[fld.key] = box;
      const holder = h("div", {}, hidden, box);
      return holder;
    }
    const opts = fld.type === "choice" ? (fld.options || []) : fld.type === "month" ? monthsAround() : null;
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
      if (fld.key === "balance" || fld.key === "visa_owing" || fld.key === "amex_owing")
        inp.addEventListener("input", () => { if (fld.key === "balance") delete form.dataset.staleBalance; updateSweep(form); });
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
        isQuestion ? rows : h("div", { class: "fields glass" }, rows), g.foot ? h("div", { class: "gf", text: typeof g.foot === "function" ? g.foot() : g.foot }) : null));
    }
  }
  const wpRes = f.kind === "answer" ? String((pre || {}).resolution || "") : "";
  const wpShow = { deposit: wpRes === "partly-paid" || wpRes === "paid-by", amount: wpRes === "partly-paid" || wpRes === "paid-amount", expect_by: wpRes === "resubmitted" };
  const rest = f.fields.filter(x => !used.has(x.key) && !(f.kind === "answer" && x.key === "resolution")
                                    && !(f.kind === "answer" && x.key in wpShow && !wpShow[x.key]));
  if (rest.length) form.append(h("div", { class: "group" }, h("div", { class: "fields glass" }, rest.map(fieldEl))));

  const drafts = load("drafts", {});
  const collect = () => {
    const out = {};
    for (const fld of f.fields) {
      const inp = inputs[fld.key];
      if (!inp) continue;
      if (fld.type === "checklist") { const t = Array.from(inp.querySelectorAll('.tick[aria-checked="true"]')).map(x => x.dataset.id); if (t.length) out[fld.key] = t; continue; }
      const val = String(inp.value || "").trim();
      if (val) out[fld.key] = val;
    }
    if (f.kind === "answer" && pre && WORKPAY_RES.has(String(pre.resolution || ""))) {
      out.resolution = pre.resolution;
      if (pre.deposit && !out.deposit) out.deposit = pre.deposit;
    }
    return out;
  };
  form._collect = collect;
  let draftTimer = null, sentAlready = false;
  const typedIn = c => Object.keys(c).some(k => k !== "date");
  const dkey = draftKeyOf(f.kind, VIEW && VIEW.corrects);
  const writeDraft = () => {
    clearTimeout(draftTimer);
    if (sentAlready || !form.isConnected) return;
    const d = load("drafts", {}), c = collect();
    if (typedIn(c)) d[dkey] = c; else delete d[dkey];
    save("drafts", d);
  };
  const keepDraft = () => {
    clearTimeout(draftTimer);
    DRAFT_NOW = writeDraft;
    draftTimer = setTimeout(() => { if (DRAFT_NOW === writeDraft) DRAFT_NOW = null; writeDraft(); }, 400);
  };
  form.addEventListener("input", keepDraft);
  form.addEventListener("change", keepDraft);
  form.addEventListener("click", ev => { if (ev.target.closest && ev.target.closest(".tick")) keepDraft(); });
  if (VIEW.restored) {
    form.prepend(h("div", { class: "draftbar" }, h("span", { text: "Your unsent draft is back." }),
      h("button", { class: "link", type: "button", onclick: () => { const d = load("drafts", {}); delete d[dkey]; save("drafts", d); VIEW.prefill = null; VIEW.restored = false; render(true); } }, "Start again")));
  }

  const syncShowIf = () => {
    for (const fld of f.fields) {
      if (!fld.show_if || !wraps[fld.key]) continue;
      const on = Object.entries(fld.show_if).every(([k, vals]) => inputs[k] && vals.includes(inputs[k].value));
      wraps[fld.key].hidden = !on;
    }
  };
  form.addEventListener("change", syncShowIf); setTimeout(syncShowIf, 0);
  if (f.kind === "reading" && inputs.what && wraps.value) {
    const unitMark = h("span", { class: "unitmark", "aria-hidden": "true" });
    const ip = inputs.value; ip.before(unitMark);
    const syncUnit = () => { const dollars = /value$/.test(inputs.what.value); unitMark.textContent = dollars ? "$" : ""; ip.placeholder = inputs.what.value === "odometer" ? "in km" : ""; };
    inputs.what.addEventListener("change", syncUnit); syncUnit();
  }

  const syncMeal = () => {
    if (!wraps.who_why || !inputs.meal) return;
    wraps.who_why.hidden = inputs.meal.value !== "yes";
  };
  form.addEventListener("change", syncMeal); syncMeal();

  if (f.kind === "bankvisit")
    form.append(h("p", { class: "small muted", text: "This only records the day. It moves no money: make the transfer to Questrade yourself, from corporate chequing, as a bill payment." }));
  form.append(h("div", { class: "formbar" }, h("button", { class: "btn primary", type: "submit" },
    VIEW.corrects ? "Send the correction" : f.kind === "bankvisit" ? "Record the day" : "Send")));
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
    if (fields.receipt) fields.receipt = fields.receipt.replace(/^(\d{4})(\d{2})(\d{2})-(.+?)-(-?\d+(?:\.\d{2})?)(\.\w+)?$/, "$1-$2-$3 $4 - $5");
    if (f.kind === "expense" && fields.meal === "yes" && !fields.who_why) { problems.push("A meal needs who was there and why it was work"); if (wraps.who_why) wraps.who_why.classList.add("bad"); }
    const priv = privateIn(fields, f.fields);
    if (priv) { problems.push(PRIVATE_MSG); if (wraps[priv] && wraps[priv].classList) wraps[priv].classList.add("bad"); }
    if (problems.length) { errors.textContent = problems.join(". ") + "."; errors.hidden = false; window.scrollTo({ top: 0, behavior: "smooth" }); return; }
    sentAlready = true; clearTimeout(draftTimer);
    DRAFT_NOW = null;
    const d = load("drafts", {}); delete d[dkey]; save("drafts", d);
    submit(f.kind, fields, VIEW.corrects);
    closeView();
  });
  if (f.kind === "bankvisit") setTimeout(() => updateSweep(form), 0);
  return form;
}


const SHIFT_LABELS = { hours: "Hours worked", travel_hours: "Travel hours", patients: "Patients seen", patients_private: "Private patients", period: "The month these hours are for",
  amount: "Total pay", pay_base: "Base pay", billed_total: "Submitted, all payers", pay_ffs: "Paid, all payers", ffs_billed: "Fees MGH billed", shadow_pct: "Shadow billing %",
  pay_shadow: "Shadow billing pay", pay_travel: "Travel time paid", pay_stipend: "Stipend", pay_other: "The clinic's fee", expense_reimbursed: "Expenses paid back",
  invoice: "Invoice amount" };
function payLabel(key, place) { return (key === "pay_ffs" && place === "abp") ? SHIFT_LABELS.invoice : SHIFT_LABELS[key]; }
const PAY_KEYS = ["amount", "pay_base", "billed_total", "pay_ffs", "ffs_billed", "shadow_pct", "pay_shadow", "pay_travel", "pay_stipend", "expense_reimbursed"];
const BILLING_KEYS = ["patients_ohip", "billed_ohip", "patients_ifhp", "billed_ifhp", "patients_wsib", "billed_wsib",
                      "patients_private", "pay_other"];
function billingPayers() { const f = shiftForm(); return (f && f.billing) || []; }
const PAID_KEYS = ["amount", "pay_base", "pay_ffs", "pay_shadow", "pay_travel", "pay_stipend", "pay_other"];
const HOUR_KEYS = ["hours", "travel_hours", "patients", "period"];

function shiftForm() { return formsList().find(x => x.kind === "shift"); }
function placeList() { const f = shiftForm(), p = f && f.fields.find(x => x.key === "place"); return (p && p.options) || []; }
function placeInfo(v) { return placeList().find(x => x.value === v) || null; }
function placeOfShift(fields) {
  if (!fields) return "";
  if (fields.place) return fields.place;
  const t = String(fields.type || "");
  const hit = placeList().find(pl => t.startsWith(pl.value + "-"));
  return hit ? hit.value : "";
}
function shiftTitle(fields) {
  const pl = placeInfo(placeOfShift(fields));
  const site = pl && !pl.site ? fields.site : "";
  const name = pl ? pl.label.replace(" consulting", "") : "Shift";
  let d = fields.description || "";
  for (const w of [site, name]) if (w && d.toLowerCase().startsWith(w.toLowerCase() + " ")) d = d.slice(w.length + 1).replace(/^./, c => c.toUpperCase());
  d = d.replace(/,\s*[^,]+$/, m => site && m.toLowerCase().includes(site.toLowerCase()) ? "" : m);
  return [name, site, d].filter(Boolean).join(" · ");
}
function mineFor(place) {
  const out = { sites: [], shifts: [] };
  for (const e of load("outbox", []).concat(load("sent", []).map(x => x.entry))) {
    if (!e || e.kind !== "shift" || !e.fields || placeOfShift(e.fields) !== place) continue;
    if (e.fields.site && !out.sites.includes(e.fields.site)) out.sites.push(e.fields.site);
    if (e.fields.description && !out.shifts.includes(e.fields.description)) out.shifts.push(e.fields.description);
  }
  return out;
}

function combo(o) {
  const wrap = h("div", { class: "field menu combo" });
  const lab = h("label", { for: o.id, text: o.label });
  const sel = h("select", { id: o.id, name: o.name });
  const txt = h("input", { id: o.id + "-new", type: "text", maxlength: 120, autocomplete: "off", autocapitalize: "words", placeholder: o.placeholder || "", hidden: true });
  const back = h("button", { class: "link small combo-back", type: "button", hidden: true }, "Choose from the list");
  const arrows = h("span", { class: "menu-arrows", "aria-hidden": "true" }, icon("updown"));
  let all = new Set(), typing = false;
  const changed = () => { if (o.onChange) o.onChange(api.value); };
  const fill = groups => {
    clear(sel); all = new Set();
    sel.append(h("option", { value: "" }, "Choose…"));
    for (const [g, vals] of groups) {
      const vs = vals.filter(Boolean);
      if (!vs.length) continue;
      const parent = g ? h("optgroup", { label: g }) : sel;
      for (const v of vs) { parent.append(h("option", { value: v }, v)); all.add(v); }
      if (g) sel.append(parent);
    }
    if (!o.noNew) sel.append(h("option", { value: "__new__" }, o.newLabel || "New…"));
  };
  const setTyping = on => {
    typing = on; txt.hidden = !on; sel.hidden = on; arrows.hidden = on; back.hidden = !on || !all.size;
    lab.htmlFor = on ? txt.id : sel.id; wrap.classList.toggle("menu", !on);
  };
  sel.addEventListener("change", () => { if (sel.value === "__new__") { setTyping(true); txt.value = ""; txt.focus(); } changed(); });
  txt.addEventListener("input", changed);
  back.addEventListener("click", () => { setTyping(false); sel.value = ""; sel.focus(); changed(); });
  const api = {
    el: wrap, input: () => (typing ? txt : sel),
    get value() { return typing ? txt.value.trim() : (sel.value === "__new__" ? "" : sel.value); },
    set value(v) { if (!v && all.size) { setTyping(false); sel.value = ""; } else if (all.has(v)) { setTyping(false); sel.value = v; } else { setTyping(true); txt.value = v || ""; } },
  };
  wrap.append(lab, arrows, sel, txt, back);
  fill(o.groups || []);
  api.value = o.value || "";
  return api;
}

function numField(key, value, onInput, label) {
  const id = "f-shift-" + key;
  const wrap = h("div", { class: "field" }, h("label", { for: id, text: label || SHIFT_LABELS[key] || key }));
  if (key === "period") {
    const sel = h("select", { id, name: key });
    sel.append(h("option", { value: "" }, "Choose the month…"));
    const months = monthsAround();
    if (value && !months.some(o => o.value === value)) months.push({ value, label: keyLabel(value, true) });   // an older month, kept
    for (const o of months) sel.append(h("option", { value: o.value, selected: o.value === value }, o.label));
    wrap.classList.add("menu");
    wrap.append(h("span", { class: "menu-arrows", "aria-hidden": "true" }, icon("updown")), sel);
    sel.addEventListener("change", () => onInput(key, sel.value));
    return { el: wrap, input: sel };
  }
  const isMoney = PAY_KEYS.includes(key) && key !== "shadow_pct";
  const inp = h("input", { id, name: key, type: "text", inputmode: "decimal", autocomplete: "off", maxlength: 12,
                           placeholder: key === "hours" ? "Leave blank to use your phone's measure" : key === "amount" ? "Leave blank to add up the parts above" : key === "patients" ? "How many you saw" : "" });
  inp.value = value || "";
  const unit = key === "shadow_pct" ? "%" : key === "hours" || key === "travel_hours" ? "h" : "";
  wrap.append(h("div", { class: "money" }, isMoney ? h("span", { text: "$", "aria-hidden": "true" }) : null, inp, unit ? h("span", { text: unit, "aria-hidden": "true" }) : null));
  if (key === "amount") wrap.append(h("span", { class: "small muted", text: "Paid as part of a block, on another shift? Type 0." }));
  inp.addEventListener("input", () => onInput(key, inp.value));
  if (isMoney) inp.addEventListener("blur", () => { const n = money(inp.value); if (inp.value.trim() && n !== null) { inp.value = n.toLocaleString("en-CA", { minimumFractionDigits: 2, maximumFractionDigits: 2 }); onInput(key, inp.value); } });
  return { el: wrap, input: inp };
}

function buildShiftForm(f) {
  const form = h("form", { novalidate: true, class: "shiftform" });
  const pre = Object.assign({}, VIEW.prefill || {});
  const known = new Set(f.fields.map(x => x.key));
  const vals = Object.assign({}, pre);
  if (!vals.place) vals.place = placeOfShift(pre);
  if (!vals.date) vals.date = todayISO();
  const origPlace = vals.place, origDesc = pre.description || "";
  const errors = h("div", { class: "errors", role: "alert", hidden: true });
  form.append(errors);
  const drafts = () => load("drafts", {});
  const dkey = draftKeyOf("shift", VIEW && VIEW.corrects);
  if (VIEW.restored) {
    form.append(h("div", { class: "draftbar" }, h("span", { text: "Your unsent draft is back." }),
      h("button", { class: "link", type: "button", onclick: () => { const d = drafts(); delete d[dkey]; save("drafts", d); VIEW.prefill = null; VIEW.restored = false; render(true); } }, "Start again")));
  }
  let draftTimer = null, sent = false;
  const writeDraft = () => {
    clearTimeout(draftTimer);
    if (sent || !form.isConnected) return;
    const d = drafts(), c = collect();
    const typed = Object.keys(c).filter(k => !(k === "date" && c.date === todayISO()));
    if (typed.length) d[dkey] = c; else delete d[dkey];
    save("drafts", d);
  };
  const keepDraft = () => {
    clearTimeout(draftTimer);
    DRAFT_NOW = writeDraft;
    draftTimer = setTimeout(() => { if (DRAFT_NOW === writeDraft) DRAFT_NOW = null; writeDraft(); }, 400);
  };
  const setVal = (k, v) => { vals[k] = v; keepDraft(); };

  const date = h("input", { id: "f-shift-date", name: "date", type: "date" });
  date.value = vals.date;
  const yday = h("button", { class: "btn small gray", type: "button" }, "Yesterday");
  const syncY = () => { yday.textContent = date.value === todayISO() ? "Yesterday" : "Today"; };
  yday.addEventListener("click", () => { const d = new Date(); if (date.value === todayISO()) d.setDate(d.getDate() - 1); date.value = isoOf(d); setVal("date", date.value); syncY(); });
  date.addEventListener("input", () => { setVal("date", date.value); syncY(); });
  date.addEventListener("change", () => { setVal("date", date.value); syncY(); });
  syncY();
  const dateWrap = h("div", { class: "field datefield" }, h("label", { for: "f-shift-date", text: "Date" }), h("div", { class: "daterow" }, date, yday));
  const identity = h("div", { class: "shiftpart" });
  const moreBox = h("div", { class: "shiftpart" });
  identity.append(h("div", { class: "group" }, h("div", { class: "fields glass" }, dateWrap)));

  const places = placeList();
  const pills = h("div", { class: "pills", role: "radiogroup", "aria-label": "Where you worked" });
  for (const pl of places) {
    const b = h("button", { type: "button", role: "radio", "aria-checked": String(pl.value === vals.place), "data-place": pl.value }, pl.label.replace(" consulting", ""));
    b.addEventListener("click", () => {
      if (vals.place === pl.value) return;
      vals.place = pl.value;
      for (const x of pills.children) x.setAttribute("aria-checked", String(x === b));
      if (wraps.place) wraps.place.classList.remove("bad");
      vals.site = ""; vals.description = "";
      const fromLedger = ((SNAP && SNAP.defaults && SNAP.defaults.shift_by_place) || {})[pl.value];
      const mineLast = load("outbox", []).concat(load("sent", []).map(x => x.entry), ((SNAP && SNAP.shifts) || []).map(x => ({ kind: "shift", fields: x.fields })))
        .filter(e => e && e.kind === "shift" && e.fields && placeOfShift(e.fields) === pl.value && e.fields.site && !/stipend/i.test(e.fields.description || ""))
        .sort((a1, b1) => String(b1.fields.date).localeCompare(String(a1.fields.date)))[0];
      const last = mineLast && (!fromLedger || String(mineLast.fields.date) >= String(fromLedger.date || "")) ? mineLast.fields : fromLedger;
      if (last && last.site && !pl.site) { vals.site = last.site; vals.siteAuto = true; }
      keepDraft(); drawRest(true);
    });
    pills.append(b);
  }
  const wraps = { place: pills };
  identity.append(h("div", { class: "group" }, h("div", { class: "gh", text: "Where" }), pills,
    h("div", { class: "gf", text: "Somewhere new? Send a note: it is set up on the MacBook, then appears here." })));

  const rest = h("div", { class: "shiftpart" });
  identity.append(rest);
  if (VIEW.details) {
    form.append(moreBox, h("details", { class: "more glass identity" },
      h("summary", {}, h("span", {}, "Date, place and shift", " ", h("span", { class: "hint", text: "Change them only if they were wrong" })), icon("chevR")),
      h("div", { class: "identity-in" }, identity)));
  } else form.append(identity, moreBox);
  let site = null, shift = null, stipendMonth = null;
  const inputs = {};
  function syncStipend() {
    if (!stipendMonth) return;
    const on = /stipend/i.test(shift ? shift.value : vals.description || "");
    stipendMonth.el.hidden = !on;
    if (on) inputs.period = stipendMonth.input; else { delete inputs.period; stipendMonth.input.value = ""; }
  }
  function drawRest(focus) {
    clear(rest); clear(moreBox);
    const pl = placeInfo(vals.place);
    site = null; shift = null;
    for (const k of Object.keys(inputs)) delete inputs[k];
    if (!pl) return;
    const mine = mineFor(pl.value);
    const box = h("div", { class: "fields glass" });
    if (!pl.site) {
      const sites = pl.sites.slice();
      site = combo({ id: "f-shift-site", name: "site", label: vals.siteAuto && vals.site ? "Site, as your last shift there" : "Site", groups: [[null, sites]], value: vals.site || "", noNew: true, placeholder: "The town or clinic",
                     onChange: v => { setVal("site", v); if (shift) { const cur = shift.value; shift.el.replaceWith((shift = shiftCombo(pl, mine, cur)).el); } } });
      box.append(site.el);
      box.append(h("p", { class: "foot", text: "A site not listed? Send a Note saying where: it is added on the MacBook, then appears here." }));
    }
    shift = shiftCombo(pl, mine, vals.description || "");
    box.append(shift.el);
    stipendMonth = null;
    if (pl.value === "edlp") {
      stipendMonth = numField("period", vals.period, setVal, "The month the stipend is for");
      box.append(stipendMonth.el);
      syncStipend();
    }
    rest.append(h("div", { class: "group" }, box));
    const asks = pl.asks || ["hours"];
    const section = (title, hint, keys, open) => {
      const rows = keys.map(k => { const nf = numField(k, vals[k], setVal, payLabel(k, pl.value)); inputs[k] = nf.input; return nf.el; });
      if (!rows.length) return null;
      return h("details", { class: "more glass", open: open || keys.some(k => vals[k]) },
        h("summary", {}, h("span", {}, title, " ", h("span", { class: "hint", text: hint })), icon("chevR")), h("div", { class: "fields" }, rows));
    };
    const hk = HOUR_KEYS.filter(k => asks.includes(k));
    const pk = PAY_KEYS.filter(k => k !== "amount" && k !== "billed_total" && asks.includes(k)).concat(["amount"]);
    const later = VIEW.corrects ? "" : "Now, or later from Your shifts";
    moreBox.append(section(hk.includes("patients") ? "What you did" : "Hours", hk.includes("patients") ? "Hours, and how many you saw" : (later || "Optional"), hk, !!VIEW.details));
    moreBox.append(billingSection(pl, asks));
    moreBox.append(section("What it paid", later || "Optional", pk, !!VIEW.details));
    const note = h("textarea", { id: "f-shift-note", name: "note", maxlength: 500, rows: 2, placeholder: "Anything to add" });
    note.value = vals.note || "";
    note.addEventListener("input", () => setVal("note", note.value));
    moreBox.append(h("div", { class: "fields glass" }, h("div", { class: "field" }, h("label", { for: "f-shift-note" }, "Note", h("span", { class: "opt", text: "optional" })), note)));
    if (focus && motionOK()) { rest.classList.add("fadein"); moreBox.classList.add("fadein"); }
  }
  function billingSection(pl, asks) {
    const payers = billingPayers().filter(p => (!p.places.length || p.places.includes(pl.value))
                                                && asks.includes(p.patients) && asks.includes(p.amount));
    if (!payers.length) return null;
    const used = payers.filter(p => vals[p.patients] || vals[p.amount]);
    const billsHimself = pl.value === "bochner" || pl.value === "endoscopy";
    const wrap = h("details", { class: "more glass billing", open: !!used.length || billsHimself || !!VIEW.details });
    const tot = h("div", { class: "billtot" });
    const lines = h("div", { class: "billlines" });
    const sync = () => {
      clear(tot);
      let pats = 0, billed = 0, any = false;
      for (const p of payers) {
        const raw = String(vals[p.amount] || "").trim();
        const n = Number(String(vals[p.patients] || "").replace(/[^\d.-]/g, "")), m = raw ? money(raw) : null;
        if (!isNaN(n) && n) { pats += n; any = true; }
        if (m !== null) { billed += m; any = true; }
      }
      const seen = Number(String(vals.patients || "").replace(/[^\d.-]/g, ""));
      if (!any && !seen) { tot.hidden = true; return; }
      tot.hidden = false;
      const over = seen && pats > seen;
      const bits = [];
      if (seen) bits.push(h("span", { text: `${seen} seen` }), h("span", { class: "sep", text: "\u00b7" }));
      bits.push(h("b", { class: over ? "warn" : "", text: `${pats} billed by you` }));
      if (billed) bits.push(h("span", { class: "sep", text: "\u00b7" }), h("b", { text: fmt$(billed) }));
      tot.append(...bits);
      if (over) tot.append(h("div", { class: "small warn", text: `You billed ${pats} but saw ${seen}. Check the counts \u2014 it sends either way.` }));
      const typedTot = String(vals.billed_total || "").trim() ? money(vals.billed_total) : null;
      if (typedTot !== null && billed && Math.abs(typedTot - billed) > 0.005)
        tot.append(h("div", { class: "small warn", text: `The payers add to ${fmt$(billed)}, and you typed ${fmt$(typedTot)}. Check which is right \u2014 it sends either way.` }));
    };
    for (const p of payers) {
      const line = h("div", { class: "billline" });
      const who = h("span", { class: "who", text: p.label });
      const np = h("input", { type: "text", inputmode: "numeric", maxlength: 4, class: "pt", "aria-label": `${p.full}: patients`, placeholder: "\u2013" });
      const na = h("input", { type: "text", inputmode: "decimal", maxlength: 12, class: "amt", "aria-label": `${p.full}: submitted`, placeholder: "$" });
      np.value = vals[p.patients] || ""; na.value = vals[p.amount] || "";
      np.addEventListener("input", () => { setVal(p.patients, np.value.trim()); sync(); });
      na.addEventListener("input", () => { setVal(p.amount, na.value.trim()); sync(); });
      na.addEventListener("blur", () => { const n = money(na.value); if (na.value.trim() && n !== null) { na.value = n.toLocaleString("en-CA", { minimumFractionDigits: 2, maximumFractionDigits: 2 }); } });
      inputs[p.patients] = np; inputs[p.amount] = na;
      line.append(who, np, na);
      lines.append(line);
    }
    if (inputs.patients) inputs.patients.addEventListener("input", sync);
    const totalRow = asks.includes("billed_total")
      ? numField("billed_total", vals.billed_total, (k, v) => { setVal(k, v); sync(); }, "Total submitted, if you know it another way")
      : null;
    if (totalRow) {
      inputs.billed_total = totalRow.input;
      totalRow.input.placeholder = "Leave blank to add up the payers above";
    }
    wrap.append(h("summary", {}, h("span", {}, "What you billed", " ",
      h("span", { class: "hint", text: billsHimself ? "Who each patient's care was billed to" : "Only a patient you billed yourself" })), icon("chevR")),
      h("div", { class: "fields" }, tot, lines,
        h("p", { class: "foot", text: billsHimself ? "How many patients went to each, and what you submitted for them."
                                                   : `${pl.label} bills for the rest and pays you a share back, so leave those out.` }),
        totalRow ? totalRow.el : null));
    sync();
    return wrap;
  }

  function shiftCombo(pl, mine, value) {
    const s2 = site ? site.value : "";
    const here = (pl.shifts_by_site || {})[s2] || [];
    const extra = mine.shifts.filter(x => !pl.shifts.includes(x));
    const usual = here.length ? here.slice(0, 5) : (pl.usual || []);
    const groups = [[here.length ? `Usual at ${s2}` : usual.length && pl.shifts.length > 6 ? "Most used" : null, usual],
                    [usual.length ? "All" : null, pl.shifts.concat(extra)]];
    if (usual.length && pl.shifts.length <= 6) groups.splice(0, 2, [null, pl.shifts.concat(extra)]);
    if (!value && pl.shifts.length === 1 && !extra.length) value = pl.shifts[0];
    const c = combo({ id: "f-shift-description", name: "description", label: "Which shift", groups, value,
                      newLabel: "A new shift…", placeholder: pl.value === "mgh" ? "0630, 1st Call, 1600 Flex…" : "Its name",
                      onChange: v => { setVal("description", v); syncStipend(); } });
    if (value) vals.description = value;
    return c;
  }
  drawRest(false);

  const collect = () => {
    const out = {};
    const put = (k, v) => { v = String(v || "").trim(); if (v) out[k] = v; };
    put("date", date.value);
    put("place", vals.place);
    const pl = placeInfo(vals.place);
    if (site) put("site", site.value);
    if (shift) put("description", shift.value);
    for (const [k, inp] of Object.entries(inputs)) put(k, inp.value);
    put("note", vals.note);
    for (const [k, v] of Object.entries(pre)) {
      if (!known.has(k) || k in out || k === "place" || k === "note" || k === "date" || k === "description" || inputs[k] || (site && k === "site")) continue;
      if (k === "type" && (vals.place !== origPlace || (out.description || "") !== origDesc)) continue;   // the MacBook works it out again
      if (k === "site" && vals.place !== origPlace) continue;
      if ((k === "shift_start" || k === "shift_end") && (vals.place !== origPlace || (out.description || "") !== origDesc)) continue;
      put(k, v);
    }
    return out;
  };
  form._collect = collect;

  form.append(h("div", { class: "formbar" }, h("button", { class: "btn primary", type: "submit" }, VIEW.corrects ? "Send the change" : "Send")));
  if (VIEW.corrects) {
    form.append(h("button", { class: "btn danger wide", type: "button", onclick: () => {
      const id = VIEW.corrects, label = VIEW.label;
      sheet("Delete this shift?", `${label}. It comes out of your books; the record keeps a copy, marked as deleted.`,
        [{ label: "Delete it", kind: "danger", run: () => { submit("withdraw", {}, id); closeView(); } }]);
    } }, "Delete this shift"));
  }
  form.addEventListener("submit", ev => {
    ev.preventDefault();
    const fields = collect(), problems = [];
    for (const w of form.querySelectorAll(".bad")) w.classList.remove("bad");
    const bad = (el, msg) => { problems.push(msg); if (el) el.classList.add("bad"); };
    if (!fields.date) bad(dateWrap, "The date is missing");
    if (!fields.place) bad(pills, "Choose where you worked");
    else if (site && !fields.site && !/stipend/i.test(fields.description || "")) bad(site.el, "Choose the site");
    if (fields.place && !fields.description) bad(shift && shift.el, "Choose which shift");
    if ((fields.place === "abp" || (fields.place === "edlp" && /stipend/i.test(fields.description || ""))) && !fields.period)
      bad(inputs.period && inputs.period.closest(".field"), "Choose the month it is for");
    for (const k of PAY_KEYS.concat(["hours", "travel_hours", "patients"])) {
      if (fields[k] === undefined) continue;
      const v = fields[k].replace(/[,$\s]/g, "");
      if (!/^-?\d{1,7}(\.\d{1,2})?$/.test(v)) bad(inputs[k] && inputs[k].closest(".field"), `${SHIFT_LABELS[k]}: type a number like 18.50`);
      else fields[k] = v;
    }
    const partsSum = PAID_KEYS.slice(1).filter(k => fields[k] !== undefined).reduce((a1, k) => a1 + Number(fields[k]), 0);
    if (fields.amount !== undefined && PAID_KEYS.slice(1).some(k => fields[k] !== undefined) && Math.abs(partsSum - Number(fields.amount)) > 0.01)
      bad(inputs.amount && inputs.amount.closest(".field"), `Total pay is ${fmt$(fields.amount)} but the parts add up to ${fmt$(partsSum)}: leave the total blank, or make them agree`);
    const priv = privateIn(fields, (shiftForm() || {}).fields);
    if (priv) bad(inputs[priv] && inputs[priv].closest && inputs[priv].closest(".field"), PRIVATE_MSG);
    const hasStart = fields.place !== "abp" && !/stipend/i.test(fields.description || "");
    const st = hasStart ? /\b(\d{2})(\d{2})\b/.exec(fields.description || "") : null;
    if (!problems.length && fields.date > todayISO() && !VIEW.corrects)
      bad(date.closest(".field"), "This shift is dated after today, so the MacBook would hold it. Check the date, or send it once it has started");
    if (!problems.length && fields.date === todayISO() && !VIEW.corrects) {
      const now = new Date(), nowMin = now.getHours() * 60 + now.getMinutes();
      const startMin = st ? +st[1] * 60 + +st[2] : null;
      if (startMin !== null && startMin < 24 * 60 && startMin > nowMin + 60) {
        bad(date.closest(".field"), `This ${st[0]} shift starts more than an hour from now, so the MacBook would hold it. If you worked it last night, tap Yesterday; otherwise send it after it starts`);
      } else if (startMin === null && /\bcall\b/i.test(fields.description || "") && now.getHours() < 12 && !form._callOk) {
        form._callOk = true;
        bad(date.closest(".field"), "A call sent this morning is usually last night's: tap Yesterday if so; tap Send again to keep today");
      }
    }
    if (!problems.length && !VIEW.corrects && !form._dupOk && fields.place === "abp" && fields.period) {
      const twin = allShifts().find(x => x.fields.place === "abp" && String(x.fields.period || "").slice(0, 7) === String(fields.period).slice(0, 7));
      if (twin) {
        form._dupOk = true;
        bad(inputs.period && inputs.period.closest(".field"), `ABP is one entry a month, and ${keyLabel(String(fields.period).slice(0, 7), true)} has one already. Open it under Your shifts and change its hours; tap Send again to send this one anyway, and the MacBook will hold it for a check`);
      }
    }
    if (!problems.length && !VIEW.corrects && !form._dupOk && !/stipend/i.test(fields.description || "") && fields.place !== "abp") {
      const norm = x => String(x || "").toLowerCase().replace(/\s*\b(we|covered)\b/g, "").replace(/\s+/g, " ").trim();
      const twin = allShifts().find(x => x.fields.place === fields.place && x.fields.date === fields.date
        && norm(x.fields.site) === norm(fields.site) && norm(x.fields.description) === norm(fields.description));
      if (twin) {
        form._dupOk = true;
        bad(date.closest(".field"), `You already sent this ${fields.description} shift for ${shortDate(fields.date)}. To change it, open it under Your shifts. Tap Send again to send it anyway: the MacBook will hold it for a check`);
      }
    }
    if (problems.length) {
      errors.textContent = problems.join(". ") + "."; errors.hidden = false;
      const first = form.querySelector(".bad");
      for (let d = first && first.closest("details"); d; d = d.parentElement && d.parentElement.closest("details")) d.open = true;
      window.scrollTo({ top: 0, behavior: motionOK() ? "smooth" : "auto" });
      return;
    }
    sent = true; clearTimeout(draftTimer); DRAFT_NOW = null;
    const d = drafts(); delete d[dkey]; save("drafts", d);
    submit("shift", fields, VIEW.corrects);
    closeView();
  });
  return form;
}


function allShifts() {
  const list = new Map(), gone = new Set();
  const heldFor = new Set();
  for (const x of (SNAP && SNAP.shifts) || []) {
    if (x.status === "held" && x.corrects) { heldFor.add(x.corrects); continue; }
    list.set(x.id, { id: x.id, fields: x.fields || {}, state: x.status === "held" ? "held" : "filed" });
  }
  const seen = new Set((SNAP && SNAP.shifts_seen) || []);
  const local = load("outbox", []).map(e => [e, "unsent"]).concat(load("sent", []).map(x => [x.entry, "sent"]));
  for (const [e, state] of local) {
    if (!e || (state === "sent" && seen.has(e.id) && !list.has(e.id))) continue;
    if (e.corrects) gone.add(e.corrects);
    if (e.kind !== "shift" || list.has(e.id)) continue;
    list.set(e.id, { id: e.id, fields: e.fields || {}, state });
  }
  for (const x of list.values()) if (heldFor.has(x.id)) x.changeHeld = true;
  return [...list.values()].filter(x => !gone.has(x.id)).sort((a1, b1) => String(b1.fields.date || "").localeCompare(String(a1.fields.date || "")));
}
function missingOf(x) {
  const pl = placeInfo(placeOfShift(x.fields)), asks = (pl && pl.asks) || [];
  const out = [];
  if (!PAID_KEYS.some(k => String(x.fields[k] || "").trim() !== "") && !/practice plan/i.test(x.fields.description || "")) out.push("pay");
  if (asks.includes("patients") && !x.fields.patients) out.push("patients");
  if (!x.fields.hours) out.push("hours");
  return out;
}

function renderShifts() {
  const p = h("div", { class: "page narrow" });
  p.append(head("Your shifts", "Every shift you have sent from this page. Tap one to add its hours, patients or pay, however long ago it was."));
  const all = allShifts();
  if (!all.length) { p.append(h("div", { class: "card glass" }, h("p", { class: "muted", text: "None yet. Shifts you send from Add appear here." }))); return p; }
  const needs = all.filter(x => missingOf(x).some(m => m !== "hours"));
  const which = VIEW.filter === "needs" && needs.length ? "needs" : "all";
  const holder = h("div", { class: "page" });
  const draw = v => {
    VIEW.filter = v;
    clear(holder);
    const rows = v === "needs" ? needs : all;
    let month = "", ul = null;
    for (const x of rows) {
      const m = String(x.fields.date || "").slice(0, 7);
      if (m !== month) {
        month = m;
        ul = h("div", { class: "list glass" });
        holder.append(h("section", { class: "section" }, h("h2", { text: m ? keyLabel(m, true) : "No date" }), ul));
      }
      const miss = missingOf(x), f = x.fields;
      const have = [f.hours ? `${f.hours} h` : "", f.patients ? plural(Number(f.patients), "patient") : "",
                    PAID_KEYS.some(k => f[k]) ? fmtWhole$(Math.round(f.amount ? money(f.amount) : PAID_KEYS.slice(1).reduce((a1, k) => a1 + (money(f[k] || 0) || 0), 0))) : ""].filter(Boolean).join(" · ");
      const chips = [];
      if (x.state === "unsent") chips.push(h("span", { class: "chip orange", text: "Not sent" }));
      else if (x.state === "sent") chips.push(h("span", { class: "chip blue", text: "Waiting for MacBook" }));
      else if (x.state === "held") chips.push(h("span", { class: "chip red", text: "Held" }));
      if (x.changeHeld) chips.push(h("span", { class: "chip red", text: "A change is held: see Today" }));
      if (miss.includes("pay")) chips.push(h("span", { class: "chip orange", text: "Pay to add" }));
      if (miss.includes("patients")) chips.push(h("span", { class: "chip", text: "Patients to add" }));
      const dt = dateOf(f.date);
      ul.append(h("button", { class: "row", type: "button", onclick: () => openView({ type: "form", kind: "shift", corrects: x.id, prefill: load("drafts", {})[draftKeyOf("shift", x.id)] || f, restored: !!load("drafts", {})[draftKeyOf("shift", x.id)], details: true,
                                                                                         label: `${shiftTitle(f)}, ${shortDate(f.date)}` }) },
        h("span", { class: "day", "aria-hidden": "true" }, h("span", { class: "wd", text: dt ? dt.toLocaleDateString("en-CA", { weekday: "short" }) : "" }),
          h("span", { class: "dn", text: dt ? String(dt.getDate()) : "" }), h("span", { class: "mo", text: dt ? dt.toLocaleDateString("en-CA", { month: "short" }) : "" })),
        h("span", { class: "main" }, h("span", { class: "title", text: shiftTitle(f) }), have ? h("span", { class: "meta", text: have }) : null,
          chips.length ? h("span", { class: "chiprow" }, chips) : null),
        icon("chevR")));
    }
    if (!rows.length) holder.append(h("div", { class: "card glass" }, h("p", { class: "muted", text: "Every shift has its pay and patients." })));
  };
  if (needs.length) {
    const seg = segControl([["all", `All · ${all.length}`], ["needs", `Needs details · ${needs.length}`]], which, draw, "Which shifts", "range wide");
    p.append(seg);
    swipeAlong(seg, holder, BACK, null);
  }
  p.append(holder);
  draw(which);
  p.append(h("p", { class: "foot", text: "Shifts typed in the Work tab are changed there. A change here replaces the shift in your books; the record keeps both, marked." }));
  return p;
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
  const typed = name => { const el = form.querySelector(`[name="${name}"]`); const s = el ? String(el.value || "").trim() : ""; return s ? money(s) : null; };
  const bal = typed("balance");
  const ticked = new Set(Array.from(form.querySelectorAll('.tick[aria-checked="true"]')).map(x => x.dataset.id));
  const shortly = w => w.split(/[:;.]\s|, | about | for the /)[0].split(/[:;]/)[0];
  const lines = [];
  const isEst = it => (it.basis || "").startsWith("estimate");
  const reserve = (pd.reserve || []).filter(r => !r.due || r.due >= todayISO());
  const estOpen = pd.items.filter(it => !ticked.has(it.id) && money(it.amount) && isEst(it)).concat(reserve.filter(r => money(r.amount) && isEst(r)));
  const itemName = w => { const m = /^Pay [^:]+: (?:the )?(.*)$/.exec(w); return m ? m[1].replace(/^./, c => c.toUpperCase()) : shortly(w); };
  for (const it of pd.items) if (!ticked.has(it.id) && money(it.amount)) lines.push([itemName(it.what) + ", not ticked yet", money(it.amount), isEst(it)]);
  const cardsOpen = [];
  for (const c of (pd.cards || [])) {
    const v = typed(c.field);
    if (v === null) cardsOpen.push(c.name); else if (v > 0) lines.push([`${c.name} balance, ${c.pays_itself ? "pays itself next month" : "still owing"}`, v, false]);
  }
  for (const r of reserve) lines.push([shortly(r.what) + (r.due === todayISO() ? ", a bill due today (kept back unless you see it has already left)" : ", a bill due " + shortDate(r.due)) + " (on Today's Coming up)", money(r.amount), isEst(r)]);
  lines.push(["The cushion, always left in chequing", money(pd.cushion) || 0, false, true]);
  const cardNames = cardsOpen.join(" and ") + (cardsOpen.length > 1 ? " balances" : " balance");
  box.append(h("h3", { text: "What to send to Questrade" }));
  if (/not yet approved/i.test(pd.rule || "")) box.append(h("p", { class: "small muted", text: "A suggestion only: the plan it follows (pay everything first, send the rest, keep a cushion) is still waiting for your yes." }));
  if (!pd.ready) box.append(h("p", { class: "small warnline", text: "Step 2 is not done: the two payments above are last month's figures, so the amount worked out here will change. Do not send anything to Questrade until steps 2 and 3 are done." }));
  if (bal === null) { delete form.dataset.staleBalance; box.append(h("p", { class: "small muted", text: "Type the chequing balance above, and the amount to send is worked out here." })); return; }
  if (form.dataset.staleBalance) box.append(h("p", { class: "small warnline", text: "You ticked a payment after typing the chequing balance, so the balance above is the one from before that money left. Look at your bank again and type the balance it shows now, or the amount worked out here will be too big." }));
  box.append(h("div", { class: "line" }, h("span", { text: "Chequing balance" }), h("span", { class: "amt", text: fmt$(bal) })));
  box.append(h("div", { class: "sh", text: "Kept back" }));
  let left = bal;
  const anyEstLine = lines.some(l => l[2]);
  for (const [w, a, e, round] of lines) {
    left -= a;
    box.append(h("div", { class: "line muted" }, h("span", {}, w, e ? h("span", { class: "chip orange tick-chip", text: "estimate" }) : null),
      h("span", { class: "amt", text: (e ? "about −" + fmtWhole$(Math.round(a)) : "−" + (round && anyEstLine ? fmtWhole$(Math.round(a)) : fmt$(a)).replace("−", "")) })));
  }
  if (cardsOpen.length) box.append(h("div", { class: "line muted" }, h("span", { text: cardNames.replace(/^./, c => c.toUpperCase()) + ", not typed yet" }), h("span", { class: "amt", text: "not counted" })));
  const v = left > 0 ? Math.round(left * 100) / 100 : 0;
  const wait = cardsOpen.length > 0;
  const approx = !wait && estOpen.length > 0;
  const shown = approx ? Math.max(0, Math.floor(v)) : v;
  box.append(h("div", { class: "res" + (wait ? " wait" : "") }, h("span", { text: "Amount to send" }),
    wait ? h("span", { class: "v num rounded", text: "once the card balances are typed" })
         : h("span", { class: "est-wrap" }, h("span", { class: "v num rounded" + (approx ? " approx" : ""), text: (approx ? "about " + fmtWhole$(shown) : fmt$(v)) }))));
  if (approx) {
    const unpaidEst = pd.items.filter(it => !ticked.has(it.id) && money(it.amount) && isEst(it));
    box.append(h("p", { class: "small muted", text: "Some amounts kept back are estimates, so this is approximate and rounded down." +
      (unpaidEst.length ? ` Tick ${unpaidEst.map(it => "the " + itemName(it.what).toLowerCase()).join(" and ")} once paid, and it gets closer.` : "") }));
  }
  if (wait) box.append(h("p", { class: "small muted", text: `Type the ${cardNames} above (0 if nothing is owing). The amount to send appears then.` }));
  else if (v > 0 && !pd.ready) box.append(h("p", { class: "small muted", text: "Once step 2 is done and this page has the month's own figures, a button here puts the amount in the box below." }));
  else if (v > 0) {
    const use = h("button", { class: "btn small tinted", type: "button" }, `Put ${approx ? fmtWhole$(shown) : fmt$(v)} in the box below`);
    use.addEventListener("click", () => { const s2 = form.querySelector('[name="sweep"]'); if (s2) { s2.value = (approx ? shown : v).toFixed(2); s2.focus(); } });
    box.append(use);
  } else box.append(h("p", { class: "small muted", text: "Nothing to send this month: the balance does not cover what is still due plus the cushion." }));
}


const BASIS_NAME = { verified: "Verified", derived: "Derived", recorded: "Recorded", measured: "Measured", estimate: "Estimate" };
const MEANS_LONG = {
  verified: "Read from a document, such as a bank statement or a tax notice, or from an authoritative screen.",
  derived: "Worked out from other figures, by a method written down in the Finance System.",
  recorded: "Typed by you, in the workbook or on this page. It becomes verified once a document ties to it.",
  measured: "Logged by an instrument without anyone typing it, such as your phone's record of time at work.",
  estimate: "Rests on an assumption, which is written down beside it.",
};
function basisOf(label) { const m = /^(verified|derived|recorded|measured|estimate)/.exec(String(label || "").trim()); return m ? m[1] : ""; }

function basisDot(basis, extra) {
  const b = basisOf(basis);
  if (!b) return null;
  const btn = h("button", { class: "bdot " + b, type: "button", "aria-label": `${BASIS_NAME[b]}: what this means`, "aria-haspopup": "dialog" }, h("span", { class: "d" }));
  btn.addEventListener("click", ev => { ev.stopPropagation(); ev.preventDefault(); if (closePop.anchor === btn) { closePop(); return; } explain(btn, b, extra); });
  btn.addEventListener("keydown", ev => { if (ev.key === "Enter" || ev.key === " ") ev.stopPropagation(); });
  return btn;
}
function explain(anchor, b, extra) {
  closePop();
  const pop = h("div", { class: "pop", role: "dialog", tabindex: "-1", "aria-label": BASIS_NAME[b] },
    h("div", { class: "pop-h" }, h("span", { class: "bd " + b }), h("strong", { text: BASIS_NAME[b] })),
    h("p", { text: MEANS_LONG[b] }),
    (extra || []).filter(Boolean).map(t => h("p", { class: "pop-x", text: t })),
    h("div", { class: "pop-all", "aria-label": "The five labels" }, Object.keys(BASIS_NAME).map(k => h("span", { class: k === b ? "on" : "" }, h("span", { class: "bd " + k }), BASIS_NAME[k]))));
  document.body.append(pop);
  const r = anchor.getBoundingClientRect(), pw = pop.offsetWidth, ph = pop.offsetHeight;
  const left = Math.min(window.innerWidth - pw - 12, Math.max(12, r.right - pw + 10));
  let top = r.bottom + 8;
  if (top + ph > window.innerHeight - 12) top = Math.max(12, r.top - ph - 8);
  pop.style.left = left + "px"; pop.style.top = top + "px";
  pop.style.setProperty("--ax", Math.max(14, Math.min(pw - 14, r.left + r.width / 2 - left)) + "px");
  if (top < r.top) pop.classList.add("above");
  const off = ev => { if (!pop.contains(ev.target) && ev.target !== anchor && !anchor.contains(ev.target)) closePop(); };
  const esc = ev => { if (ev.key === "Escape") { closePop(); anchor.focus(); } };
  const away = () => closePop();
  document.addEventListener("pointerdown", off, true);
  document.addEventListener("keydown", esc);
  window.addEventListener("scroll", away, { passive: true });
  closePop.anchor = anchor;
  try { pop.focus({ preventScroll: true }); } catch (e) { /* ignore */ }
  closePop.cleanup = () => { document.removeEventListener("pointerdown", off, true); document.removeEventListener("keydown", esc); window.removeEventListener("scroll", away); };
}
function closePop() {
  if (ASIDE) return;            // a neighbour drawn aside for the swipe must not close a bubble on the screen (r2-page-01)
  for (const p of document.querySelectorAll(".pop")) p.remove();
  if (closePop.cleanup) closePop.cleanup();
  closePop.cleanup = null; closePop.anchor = null;
}
function sentence(t) { t = String(t || "").trim(); return t ? t[0].toUpperCase() + t.slice(1).replace(/\.?$/, ".") : ""; }
function whyLines(o) {
  return [o.as_of ? "As of " + (dateOf(o.as_of) ? prettyDates(o.as_of) : o.as_of) + "." : "",
          o.source ? plainSource(o.source) + "." : "", o.note ? o.note.replace(/\.?$/, ".") : "",
          o.provisional ? sentence(o.provisional) : "",
          ["corp_market", "household"].includes(o.id || o.series) ? "Before the tax paid to take money out of the corporation." : ""];
}

function ov(id) { return ((SNAP && SNAP.overview) || []).find(o => (o.id || o.series) === id) || null; }

function tapArea(host, label, fn) {
  host.classList.add("tap-host");
  host.prepend(h("button", { class: "tap-hit", type: "button", "aria-label": label, onclick: fn }));
  return host;
}

function figCard(o, opts) {
  opts = opts || {};
  const tap = !!opts.onOpen;
  const card = h("div", { class: "fig glass" + (opts.hero ? " hero" : "") + (opts.wide ? " wide" : "") + (tap ? " tappable" : "") });
  card.append(h("div", { class: "ftop" }, h("span", { class: "l", text: opts.label || o.label }),
    basisDot(opts.basis || o.basis, opts.why || whyLines(o)),
    tap ? h("span", { class: "chev-go", "aria-hidden": "true" }, icon("chevR")) : null));
  card.append(h("span", { class: "v rounded" + (opts.hero ? "" : " num") }, opts.about ? h("span", { class: "about", text: "about " }) : null, opts.value || wholeValue(o.value)));
  const ser = opts.series;
  if (opts.body && ser && ser.points.length >= 4) {
    card.append(h("span", { class: "spark" }, chart([sparkOf(ser, o)], { form: ser.form, unit: ser.unit, spark: true, height: 64 })));
    card.append(h("span", { class: "spark" }, opts.body));
  } else
  card.append(opts.body ? h("span", { class: "spark" }, opts.body)
    : ser && ser.points.length >= 4 ? h("span", { class: "spark" }, chart([sparkOf(ser, o)], { form: ser.form, unit: ser.unit, spark: true, height: opts.hero ? 56 : 34 }))
    : h("span", { class: "spark none" }));
  card.append(h("span", { class: "fmeta" }, opts.meta || null));
  if (tap) tapArea(card, `${opts.label || o.label}, ${opts.about ? "about " : ""}${opts.value || wholeValue(o.value)}. Open`, () => opts.onOpen());
  return card;
}
function balance(grid) {
  const small = Array.from(grid.children).filter(c => !c.classList.contains("hero") && !c.classList.contains("wide"));
  if (small.length % 2) small[small.length - 1].classList.add("wide");
  return grid;
}

function segControl(choices, value, onPick, label, cls) {
  const segs = h("div", { class: "segs" + (cls ? " " + cls : ""), role: "radiogroup", "aria-label": label });
  for (const [v, lab] of choices) {
    const b = h("button", { type: "button", role: "radio", "aria-checked": String(v === value) }, lab);
    b.addEventListener("click", () => { for (const x of segs.children) x.setAttribute("aria-checked", String(x === b)); onPick(v); });
    segs.append(b);
  }
  return segs;
}
function chipRow(choices, value, onPick, label) {
  const row = h("div", { class: "chips", role: "radiogroup", "aria-label": label });
  for (const [v, lab] of choices) {
    const b = h("button", { class: "chip-b", type: "button", role: "radio", "aria-checked": String(v === value) }, lab);
    b.addEventListener("click", () => {
      for (const x of row.children) x.setAttribute("aria-checked", String(x === b));
      const r = b.getBoundingClientRect(), rr = row.getBoundingClientRect();
      if (r.left < rr.left) row.scrollLeft -= rr.left - r.left + 16; else if (r.right > rr.right) row.scrollLeft += r.right - rr.right + 16;
      onPick(v);
    });
    row.append(b);
  }
  const edge = () => { row.classList.toggle("more-r", row.scrollLeft + row.clientWidth < row.scrollWidth - 4); row.classList.toggle("more-l", row.scrollLeft > 4); };
  row.addEventListener("scroll", edge, { passive: true });
  setTimeout(() => { const on = row.querySelector('[aria-checked="true"]'); if (on && on.offsetLeft + on.offsetWidth > row.clientWidth) row.scrollLeft = on.offsetLeft - 16; edge(); }, 0);
  return row;
}
function meter(parts, total, cls) {
  const bar = h("div", { class: "meter" + (cls ? " " + cls : ""), role: "img",
                         "aria-label": parts.map(pt => `${pt.label} ${fmtWhole$(Math.round(pt.value))}`).join(", ") + (total ? ` of ${fmtWhole$(Math.round(total))}` : "") });
  const whole = total || parts.reduce((a, pt) => a + Math.max(0, pt.value), 0) || 1;
  for (const pt of parts) if (pt.value > 0) bar.append(h("span", { class: "mseg " + (pt.cls || ""), style: `flex-grow:${pt.value / whole}` }));
  const rest = whole - parts.reduce((a, pt) => a + Math.max(0, pt.value), 0);
  if (total && rest > 0.5) bar.append(h("span", { class: "mseg rest", style: `flex-grow:${rest / whole}` }));
  return bar;
}
function hbars(rows, fmtV, onPick) {
  const max = Math.max(...rows.map(r => r.value), 1), anyOn = rows.some(r => r.on);
  const box = h("div", { class: "hbars" });
  for (const r of rows) {
    const inner = [h("span", { class: "hb-lab" }, h("span", { class: "hb-l", text: r.label }), r.sub ? h("span", { class: "hb-s", text: r.sub }) : null),
                   h("span", { class: "hb-t" }, h("span", { class: "hb-f" + (anyOn && !r.on ? " dim" : ""), style: `width:${Math.max(1.5, r.value / max * 100)}%` })),
                   h("span", { class: "hb-v num", text: (r.est ? "about " : "") + fmtV(r.value) }), onPick && r.key ? icon("chevR") : null];
    box.append(onPick && r.key ? h("button", { class: "hb tap", type: "button", onclick: () => onPick(r.key) }, inner) : h("div", { class: "hb" }, inner));
  }
  return box;
}
function withCommute() { return load("pph_commute", true) !== false; }
const COMMUTE_WORDS = { measured: "measured by your phone", recorded: "typed by you", derived: "worked out from one leg the phone saw, or the usual round trip there",
                        estimate: "an estimate" };
function commuteFrom(src) {
  const parts = String(src || "").split(",").map(x => x.trim()).filter(Boolean).map(x => {
    const m = /^(\w+) (\d+%)$/.exec(x); return m ? `${m[2]} ${COMMUTE_WORDS[m[1]] || m[1]}` : x;
  });
  if (parts.length === 1) return parts[0].replace(/^100% /, "all ");
  return parts.length ? parts.join(", ") : "";
}
function commuteShort(src) {
  const parts = String(src || "").split(",").map(x => x.trim()).filter(Boolean);
  const m = parts.length === 1 ? /^(\w+) /.exec(parts[0]) : null;
  return m ? (COMMUTE_WORDS[m[1]] || m[1]).replace(/, or the usual round trip there$/, "") : parts.length ? "mixed" : "none";
}
function sumPart() { const v = load("sumpart", "total"); return ["total", "personal", "corporation", "cards"].includes(v) ? v : "total"; }

function renderSummary() {
  const p = h("div", { class: "page" });
  p.append(head("Summary", "Tap a card for more. Its dot says how sure the figure is.", true));
  if (!SNAP || !((SNAP.overview || []).length)) { p.append(h("div", { class: "card glass" }, h("p", { class: "muted", text: "No figures yet." }))); return p; }
  const part = sumPart();
  const holder = h("div", { class: "page" });
  const draw = v => {
    clear(holder);
    const body = v === "personal" ? summaryPersonal() : v === "corporation" ? summaryCorp()
               : v === "cards" ? summaryCards() : summaryTotal();
    if (motionOK()) { body.classList.add("fadein"); }
    holder.append(body);
  };
  const parts = segControl([["total", "Total"], ["corporation", "Corporation"], ["personal", "Personal"], ["cards", "Cards"]], part,
    v => { save("sumpart", v); closePop(); draw(v); }, "Which part of the Summary", "partseg");
  p.append(parts, holder);
  draw(part);
  swipeAlong(parts, holder, () => tabStep(-1), () => tabStep(1));
  return p;
}
function openTrendOf(id) {
  const idx = ((SNAP && SNAP.overview) || []).findIndex(o => (o.id || o.series) === id);
  const o = SNAP.overview[idx];
  if (o && o.series && SNAP.series && SNAP.series[o.series]) openView({ type: "trend", figId: id, title: o.label });
}

function householdNow() {
  const nw = (SNAP && SNAP.networth) || {};
  if (nw.now) return { date: nw.now.date, total: money(nw.now.household), corp: money(nw.now.corporation), pers: money(nw.now.personal),
                       since: money(nw.now.personal_since), from: nw.now.personal_from, basis: "estimate", corpBasis: nw.now.corporation_label, note: nw.now.note, est: true };
  if (nw.household) return { date: nw.date, total: money(nw.household), corp: money(nw.corporation), pers: money(nw.personal), since: 0, from: nw.date,
                             basis: "recorded", corpBasis: nw.corporation_label, est: false };
  return null;
}
function householdWhy(n) {
  const nw = (SNAP && SNAP.networth) || {};
  return [`At ${prettyDates(n.date)}${n.est ? ", the corporation's latest month-end with a bank and Questrade statement" : ""}.`,
          "It counts the corporation, at market, and your TFSA, RRSP and FHSA. Before the tax paid to take money out of the corporation.",
          n.est ? `An estimate: ${n.note}.` : "", nw.household && n.est ? `At ${prettyDates(nw.date)}, the last year end with every account's value, it was ${fmtWhole$(Math.round(money(nw.household)))}.` : "",
          nw.now && nw.now.source ? "Worked out in the net worth workings: the corporation at its month-end, and your accounts at the latest value their Questrade statements give, plus what went in or came out since, from your Registered Contributions tab and this page." : ""];
}
function summaryTotal() {
  const out = h("div", { class: "page" }), S = (SNAP && SNAP.series) || {}, nw = SNAP.networth || {};
  const n = householdNow();
  if (!n) return out;
  const up = nw.household ? Math.round((n.total - money(nw.household)) / 1000) * 1000 : null;
  const g = h("div", { class: "figs" });
  const tmc = moneyCard({
    worth: "net_worth", put: "put_in_total", label: "Net worth and investments", nets: true,
    worthLabel: "What it is all worth",
    basis: (S.net_worth || {}).basis, why: householdWhy(n),
    foot: "The corporation whole and your TFSA, RRSP and FHSA. Not the car, the condo or your personal chequing account.",
    meta: [up !== null ? h("span", { class: "delta", text: `${up >= 0 ? "Up" : "Down"} ${compact(Math.abs(up), "$")} since ${prettyDates(nw.date)}.` }) : null,
           n.since ? h("span", { class: "asof", text: `Plus ${fmtWhole$(Math.round(n.since))} put in since, which no statement covers yet.` }) : null,
           h("span", { class: "asof", text: "Before the tax paid to take money out of the corporation." })] });
  if (tmc) g.append(tmc);
  else {
    g.append(figCard({ label: "Household net worth", basis: n.basis }, { hero: true, label: `Household net worth, ${prettyDates(n.date)}`, value: fmtWhole$(Math.round(n.total)), about: n.est,
      series: S.household, onOpen: () => openTrendOf("household"), why: householdWhy(n),
      meta: [up !== null ? h("span", { class: "delta", text: `${up >= 0 ? "Up" : "Down"} ${compact(Math.abs(up), "$")} since ${prettyDates(nw.date)}.` }) : null,
             h("span", { class: "asof", text: "Before the tax paid to take money out of the corporation." })] }));
    const old = moneyCard({ worth: "total_market", put: "put_in_total", label: "Everything invested", nets: true,
                            foot: "The corporation's investments and yours together. Not the car, and not cash." });
    if (old) g.append(old);
  }
  out.append(balance(g));
  const pct = v => Math.round(v / n.total * 100) + "%";
  const row = (cls, label, sub, v, basis, why, part) => tapArea(h("div", { class: "row legendrow" },
    h("span", { class: "sw2 " + cls }), h("span", { class: "main" }, h("span", { class: "title", text: label }), h("span", { class: "meta", text: sub })),
    h("span", { class: "amt", text: fmtWhole$(Math.round(v)) }), basisDot(basis, why)), `${label}, ${fmtWhole$(Math.round(v))}. Show in detail`, () => { save("sumpart", part); render(); window.scrollTo(0, 0); });
  const oneDate = new Set(Object.values(((SNAP.networth || {}).now || {}).personal_dates || { x: n.from })).size === 1;
  const valueWord = oneDate ? `${monthDay(n.from)} value` : "latest values";
  const persSub = n.since ? `${pct(n.pers)} · ${valueWord} + ${fmtWhole$(Math.round(n.since))} put in to ${monthDay(n.date)}` : `${pct(n.pers)} · ${valueWord}`;
  out.append(h("section", { class: "section" }, h("h2", { text: "Breakdown" }),
    h("div", { class: "card glass splitcard" },
      meter([{ value: n.corp, cls: "s0", label: "Corporation" }, { value: n.pers, cls: "s1", label: "TFSA, RRSP, FHSA" }]),
      h("div", { class: "list flat" },
        row("s0", "Corporation", `${pct(n.corp)} · at market, ${monthDay(n.date)}`, n.corp, n.corpBasis,
            [`At ${prettyDates(n.date)}.`, "Its investments and chequing, plus money on its way from chequing to Questrade, less what it owes on its Visa.", "Before the tax paid to take money out of the corporation, and before a payroll remittance still to be paid."], "corporation"),
        row("s1", "TFSA, RRSP, FHSA", persSub, n.pers, n.since ? "estimate" : nw.personal_label,
            [oneDate ? `Their values at ${prettyDates(n.from)}, from each account's own Questrade statement (or a reading you sent from this page).`
                     : `Each at its latest value: ${Object.entries(((SNAP.networth || {}).now || {}).personal_dates || {}).map(([a, d]) => `${({ "qt-tfsa": "TFSA", "qt-rrsp": "RRSP", "qt-fhsa": "FHSA" })[a]} ${monthDay(d)}`).join(", ")}, from each account's own Questrade statement (or a reading you sent from this page).`,
             n.since ? `Plus ${fmtWhole$(Math.round(n.since))} you put in between then and ${prettyDates(n.date)}, from your Registered Contributions tab and this page. How their investments moved since is not known until the next statements, so this is an estimate.` : ""], "personal"))),
      h("p", { class: "foot", text: "Choose either line to see it in detail." })));
  const g2 = h("div", { class: "figs" });
  const sv = savingCard(); if (sv) g2.append(sv);
  if (!tmc) { const rt = returnsCard(); if (rt) g2.append(rt); }
  if (g2.children.length) out.append(balance(g2));
  return out;
}

function pctText(v) { return Math.round(Number(v) * 100) + "%"; }
function savingCard() {
  const B = (SNAP && SNAP.saving) || {};
  if (!B.life || B.life.pct === undefined || !(B.years || []).length) return null;
  const life = B.life, last = B.years[B.years.length - 1];
  const income = money(life.income), invested = money(life.investment);
  const why = [`Since ${B.since}.`, `${plainSource(B.source)}.`, B.note];
  const body = h("div", {},
    meter([{ value: invested, cls: "s0", label: "Invested" }], income),
    h("div", { class: "legend3" },
      h("span", {}, h("span", { class: "sw2 s0" }), "Invested ", h("b", { text: compact(invested, "$") })),
      h("span", { class: "muted" }, "Earned ", h("b", { text: compact(income, "$") }))));
  return figCard({ label: "Of what you earned, you invested", basis: B.basis }, {
    hero: true, label: `Of what you earned, you invested`, value: pctText(life.pct), why, body,
    onOpen: () => openView({ type: "saving" }),
    meta: [h("span", { class: "asof", text: `Since ${B.since}. ${last.year}: ${pctText(last.pct)}.` })] });
}
function runningYear(y) { return Number(y) >= new Date().getFullYear(); }
function yearAt(y) { return runningYear(y) ? `${y} so far` : `End of ${y}`; }          // a card's or page's label
function yearIn(y) { return runningYear(y) ? `in ${y} so far` : `at the end of ${y}`; } // inside a sentence
const RETURNS_SIDES = {
  undefined: { inKey: "in", valKey: "value", label: "What you put in, and what it is worth",
               what: "every dollar the corporation and you moved into investments",
               foot: "The corporation's investments and yours together. Not the car, and not cash." },
  corp: { inKey: "corp_in", valKey: "corp_value", label: "What the corporation put in, and what it is worth",
          what: "every dollar the corporation moved into its investments",
          foot: "The corporation's investments only. Not its chequing account." },
  personal: { inKey: "personal_in", valKey: "personal_value", label: "What you put in, and what it is worth",
              what: "every dollar you put into your TFSA, RRSP and FHSA",
              foot: "Your TFSA, RRSP and FHSA. Not the car, and not cash." },
};

function moneyCard(opts) {
  const S = (SNAP && SNAP.series) || {}, worth = S[opts.worth], put = S[opts.put], all = opts.all ? S[opts.all] : null;
  if (!worth || !worth.points.length) return null;
  const o = ov(opts.worth) || { label: opts.label, basis: worth.basis };
  const last = k => { const p = (S[k] || {}).points; return p && p.length ? p[p.length - 1] : null; };
  const lw = last(opts.worth), la = opts.all ? last(opts.all) : null;
  const head = la ? la[1] : lw[1];
  const putLabel = opts.nets ? "Put in, less taken out" : "Put in";
  const worthLabel = opts.worthLabel || (all ? "Invested" : "What it is worth");
  const sers = [];
  if (all) sers.push({ ...all, label: "All of it" });
  sers.push({ ...worth, label: worthLabel }, { ...put, label: putLabel });
  const money$ = v => v == null ? "—" : fmtWhole$(Math.round(v));
  const rows = (key, S2) => {
    const get = lab => { const s2 = S2.find(x => x.label === lab); if (!s2) return null;
                         const p = s2.points.find(q => q[0] === key); return p ? p[1] : null; };
    const iOf = lab => sers.findIndex(x => x.label === lab);
    const a = all ? get("All of it") : null;
    const w = get(worthLabel);
    const pv = get(putLabel);
    const out = [];
    if (all) out.push({ swatch: iOf("All of it"), name: "All of it", value: money$(a) });
    out.push({ swatch: iOf(worthLabel), name: all ? "Invested" : "Worth", value: money$(w) });
    if (pv != null && pv < 0) out.push({ swatch: iOf(putLabel), name: "Taken out more than put in", value: money$(-pv) });
    else out.push({ swatch: iOf(putLabel), name: "Put in", value: money$(pv) });
    if (w != null && pv != null && pv > 0) out.push({ name: "Growth", value: money$(w - pv), cls: "up" });
    if (all && a != null && w != null) out.push({ name: "Cash", value: money$(a - w), cls: "cash" });
    return out;
  };
  const body = chart(sers, { form: "line", unit: "$", height: 128, legend: true, tip: rows });
  return figCard(o, { hero: true, label: opts.label, value: fmtWhole$(Math.round(head)), body,
    basis: opts.basis, why: opts.why,
    onOpen: () => openView({ type: "trend", keys: [opts.all, opts.worth, opts.put].filter(Boolean), title: opts.label }),
    meta: (opts.meta || []).concat([h("span", { class: "asof", text: opts.foot })]) });
}

function returnsCard(side) {
  const B = (SNAP && SNAP.returns) || {}, K = RETURNS_SIDES[side];
  if (!(B.years || []).length || !K) return null;
  const r = B.years[B.years.length - 1];
  if (r[K.inKey] === null || r[K.inKey] === undefined || r[K.valKey] === null || r[K.valKey] === undefined) return null;
  const put = money(r[K.inKey]), val = money(r[K.valKey]), gain = val - put;
  const why = [runningYear(r.year) ? `${r.year} so far: the year is still running, so this is its latest statement.` : `At the end of ${r.year}.`,
               `${plainSource(B.source)}.`,
               `What you put in is ${K.what}; what it is worth is what those investments were worth at that date.`,
               "The gap between the two is worked out from them.", B.note];
  const body = h("div", {},
    meter([{ value: put, cls: "s0", label: "Put in" }, { value: Math.max(0, gain), cls: "s1", label: "Growth" }]),
    h("div", { class: "legend3" },
      h("span", {}, h("span", { class: "sw2 s0" }), "Put in ", h("b", { text: compact(put, "$") })),
      h("span", {}, h("span", { class: "sw2 s1" }), gain >= 0 ? "Growth " : "Fallen ", h("b", { text: compact(Math.abs(gain), "$") }))));
  return figCard({ label: K.label, basis: B.basis }, {
    hero: true, label: K.label, value: fmtWhole$(Math.round(val)), why, body,
    onOpen: () => openView({ type: "returns" }),
    meta: [h("span", { class: "delta", text: `${gain >= 0 ? "Worth" : "Down"} ${compact(Math.abs(gain), "$")} ${gain >= 0 ? "more than you put in" : "on what you put in"}, ${yearIn(r.year)}.` }),
           h("span", { class: "asof", text: K.foot })] });
}

function incomeVsLastYear() {
  const I = (SNAP && SNAP.income) || {}, cur = (I.years || {})[String(new Date().getFullYear())];
  if (!cur || !I.same_months_last_year) return "";
  const d = money(I.same_months_this_year || cur.total) - money(I.same_months_last_year);
  return `${d >= 0 ? "Up" : "Down"} ${compact(Math.abs(d), "$", true)} on the same months of ${new Date().getFullYear() - 1}`;
}
function summaryCorp() {
  const out = h("div", { class: "page" }), S = (SNAP && SNAP.series) || {};
  const g = h("div", { class: "figs" });
  const cmc = moneyCard({ worth: "invest_market", put: "put_in_corp", all: "corp_market",
                          label: "The corporation",
                          foot: "All of it: its investments, its chequing account and money on its way, less the Visa owed." });
  if (cmc) g.append(cmc);
  else { const cm = ov("corp_market");
         if (cm) g.append(figCard(cm, { hero: true, series: S.corp_market, onOpen: () => openTrendOf("corp_market"), meta: [deltaOf(S.corp_market, "corp_market")] })); }
  const inc = ov("income");
  const exp = ((SNAP && SNAP.income) || {}).expected;
  if (inc) g.append(figCard(inc, { label: inc.label.replace("Income into the corporation", "Income"), series: S.income, onOpen: () => openView({ type: "income" }),
    meta: [h("span", { class: "asof" }, exp ? h("span", { class: "expect" }, h("span", { class: "bd estimate", "aria-hidden": "true" }), `About ${compact(money(exp.total), "$")} expected by Dec 31`) : (incomeVsLastYear() || "Every year, by month"))] }));
  const wh = ov("work_hours"), pph = ov("pay_per_hour");
  const lagNote = o => daysFrom(o.mgh_through || o.as_of) < -35 ? `MGH counted to ${monthDay(o.mgh_through || o.as_of)}` : "";
  if (wh) g.append(figCard(wh, { label: wh.label.replace(/ · .*/, ""), value: wholeValue(wh.value) + " h", series: S.work_hours, onOpen: () => openView({ type: "work", metric: "hours" }),
    meta: [h("span", { class: "asof", text: lagNote(wh) || "By year, by place" })] }));
  if (pph) {
    const wc = withCommute() && pph.value_incl_travel;
    const from = commuteFrom(pph.travel_source);
    g.append(figCard(pph, { label: pph.label.replace(/ · .*/, ""), value: wholeValue(wc ? pph.value_incl_travel : pph.value) + "/h",
      basis: wc ? pph.basis_incl_travel : pph.basis, series: wc && S.pay_per_hour_incl_travel ? S.pay_per_hour_incl_travel : S.pay_per_hour,
      why: whyLines(wc ? Object.assign({}, pph, { note: pph.note_incl_travel || pph.note }) : pph).concat(wc ? [`With the commute: the round trip to each shift counts as time worked. The commute part is ${from || "not known"}.`,
                                      `Without it, ${wholeValue(pph.value)}/h.`]
                                   : [`Without the commute. With it, ${wholeValue(pph.value_incl_travel || pph.value)}/h.`]),
      onOpen: () => openView({ type: "work", metric: "rate" }),
      meta: [h("span", { class: "asof" }, h("span", { class: "which", text: wc ? "With the commute" : "Without the commute" }),
               " · " + ([lagNote(pph), (wc ? pph.note_incl_travel : pph.note)].filter(Boolean).join(" · ") || "By year, by place and site"))] }));
  }
  const rm = ov("remit");
  if (rm) g.append(figCard(rm, { series: S.remit, onOpen: () => openTrendOf("remit"), meta: [h("span", { class: "asof", text: "Due by the 15th of the next month" })] }));
  const tx = ov("tax_left");
  if (tx) g.append(figCard(tx, { label: "Tax instalments left this year", meta: [h("span", { class: "asof", text: tx.note || "As planned" })] }));
  out.append(balance(g));
  const cards = [["invest", "Their value, and what they cost", ["invest_market", "invest_cost"]]].filter(c => c[2].every(k => S[k]));
  if (cards.length) {
    const sec = h("section", { class: "section" }, h("h2", { text: "Investments" }));
    const grid = h("div", { class: "trend-cards" });
    for (const [id, title, keys] of cards) {
      let sub = null, basis = S[keys[0]].basis, why = [plainSource(S[keys[0]].source) + "."];
      if (id === "invest") {
        const mv = S.invest_market.points, cv = S.invest_cost.points, lm = mv[mv.length - 1], lc = cv[cv.length - 1];
        if (lm && lc && lm[0] === lc[0]) {
          const gv = lm[1] - lc[1];
          sub = h("span", { class: "tc-sub" }, `Worth ${compact(Math.abs(gv), "$", true)} ${gv >= 0 ? "more" : "less"} than they cost, at ${keyLabel(lm[0], true)}`);
          why.push("The gap between the two lines is worked out from them, so it is derived.");
        }
      }
      const b = h("div", { class: "card glass trendcard tappable" },
        h("span", { class: "tc-h" }, h("span", { class: "t", text: title }), basisDot(basis, why),
          h("span", { class: "chev-go", "aria-hidden": "true" }, icon("chevR"))), sub || h("span", { class: "tc-sub" }),
        chart(keys.map(k => S[k]), { form: "line", unit: "$", height: 150, legend: keys.length > 1, axis: true, hover: false, range: 36 }));
      grid.append(tapArea(b, `Investments: ${title}. Open`, () => openView({ type: "trend", keys, title: "Investments" })));
    }
    sec.append(grid);
    out.append(sec);
  }
  return out;
}

const ACCOUNTS = [["qt-tfsa", "TFSA"], ["qt-rrsp", "RRSP"], ["qt-fhsa", "FHSA"]];
function regOf(a) { return (SNAP && SNAP.registered && SNAP.registered.accounts && SNAP.registered.accounts[a]) || null; }
function leftBasis(acct) { return basisOf(acct.room_basis) === "estimate" ? "estimate" : "recorded"; }
function roomWhy(acct) {
  return ["The year's room, less what has gone in this year." + (leftBasis(acct) === "estimate" ? " An estimate, because the year's limit is not yet confirmed on CRA's site." : ""),
          `The room is ${BASIS_NAME[basisOf(acct.room_basis)] ? BASIS_NAME[basisOf(acct.room_basis)].toLowerCase() : acct.room_basis}: ${acct.room_note || ""}`,
          `What went in is recorded: ${plainSource(SNAP.registered.source).replace(/^From /, "")}.`];
}
function lastValue(acct) { const v = (acct && acct.values) || []; return v.length ? v[v.length - 1] : null; }
function roomBar(put, room) {
  const f = room > 0 ? Math.min(1, Math.max(0, put / room)) : 0;
  const bar = h("div", { class: "meter roombar", role: "img", "aria-label": `${fmtWhole$(Math.round(put))} put in of ${fmtWhole$(Math.round(room))}` });
  if (put > 0) bar.append(h("span", { class: "mseg", style: `flex-grow:${f};background:hsl(${Math.round(120 * f)} 72% 47%)` }));
  if (f < 1) bar.append(h("span", { class: "mseg rest", style: `flex-grow:${1 - f}` }));
  return bar;
}

const MONTH_FULL = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
function salaryCard(sal, S) {
  const paid = money(sal.value), target = money(sal.rrsp_target), expected = sal.expected ? money(sal.expected) : null;
  const yr = (sal.as_of || "").slice(0, 4), nextYr = sal.rrsp_year, left = Number(sal.months_left || 0);
  const whole = Math.max(target, expected || 0, paid) || 1;
  const bar = h("div", { class: "meter salbar", role: "img", "aria-label": `${fmtWhole$(Math.round(paid))} paid of ${fmtWhole$(Math.round(target))}` });
  bar.append(h("span", { class: "mseg s0", style: `flex-grow:${paid / whole}` }));
  if (expected && expected > paid) bar.append(h("span", { class: "mseg s0 planned", style: `flex-grow:${(expected - paid) / whole}` }));
  const short = expected !== null ? target - expected : 0;
  if (short > 0.5) bar.append(h("span", { class: "mseg gap", style: `flex-grow:${short / whole}` }));
  else if (!expected && target > paid) bar.append(h("span", { class: "mseg rest", style: `flex-grow:${(target - paid) / whole}` }));
  const firstLeft = Number((sal.as_of || "").slice(5, 7));   // the month after the last one paid, 0-based
  const span = left > 0 ? (left === 1 ? MONTH_FULL[firstLeft] : `${MONTH_FULL[firstLeft]} to December`) : "";
  const room = sal.rrsp_limit ? ` is the full ${fmtWhole$(Number(sal.rrsp_limit))}` : " is full";
  const why = [`Paid to ${prettyDates(sal.as_of)}. ${plainSource(sal.source)}.`,
    expected ? `Expected for ${yr}: what is paid, and ${left} month${left === 1 ? "" : "s"} still to come at ${fmtWhole$(Math.round(money(sal.monthly)))}, an estimate until they are paid.` : "",
    `${fmtWhole$(Math.round(target))} fills ${nextYr}'s RRSP room${sal.rrsp_limit ? " of " + fmtWhole$(Number(sal.rrsp_limit)) : ""}. The room is 18% of ${yr}'s earned income, which is your salary and any consulting income, less your employment expenses.`
    + (basisOf(sal.rrsp_target_basis) === "estimate" ? ` An estimate: it counts only the consulting income actually invoiced in ${yr}, and takes this year's employment expenses to be last year's.` : "")];
  let note = null;
  if (paid >= target - 0.5) note = h("div", { class: "salnote ok" }, h("b", { text: "Reached. " }), `What has been paid already fills ${nextYr}'s RRSP room.`);
  else if (expected !== null && short > 0.5) note = h("div", { class: "salnote short" }, h("b", { text: `${fmtWhole$(Math.round(short))} short. ` }),
    `The payroll plan pays ${fmtWhole$(Math.round(expected))} this year.` + (sal.monthly_needed && span ? " Pay " : ""),
    sal.monthly_needed && span ? h("b", { text: fmtWhole$(Number(sal.monthly_needed)) }) : null,
    sal.monthly_needed && span ? ` a month for ${span}, ${fmtWhole$(Number(sal.monthly_needed) - Math.round(money(sal.monthly)))} more than now, and ${nextYr}'s RRSP room${room}.` : "");
  else if (expected !== null) note = h("div", { class: "salnote ok" }, h("b", { text: "On target. " }),
    `The payroll plan pays ${fmtWhole$(Math.round(expected))} this year` + (expected - target > 0.5 ? `, ${fmtWhole$(Math.round(expected - target))} more than ${nextYr}'s RRSP room needs.` : `, what ${nextYr}'s RRSP room needs.`));
  const card = h("div", { class: "fig hero glass tappable salcard" },
    h("div", { class: "ftop" }, h("span", { class: "l", text: `Your salary, ${yr}` }), basisDot(sal.basis, why),
      h("span", { class: "chev-go", "aria-hidden": "true" }, icon("chevR"))),
    h("div", { class: "salhead" }, h("span", { class: "v rounded", text: fmtWhole$(Math.round(paid)) }),
      h("span", { class: "salof" }, "paid of ", h("b", { text: fmtWhole$(Math.round(target)) }))),
    bar,
    h("div", { class: "salends" }, h("span", { text: `Paid to ${monthDay(sal.as_of)}` }),
      h("span", {}, `${fmtWhole$(Math.round(target))} fills ${nextYr}'s RRSP room`, basisDot(sal.rrsp_target_basis, why.slice(2)))),
    note,
    h("span", { class: "fmeta" }, h("span", { class: "asof", text: "Before tax and deductions." })));
  tapArea(card, `Your salary, ${fmtWhole$(Math.round(paid))} paid of ${fmtWhole$(Math.round(target))}. Open`, () => openTrendOf("salary"));
  return card;
}

function summaryPersonal() {
  const out = h("div", { class: "page" }), S = (SNAP && SNAP.series) || {};
  const g = h("div", { class: "figs" });
  const pmc = moneyCard({ worth: "personal_market", put: "put_in_personal", label: "Your registered accounts",
                          nets: true,
                          foot: "Your TFSA, RRSP and FHSA. Not the car, and not cash." });
  if (pmc) g.append(pmc);
  const vals = ACCOUNTS.map(([a, n]) => [a, n, lastValue(regOf(a))]).filter(x => x[2]);
  const tabTo = ACCOUNTS.map(([a]) => (regOf(a) || {}).last_row || "").sort().pop();
  if (vals.length) {
    const at = vals[0][2][0], total = vals.reduce((s2, x) => s2 + x[2][1], 0);
    const same = vals.every(x => x[2][0] === at);
    const y = new Date().getFullYear();
    const withRoom = vals.filter(([a]) => regOf(a).room_this_year !== undefined);
    const roomBasis = withRoom.some(([a]) => leftBasis(regOf(a)) === "estimate") ? "estimate" : "recorded";
    const head2 = h("div", { class: "regcols" }, h("span", { text: "Value" }),
      h("span", {}, String(y), withRoom.length ? basisDot(roomBasis, [`What has gone into each account in ${y}, against its room for the year.`,
        ...withRoom.map(([a, n]) => `${n}: ${roomWhy(regOf(a))[1]}`), roomWhy(regOf(withRoom[0][0]))[2]]) : null), h("span", {}));
    const rows = h("div", { class: "list flat regrows" }, head2, vals.map(([a, n, v], i) => {
      const acct = regOf(a), hasRoom = acct.room_this_year !== undefined;
      const room = money(acct.room_this_year), put = money(acct.this_year), left = Math.max(0, room - put);
      return h("button", { class: "row regrow", type: "button", onclick: ev => { ev.stopPropagation(); openView({ type: "account", account: a }); } },
        h("span", { class: "main" }, h("span", { class: "regname" }, h("span", { class: "sw2 s" + i }), n),
          h("span", { class: "regval rounded", text: fmtWhole$(Math.round(v[1])) })),
        hasRoom ? h("span", { class: "regyear" }, roomBar(put, room),
          h("span", { class: "small muted" }, left > 0.5 ? h("b", { text: `${fmtWhole$(Math.round(left))} left` }) : h("b", { class: "regfull", text: "Full" }),
            left > 0.5 ? ` of ${fmtWhole$(Math.round(room))}` : ` · ${fmtWhole$(Math.round(put))} of ${fmtWhole$(Math.round(room))}`)) : h("span", {}),
        icon("chevR"));
    }));
    const since = ACCOUNTS.reduce((s2, [a]) => s2 + (money((regOf(a) || {}).since_value) || 0), 0);
    g.append(figCard({ label: "Your registered accounts", basis: vals[0][2][2] },
      { hero: true, label: same ? `Each account, ${prettyDates(at)}` : "Each account, latest values", value: fmtWhole$(Math.round(total)),
        why: [same ? `At ${prettyDates(at)}.` : "Each at its latest value: " + vals.map(([a, n, v]) => `${n} ${prettyDates(v[0])}`).join(", ") + ".",
              "From each account's own Questrade statement, or a value you read off Questrade and sent from this page (Add › A reading)."],
        body: h("div", {}, meter(vals.map(([a, n, v], i) => ({ value: v[1], cls: "s" + i, label: n }))), rows),
        meta: [h("span", { class: "asof", text: (since > 0 ? `${fmtWhole$(Math.round(since))} more has gone in since the statements. `
                                                   : since < 0 ? `${fmtWhole$(Math.round(-since))} more has come out than gone in since the statements. ` : "")
                                                   + (withRoom.length ? `${y} is counted${tabTo ? " to " + monthDay(tabTo) : ""}, from your Registered Contributions tab${withRoom.some(([a]) => (regOf(a).waiting || []).length) ? " and this page" : ""}.` : "") })] }));
  }
  const sal = ov("salary");
  if (sal && sal.rrsp_target) g.append(salaryCard(sal, S));
  else if (sal) g.append(figCard(sal, { label: sal.label.replace("Salary paid", "Your salary"), series: S.salary, onOpen: () => openTrendOf("salary"),
    meta: [h("span", { class: "asof", text: "Before tax and deductions" })] }));
  const sp = ov("spending");
  const spendable = ((SNAP && SNAP.spending) || {}).months;
  if (sp) g.append(figCard(sp, { label: "What you spend a month", onOpen: spendable ? () => openView({ type: "spending" }) : null,
    meta: [h("span", { class: "asof", text: spendable ? "Average of recent months · where it goes" : "Average of recent months, now rent is gone" })] }));
  const car = vehicleCard(); if (car) g.append(car);
  out.append(balance(g));
  return out;
}

function vehicleCard() {
  const V = (SNAP && SNAP.vehicle) || {};
  const last = (V.readings || [])[(V.readings || []).length - 1];
  if (!last) return null;
  const y = (V.per_year || [])[(V.per_year || []).length - 1];
  return figCard({ label: V.name, basis: V.basis }, {
    label: V.name, value: Math.round(last.km).toLocaleString("en-CA") + " km",
    why: [`At ${prettyDates(last.date)}.`, `${plainSource(V.source)}.`, V.note],
    onOpen: () => openView({ type: "vehicle" }),
    meta: [h("span", { class: "asof", text: y ? `${y.km.toLocaleString("en-CA")} km in ${y.year} · ${fmtWhole$(Math.round(money(V.spent)))} of upkeep so far` : `At ${prettyDates(last.date)}` })] });
}



const CARD_STATE = {
  ACT: { word: "Needs you", cls: "act" },
  MISSED: { word: "Missed", cls: "act" },
  UNKNOWN: { word: "Not known", cls: "unk" },
  "CHECK FIRST": { word: "Check first", cls: "unk" },
  "NOT ELIGIBLE": { word: "Not eligible", cls: "off" },
  "ON TRACK": { word: "On track", cls: "ok" },
  WATCH: { word: "Watching", cls: "ok" },
  DONE: { word: "Done", cls: "off" },
  EXPLAINED: { word: "Settled", cls: "off" },
  ASKED: { word: "Asked", cls: "off" },
};
const CARD_ITEM = {
  "minimum-spend": "Spending for its welcome bonus", "spend-record": "What it has been charged",
  "annual-fee": "Its yearly fee", "close-by": "Whether to keep it", points: "Points", gap: "Something to settle",
  "you-told-us": "Something you sent", nothing: "Nothing to watch",
  "next-card": "Worth opening",
  "keep-until": "The day it is safe to close", "first-fee-refund": "Asking the first year's fee back",
};
function cardItemName(item) {
  return CARD_ITEM[item] || String(item || "").replace(/-/g, " ").replace(/^./, c => c.toUpperCase());
}
function cardChip(status, item) {
  const s = CARD_STATE[status] || { word: status, cls: "ok" };
  const word = item === "across-cards" ? ({ UNKNOWN: "Not counted" })[status] || ""
    : item !== "next-card" ? s.word
    : ({ ACT: "Ending soon", WATCH: "Open to you", "CHECK FIRST": "Check first", "NOT ELIGIBLE": "Not eligible" })[status] || s.word;
  return word ? h("span", { class: "cchip " + s.cls, text: word }) : null;
}
const CARD_LEAD_ORDER = { ACT: 0, MISSED: 1, "CHECK FIRST": 2, "ON TRACK": 3, WATCH: 4, UNKNOWN: 5, DONE: 6, EXPLAINED: 7, ASKED: 7 };
function cardLead(it) {
  if (!it) return "";
  const $ = v => fmtWhole$(Math.round(Number(String(v).replace(/[$,]/g, "")) || 0));
  if (it.item === "minimum-spend" && it.need) {
    const toGo = Number(it.need) - Number(it.spent || 0);
    if (it.status === "DONE") return "Its welcome bonus is earned.";
    if (it.status === "MISSED") return `Its ${$(it.need)} was not spent in time.`;
    if (toGo <= 0) return "The spending is done; waiting for the points.";
    return `${$(toGo)} still to spend${it.due ? " by " + monthDay(it.due) : ""}.`;
  }
  if (it.item === "close-by") {
    if (it.due && it.due < todayISO()) return `That day passed on ${monthDay(it.due)}.`;
    return `Keep it, or close it${it.due ? " by " + monthDay(it.due) : ""}?`;
  }
  if (it.item === "you-told-us") return "Something you sent is not in your books yet.";
  if (it.item === "nothing") return "Nothing about it is on a date.";
  if (it.item === "annual-fee") return `${$(it.figure)} a year${it.due ? ", next on " + monthDay(it.due) : ""}.`;
  if (it.item === "points") {
    if (!it.figure) return `No ${it.unit || "points"} balance sent yet.`;
    return /cash back|money/i.test(it.unit || "")
      ? `${$(it.figure)} paid${it.due ? " " + monthDay(it.due) : ""}; since, not known.`
      : `${it.figure} ${it.unit}.`;
  }
  const m = /^[\s\S]*?\.(?=\s|$)/.exec(String(it.note || ""));
  return m ? m[0] : String(it.note || "");
}
function spendBar(it) {
  const need = Number(it.need), spent = Number(it.spent || 0), planned = Number(it.planned || 0);
  if (!need) return null;
  const room = Math.max(0, need - spent);
  const extra = Math.min(Math.max(0, planned - spent), room * 0.92);
  const bar = meter([{ value: spent, cls: "s0", label: "Charged so far" },
                     { value: extra, cls: "s1 planned", label: "Planned, not yet charged" }], need);
  const money$ = v => fmtWhole$(Math.round(v));
  return h("div", { class: "spendbar" }, bar,
    h("div", { class: "legend3" },
      h("span", {}, h("span", { class: "sw2 s0" }), "Charged ", h("b", { text: money$(spent) })),
      planned > spent ? h("span", {}, h("span", { class: "sw2 s1 planned" }), "Planned ",
                          h("b", { text: money$(Math.min(planned - spent, room)) }),
                          planned - spent > room + 1 ? h("span", { class: "muted", text: ` of ${money$(planned - spent)}` }) : null) : null,
      h("span", { class: "muted" }, "Needs ", h("b", { text: money$(need) }), it.due ? ` by ${monthDay(it.due)}` : "")));
}


function summaryCards() {
  const out = h("div", { class: "page" });
  const b = (SNAP && SNAP.cards) || {};
  if (b.failed) {
    out.append(h("div", { class: "card glass" }, h("p", { class: "muted", text: "The card workings could not be run on the MacBook, so nothing here is up to date. Ask a session to look: " + b.failed })));
    return out;
  }
  const cards = b.cards || [];
  if (!cards.length) {
    out.append(h("div", { class: "card glass" }, h("p", { class: "muted", text: "No cards yet." })));
    return out;
  }
  const needs = b.needs || [];
  out.append(h("div", { class: "card glass leadline" + (needs.length ? " act" : "") },
    h("p", { text: needs.length ? (needs.length === 1 ? `${needs[0]} needs you.` : `${needs.length} cards need you.`)
                                : "Every card is on course. Nothing needs you today." }),
    h("p", { class: "small muted", text: "Churning means opening a card for the points it pays for joining, spending enough to earn them, and closing it before the next yearly fee. These three dates are what this page watches." })));

  const open = cards.filter(c => c.open), shut = cards.filter(c => !c.open);
  const cardRow = c => {
    const items = (c.items || []).slice().sort((a, b) =>
      (CARD_LEAD_ORDER[a.status] ?? 9) - (CARD_LEAD_ORDER[b.status] ?? 9) || (a.due || "9999").localeCompare(b.due || "9999"));
    const it = items[0];
    const ms = items.find(x => x.item === "minimum-spend" && x.need && x.due >= todayISO()
                               && !["DONE", "MISSED", "EXPLAINED"].includes(x.status));
    const sec = h("section", { class: "card glass cardcard" },
      h("div", { class: "ftop" },
        h("span", { class: "l" }, h("span", { class: "cname", text: c.name }), h("span", { class: "cwhose", text: c.whose })),
        basisDot(it ? it.basis : "recorded", [it ? cardItemName(it.item) : "", it ? it.note : "",
                                              "Worked out in the card workings on the MacBook, from what you have typed and the issuers' own pages."])),
      h("div", { class: "cardline" }, cardChip(it ? it.status : c.status, it ? it.item : ""), h("span", { class: "clead", text: cardLead(it) })));
    if (ms) sec.append(spendBar(ms));
    return tapArea(sec, `${c.name}. Open`, () => openView({ type: "card", card: c.id, title: c.name }));
  };
  out.append(h("section", { class: "section" }, h("h2", { text: "Your cards" }), open.map(cardRow)));

  const across = b.across || [];
  if (across.length) {
    const sec = h("section", { class: "section" }, h("h2", { text: "Across all your cards" }));
    const list = h("div", { class: "list glass" });
    for (const a of across) {
      const r = h("button", { class: "row nextcard acrossrow", type: "button" },
        h("span", { class: "main" }, h("span", { class: "title", text: a.what }),
          h("span", { class: "meta" }, cardChip(a.status, "across-cards"),
            a.figure ? h("span", { text: ` ${a.unit === "CAD" ? fmtWhole$(Math.round(Number(String(a.figure).replace(/[$,]/g, "")))) : a.figure + " " + (a.unit || "")}` }) : null)),
        h("span", { class: "chev" }, icon("chevR")));
      const why = h("p", { class: "small muted detail", text: a.note, hidden: true });
      r.addEventListener("click", () => { why.hidden = !why.hidden; r.classList.toggle("open", !why.hidden); });
      list.append(h("div", { class: "rowpair" }, r, why));
    }
    sec.append(list);
    out.append(sec);
  }
  const nxt = (b.next || []).filter(x => x.id);
  if (nxt.length) {
    const sec = h("section", { class: "section" }, h("h2", { text: "Worth opening next" }));
    const list = h("div", { class: "list glass" });
    for (const o of nxt) {
      const r = h("button", { class: "row nextcard", type: "button" },
        h("span", { class: "main" }, h("span", { class: "title", text: o.card }),
          h("span", { class: "meta" }, cardChip(o.status, "next-card"),
            o.figure ? h("span", { text: ` ${fmtWhole$(Math.round(Number(String(o.figure).replace(/[$,]/g, ""))))} after the fees it costs to get` }) : h("span", { text: " worth unknown" }),
            / does NOT fit/.test(o.note || "") ? h("span", { class: "cchip off", text: "More than you spend" }) : null)),
        h("span", { class: "chev" }, icon("chevR")));
      const why = h("p", { class: "small muted detail", text: o.note, hidden: true });
      r.addEventListener("click", () => { why.hidden = !why.hidden; r.classList.toggle("open", !why.hidden); });
      list.append(h("div", { class: "rowpair" }, r, why));
    }
    const tail = (b.next || []).find(x => !x.id);
    sec.append(list, h("p", { class: "small muted", text: tail ? tail.note : "" }));
    out.append(sec);
  }
  if (shut.length) {
    const d = h("details", { class: "fold" }, h("summary", { text: `Cards you have closed (${shut.length})` }),
      h("div", { class: "list" }, shut.map(cardRow)));
    out.append(h("section", { class: "section" }, d));
  }
  out.append(h("p", { class: "small muted asof", text: `Worked out ${b.as_of ? prettyDates(b.as_of) : "on the MacBook"}. Nothing here is a decision: opening or closing a card is written down and waits for your yes.` }));
  return out;
}

function renderCard() {
  const b = (SNAP && SNAP.cards) || {};
  const c = (b.cards || []).find(x => x.id === VIEW.card);
  const p = h("div", { class: "page narrow" });
  if (!c) { p.append(head("Not available", "This card's figures have not arrived yet.")); return p; }
  p.append(head(c.name, c.whose === "yours" ? "Your card" : "The corporation's card"));
  for (const it of c.items || []) {
    const sec = h("section", { class: "card glass" },
      h("div", { class: "ftop" }, h("h3", { text: cardItemName(it.item) }),
        basisDot(it.basis, [it.due ? "By " + prettyDates(it.due) + "." : "", "Worked out in the card workings on the MacBook."])),
      h("div", { class: "cardline" }, cardChip(it.status, it.item),
        it.figure ? h("span", { class: "camt num", text: (it.unit === "CAD" || /cash back|money/i.test(it.unit || "")
          ? fmtWhole$(Math.round(Number(String(it.figure).replace(/[$,]/g, "")))) : `${it.figure} ${it.unit || ""}`.trim()) }) : null),
      h("p", { class: "small", text: dropIds(it.note) }));
    if (it.item === "minimum-spend" && it.need && it.due >= todayISO()
        && !["DONE", "MISSED", "EXPLAINED"].includes(it.status)) sec.append(spendBar(it));
    p.append(sec);
  }
  return p;
}

function renderAccount() {
  const a = VIEW.account, acct = regOf(a), y = new Date().getFullYear();
  const p = h("div", { class: "page narrow" });
  if (!acct) { p.append(head("Not available", "This account's figures have not arrived yet.")); return p; }
  p.append(head(acct.name));
  const src = SNAP.registered.source;
  const room = money(acct.room_this_year), put = money(acct.this_year);
  const tfsa = a === "qt-tfsa";
  if (acct.room_this_year !== undefined) {
    const left = Math.max(0, room - put);
    p.append(h("div", { class: "trend-top" },
      h("div", { class: "ftop" }, h("span", { class: "l", text: `Room left for ${y}` }), basisDot(leftBasis(acct), roomWhy(acct))),
      h("div", { class: "v rounded", text: fmtWhole$(Math.round(left)) }),
      h("div", { class: "fmeta" }, h("span", { class: "asof", text: `Counting what went in up to ${acct.last_row ? prettyDates(acct.last_row) : "now"}, the last row in your Registered Contributions tab${(acct.waiting || []).length ? ", and what you sent from here" : ""}.` + (tfsa ? " Check CRA My Account before putting money in: going over is taxed." : "") }))));
    const card = h("section", { class: "card glass roomcard" }, h("h3", { text: `This year` }),
      meter([{ value: put, cls: "s0", label: "Put in" }], room),
      h("div", { class: "legend3" },
        h("span", {}, h("span", { class: "sw2 s0" }), "Put in ", h("b", { text: fmtWhole$(Math.round(put)) }), ` of ${fmtWhole$(Math.round(room))}`),
        h("span", {}, h("span", { class: "sw2 rest" }), "Left ", h("b", { text: fmtWhole$(Math.round(left)) }))));
    if (tfsa) card.append(h("p", { class: "small muted", text: basisOf(acct.room_basis) === "verified" ? acct.room_note
      : `The room is what CRA's rule leaves at January 1: each year's limit since ${acct.room_since}, plus what came out before this year, less what went in before this year.` }));
    if (acct.waiting && acct.waiting.length) card.append(h("p", { class: "small muted", text: `Counted here and not yet in your Registered Contributions tab: ${acct.waiting.map(w => `${fmtWhole$(w.amount)} on ${shortDate(w.date)}`).join(", ")}.` }));
    p.append(card);
  }
  const years = acct.by_year || [];
  if (years.length) {
    const ser = { label: "Put in", unit: "$", form: "bars", basis: "recorded", source: src, points: years.map(r => [r[0], r[1]]) };
    const sec = h("section", { class: "card glass" }, h("div", { class: "ftop" }, h("h3", { text: "Every year" }), basisDot("recorded", [`${plainSource(src)}.`, "Each year's total of the rows you typed."])));
    sec.append(chart([ser], { form: "bars", unit: "$", height: 170, axis: true, hover: true }));
    const lifeRoom = tfsa ? money(acct.lifetime_limits) : acct.lifetime_limit ? money(acct.lifetime_limit) : null;
    const opening = (acct.opening || []).reduce((s2, o) => s2 + money(o.amount), 0);
    const net = money(acct.put_in) + opening - (tfsa ? money(acct.taken_out) : 0);
    const facts = [["Last year", fmtWhole$(Math.round(money(acct.last_year)))], ["This year", fmtWhole$(Math.round(put || 0))]];
    if (!lifeRoom) facts.push(["Every year", fmtWhole$(Math.round(money(acct.put_in)))]);
    sec.append(h("div", { class: "facts" }, facts.map(([k, v]) => h("div", {}, h("span", { class: "k", text: k }), h("span", { class: "fv num", text: v })))));
    if (lifeRoom) {
      sec.append(h("div", { class: "life" },
        h("div", { class: "life-h" }, h("span", { text: tfsa ? `Over its life, since ${acct.room_since}` : "Over its life" }),
          h("span", { class: "num" }, h("b", { text: fmtWhole$(Math.round(net)) }), ` of ${fmtWhole$(Math.round(lifeRoom))}`)),
        meter([{ value: net, cls: "s1", label: tfsa ? "In, less what came out" : "Put in" }], lifeRoom, "thin"),
        tfsa ? h("div", { class: "legend3" }, h("span", {}, "Put in ", h("b", { text: fmtWhole$(Math.round(money(acct.put_in))) })),
          opening ? h("span", {}, `Moved in, ${(acct.opening[0].date || "").slice(0, 4)} `, h("b", { text: fmtWhole$(Math.round(opening)) })) : null,
          h("span", {}, "Taken out ", h("b", { text: fmtWhole$(Math.round(money(acct.taken_out))) })),
          h("span", { class: "muted" }, "Room since " + acct.room_since + " ", h("b", { text: fmtWhole$(Math.round(lifeRoom)) }))) : null,
        h("p", { class: "small muted", text: tfsa ? "The bar is what went in, less what came out, against every year's limit added up. A year can take more than its own limit: room not used carries forward, and what comes out is room again the next January."
                                                    + (opening ? " Moved in is the account brought over from an earlier institution: what went in there, less what came out, not a year's contribution." : "")
                                                   : `An FHSA takes ${fmtWhole$(Math.round(lifeRoom))} over its life, at most $8,000 a year.` })));
    }
    const list = h("div", { class: "list flat", hidden: true },
      years.slice().reverse().map(r => h("div", { class: "row plain" }, h("span", { class: "title", text: r[0] }),
        h("span", { class: "amt num", text: fmtWhole$(Math.round(r[1])) + (r[2] ? ` in, ${fmtWhole$(Math.round(r[2]))} out` : "") }))));
    const toggle = h("button", { class: "btn small gray", type: "button" }, "Show as a list");
    toggle.addEventListener("click", () => { list.hidden = !list.hidden; toggle.textContent = list.hidden ? "Show as a list" : "Hide the list"; });
    sec.append(h("div", { class: "trend-actions" }, toggle), list);
    p.append(sec);
  }
  const vs = acct.values || [];
  if (vs.length) {
    const lv = vs[vs.length - 1];
    p.append(h("div", { class: "list glass" },
      h("div", { class: "row plain" }, h("span", { class: "main" }, h("span", { class: "title", text: `Value at ${prettyDates(lv[0])}` }),
        h("span", { class: "meta", text: vs.length > 1 ? `${fmtWhole$(Math.round(vs[vs.length - 2][1]))} a year before` : "" })),
        h("span", { class: "est-wrap" }, h("span", { class: "amt", text: fmtWhole$(Math.round(lv[1])) }), basisDot(lv[2], [String(lv[2] || "").startsWith("verified") ? "From this account's own Questrade statement." : "A value you read off Questrade and sent from this page."])))));
  }
  p.append(h("button", { class: "btn tinted wide", type: "button", onclick: () => startForm("registered", { account: a, direction: "contribution" }) }, `Record money into or out of your ${acct.name}`));
  p.append(h("p", { class: "foot", text: `${plainSource(src)}.${SNAP.registered.values_source ? " " + plainSource(SNAP.registered.values_source) + "." : ""} Last row ${acct.last_row ? prettyDates(acct.last_row) : "none"}. What you send from this page is counted as soon as the MacBook has it.` }));
  return p;
}


function renderSaving() {
  const B = (SNAP && SNAP.saving) || {}, p = h("div", { class: "page narrow" });
  p.append(head("What you invest", "Of what was earned, how much was put into investments."));
  if (!(B.years || []).length) { p.append(h("div", { class: "card glass" }, h("p", { class: "muted", text: "Not available yet." }))); return p; }
  const life = B.life || {}, income = money(life.income), invested = money(life.investment);
  p.append(h("div", { class: "trend-top" },
    h("div", { class: "ftop" }, h("span", { class: "l", text: `Since ${B.since}` }), basisDot(B.basis, [`${plainSource(B.source)}.`, B.note])),
    h("div", { class: "v rounded", text: pctText(life.pct) }),
    h("div", { class: "fmeta" }, h("span", { class: "asof", text: `${fmtWhole$(Math.round(invested))} invested of ${fmtWhole$(Math.round(income))} earned.` }))));
  const sec = h("section", { class: "card glass" }, h("h3", { text: "Year by year" }),
    hbars(B.years.map(y => ({ key: y.year, label: y.year, value: Number(y.pct) || 0,
                              sub: `${compact(money(y.corp_invested) + money(y.personal_invested), "$")} of ${compact(money(y.corp_income), "$")}` })), pctText));
  sec.append(h("p", { class: "small muted", text: B.note }));
  p.append(sec);
  const side = h("section", { class: "card glass" }, h("h3", { text: "The corporation, and you" }));
  const rows = h("div", { class: "trio" },
    h("span", { text: "Year" }), h("span", { class: "tv", text: "The corporation" }), h("span", { class: "tv", text: "You" }),
    B.years.slice().reverse().map(y => [
      h("span", { class: "ty", text: y.year }),
      h("span", { class: "tv", text: y.corp_pct === null ? "—" : pctText(y.corp_pct) }),
      h("span", { class: "tv", text: y.personal_pct === null ? "—" : pctText(y.personal_pct) })]));
  side.append(rows, h("p", { class: "small muted", text: "The corporation's share is what it invested of what it earned before tax. Yours is what went into your TFSA, RRSP and FHSA, against your gross salary that year." }));
  p.append(side);
  p.append(h("p", { class: "foot", text: `${plainSource(B.source)}. Typed by you, or worked out by that tab's own formulas from cells you typed.` }));
  return p;
}

function renderReturns() {
  const B = (SNAP && SNAP.returns) || {}, p = h("div", { class: "page narrow" });
  p.append(head("What it is worth", "What was put in, against what it is worth. The year still running is at its latest statement."));
  if (!(B.years || []).length) { p.append(h("div", { class: "card glass" }, h("p", { class: "muted", text: "Not available yet." }))); return p; }
  const r = B.years[B.years.length - 1], put = money(r.in), val = money(r.value);
  p.append(h("div", { class: "trend-top" },
    h("div", { class: "ftop" }, h("span", { class: "l", text: yearAt(r.year) }), basisDot(B.basis, [`${plainSource(B.source)}.`, B.note])),
    h("div", { class: "v rounded", text: fmtWhole$(Math.round(val)) }),
    h("div", { class: "fmeta" }, h("span", { class: "asof", text: `${fmtWhole$(Math.round(put))} put in. ${val >= put ? "Worth" : "Down"} ${fmtWhole$(Math.round(Math.abs(val - put)))} ${val >= put ? "more" : ""}.` }))));
  const src = B.source;
  const line = (label, key) => ({ label, unit: "$", form: "line", basis: B.basis, source: src,
                                  points: B.years.filter(y => y[key] !== null && y[key] !== undefined).map(y => [y.year, money(y[key])]) });
  const sec = h("section", { class: "card glass" }, h("h3", { text: "Every year" }),
    chart([line("What it is worth", "value"), line("What was put in", "in")],
          { form: "line", unit: "$", height: 190, legend: true, axis: true, hover: true }));
  p.append(sec);
  const both = h("section", { class: "card glass" }, h("h3", { text: "The corporation, and you" }));
  const part = (name, ik, vk) => {
    const y = B.years[B.years.length - 1], pin = money(y[ik]), pv = money(y[vk]);
    if (!pin && !pv) return null;
    const grew = Math.max(0, pv - pin);
    return h("div", { class: "life" },
      h("div", { class: "life-h" }, h("span", { text: name }), h("span", { class: "num" }, h("b", { text: fmtWhole$(Math.round(pv)) }))),
      meter([{ value: pin, cls: "s0", label: "Put in" }, { value: grew, cls: "s1", label: "Growth" }]),
      h("div", { class: "legend3" },
        h("span", {}, h("span", { class: "sw2 s0" }), "Put in ", h("b", { text: fmtWhole$(Math.round(pin)) })),
        h("span", {}, h("span", { class: "sw2 s1" }), pv >= pin ? "Growth " : "Fallen ", h("b", { text: fmtWhole$(Math.round(Math.abs(pv - pin))) }))));
  };
  both.append(part("The corporation", "corp_in", "corp_value"), part("You", "personal_in", "personal_value"));
  const list = h("div", { class: "list flat", hidden: true },
    B.years.slice().reverse().map(y => h("div", { class: "row plain" }, h("span", { class: "title", text: y.year }),
      h("span", { class: "amt num", text: `${fmtWhole$(Math.round(money(y.value)))} of ${fmtWhole$(Math.round(money(y.in)))}` }))));
  const toggle = h("button", { class: "btn small gray", type: "button" }, "Show as a list");
  toggle.addEventListener("click", () => { list.hidden = !list.hidden; toggle.textContent = list.hidden ? "Show as a list" : "Hide the list"; });
  both.append(h("div", { class: "trend-actions" }, toggle), list);
  p.append(both);
  p.append(h("p", { class: "foot", text: `${plainSource(src)}. ${B.note}` }));
  return p;
}

function renderSpending() {
  const B = (SNAP && SNAP.spending) || {}, p = h("div", { class: "page narrow" });
  p.append(head("What you spend", "Every month since the records begin, and where it goes."));
  if (!(B.months || []).length) { p.append(h("div", { class: "card glass" }, h("p", { class: "muted", text: "Not available yet." }))); return p; }
  const cols = B.columns || [], burn = B.burn_columns || [];
  const hl = B.headline || {};
  const want = ["Trailing 12-Mo Burn", "Avg Monthly Burn (12 mo)", "Burn Since 2024-04"];
  const NAMES = { "Trailing 12-Mo Burn": "The last 12 months", "Avg Monthly Burn (12 mo)": "A month, on average", "Burn Since 2024-04": "Since the records begin" };
  const ytd = Object.keys(hl).find(k => /YTD Burn$/.test(k));
  if (ytd) { want.splice(2, 0, ytd); NAMES[ytd] = ytd.replace(" YTD Burn", " so far"); }
  p.append(h("div", { class: "trend-top" },
    h("div", { class: "ftop" }, h("span", { class: "l", text: "A month, on average" }), basisDot(B.basis, [`Months to ${keyLabel(B.as_of, true)}.`, `${plainSource(B.source)}.`, B.note])),
    h("div", { class: "v rounded", text: fmtWhole$(Math.round(money(hl["Avg Monthly Burn (12 mo)"]))) }),
    h("div", { class: "fmeta" }, h("span", { class: "asof", text: `Everyday cost of living, over the twelve months to ${keyLabel(B.as_of, true)}.` }))));
  p.append(h("section", { class: "card glass" }, h("h3", { text: "Everyday cost of living" }),
    h("div", { class: "facts" }, want.filter(k => hl[k] !== undefined).map(k =>
      h("div", {}, h("span", { class: "k", text: NAMES[k] }), h("span", { class: "fv num", text: fmtWhole$(Math.round(money(hl[k]))) })))),
    h("p", { class: "small muted", text: B.note })));
  const bi = cols.findIndex(c => c.group === "Computed" && c.name === "Burn");
  if (bi >= 0) p.append(h("section", { class: "card glass" }, h("h3", { text: "Month by month" }),
    chart([{ label: "Burn", unit: "$", form: "bars", basis: B.basis, source: B.source,
             points: B.months.map(m => [m.month, m.cells[bi]]) }], { form: "bars", unit: "$", height: 180, axis: true, hover: true })));
  const last12 = B.months.slice(-12);
  const avg = burn.map(i => ({ key: String(i), label: cols[i].name, sub: cols[i].group,
                               value: last12.reduce((s2, m) => s2 + Number(m.cells[i] || 0), 0) / (last12.length || 1) }))
                  .filter(r => Math.abs(r.value) >= 1).sort((a, b) => b.value - a.value);
  if (avg.length) {
    const sec = h("section", { class: "card glass" }, h("h3", { text: "Where it goes, a month" }),
      hbars(avg.slice(0, 14), v => fmtWhole$(Math.round(v))));
    if (avg.length > 14) sec.append(h("p", { class: "small muted", text: `The ${avg.length - 14} smaller categories are left off; each is under ${fmtWhole$(Math.round(avg[14].value))} a month.` }));
    sec.append(h("p", { class: "small muted", text: `Averaged over the twelve months to ${keyLabel(B.as_of, true)}. Money into your TFSA, RRSP and FHSA is not spending and is not here.` }));
    p.append(sec);
  }
  p.append(h("p", { class: "foot", text: `${plainSource(B.source)}. The whole table is rebuilt from your YNAB export each time, so a change you make in YNAB comes through by itself.` }));
  return p;
}

function renderVehicle() {
  const V = (SNAP && SNAP.vehicle) || {}, p = h("div", { class: "page narrow" });
  p.append(head(V.name || "Your car", "The odometer at each year end, and what upkeep has cost."));
  const rd = V.readings || [];
  if (!rd.length) { p.append(h("div", { class: "card glass" }, h("p", { class: "muted", text: "Not available yet." }))); return p; }
  const last = rd[rd.length - 1];
  p.append(h("div", { class: "trend-top" },
    h("div", { class: "ftop" }, h("span", { class: "l", text: `At ${prettyDates(last.date)}` }), basisDot(V.basis, [`${plainSource(V.source)}.`, V.note])),
    h("div", { class: "v rounded", text: Math.round(last.km).toLocaleString("en-CA") + " km" }),
    h("div", { class: "fmeta" }, h("span", { class: "asof", text: "What you typed on the Vehicle Mileage tab, or sent from here as a reading." }))));
  if ((V.per_year || []).length) p.append(h("section", { class: "card glass" }, h("h3", { text: "Driven each year" }),
    chart([{ label: "km", unit: "km", form: "bars", basis: V.basis, source: V.source,
             points: V.per_year.map(y => [y.year, y.km]) }], { form: "bars", unit: "km", height: 160, axis: true, hover: true }),
    h("p", { class: "small muted", text: V.note })));
  const bills = V.bills || [];
  if (bills.length) {
    const sec = h("section", { class: "card glass" }, h("div", { class: "ftop" }, h("h3", { text: "Upkeep" }),
      h("span", { class: "num" }, h("b", { text: fmtWhole$(Math.round(money(V.spent))) }))));
    sec.append(h("div", { class: "list flat" }, bills.slice().reverse().map(b =>
      h("div", { class: "row plain" }, h("span", { class: "title", text: prettyDates(b.date) }),
        h("span", { class: "amt num", text: fmtWhole$(Math.round(money(b.amount))) })))));
    sec.append(h("p", { class: "small muted", text: `${bills.length} bills since ${prettyDates(bills[0].date)}. A bill you have not typed on the Vehicle Maintenance tab is not here.` }));
    p.append(sec);
  }
  p.append(h("button", { class: "btn tinted wide", type: "button", onclick: () => startForm("reading", { what: "odometer" }) }, "Send an odometer reading"));
  p.append(h("p", { class: "foot", text: `${plainSource(V.source)}.` }));
  return p;
}


function renderIncome() {
  const I = (SNAP && SNAP.income) || {}, Y = I.years || {};
  const p = h("div", { class: "page narrow" });
  p.append(head("Income", "What came into the corporation, by the month it arrived."));
  const ys = Object.keys(Y).sort();
  if (!ys.length) { p.append(h("p", { class: "muted", text: "Not arrived yet." })); return p; }
  const now = String(new Date().getFullYear());
  const withMonths = ys.filter(y => Y[y].months.length).reverse();
  const choices = withMonths.slice(0, 3).map(y => [y, Y[y].so_far ? `${y} so far` : y]).concat([["all", "All years"]]);
  const sel = VIEW.year && choices.some(c => c[0] === VIEW.year) ? VIEW.year : choices[0][0];
  const holder = h("div", { class: "page" });
  const draw = v => {
    VIEW.year = v;
    clear(holder);
    if (v === "all") {
      const total = ys.reduce((s2, y) => s2 + money(Y[y].total), 0);
      const basis = ys.every(y => Y[y].basis === "verified") ? "verified" : "recorded";
      holder.append(h("div", { class: "trend-top" },
        h("div", { class: "ftop" }, h("span", { class: "l", text: `Since ${ys[0]}` }), basisDot(basis, [ys.map(y => `${y}: ${BASIS_NAME[Y[y].basis].toLowerCase()}, ${Y[y].note}.`).join(" "), plainSource(I.source) + "."])),
        h("div", { class: "v rounded", text: fmtWhole$(Math.round(total)) }),
        h("div", { class: "fmeta" }, h("span", { class: "asof", text: `${ys.length} years with a year tab; 2022 has none of its own, and its last days, from December 23, are counted in 2023.` +
          (Y[now] && Y[now].so_far ? ` ${now} counts ${keyLabel(`${now}-01`, true).replace(/ \d{4}$/, "")} to ${keyLabel(Y[now].through, true).replace(/ \d{4}$/, "")} only.` : "") }))));
      const ser = { label: "Income", unit: "$", form: "bars", points: ys.map(y => [y, money(Y[y].total)]) };
      holder.append(h("div", { class: "card glass chartcard" }, chart([ser], { form: "bars", unit: "$", height: 220, axis: true, hover: true })));
      holder.append(h("div", { class: "list glass" }, ys.slice().reverse().map(y => {
        const row = h("div", { class: "row plain" },
          h("span", { class: "main" }, h("span", { class: "title", text: Y[y].so_far ? `${y} so far` : y }), h("span", { class: "meta", text: Y[y].note.replace(/^./, c => c.toUpperCase()) })),
          h("span", { class: "est-wrap" }, h("span", { class: "amt", text: fmtWhole$(Math.round(money(Y[y].total))) }), basisDot(Y[y].basis, [`${y}: ${Y[y].note}.`])));
        return Y[y].months.length ? tapArea(row, `${y}, ${fmtWhole$(Math.round(money(Y[y].total)))}. Show by month`, () => pick(y)) : row;
      })));
      return;
    }
    const yr = Y[v];
    const ser = { label: "Income", unit: "$", form: "bars", points: yr.months };
    const top = h("div", { class: "trend-top" },
      h("div", { class: "ftop" }, h("span", { class: "l", text: yr.so_far ? `January to ${keyLabel(yr.through, true).replace(/ \d{4}$/, "")}` : `January to December ${v}` }), basisDot(yr.basis, [`${yr.note.replace(/^./, c => c.toUpperCase())}.`, plainSource(I.source) + "."])),
      h("div", { class: "v rounded", text: fmtWhole$(Math.round(money(yr.total))) }));
    if (yr.so_far && I.same_months_last_year) {
      const before = money(I.same_months_last_year), diff = money(I.same_months_this_year || yr.total) - before;
      top.append(h("div", { class: "fmeta rise" }, `${compact(Math.abs(diff), "$", true)} ${diff >= 0 ? "more" : "less"} than January to ${keyLabel(I.same_months_through, true).replace(/ \d{4}$/, "")} ${Number(v) - 1} (${compact(before, "$", true)}).`));
    }
    holder.append(top);
    const exp = v === now && I.expected && I.expected.year === v ? I.expected : null;
    if (exp) {
      const first = exp.months.find(m => m[2] !== "arrived");
      const ser2 = { label: "Income", unit: "$", form: "bars", points: exp.months.map(m => [m[0], m[1]]), est_from: first ? first[0] : "" };
      holder.append(h("div", { class: "card glass chartcard" }, chart([ser2], { form: "bars", unit: "$", height: 220, axis: true, hover: true })));
      holder.append(expectedCard(exp));
    } else holder.append(h("div", { class: "card glass chartcard" }, chart([ser], { form: "bars", unit: "$", height: 220, axis: true, hover: true })));
    const avg = money(yr.total) / yr.months.length;
    holder.append(h("div", { class: "facts glass card" },
      h("div", {}, h("span", { class: "k", text: "A month, on average" }), h("span", { class: "fv num", text: fmtWhole$(Math.round(avg)) })),
      h("div", {}, h("span", { class: "k", text: "Best month" }), h("span", { class: "fv num", text: (() => { const b = yr.months.reduce((m, x) => x[1] > m[1] ? x : m); return `${keyLabel(b[0], true).replace(/ \d{4}$/, "")}, ${fmtWhole$(Math.round(b[1]))}`; })() }))));
    const list = h("div", { class: "list glass", hidden: true }, yr.months.slice().reverse().map(m => h("div", { class: "row plain" },
      h("span", { class: "title", text: keyLabel(m[0], true) }), h("span", { class: "amt num", text: fmt$(m[1]) }))));
    const toggle = h("button", { class: "btn small gray", type: "button" }, "Show as a list");
    toggle.addEventListener("click", () => { list.hidden = !list.hidden; toggle.textContent = list.hidden ? "Show as a list" : "Hide the list"; });
    holder.append(h("div", { class: "trend-actions" }, toggle), list);
    if (v === now && yr.through === todayISO().slice(0, 7)) holder.append(h("p", { class: "foot", text: `${keyLabel(yr.through, true).replace(/ \d{4}$/, "")} is still going: it counts what has arrived so far.` }));
  };
  const chips = chipRow(choices, sel, v => draw(v), "Which year");
  const pick = y => { for (const x of chips.children) x.setAttribute("aria-checked", String(x.textContent.startsWith(y))); draw(y); };
  p.append(chips, holder);
  draw(sel);
  swipeAlong(chips, holder, BACK, null);
  p.append(h("p", { class: "foot", text: `${plainSource(I.source)}. Your workbook's tab for each year is the record of what came in; the shifts' pay is filled in months later, when the pay details arrive.` }));
  return p;
}

function expectedCard(exp) {
  const total = money(exp.total), arrived = money(exp.arrived), usual = money(exp.usual_month), bonus = money(exp.bonus) || 0;
  const toCome = total - arrived, n = exp.to_come;
  const mon = k => keyLabel(k, true).replace(/ \d{4}$/, "");
  const last = exp.months.filter(m => m[2] === "arrived").pop();
  const why = ["What has arrived, from your year tab, plus each month still to come at your usual month" + (bonus ? ", plus MGH's active staff bonus in December" : "") + ".",
               `Your usual month is the middle one of the ${plural(12, "month")} from ${keyLabel(exp.usual_from, true)} to ${keyLabel(exp.usual_to, true)}: a lump, such as a December's retro pay, or a payment that lands a month early or late, does not move it.`,
               bonus ? `The bonus is taken as one month of MGH pay at ${exp.year}'s average so far (${plural(exp.bonus_months, "month")}), as you expect. December's other lumps, such as retro pay, are not counted until they are known.` : "",
               (exp.assumptions || []).length ? `Written down as ${exp.assumptions.length > 1 ? "assumptions" : "assumption"} ${exp.assumptions.join(" and ")} in the Finance System (profile/assumptions.csv), each with the date it is checked again.` : ""];
  const rows = [[last ? `Arrived, January to ${mon(last[0])}` : "Arrived", arrived, "s0"],
                [n ? `${plural(n, "month")} to come at your usual ${fmtWhole$(Math.round(usual))}` : "", usual * n, "later"],
                [bonus ? "MGH's active staff bonus, in December" : "", bonus, "later"]].filter(r => r[0]);
  return h("section", { class: "card glass expectcard" },
    h("div", { class: "ftop" }, h("span", { class: "l", text: `Expected for ${exp.year}` }), basisDot("estimate", why)),
    h("div", { class: "v rounded", text: "about " + fmtWhole$(Math.round(total / 100) * 100) }),
    meter([{ value: arrived, cls: "s0", label: "Arrived" }, { value: toCome, cls: "s0 faint", label: "To come" }]),
    h("div", { class: "list flat" }, rows.map(([t, v, c]) => h("div", { class: "row plain legendrow2" },
      h("span", { class: "main" }, h("span", { class: "title" }, h("span", { class: "sw2 s0" + (c === "later" ? " faint" : "") }), t)), h("span", { class: "amt", text: fmtWhole$(Math.round(v)) })))),
    exp.months.some(m => m[2] === "logged on the page") ? h("p", { class: "small muted", text: "Counted from what you logged on this page (" + plainSource(((SNAP.income || {}).logged || {}).source || "ledger/web-entries.csv").replace(/^Read from the /, "the ") + "), until your year tab has the month: " +
      exp.months.filter(m => m[2] === "logged on the page").map(m => `${mon(m[0])} ${fmtWhole$(Math.round(m[1]))}`).join(", ") + ". The tab then replaces it, so nothing is counted twice." }) : null,
    ((SNAP.income || {}).logged_not_counted || []).length ? h("p", { class: "small muted", text: "Not counted until your year tab has it in dollars: " +
      SNAP.income.logged_not_counted.map(x => `${x.currency} ${Number(x.amount).toLocaleString("en-CA")} on ${shortDate(x.date)}`).join(", ") + "." }) : null,
    (exp.counted_from_calendar || []).length ? h("p", { class: "small muted", text: "Counted from your calendar: " + exp.counted_from_calendar.map(x => `${x.what.replace(/^./, c => c.toLowerCase())}, ${fmtWhole$(Math.round(money(x.amount)))} in ${mon(x.month)}`).join("; ") + "." }) : null,
    (exp.left_out || []).length ? h("p", { class: "small muted", text: "Not counted: " + exp.left_out.map(x => `${x.what.replace(/^./, c => c.toLowerCase())} (${x.why.replace(/ \(Q-[\d-]+\)$/, "")})`).join("; ") + "." }) : null);
}


const WORKVIEW = { type: "work", metric: "rate" };
function renderWork(embedded) {
  const W = (SNAP && SNAP.work) || {}, C = W.cells || {};
  const V = VIEW && VIEW.type === "work" ? VIEW : WORKVIEW;
  const p = h("div", { class: "page narrow" });
  if (!W.cells) { p.append(embedded ? h("div", { class: "card glass" }, h("p", { class: "muted", text: "These figures have not arrived yet." })) : head("Not available", "These figures have not arrived yet.")); return p; }
  const metric = V.metric === "rate" ? "rate" : "hours";
  if (!embedded) p.append(head("Your work"));
  const years = (W.years || []).slice().reverse();
  const yearC = [["all", "All years"]].concat(years.map(y => [y, y]));
  yearC.push(yearC.shift());
  const places = [["all", "Everywhere"]].concat((W.places || []).map(x => [x.value, x.label.replace(" consulting", "")]));
  V.year = V.year || (years.includes(W.default_year) ? W.default_year : years[0]); V.place = V.place || "all";
  const holder = h("div", { class: "page" });
  const metricSeg = segControl([["hours", "Hours"], ["rate", "Pay per hour"]], metric, v => { V.metric = v; render(); }, "Show", "partseg");
  p.append(metricSeg);
  swipeAlong(metricSeg, holder, embedded ? null : BACK, null);
  const wc = withCommute();
  if (metric === "rate") p.append(segControl([["with", "With the commute"], ["without", "Without"]], wc ? "with" : "without",
    v => { save("pph_commute", v === "with"); render(); }, "Pay per hour, with the commute or without", "range wide"));
  p.append(h("div", { class: "filters" }, chipRow(yearC, V.year, v => { V.year = v; draw(); }, "Which year"),
    chipRow(places, V.place, v => { V.place = v; draw(); }, "Which place")));
  p.append(holder);
  const nameOf = pl => pl === "all" ? "everywhere" : (places.find(x => x[0] === pl) || [pl, pl])[1];
  const cell = (y, pl, site) => C[[y, pl, site || ""].join("|")];
  const rate = c => money(wc ? c.pay_per_hour_incl_travel : c.pay_per_hour), other = c => money(wc ? c.pay_per_hour : c.pay_per_hour_incl_travel);
  const rateBasis = c => (wc ? c.basis_incl_travel : c.basis) || "recorded";
  const paidHours = c => money(c.hours) - (money(c.hours_awaiting_pay) || 0) - (money(c.hours_no_pay_per_activity) || 0);
  const estRow = c => rateBasis(c) === "estimate";
  const caveats = (c, onRate) => {
    if (!c) return null;
    const t = [onRate && c.too_few_shifts ? sentence(c.too_few_shifts) : "", c.provisional ? sentence(c.provisional) : ""].filter(Boolean);
    return t.length ? h("div", { class: "fmeta" }, h("span", { class: "asof", text: t.join(" ") })) : null;
  };
  const thin = c => c && c.too_few_shifts ? "; too few to rest a rate on" : "";
  const why = () => ["Your pay for each shift over its hours. Hours are ones you typed, measured by your phone, or the usual length of that kind of shift.",
                     plainSource(W.source) + "."];
  const draw = () => {
    clear(holder);
    const y = V.year, pl = V.place, c = cell(y, pl);
    const cur = y === String(new Date().getFullYear()) || (W.default_year === y && y === String(new Date().getFullYear() - 1));
    let lagText = "";
    if ((cur || y === "all") && W.last) {
      const countedWord = p => ({ abp: "month invoiced", bochner: "list typed", endoscopy: "list typed" })[p] || "shift typed";
      if (pl !== "all") lagText = W.last[pl] ? `Counted to your last ${countedWord(pl)} there, ${shortDate(W.last[pl])}.` : "";
      else {
        const at = (W.places || []).filter(x => W.last[x.value] && cell(y, x.value)).map(x => `${x.label.replace(" consulting", "")} ${monthDay(W.last[x.value])}`);
        lagText = at.length ? `Counted to the last one typed at each place: ${at.join(", ")}.` : "";
      }
    }
    const K = W.kinds || {};
    const kind = t => K[`${y}|${t}`];
    const unitWord = (place, n) => plural(n, ({ mgh: "shift or call", edlp: "shift", bochner: "list", endoscopy: "list", abp: "month" })[place] || "entry",
                                          ({ mgh: "shifts and calls", edlp: "shifts", bochner: "lists", endoscopy: "lists", abp: "months" })[place] || "entries");
    const unitsText = () => {
      if (pl === "edlp") { const sh = kind("edlp-shift"); return sh ? plural(Number(sh.units), "shift") : ""; }
      const ppk = (pl === "mgh" || pl === "all") && kind("mgh-practice-plan");   // its activities are not shifts
      const stk = pl === "all" && kind("edlp-stipend");                          // nor is a month's stipend (since 2026-09-15)
      const abk = pl === "all" && kind("abp-consulting");                        // ABP's months are named apart (since 2026-09-15)
      const n = units - (ppk ? Number(ppk.units) : 0) - (stk ? Number(stk.units) : 0) - (abk ? Number(abk.units) : 0);
      if (abk && Number(abk.units)) return plural(n, "shift or list", "shifts and lists") + ` and ${plural(Number(abk.units), "month", "months")} of ABP`;
      return plural(n, ({ mgh: "shift or call", bochner: "list", endoscopy: "list", abp: "month's entry", all: "shift or list" })[pl] || "entry",
                    ({ mgh: "shifts and calls", bochner: "lists", endoscopy: "lists", abp: "months' entries", all: "shifts and lists" })[pl] || "entries");
    };
    if (!c) { holder.append(h("div", { class: "card glass" }, h("p", { class: "muted", text: `No work at ${nameOf(pl)} ${y === "all" ? "yet" : "in " + y}.` }))); return; }
    const hrs = money(c.hours), units = Number(c.units), tr = money(c.travel_hours);
    const est = money(c.assumed_hours !== undefined && c.assumed_hours !== "" ? c.assumed_hours : c.estimated_hours);
    const ppHours = money(c.hours_no_pay_per_activity) || 0;
    const ppNote = `${Math.round(ppHours)} h of it is the practice plan, typed once a year and shared evenly over the months of its cycle`;
    const label = `${y === "all" ? "All years" : cur ? y + " so far" : y}, ${nameOf(pl)}` + (metric === "rate" && pl === "edlp" && kind("edlp-stipend") ? " with its stipend"
                  : metric === "rate" && pl === "all" && kind("all:shifts") ? ", all work" : "") + (metric === "rate" ? (wc ? ", with the commute" : ", without the commute") : "");
    if (metric === "hours") {
      holder.append(h("div", { class: "trend-top" },
        h("div", { class: "ftop" }, h("span", { class: "l", text: label }), basisDot(c.basis || "recorded", why())),
        h("div", { class: "v rounded", text: `${Math.round(hrs).toLocaleString("en-CA")} h` }),
        h("div", { class: "fmeta" }, h("span", { class: "asof", text: [unitsText(), tr ? `${Math.round(tr)} h of travel besides` : "",
          est ? `${Math.round(est / hrs * 100)}% of the hours are the usual length of that kind of shift, not typed or measured` : ""].filter(Boolean).join(" · ") })),
        ppHours ? h("div", { class: "fmeta" }, h("span", { class: "asof", text: ppNote })) : null,
        lagText ? h("div", { class: "fmeta" }, h("span", { class: "asof", text: lagText })) : null,
        caveats(c)));
      let ser;
      if (y === "all") ser = { label: "Hours", unit: "h", form: "bars", points: years.slice().reverse().map(k => [k, cell(k, pl) ? money(cell(k, pl).hours) : 0]) };
      else ser = { label: "Hours", unit: "h", form: "bars", points: ((W.monthly || {})[pl] || []).filter(m => m[0].startsWith(y)).map(m => [m[0], m[1]]) };
      if (y !== "all" && (pl === "all" || pl === "mgh") && (W.last || {}).mgh) {
        const [ly, lm] = W.last.mgh.slice(0, 7).split("-").map(Number);
        ser.est_from = lm === 12 ? `${ly + 1}-01` : `${ly}-${String(lm + 1).padStart(2, "0")}`;
        ser.est_word = "so far: MGH's shifts not yet typed";
      }
      if (ser.points.length >= 2) holder.append(h("div", { class: "card glass chartcard" }, chart([ser], { form: "bars", unit: "h", height: 200, axis: true, hover: true })));
      if (pl === "all") {
        const rows = (W.places || []).map(x => ({ key: x.value, label: x.label.replace(" consulting", ""), value: cell(y, x.value) ? money(cell(y, x.value).hours) : 0,
                                                 sub: cell(y, x.value) ? unitWord(x.value, Number(cell(y, x.value).units)
                                                        - (x.value === "mgh" && kind("mgh-practice-plan") ? Number(kind("mgh-practice-plan").units) : 0)
                                                        - (x.value === "edlp" && kind("edlp-stipend") ? Number(kind("edlp-stipend").units) : 0))
                                                      + (x.value === "mgh" && kind("mgh-practice-plan") ? ", and the practice plan" : "") : "" })).filter(r => r.value > 0).sort((a1, b1) => b1.value - a1.value);
        if (rows.length > 1) holder.append(h("section", { class: "section" }, h("h2", { text: "By place" }),
          h("div", { class: "card glass" }, hbars(rows, v => `${Math.round(v).toLocaleString("en-CA")} h`, k => pickPlace(k)))));
      }
    } else {
      holder.append(h("div", { class: "trend-top" },
        h("div", { class: "ftop" }, h("span", { class: "l", text: label }), basisDot(rateBasis(c), why().concat(
          [rateBasis(c) === "estimate" ? "An estimate: more of it rests on the usual length of a shift, or on a commute not measured, than on hours typed or measured." : ""]))),
        h("div", { class: "v rounded" }, estRow(c) ? h("span", { class: "about", text: "about " }) : null, `${fmtWhole$(Math.round(rate(c)))}/h`),
        c.travel_source && wc ? h("div", { class: "fmeta" }, h("span", { class: "asof commute-from" }, basisDot(c.basis_incl_travel || "recorded",
          ["Where the commute hours came from, by share.", "Measured: both legs of the round trip seen by your phone. Worked out: one leg seen and doubled, or the usual round trip for that place. Estimate: an assumption written down in profile/assumptions.csv, such as the Rudd walk and the Don Valley drive."]),
          ` The commute: ${commuteFrom(c.travel_source)}.`)) : null,
        wc && pl === "mgh" && ((W.commute || {}).mgh || {}).median_round_trip_hours && (y === "all" || y >= String(W.commute.mgh.from).slice(0, 4)) ? h("div", { class: "fmeta" }, h("span", { class: "asof",
          text: `MGH's round trip, as your phone measured it: ${Math.round(Number(W.commute.mgh.median_round_trip_hours) * 60)} minutes, the middle of ${W.commute.mgh.round_trips_measured} trips since the move, from ${keyLabel(W.commute.mgh.from, true)} to ${keyLabel(W.commute.mgh.to, true)}` })) : null,
        h("div", { class: "fmeta" }, h("span", { class: "asof", text: `${fmtWhole$(Math.round(other(c)))}/h ${wc ? "without" : "with"} the commute · ${fmtWhole$(Math.round(money(c.pay)))} over ${Math.round(paidHours(c)).toLocaleString("en-CA")} h` + (wc && tr ? ` and ${Math.round(tr).toLocaleString("en-CA")} h of commute` : "") +
          (money(c.hours_awaiting_pay) ? `; ${Math.round(money(c.hours_awaiting_pay))} h of shifts still waiting for their pay are left out` : "") +
          (ppHours ? `; the practice plan's ${Math.round(ppHours)} h are left out, since it is paid as points once a year, not per activity` : "") })),
        lagText ? h("div", { class: "fmeta" }, h("span", { class: "asof", text: lagText })) : null,
        caveats(c, true)));
      const sh = kind(pl + ":shifts");
      const st = pl === "edlp" || pl === "all" ? kind("edlp-stipend") : null, pp = pl === "mgh" || pl === "all" ? kind("mgh-practice-plan") : null;
      if (sh && st) holder.append(h("div", { class: "facts glass card" },
        h("div", {}, h("span", { class: "k", text: "Without EDLP's stipend" }), h("span", { class: "fv num", text: `${fmtWhole$(Math.round(rate(sh)))}/h` })),
        h("div", {}, h("span", { class: "k", text: `EDLP's stipend, ${plural(Number(st.units), "month")}` }), h("span", { class: "fv num", text: fmtWhole$(Math.round(money(st.pay))) })),
        pp ? h("div", {}, h("span", { class: "k", text: "Practice plan, left out" }), h("span", { class: "fv num", text: `${Math.round(money(pp.hours))} h` })) : null));
      if (pl === "all") {
        const rows = (W.places || []).map(x => {
          const alone = K[`${y}|${x.value}:shifts`], mixed = K[`${y}|edlp-stipend`] && x.value === "edlp" || K[`${y}|mgh-practice-plan`] && x.value === "mgh";
          const c2 = mixed && alone ? alone : cell(y, x.value);
          return { key: x.value, label: x.label.replace(" consulting", ""), value: c2 ? rate(c2) : 0, est: c2 ? estRow(c2) : false,
                   sub: c2 ? `${Math.round(paidHours(c2))} h` + (mixed && alone ? ", shifts alone" : "") + thin(c2) : "" };
        }).filter(r => r.value > 0).sort((a1, b1) => b1.value - a1.value);
        if (rows.length) holder.append(h("section", { class: "section" }, h("h2", { text: "By place" }),
          h("div", { class: "card glass" }, hbars(rows, v => `${fmtWhole$(Math.round(v))}/h`, k => pickPlace(k)))));
      } else {
        const rows = years.map(k => { const ck = cell(k, pl); return { label: k, value: ck ? rate(ck) : 0, on: k === y, est: ck ? estRow(ck) : false,
          sub: ck ? `${Math.round(paidHours(ck))} h` + thin(ck) : "" }; }).filter(r => r.value > 0);
        if (rows.length > 1) holder.append(h("section", { class: "section" }, h("h2", { text: `${nameOf(pl)}, year by year` }), h("div", { class: "card glass" }, hbars(rows, v => `${fmtWhole$(Math.round(v))}/h`)),
          pl === "edlp" ? h("p", { class: "foot", text: "Each year counts the monthly stipend with the shifts' pay, over the shifts' hours." }) : null));
        bySite(k => rate(C[k]), v => `${fmtWhole$(Math.round(v))}/h`, k => `${unitWord(pl, Number(C[k].units))}, ${Math.round(paidHours(C[k]))} h`
               + (wc && C[k].travel_source ? `; commute ${commuteShort(C[k].travel_source)}` : "") + thin(C[k]),
               pl === "edlp" ? "The shifts alone: the monthly stipend belongs to no site." : "", k => estRow(C[k]));
      }
    }
    if (metric === "hours" && pl !== "all") bySite(k => money(C[k].hours), v => `${Math.round(v).toLocaleString("en-CA")} h`, k => unitWord(pl, Number(C[k].units)), "");
    const stEnd = W.last && W.last["edlp-stipend"], shEnd = W.last && W.last.edlp;
    if (metric === "rate" && (pl === "edlp" || pl === "all") && kind("edlp-stipend") && stEnd && shEnd && stEnd.slice(0, 7) > shEnd.slice(0, 7) && (cur || y === "all"))
      holder.append((W.seen && W.seen.edlp && W.seen.edlp > shEnd)
        ? h("p", { class: "foot warnline", text: `EDLP's stipend is counted to ${monthDay(stEnd)}, its shifts to ${monthDay(shEnd)}, and your phone saw EDLP work on ${monthDay(W.seen.edlp)}. Until those shifts are typed, the figure with the stipend is too high; the shifts alone are not affected.` })
        : h("p", { class: "foot", text: `EDLP's stipend is counted to ${monthDay(stEnd)}, its shifts to ${monthDay(shEnd)}; your phone saw no EDLP shift after that${W.seen_to ? ` (to ${monthDay(W.seen_to)})` : ""}, so the months since are stipend with no hours, which lifts the figure with the stipend.` }));
    holder.append(h("p", { class: "foot", text: (metric === "rate" ? "Your pay for each shift, over its hours" + (wc ? " and the round trip to it" : "") + ". " : "") + "Hours are ones you typed, measured by your phone, or the usual length of that kind of shift." + (metric === "rate" && wc ? " A commute is measured where your phone saw both legs, doubled from one leg, or the usual round trip for that place: the Rudd walk and the Don Valley drive are estimates you gave." : "") + " Worked out in the work-hours workings, from your Work tab and the shifts sent from this page." }));
  };
  const pickPlace = k => { V.place = k; render(); };
  function bySite(valOf, fmtV, subOf, note, estOf) {
    const y = V.year, pl = V.place;
    const keysOf = yy => Object.keys(C).filter(k => { const [a1, b1, s2] = k.split("|"); return a1 === yy && b1 === pl && s2; });
    const here = keysOf(y).map(k => ({ label: k.split("|")[2], value: valOf(k), sub: subOf(k), est: estOf ? estOf(k) : false })).filter(r => r.value > 0).sort((a1, b1) => b1.value - a1.value);
    const others = keysOf("all").map(k => k.split("|")[2]).filter(s2 => !here.some(r => r.label === s2)).sort();
    if (!here.length && !others.length) return;
    const sec = h("section", { class: "section" }, h("h2", { text: `By site, ${y === "all" ? "all years" : y}` }));
    if (here.length) sec.append(h("div", { class: "card glass" }, hbars(here, fmtV)));
    if (note && here.length) sec.append(h("p", { class: "foot", text: note }));
    if (others.length && y !== "all") sec.append(h("p", { class: "foot" }, `Worked in other years only: ${others.join(", ")}. `,
      h("button", { class: "link", type: "button", onclick: () => { V.year = "all"; render(); } }, "Show all years")));
    holder.append(sec);
  }
  draw();
  return p;
}

function sparkOf(ser, o) {
  const y = String(new Date().getFullYear());
  if (ser.form === "bars" && (/so far/.test(o.label || "") || (o.label || "").includes(y))) {
    const pts = ser.points.filter(p2 => String(p2[0]).startsWith(y));
    if (pts.length >= 2) return { ...ser, points: pts };
  }
  return ser;
}
function wholeValue(v) {
  return String(v || "").replace(/^(-?)\$([\d,]+)\.(\d\d)\b/, (m, sg, d, c) => sg + "$" + Math.round(Number(d.replace(/,/g, "")) + Number(c) / 100).toLocaleString("en-CA"));
}
function priceSplit(d0, d1, ch) {
  const S = (SNAP && SNAP.series) || {};
  if (!S.invest_market || !S.invest_cost || !ch) return "";
  const at = (ser2, d) => ser2.points.find(q => String(q[0]).slice(0, 7) === String(d).slice(0, 7));
  const m0 = at(S.invest_market, d0), m1 = at(S.invest_market, d1), b0 = at(S.invest_cost, d0), b1 = at(S.invest_cost, d1);
  if (!(m0 && m1 && b0 && b1)) return "";
  const prices = Math.round(((m1[1] - b1[1]) - (m0[1] - b0[1])) / 1000) * 1000, kept = ch - prices;
  return ` Prices ${prices >= 0 ? "added" : "took away"} ${compact(Math.abs(prices), "$")}; ${kept >= 0 ? "the other " + compact(kept, "$") + " is money it kept from your work and its funds' reinvested distributions" : "money also went out"}.`;
}
function deltaOf(ser, sid) {
  if (!ser || ser.form !== "line" || ser.points.length < 6) return null;
  const pts = ser.points, last = pts[pts.length - 1], lastD = dateOf(last[0]);
  let prev = null, bestGap = Infinity;
  for (const q of pts) {
    const d = dateOf(q[0]); if (!d) continue;
    const days = (lastD - d) / 864e5;
    if (days >= 350 && days <= 380 && Math.abs(days - 365) < bestGap) { bestGap = Math.abs(days - 365); prev = q; }
  }
  if (!prev) return null;
  const k1 = v => Math.round(v / 1000) * 1000;
  const ch = k1(last[1] - prev[1]);
  let text = ch === 0 ? `About the same since ${prettyDates(prev[0])}.` : `${ch > 0 ? "Up" : "Down"} ${compact(Math.abs(ch), ser.unit)} since ${prettyDates(prev[0])}.`;
  const S = (SNAP && SNAP.series) || {};
  if (sid === "invest_market" && S.invest_cost) {
    const c = S.invest_cost.points, c0 = c.find(q => q[0] === prev[0]), c1 = c.find(q => q[0] === last[0]);
    if (c0 && c1 && c1[1] - c0[1] > 0) {
      const moved = k1((last[1] - c1[1]) - (prev[1] - c0[1])), put = ch - moved;
      text += ` ${compact(put, "$")} was money put in or distributions reinvested; ` + (moved === 0 ? "prices made little difference." : `prices ${moved > 0 ? "added" : "took away"} ${compact(Math.abs(moved), "$")}.`);
    } else if (c0 && c1 && c1[1] - c0[1] < 0) text += " Money was also taken out, so this is not what prices did.";
  }
  if (sid === "corp_market") text += priceSplit(prev[0], last[0], ch);
  return h("span", { class: "delta", text });
}


function renderTrend() {
  const S = (SNAP && SNAP.series) || {};
  const p = h("div", { class: "page narrow" });
  let keys, title, fig = null;
  if (VIEW.figId !== undefined) { fig = ov(VIEW.figId); keys = fig && fig.series ? [fig.series] : []; title = fig ? fig.label : ""; }
  else { keys = VIEW.keys || []; title = VIEW.title || ""; }
  const house = VIEW.figId === "household" ? householdNow() : null;
  if (house && S.corp_market) keys = keys.concat(["corp_market"]);
  const sers = keys.map(k => k === "corp_market" && house ? { ...S[k], label: "Corporation alone" } : k === "household" && house ? { ...S[k], label: "Household" } : S[k]).filter(Boolean);
  if (!sers.length) { p.append(head("Not available", "This history has not arrived yet.")); return p; }
  const main = sers[0], last = main.points[main.points.length - 1];
  p.append(head(title, fig ? "" : ""));
  if (house) {
    const nw = SNAP.networth || {};
    const up = house.est && nw.household ? Math.round((house.total - money(nw.household)) / 1000) * 1000 : null;
    const top = h("div", { class: "trend-top" },
      h("div", { class: "ftop" }, h("span", { class: "l", text: "At " + prettyDates(house.date) }), basisDot(house.basis, householdWhy(house))),
      h("div", { class: "v rounded", text: (house.est ? "about " : "") + fmtWhole$(Math.round(house.total)) }));
    if (up !== null) top.append(h("div", { class: "fmeta rise" }, h("span", { class: "delta", text: `${up >= 0 ? "Up" : "Down"} ${compact(Math.abs(up), "$")} since ${prettyDates(nw.date)}, when it was ${fmtWhole$(Math.round(money(nw.household)))}.` })));
    top.append(h("div", { class: "fmeta" }, h("span", { class: "asof", text: "Before the tax paid to take money out of the corporation." })));
    p.append(top);
    p.append(h("div", { class: "card glass chartcard" }, chart(sers, { form: "line", unit: "$", height: 240, legend: true, axis: true, hover: true })));
    const pts = main.points.slice().reverse();
    p.append(h("section", { class: "section" }, h("h2", { text: "Each point" }), h("div", { class: "list glass" }, pts.map(pt => {
      const est = main.est_from && String(pt[0]) >= main.est_from;
      return h("div", { class: "row plain" }, h("span", { class: "main" }, h("span", { class: "title", text: prettyDates(pt[0]) }),
        h("span", { class: "meta", text: est ? "Latest, an estimate" : "Year end" })),
        h("span", { class: "est-wrap" }, h("span", { class: "amt", text: (est ? "about " : "") + fmtWhole$(Math.round(pt[1])) }), basisDot(est ? "estimate" : "derived", est ? householdWhy(house) : ["The corporation at market plus the TFSA, RRSP and FHSA at their December statements."])));
    }))));
    p.append(h("p", { class: "foot", text: "The household has a point at each year end, from the TFSA, RRSP and FHSA's December statements, and at the latest estimate. " +
      "Dec 31, 2023 is missing because the corporation's 2023 bank statements can no longer be obtained. The corporation alone has a point every month." }));
    return p;
  }
  let lead = fig ? String(fig.value).replace(/\.00$/, "") : compact(last[1], main.unit, true), leadNote = null;
  if (!fig && keys[0] === "invest_market" && S.invest_cost) {
    const lc = S.invest_cost.points[S.invest_cost.points.length - 1];
    if (lc && lc[0] === last[0]) {
      lead = compact(last[1], "$", true);
      const gapV = last[1] - lc[1];
      leadNote = h("div", { class: "fmeta rise" },
        `Worth ${compact(Math.abs(gapV), "$", true)} ${gapV >= 0 ? "more" : "less"} than the ${compact(lc[1], "$", true)} they cost, at ${keyLabel(last[0], true)}. The cost counts the money put in and the distributions reinvested.`);
    }
  }
  const asOf = fig && fig.as_of ? prettyDates(fig.as_of) : keyLabel(last[0], true);
  const big = h("div", { class: "trend-top" },
    h("div", { class: "ftop" }, h("span", { class: "l", text: "At " + asOf }),
      basisDot(fig ? fig.basis : main.basis, fig ? whyLines(fig) : [plainSource(main.source) + "."])),
    h("div", { class: "v rounded", text: lead }));
  if (fig && fig.note) big.append(h("div", { class: "fmeta" }, h("span", { class: "asof", text: fig.note + "." })));
  if (leadNote) big.append(leadNote);
  const rise = deltaOf(main, keys[0]);
  if (rise) big.append(h("div", { class: "fmeta rise" }, rise));
  if (/corp_market|household/.test(keys[0])) big.append(h("div", { class: "fmeta" }, h("span", { class: "asof", text: "Before the tax paid to take money out of the corporation." })));
  p.append(big);
  const ranges = main.points.length > 14 ? [[12, "1 year"], [36, "3 years"], [0, "All"]] : [];
  const holder = h("div", { class: "card glass chartcard" });
  const draw = n => { clear(holder); holder.append(chart(sers, { form: main.form, unit: main.unit, height: 240, legend: sers.length > 1, axis: true, hover: true, range: n })); };
  if (ranges.length) {
    const rs = VIEW.range !== undefined ? VIEW.range : keys[0] === "remit" ? 12 : 36;
    const segs = h("div", { class: "segs range", role: "radiogroup", "aria-label": "How far back" });
    for (const [n, lab] of ranges) {
      const b = h("button", { type: "button", role: "radio", "aria-checked": String(n === rs) }, lab);
      b.addEventListener("click", () => { VIEW.range = n; for (const x of segs.children) x.setAttribute("aria-checked", String(x === b)); draw(n); });
      segs.append(b);
    }
    p.append(segs);
    draw(rs);
    swipeAlong(segs, holder, BACK, null);
  } else draw(0);
  p.append(holder);
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
  p.append(h("p", { class: "foot", text: [gap ? "A break in the line marks months whose bank statement is not filed yet." : "", plainSource(main.source) + ".",
    main.form === "bars" && /^\d{4}-\d{2}$/.test(last[0]) ? "The month in progress is left out until it is over." : ""].filter(Boolean).join(" ") }));
  return p;
}


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
  if (unit === "km") return `${Math.round(v).toLocaleString("en-CA")} km`;
  const a = Math.abs(v), sg = v < 0 ? "−" : "";
  if (full) return sg + "$" + Math.round(a).toLocaleString("en-CA");
  if (a >= 1e6) return `${sg}$${(a / 1e6).toFixed(a >= 1e7 ? 0 : 1)}M`;
  if (a >= 1e3) return `${sg}$${(a / 1e3).toFixed(a >= 1e4 ? 0 : 1).replace(/\.0$/, "")}K`;
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
function estAt(s2, k) { return !!((s2.est_from && String(k) >= s2.est_from) || (s2.estimate_keys && s2.estimate_keys.includes(String(k)))); }
function motionOK() { return !(window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches); }

function chart(sers, o) {
  const box = h("div", { class: "chart" + (o.spark ? " spark-chart" : "") + (o.hover !== false && !o.spark ? " scrub" : "") });
  const tip = h("div", { class: "tip", hidden: true });
  if (!o.spark) box.append(tip);
  if (o.legend) box.append(h("div", { class: "legend" }, sers.map((s2, j) => h("span", { class: "lk" }, h("span", { class: "sw s" + j }), s2.label))));
  const tOf = k => /^\d{4}$/.test(k) ? new Date(+k, 6, 1).getTime() : /^\d{4}-\d{2}$/.test(k) ? new Date(+k.slice(0, 4), +k.slice(5, 7) - 1, 15).getTime() : (dateOf(k) || new Date(0)).getTime();
  let lastW = 0, first = true;
  const draw = () => {
    if (!box.isConnected && !first) return;
    const W = Math.round(box.clientWidth || 300), H = o.height || 160;
    if (!W || W === lastW) return;
    lastW = W;
    const old = box.querySelector("svg"); if (old) old.remove();
    const bars = o.form === "bars";
    const lastT = Math.max(...sers.map(s2 => tOf(s2.points[s2.points.length - 1][0])));
    const fromT = o.range ? lastT - o.range * 30.44 * 864e5 - 15 * 864e5 : -Infinity;
    const S2 = sers.map(s2 => ({ ...s2, points: s2.points.filter(p2 => tOf(p2[0]) >= fromT) })).filter(s2 => s2.points.length);
    if (!S2.length) return;
    const keys = bars || S2.length === 1 ? S2[0].points.map(p2 => p2[0])
      : [...new Set(S2.flatMap(s2 => s2.points.map(p2 => p2[0])))].sort((a1, b1) => tOf(a1) - tOf(b1));
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
          const oneYear = new Date(t0).getFullYear() === new Date(t1).getFullYear();
          if (xi !== null && xi >= L - 1 && xi <= W - R + 1) labs.push([xi, m === 0 && !oneYear ? String(d.getFullYear()) : d.toLocaleDateString("en-CA", { month: "short" })]);
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
        const bw = Math.max(2, Math.min(24, band - Math.max(2, band * .32)));
        s2.points.forEach((p2, i) => {
          const x0 = x(i, p2[0]) - bw / 2, y0 = y(Math.max(0, p2[1])), hh = Math.max(0, y(0) - y0), r = Math.min(4, bw / 2, hh);
          if (hh <= 0) { svg.append(sv("line", { class: "zero", x1: x0 + 1, x2: x0 + bw - 1, y1: y(0) - .5, y2: y(0) - .5 })); return; }
          const d = `M${x0},${y(0)} V${y0 + r} Q${x0},${y0} ${x0 + r},${y0} H${x0 + bw - r} Q${x0 + bw},${y0} ${x0 + bw},${y0 + r} V${y(0)} Z`;
          const bar = sv("path", { class: "col s" + j + (anim ? " grow" : "") + (estAt(s2, p2[0]) ? " est" : ""), d });
          if (anim) bar.style.setProperty("--d", `${Math.min(i * 12, 400)}ms`);
          svg.append(bar);
        });
      } else {
        const steps = s2.points.slice(1).map((p2, i) => tOf(p2[0]) - tOf(s2.points[i][0])).sort((a1, b1) => a1 - b1);
        const usual = steps.length ? steps[Math.floor(steps.length / 2)] : 0;
        const segs = [[]];
        const ei = s2.est_from ? s2.points.findIndex(p2 => String(p2[0]) >= s2.est_from) : -1;
        const solidN = ei > 0 ? ei : s2.points.length;
        s2.points.slice(0, solidN).forEach((p2, i) => {
          if (i && (!o.spark || W > 400) && tOf(p2[0]) - tOf(s2.points[i - 1][0]) > Math.max(40 * 864e5, usual * 1.6)) segs.push([]);
          segs[segs.length - 1].push([x(i, p2[0]), y(p2[1])]);
        });
        const estSeg = ei > 0 ? s2.points.slice(ei - 1).map(p2 => [x(0, p2[0]), y(p2[1])]) : null;
        const dOf = seg => seg.map((q, i) => (i ? "L" : "M") + q[0].toFixed(1) + "," + q[1].toFixed(1)).join(" ");
        if (S2.length === 1) for (const seg of segs) if (seg.length > 1) svg.append(sv("path", { class: "area s" + j + (anim ? " fade" : ""), d: dOf(seg) + ` L${seg[seg.length - 1][0].toFixed(1)},${T + ih} L${seg[0][0].toFixed(1)},${T + ih} Z` }));
        for (const seg of segs) {
          if (seg.length === 1) { svg.append(sv("circle", { class: "end s" + j, cx: seg[0][0], cy: seg[0][1], r: S2.length > 1 ? 3 : 2 })); continue; }
          svg.append(sv("path", { class: "line s" + j + (anim ? " draw" : ""), d: dOf(seg) }));
        }
        if (estSeg) svg.append(sv("path", { class: "line est s" + j, d: dOf(estSeg) }));
        if (s2.points.length <= 6 && !o.spark) for (const q of segs.flat()) svg.append(sv("circle", { class: "end s" + j, cx: q[0], cy: q[1], r: 3.2 }));
        const all = estSeg || segs[segs.length - 1], e = all[all.length - 1];
        if (!o.spark || j === 0) svg.append(sv("circle", { class: "end s" + j + (estSeg ? " est" : ""), cx: e[0], cy: e[1], r: o.spark ? 2.6 : 4 }));
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
        tip.append(h("div", { class: "tk", text: keyLabel(keys[i], true) }));
        if (o.tip) {
          tip.classList.add("wide");
          for (const r of o.tip(keys[i], S2))
            tip.append(h("div", { class: "tr " + (r.cls || "") },
              r.swatch == null ? null : h("span", { class: "sw s" + r.swatch }),
              h("span", { class: "tn", text: r.name }), h("b", { text: r.value })));
        } else
        tip.append(...S2.map((s2, j) => {
          const pt = s2.points.find(q => q[0] === keys[i]);
          if (!pt) return null;             // a history with no point on this date says nothing
          const est = estAt(s2, pt[0]);
          return h("div", { class: "tr" }, S2.length > 1 ? h("span", { class: "sw s" + j }) : null, h("span", { text: (S2.length > 1 ? s2.label + ": " : "") + (est && !s2.est_word ? "about " : "") + compact(pt[1], s2.unit, true) + (est && s2.est_word ? ", " + s2.est_word : "") }));
        }).filter(Boolean));
        tip.hidden = false;
        const tx = xs[i] / W * box.clientWidth, tw = tip.offsetWidth, cw = box.clientWidth;
        tip.style.left = (tx > cw / 2 ? Math.max(0, tx - tw - 14) : Math.min(cw - tw, tx + 14)) + "px";
      };
      const hide = () => { cross.setAttribute("hidden", ""); dots.forEach(d => d.setAttribute("hidden", "")); tip.hidden = true; };
      hit.addEventListener("pointermove", show); hit.addEventListener("pointerdown", show);
      hit.addEventListener("pointerleave", hide); hit.addEventListener("pointercancel", hide);
    }
  };
  if (window.ResizeObserver) {
    const ro = new ResizeObserver(() => { if (!box.isConnected && !first) { ro.disconnect(); return; } requestAnimationFrame(draw); });
    ro.observe(box);
  }
  setTimeout(draw, 0);
  return box;
}

function dropPaths(t) {
  return String(t || "")
    .replace(/\s*\((?=[^)]*[\w-]+\/)[^)]*\)/g, "")   // a bracket that holds a path, anywhere
    .replace(/\s*\([^)]*\)\s*$/, "")                  // and still the trailing bracket, whatever it holds
    .replace(/\s{2,}/g, " ").replace(/\s+([,;.])/g, "$1").trim();
}
const ID_RE = "[QDA]-20\\d\\d-\\d\\d-\\d\\d(?:-\\d\\d)?";
function dropIds(t) {
  return String(t || "")
    .replace(new RegExp("\\s*\\((?:see\\s+|under\\s+)?" + ID_RE + "\\)", "gi"), "")
    .replace(new RegExp("\\s*(?:Recorded as|Recorded under|Under|See)\\s+" + ID_RE + "\\s*\\.", "gi"), "")
    .replace(new RegExp("\\s*,?\\s*" + ID_RE, "g"), "")
    .replace(/\s{2,}/g, " ").replace(/\s+([,;.])/g, "$1").trim();
}
function plainSource(src) {
  const m = /^(models|ledger)\/([^/]+?)(?:\/|\.csv)/.exec(src || "");
  if (!m) return "From " + dropPaths(src);
  const name = m[2].replace(/-/g, " ").replace(/\bqt\b/, "Questrade").replace(/\bcorp\b/, "corporate");
  const more = /[;,]\s*(.+)$/.exec(String(src).slice(m.index + m[0].length));
  return (m[1] === "models" ? `Worked out in the ${name} workings` : `Read from the ${name} record`)
    + (more ? `; ${dropPaths(more[1]).replace(/\.$/, "")}` : "");
}


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
    h("p", { class: "foot", text: "Only what you send from Add leaves this device. This page refuses to send text holding a number shaped like a SIN, a card, an account or a phone number. What you send waits in your private mailbox until the MacBook collects it, within 15 minutes of being open, and blacks out anything of that shape it still finds before it is written down. Never type a password here." }),
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
  const prefix = ["github", "pat", ""].join("_");
  return v.startsWith(prefix) && /^[A-Za-z0-9_]{30,}$/.test(v);
}


let LOCK = { mode: "unlock", pin: "", first: "", msg: "", bad: false, shook: false, busy: false, migrating: false };
let OPENING = false;

function lockScreen(mode, extra) {
  LOCK = Object.assign({ mode, pin: "", first: "", msg: "", bad: false, shook: false, busy: false, migrating: LOCK.migrating }, extra || {});
  const el = document.getElementById("lock");
  const overApp = mode === "change-old" || mode === "change-new" || mode === "change-confirm";
  const entering = el.hidden && !el.classList.contains("at-start");
  el.classList.remove("going");
  el.classList.toggle("over-app", overApp);
  el.hidden = false;
  OPENING = false;
  if (!overApp) {
    document.getElementById("app").hidden = true;
    clear(document.getElementById("main"));
  }
  drawLock(entering);
}
function closeLock() {
  const el = document.getElementById("lock");
  clearTimeout(unlockInto.fallback);
  el.classList.remove("going");
  el.classList.remove("over-app");
  el.hidden = true;
  OPENING = false;
}
function unlockInto(draw) {
  const el = document.getElementById("lock");
  if (!motionOK()) { closeLock(); draw(); return; }
  OPENING = true;
  el.classList.add("over-app");
  draw();
  const done = ev => { if (ev && ev.target !== el) return; el.removeEventListener("animationend", done); closeLock(); };
  el.addEventListener("animationend", done);
  clearTimeout(unlockInto.fallback);
  unlockInto.fallback = setTimeout(() => { if (OPENING) done(); }, 600);
  requestAnimationFrame(() => { if (OPENING) el.classList.add("going"); });
}

function drawLock(entering) {
  const el = clear(document.getElementById("lock"));
  const inner = h("div", { class: "lock-inner" + (entering ? " enter" : "") });
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
  const sub = h("p", { class: "sub" });
  const dots = h("div", { class: "dots", "aria-hidden": "true" });
  for (let i = 0; i < PIN_LEN; i++) dots.append(h("span", {}));
  const sr = h("p", { class: "sr", "aria-live": "polite" });
  inner.append(sub, dots, sr);
  const pad = h("div", { class: "pad" });
  const letters = ["", "ABC", "DEF", "GHI", "JKL", "MNO", "PQRS", "TUV", "WXYZ"];
  const digits = [];
  for (let d = 1; d <= 9; d++) {
    const b = h("button", { type: "button", "aria-label": String(d) }, h("span", {}, String(d), h("span", { class: "sub2", text: letters[d - 1] || "\u00a0" })));
    tapKey(b, () => press(String(d))); digits.push(b); pad.append(b);
  }
  const cancelable = LOCK.mode.startsWith("change");
  pad.append(cancelable ? h("button", { class: "txt", type: "button", onclick: () => { if (LOCK.busy) return; LOCK.mode = "cancelled"; closeLock(); render(); } }, "Cancel") : h("span", { class: "blank" }));
  const zero = h("button", { type: "button", "aria-label": "0" }, "0");
  tapKey(zero, () => press("0")); digits.push(zero); pad.append(zero);
  const del = h("button", { class: "txt", type: "button", "aria-label": "Delete the last digit" }, "Delete");
  tapKey(del, () => press("del")); pad.append(del);
  inner.append(pad);
  if (window.matchMedia && matchMedia("(pointer: fine)").matches) inner.append(h("p", { class: "hint2", text: "You can also type the digits." }));
  if (LOCK.mode === "unlock") inner.append(h("button", { class: "link", type: "button", onclick: () => { if (!LOCK.busy) forgot(); } }, "Forgot your passcode?"));
  LOCK.ui = { sub, dots, sr, digits, del, fallback: s };
  updateLock();
}

function tapKey(b, fn) {
  let viaPointer = false;
  const up = () => b.classList.remove("down");
  b.addEventListener("pointerdown", ev => {
    if (ev.button > 0 || b.disabled) return;
    viaPointer = true; ev.preventDefault();
    b.classList.add("down");
    if (fn() === false) b.classList.remove("down");    // a key it is ignoring must not light
  });
  for (const ev of ["pointerup", "pointercancel", "pointerleave"]) b.addEventListener(ev, up);
  b.addEventListener("click", () => { if (viaPointer) { viaPointer = false; return; } fn(); });   // the keyboard's Enter and Space
}

function updateLock() {
  const u = LOCK.ui;
  if (!u || !u.dots.isConnected) return;
  const lo = lockout();
  const waitMs = LOCK.mode === "unlock" || LOCK.mode === "change-old" ? lo.until - Date.now() : 0;
  u.sub.className = "sub" + (LOCK.bad ? " bad" : "");
  u.sub.textContent = waitMs > 0 ? `Too many tries. Try again in ${Math.ceil(waitMs / 1000)} seconds.` : (LOCK.msg || u.fallback);
  Array.from(u.dots.children).forEach((d, i) => d.classList.toggle("on", i < LOCK.pin.length));
  u.sr.textContent = `${LOCK.pin.length} of ${PIN_LEN} digits`;
  for (const b of u.digits) b.disabled = waitMs > 0;
  u.del.style.visibility = LOCK.pin.length ? "visible" : "hidden";
  clearTimeout(updateLock.shake);          // never let a shake from a past try clear digits typed since
  if (LOCK.bad && !LOCK.shook) {
    LOCK.shook = true;
    u.dots.classList.remove("shake"); void u.dots.offsetWidth; u.dots.classList.add("shake");
    updateLock.shake = setTimeout(() => {
      u.dots.classList.remove("shake");
      if (LOCK.clearAfterShake) { LOCK.clearAfterShake = false; LOCK.pin = ""; updateLock(); }
    }, 460);
  }
  clearTimeout(updateLock.t);
  if (waitMs > 0) updateLock.t = setTimeout(updateLock, 1000);
}

function forgot() {
  sheet("Forgot your passcode?", "The only way back is to erase this device's copy and paste the key again. If you no longer have the key, make a new one on GitHub, as the instructions on your MacBook describe. Nothing in your records is lost: they live on the MacBook.",
    [{ label: "Erase and start again", kind: "danger", run: () => { eraseDevice(); lockScreen("setup-key"); } }]);
}

function press(k) {
  if (LOCK.busy) return false;
  if (k === "del") {
    if (!LOCK.pin.length) return false;
    LOCK.pin = LOCK.pin.slice(0, -1);
    LOCK.bad = false;                      // pressing Delete during a shake used to restart the shake
    updateLock();
    return true;
  }
  if (LOCK.pin.length >= PIN_LEN) return false;
  if (lockout().until > Date.now() && (LOCK.mode === "unlock" || LOCK.mode === "change-old")) return false;
  LOCK.pin += k;
  LOCK.bad = false;
  updateLock();
  if (LOCK.pin.length === PIN_LEN) { LOCK.busy = true; setTimeout(() => { LOCK.busy = false; complete(); }, 120); }
  return true;
}

async function complete() {
  if (LOCK.mode === "cancelled") return;          // Cancel was tapped while the passcode was being checked
  const pin = LOCK.pin, first = LOCK.first;
  LOCK.pin = ""; LOCK.first = "";
  const m = LOCK.mode;
  if (m === "setup-new" || m === "change-new") { lockScreen(m === "setup-new" ? "setup-confirm" : "change-confirm", { first: pin }); return; }
  if (m === "setup-confirm" || m === "change-confirm") {
    if (pin !== first) { lockScreen(m === "setup-confirm" ? "setup-new" : "change-new", { msg: "The passcodes did not match. Choose one again.", bad: true }); return; }
    LOCK.busy = true; LOCK.msg = "Locking your data…"; updateLock();
    if (!MEM) MEM = {};                               // a first passcode on a device with nothing in it yet
    if (!await setPasscode(pin) || !MEM) {                 // the page locked while the key was being made
      LOCK.busy = false;
      if (!lockShowing()) lockScreen(hasVault() ? "unlock" : "setup-key",
                                     { msg: "The page locked itself before that was saved. Your passcode has not changed." });
      return;
    }
    save("lockout", { fails: 0, until: 0 });
    LOCK.migrating = false;
    const setUp = m === "setup-confirm";
    unlockInto(() => afterUnlock(setUp));
    toast(setUp ? "Passcode set." : "Passcode changed.");
    return;
  }
  const lo = lockout();
  if (lo.until > Date.now()) { LOCK.pin = ""; updateLock(); return; }
  LOCK.busy = true; LOCK.pin = pin; updateLock();
  const ok = await unlockWith(pin).catch(() => false);
  LOCK.busy = false;
  if (LOCK.mode === "cancelled") return;          // cancelled while the six digits were being checked
  if (!ok) {
    const fails = lo.fails + 1;
    save("lockout", { fails, until: Date.now() + failWait(fails) });
    LOCK.bad = true; LOCK.shook = false; LOCK.clearAfterShake = true;
    LOCK.msg = fails >= 4 ? `Wrong passcode. ${fails >= 5 ? "Wait, then try again." : "One more try before a wait."}` : "Wrong passcode. Try again.";
    updateLock();
    return;
  }
  save("lockout", { fails: 0, until: 0 });
  if (m === "change-old") { lockScreen("change-new"); return; }
  unlockInto(() => afterUnlock(false));
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
  historyBack(STACK.length + (VIEW ? 1 : 0));    // after a passcode change from Settings, its pages' history steps go too
  VIEW = null; STACK = [];
  touch();
  render();
  if (!fresh || NET !== "ok") refresh().then(flush); else flush();
}

function dropNeighbours() {
  NB = { ver: -1 }; clearTimeout(NB_TIMER);
  for (const x of document.querySelectorAll("main.peek, .peek-part")) x.remove();
}
function lockNow() {
  dropNeighbours();
  saveDraftNow();                               // what was typed in the last 400 ms, before the vault is sealed
  const saved = persist();
  if (NEW_PAGE) saved.then(() => location.reload());
  historyBack(STACK.length + (VIEW ? 1 : 0));    // the pages' history steps go with the pages
  GEN++;
  MEM = null; VKEY = null; VMETA = null; SNAP = null; SCHEMA = null; VIEW = null; STACK = [];
  for (const s of document.querySelectorAll(".scrim, .pop")) s.remove();
  lockScreen(hasVault() ? "unlock" : "setup-key");
}

let LAST = Date.now(), HIDDEN_AT = 0, NEW_PAGE = false;
function touch() { LAST = Date.now(); }
function autolockMs() { return load("autolock", 5) * 60000; }
function lockShowing() { return !document.getElementById("lock").hidden && !OPENING; }
function openBehind() { return !!MEM && (!lockShowing() || LOCK.mode.startsWith("change")); }
function checkIdle() { if (openBehind() && Date.now() - LAST > Math.max(autolockMs(), 60000)) lockNow(); }
function awayCheck() {
  document.body.classList.remove("veiled");
  if (openBehind() && HIDDEN_AT && Date.now() - HIDDEN_AT >= autolockMs()) { lockNow(); return true; }
  return false;
}


let PENDING_OLD = [];
function sweepOldAtStart() {
  try { const o = JSON.parse(rawGet(OLD.outbox) || "null"); if (Array.isArray(o)) PENDING_OLD = o; } catch (e) { /* ignore */ }
  sweepOld();
}

const WORKPAY_RES = new Set(["paid-by", "partly-paid", "write-off", "resubmitted", "not-owed", "paid-amount"]);
const PART_ORDER = ["base", "shadow", "travel", "expense", "stipend", "ohip", "private", "invoice"];
const STATUS_WORDS = { "paid": "Paid", "settled": "Settled", "waiting": "Waiting", "waiting (amount not yet known)": "Waiting, amount not known yet",
  "waiting (bank statement not filed)": "Waiting for the bank statement", "overdue": "Overdue", "short": "Paid short", "rejected": "Rejected by OHIP",
  "in question": "In question", "over": "Paid more than submitted", "partly paid": "Partly paid, rest to come", "details to come": "Paid; details to come",
  "not owed": "Not owed", "written off": "Written off", "extra": "Extra" };
const STATUS_KIND = st => /^(paid|settled|not owed|written off|details to come)/.test(st) ? "paid" : /^(overdue|short|rejected|in question|over)/.test(st) ? "problem" : /waiting|partly/.test(st) ? "waiting" : "none";
function workPay() { return (SNAP && SNAP.work_pay) || {}; }
function workPart() { const v = load("workpart", "owed"); return ["owed", "shifts", "pay"].includes(v) ? v : "owed"; }
function unitTitle(u) {
  const place = PLACE_NAMES_PAGE[u.payer] || u.payer;
  const site = u.site && !["MGH", "Bochner Eye Institute", "ABP"].includes(u.site) ? ` ${u.site}` : "";
  const esc = t => String(t || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const desc = String(u.description || "").replace(new RegExp("^" + esc(u.site) + "\\s+", "i"), "").replace(new RegExp("^" + esc(place) + "\\s+", "i"), "");
  return `${place}${site} · ${desc}`.replace(/ · $/, "");
}
const PLACE_NAMES_PAGE = { mgh: "MGH", edlp: "EDLP", bochner: "Bochner", endoscopy: "Endoscopy", abp: "ABP" };
function partDots(parts) {
  const ps = parts.slice().sort((a, b) => PART_ORDER.indexOf(a.part) - PART_ORDER.indexOf(b.part));
  return h("span", { class: "pdots", role: "img", "aria-label": ps.map(x => `${x.part_name} ${STATUS_WORDS[x.status] || x.status}`).join(", ") },
    ps.map(x => h("span", { class: "pdot " + STATUS_KIND(x.status), title: `${x.part_name}: ${STATUS_WORDS[x.status] || x.status}` })));
}
function issueOf(key) { return (workPay().issues || []).find(i => i.key === key) || null; }
function issuesAnsweredHere() { return answeredHere(); }

function renderWorkTab() {
  const p = h("div", { class: "page" });
  p.append(head("Work", "Every shift, each part of its pay, and what to chase.", true));
  const wp = workPay();
  if (!SNAP || !wp.items) {
    p.append(h("div", { class: "card glass" }, h("p", { class: "muted", text: SNAP ? "The work tracker has not run on the MacBook yet. It runs at the next round." : "Waiting for the first summary." })));
    if (SNAP && SNAP.work && SNAP.work.cells) p.append(renderWork(true));
    return p;
  }
  const part = workPart();
  const holder = h("div", { class: "page" });
  const draw = v => {
    clear(holder);
    const body = v === "shifts" ? workShifts() : v === "pay" ? renderWork(true) : workOwed();
    if (motionOK()) body.classList.add("fadein");
    holder.append(body);
  };
  const seg = segControl([["owed", "Owed"], ["shifts", "Shifts"], ["pay", "Pay"]], part, v => { save("workpart", v); closePop(); draw(v); }, "Which part of Work", "partseg");
  p.append(seg, holder);
  draw(part);
  swipeAlong(seg, holder, () => tabStep(-1), () => tabStep(1));
  return p;
}

function workOwed() {
  const wp = workPay(), out = h("div", { class: "page" });
  const t = wp.totals || {};
  const mine = issuesAnsweredHere();
  const issues = (wp.issues || []).filter(i => !mine.has(i.id));
  const chase = issues.filter(i => i.status === "CHASE"), ask = issues.filter(i => i.status !== "CHASE");
  const waiting = (wp.items || []).filter(i => /^waiting|partly|details/.test(i.status));
  out.append(h("div", { class: "card glass owedlead" },
    h("div", {}, h("span", { class: "k", text: "Overdue" }), h("span", { class: "fv num " + (money(t.overdue) > 0 ? "red" : ""), text: fmtWhole$(Math.round(money(t.overdue) || 0)) }),
      h("span", { class: "small muted", text: plural(chase.length, "payment") })),
    h("div", {}, h("span", { class: "k", text: "To explain" }), h("span", { class: "fv num " + (ask.length ? "orange" : ""), text: String(ask.length) }),
      h("span", { class: "small muted", text: "questions" })),
    h("div", {}, h("span", { class: "k", text: "Waiting" }), h("span", { class: "fv num", text: fmtWhole$(Math.round(money(t.waiting) || 0)) }),
      h("span", { class: "small muted", text: `${plural(waiting.length, "part")}${t.unknown && Number(t.unknown) ? `, ${t.unknown} with no figure yet` : ""}` }))));
  const issueRow = i => {
    const dt = dateOf(i.date);
    return tapArea(h("div", { class: "row" },
      dt ? h("span", { class: "day", "aria-hidden": "true" }, h("span", { class: "wd", text: dt.toLocaleDateString("en-CA", { weekday: "short" }) }),
        h("span", { class: "dn", text: String(dt.getDate()) }), h("span", { class: "mo", text: dt.toLocaleDateString("en-CA", { month: "short" }) })) : null,
      h("span", { class: "main" }, h("span", { class: "title clamp", text: prettyDates(i.text) }),
        h("span", { class: "meta" }, h("span", { class: "chip " + (i.status === "CHASE" ? "red" : "orange"), text: i.status === "CHASE" ? "Overdue" : "Explain" }),
          i.amount ? ` ${fmtWhole$(Math.round(money(i.amount)))}` : "", ` · ${PLACE_NAMES_PAGE[i.payer] || i.payer.toUpperCase()}`)),
      icon("chevR")), `${prettyDates(i.text)}. Answer`, () => workpayAnswer(i));
  };
  if (chase.length || ask.length) {
    const sec = h("section", { class: "section" }, h("h2", { text: "Needs you" }));
    const ul = h("div", { class: "list glass" });
    for (const i of chase.concat(ask)) ul.append(issueRow(i));
    sec.append(ul, h("p", { class: "foot", text: "Tap one to say what happened: it was paid by this deposit, partly paid, rejected, resubmitted, not owed, or paid an amount you type. Your answer is the match." }));
    out.append(sec);
  } else {
    out.append(h("div", { class: "card glass" }, h("p", { class: "muted", text: "Nothing is overdue and nothing needs explaining." })));
  }
  if (waiting.length) {
    const sec = h("section", { class: "section" }, h("h2", { text: "Waiting, as expected" }));
    const byPayer = {};
    for (const i of waiting) (byPayer[i.payer] = byPayer[i.payer] || []).push(i);
    for (const [payer, its] of Object.entries(byPayer)) {
      const ul = h("div", { class: "list glass" });
      for (const i of its.sort((a, b) => (a.expected_by || "9999").localeCompare(b.expected_by || "9999"))) {
        const u = (wp.units || []).find(x => x.id === (i.row_ids || "").split(";")[0]);
        ul.append(h("button", { class: "row plain", type: "button", onclick: () => u && openView({ type: "workunit", id: u.id, title: unitTitle(u) }) },
          h("span", { class: "main" }, h("span", { class: "title", text: `${i.part_name} · ${u ? unitTitle(u) : i.description}` }),
            h("span", { class: "meta", text: `${shortDate(i.date)}` + (i.expected_by ? ` · expected by ${shortDate(i.expected_by)}` : "") + (i.status === "waiting (bank statement not filed)" ? " · the bank statement is not filed yet" : i.status === "waiting (amount not yet known)" ? " · amount not known yet" : "") })),
          h("span", { class: "amt", text: i.expected ? fmt$(i.expected) : "" }), icon("chevR")));
      }
      out.append(h("section", { class: "section" }, h("h2", { text: PLACE_NAMES_PAGE[payer] || payer.toUpperCase() }), ul));
    }
  }
  const bp = (wp.by_payer || []).filter(x => money(x.expected) > 0 || money(x.paid) > 0);
  if (bp.length) {
    const sec = h("section", { class: "section" }, h("h2", { text: `By payer, since ${prettyDates(wp.since)}` }));
    for (const x of bp) {
      sec.append(h("div", { class: "facts glass card" },
        h("div", {}, h("span", { class: "k", text: x.label }), h("span", { class: "fv num", text: `${fmtWhole$(Math.round(money(x.paid)))} paid` })),
        h("div", {}, h("span", { class: "k", text: "Waiting" }), h("span", { class: "fv num", text: fmtWhole$(Math.round(money(x.waiting))) })),
        h("div", {}, h("span", { class: "k", text: "Overdue" }), h("span", { class: "fv num" + (money(x.overdue) > 0 ? " red" : ""), text: fmtWhole$(Math.round(money(x.overdue))) })),
        Number(x.problems) ? h("div", {}, h("span", { class: "k", text: "To explain" }), h("span", { class: "fv num orange", text: String(x.problems) })) : null));
    }
    out.append(sec);
  }
  out.append(h("p", { class: "foot", text: `Matched to the bank's deposits to ${prettyDates(wp.reach)}, the Ministry's remittance advices, and what you logged here; nothing is overdue past that day. Work before ${prettyDates(wp.settled_to)} was settled by hand and is not chased. Worked out on the MacBook by the work-pay workings.` }));
  return out;
}

function workShifts() {
  const wp = workPay(), out = h("div", { class: "page" });
  const units = (wp.units || []).slice();
  const known = new Set(units.map(u => u.entry_id).filter(Boolean));
  for (const x of allShifts()) {
    if (x.state === "filed" || known.has(x.id)) continue;
    const f = x.fields || {};
    units.push({ id: x.id, entry_id: x.id, payer: placeOfShift(f), site: f.site || "", date: f.date || "", description: f.description || "", parts: [],
                 status: x.state === "unsent" ? "not sent" : "waiting for the MacBook", local: x.state });
  }
  units.sort((a, b) => String(b.date).localeCompare(String(a.date)));
  const needs = units.filter(u => STATUS_KIND(u.status) === "problem" || u.local);
  const waiting = units.filter(u => STATUS_KIND(u.status) === "waiting");
  const which = { needs: needs, waiting: waiting, all: units };
  let v = load("workshifts", "all"); if (!which[v] || !which[v].length) v = "all";
  const holder = h("div", { class: "page" });
  const draw = k => {
    clear(holder);
    let month = "", ul = null;
    for (const u of which[k]) {
      const m = String(u.date || "").slice(0, 7);
      if (m !== month) { month = m; ul = h("div", { class: "list glass" }); holder.append(h("section", { class: "section" }, h("h2", { text: m ? keyLabel(m, true) : "No date" }), ul)); }
      const dt = dateOf(u.date);
      const paid = u.parts.filter(x => STATUS_KIND(x.status) === "paid").reduce((a, x) => a + (money(x.paid) || 0), 0);
      const expected = u.parts.reduce((a, x) => a + (money(x.expected) || 0), 0);
      const chips = [];
      if (u.local === "unsent") chips.push(h("span", { class: "chip orange", text: "Not sent" }));
      else if (u.local === "sent") chips.push(h("span", { class: "chip blue", text: "Waiting for MacBook" }));
      else if (STATUS_KIND(u.status) === "problem") chips.push(h("span", { class: "chip red", text: STATUS_WORDS[u.status] || u.status }));
      ul.append(h("button", { class: "row", type: "button", onclick: () => u.local ? openView({ type: "form", kind: "shift", corrects: u.id, prefill: (allShifts().find(x => x.id === u.id) || {}).fields || {}, details: true, label: unitTitle(u) })
                                                                                : openView({ type: "workunit", id: u.id, title: unitTitle(u) }) },
        h("span", { class: "day", "aria-hidden": "true" }, h("span", { class: "wd", text: dt ? dt.toLocaleDateString("en-CA", { weekday: "short" }) : "" }),
          h("span", { class: "dn", text: dt ? String(dt.getDate()) : "" }), h("span", { class: "mo", text: dt ? dt.toLocaleDateString("en-CA", { month: "short" }) : "" })),
        h("span", { class: "main" }, h("span", { class: "title" }, unitTitle(u), u.parts.length ? partDots(u.parts) : null),
          h("span", { class: "meta", text: u.parts.length ? `${fmtWhole$(Math.round(paid))} of ${expected ? fmtWhole$(Math.round(expected)) : "an amount not yet known"} paid · ${u.parts.length} part${u.parts.length === 1 ? "" : "s"}` : "Sent from this page" }),
          chips.length ? h("span", { class: "chiprow" }, chips) : null),
        icon("chevR")));
    }
    if (!which[k].length) holder.append(h("div", { class: "card glass" }, h("p", { class: "muted", text: "None." })));
  };
  const seg = segControl([["all", `All · ${units.length}`], ["needs", `Needs you · ${needs.length}`], ["waiting", `Waiting · ${waiting.length}`]], v, k => { save("workshifts", k); draw(k); }, "Which shifts", "range wide");
  out.append(seg, holder);
  draw(v);
  swipeAlong(seg, holder, null, null);
  out.append(h("p", { class: "foot", text: `Each dot is one part of a shift's pay: green paid, orange waiting, red needs you. Shifts from ${prettyDates(wp.since)}; earlier ones were settled by hand. Shifts typed in the workbook are changed there; a shift sent from here can be corrected from its page.` }));
  return out;
}

function renderWorkUnit() {
  const wp = workPay();
  const u = (wp.units || []).find(x => x.id === VIEW.id);
  const p = h("div", { class: "page narrow" });
  if (!u) { p.append(head("Not available", "This shift's figures have not arrived yet.")); return p; }
  p.append(head(unitTitle(u), prettyDates(u.date)));
  const card = h("div", { class: "card glass" });
  const mine = issuesAnsweredHere();
  for (const x of u.parts.slice().sort((a, b) => PART_ORDER.indexOf(a.part) - PART_ORDER.indexOf(b.part))) {
    const it = (wp.items || []).find(i => i.key === x.key) || {};
    const issue = issueOf(x.key);
    const kind = STATUS_KIND(x.status);
    const line = h("div", { class: "partrow" },
      h("span", { class: "pn" }, h("span", { class: "pdot " + kind, "aria-hidden": "true" }), " ", x.part_name),
      h("span", { class: "pv num", text: x.expected ? fmt$(x.expected) : (x.paid && money(x.paid) ? fmt$(x.paid) : "not known yet") }),
      h("span", { class: "pm" }, `${STATUS_WORDS[x.status] || x.status}` + (kind === "paid" && x.paid_date ? `, ${prettyDates(x.paid_date)}` : "")
        + (kind === "paid" && x.expected && money(x.paid) !== money(x.expected) && money(x.paid) ? `: ${fmt$(x.paid)} of ${fmt$(x.expected)}` : "")
        + (kind === "waiting" && x.expected_by ? `; expected by ${prettyDates(x.expected_by)}` : "")
        + (it.ohip_claims ? `; ${plural(Number(it.ohip_claims), "claim")} on the remittance` : "")
        + (it.note ? `. ${prettyDates(it.note)}` : "") + (it.answer ? `. ${it.answer}` : "")));
    if (issue && !mine.has(issue.id)) line.append(h("span", { class: "pm" }, h("button", { class: "btn small tinted", type: "button", onclick: () => workpayAnswer(issue) }, "Say what happened")));
    card.append(line);
  }
  p.append(card);
  if (u.entry_id) {
    const x = allShifts().find(z => z.id === u.entry_id);
    p.append(h("div", { class: "list glass" }, h("button", { class: "row", type: "button", onclick: () => openView({ type: "form", kind: "shift", corrects: u.entry_id, prefill: (x && x.fields) || {}, details: true, label: unitTitle(u) }) },
      h("span", { class: "ico blue" }, icon("work")), h("span", { class: "main" }, h("span", { class: "title", text: "Add hours, patients or pay" }), h("span", { class: "meta", text: "This shift was sent from this page; a change replaces it in your books" })), icon("chevR"))));
  } else {
    p.append(h("p", { class: "foot", text: "Typed in the workbook: its figures are changed there. What is paid comes from the bank and the Ministry's remittance advice." }));
  }
  return p;
}

function workpayAnswer(i) {
  const wp = workPay();
  const words = i.kind === "payment" ? "This deposit" : "This payment";
  const send = (resolution, extra, said) => submit("answer", Object.assign({ question: i.id, answer: said, resolution }, extra || {}), "", said);
  const pickThen = (title, choices, then) => {
    const acts = choices.slice(0, 8).map(c => ({ label: c.label, kind: "tinted", run: () => then(c.key) }));
    acts.push({ label: "Something else: type it", run: () => startForm("answer", { question: i.id }, "work") });
    sheet(title, choices.length ? "" : "No deposit still to place fits; type what you know.", acts);
  };
  const deposits = (wp.payments_open || []).map(x => ({ key: x.key, label: `${shortDate(x.date)} · ${fmt$(x.amount)}${x.label ? ` · ${x.label}` : x.source === "page" ? " · logged here" : ""}` }));
  const acts = [];
  if (i.kind === "payment") {
    acts.push({ label: "It paid these shifts", kind: "tinted", run: () => pickThen("Which shifts did it pay?", i.candidates, key => send("paid-by", { deposit: key }, "Paid by this deposit.")) });
    acts.push({ label: "It paid part of them; the rest is to come", run: () => pickThen("Which shifts, in part?", i.candidates, key => startForm("answer", { question: i.id, resolution: "partly-paid", deposit: key, answer: "Partly paid; the rest is to come." }, "work")) });
    acts.push({ label: "It is not for any shift", run: () => send("not-owed", {}, "Not for any shift.") });
  } else if (i.kind === "ohip-no-work" || i.kind === "ohip-which") {
    acts.push({ label: "Add that day's shift or list", kind: "tinted", run: () => startForm("shift", { date: i.date }, "work") });
    if (i.candidates && i.candidates.length) acts.push({ label: "It belongs to one of these", run: () => pickThen("Which one?", i.candidates, key => send("paid-by", { deposit: key }, "It belongs to this one.")) });
  } else {
    acts.push({ label: "It was paid", kind: "tinted", run: () => pickThen("By which deposit?", deposits, key => send("paid-by", { deposit: key }, "Paid by this deposit.")) });
    acts.push({ label: "Partly paid; the rest is to come", run: () => pickThen("By which deposit, in part?", deposits, key => startForm("answer", { question: i.id, resolution: "partly-paid", deposit: key, answer: "Partly paid; the rest is to come." }, "work")) });
    acts.push({ label: "Rejected: write it off", run: () => send("write-off", {}, "Rejected; written off.") });
    acts.push({ label: "I resubmitted it", run: () => startForm("answer", { question: i.id, resolution: "resubmitted", answer: "Resubmitted." }, "work") });
    acts.push({ label: "Not owed", run: () => send("not-owed", {}, "Not owed.") });
    acts.push({ label: "It was paid \u2014 let me type the amount", run: () => startForm("answer", { question: i.id, resolution: "paid-amount", answer: "Paid; the amount is typed." }, "work") });
  }
  acts.push({ label: "Something else: type it", run: () => startForm("answer", { question: i.id }, "work") });
  sheet(prettyDates(i.text), "", acts, "Not now");
}

function chqAnswer(q, from) {
  const send = label => submit("answer", { question: q.id, answer: label, resolution: "label" }, "", `Labelled: ${label}`);
  const acts = (q.chq.choices || []).slice(0, 8).map((c, i) => ({ label: c, kind: i === 0 ? "tinted" : "", run: () => send(c) }));
  acts.push({ label: "Something else: type it", run: () => startForm("answer", { question: q.id, resolution: "label" }, from) });
  sheet(prettyDates(q.text), "", acts, "Not now");
}

async function boot() {
  const wire = sel => { for (const b of document.querySelectorAll(sel)) b.addEventListener("click", () => go(b.dataset.tab)); };
  wire("#seg button"); wire("#tabbar button");
  const TAB_ICON = { today: "today", add: "plusc", work: "work", numbers: "numbers" };
  for (const b of document.querySelectorAll("#tabbar button")) {
    b.append(icon(TAB_ICON[b.dataset.tab]), h("span", { text: TAB_NAME[b.dataset.tab] }));
  }
  document.getElementById("gear").append(icon("gear"));
  document.getElementById("gear").addEventListener("click", () => openView({ type: "settings" }));
  document.getElementById("bar-done").addEventListener("click", () => closeView());
  document.getElementById("sync").addEventListener("click", () => openView({ type: "settings" }));
  window.addEventListener("scroll", onScroll, { passive: true });
  document.addEventListener("touchstart", gStart, { passive: true });
  document.addEventListener("touchmove", gMove, { passive: false });
  document.addEventListener("touchend", gEnd, { passive: true });
  document.addEventListener("touchcancel", gEnd, { passive: true });
  document.addEventListener("click", ev => {
    if (Date.now() < NO_CLICK_UNTIL) { ev.stopPropagation(); ev.preventDefault(); return; }
    if (!(ev.target && ev.target.closest && ev.target.closest(".bdot, .pop"))) neighboursStale();
  }, true);
  if (window.ResizeObserver) new ResizeObserver(measureBar).observe(document.getElementById("bar"));
  window.addEventListener("resize", measureBar);
  window.addEventListener("popstate", () => {
    if (OWN_BACKS) { OWN_BACKS -= 1; return; }     // a step back the page took itself has already been drawn
    if (VIEW) closeView(true);
  });
  for (const ev of ["pointerdown", "keydown", "scroll", "touchstart"]) window.addEventListener(ev, touch, { passive: true });
  setInterval(checkIdle, 20000);
  let wasStale = null;
  setInterval(() => {
    if (!MEM || lockShowing()) return;
    const stale = !!(SNAP && hoursSince(SNAP.checked_at) > STALE_HOURS);
    if (wasStale !== null && stale !== wasStale) quietRender(); else renderChrome();
    wasStale = stale;
  }, 60000);
  document.addEventListener("keydown", ev => {
    if (document.getElementById("lock").hidden || OPENING || document.querySelector(".scrim") || LOCK.mode === "setup-key") return;
    if (ev.target && /^(INPUT|TEXTAREA|SELECT)$/.test(ev.target.tagName)) return;
    if (/^[0-9]$/.test(ev.key)) press(ev.key);
    else if (ev.key === "Backspace") press("del");
  });
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) { saveDraftNow(); HIDDEN_AT = Date.now(); document.body.classList.add("veiled"); if (MEM) persist(); return; }
    if (awayCheck()) return;
    touch();
    if (MEM) { flush(); refresh(); }
  });
  window.addEventListener("pagehide", () => { saveDraftNow(); HIDDEN_AT = Date.now(); document.body.classList.add("veiled"); if (MEM) persist(); });
  window.addEventListener("pageshow", () => { awayCheck(); });
  window.addEventListener("online", () => { if (MEM) { flush(); refresh(); } });

  const fresh = fetch("config.json", { cache: "no-store" }).then(r => r.json()).then(c => { CFG = c; save("cfg", c); }).catch(() => {});
  CFG = load("cfg", null);
  if (!CFG) await fresh;
  if ("serviceWorker" in navigator) {
    const had = !!navigator.serviceWorker.controller;
    navigator.serviceWorker.addEventListener("controllerchange", () => {
      if (!had) return;
      if (!MEM && LOCK.mode === "unlock" && !LOCK.pin && !LOCK.busy && !PENDING_OLD.length) location.reload(); else NEW_PAGE = true;
    });
    navigator.serviceWorker.register("sw.js").then(reg => {
      document.addEventListener("visibilitychange", () => { if (!document.hidden) reg.update().catch(() => {}); });
    }).catch(() => { /* the page works without it, only not offline */ });
  }

  document.getElementById("lock").classList.add("at-start");
  setTimeout(() => document.getElementById("lock").classList.remove("at-start"), 1000);
  if (hasVault()) { sweepOldAtStart(); lockScreen("unlock"); return; }
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
