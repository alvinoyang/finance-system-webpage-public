/* Lets the web page open with no signal, and open fast with one. The page's own files are answered from the copy
   kept here at once, and fetched fresh behind it, so the next opening has the newest (since 2026-09-15: every
   opening waited on the network for each file first, the copy used only with no signal). config.json is still
   fetched fresh first, as the page asks. Requests to GitHub's API are never touched here: the page keeps its own
   saved summary and its outbox.
   A file missing from the list no longer stops the worker from installing (until 2026-09-15 the two PNG icons,
   drawn only at deploy, were on the list though missing from webpage/, and a copy served from there never
   installed). */
"use strict";
const CACHE = "finance-system-webpage-v8";
// The two PNG icons are left out (since 2026-09-15): the page never shows them, the phone fetches them itself when
// the page is added to the Home Screen, and they were 260 KB of a first opening on a slow connection.
const FILES = ["./", "index.html", "app.js", "style.css", "config.json", "manifest.webmanifest", "icon.svg"];
const FRESH_FIRST = new Set(["config.json"]);

self.addEventListener("install", ev => {
  ev.waitUntil(caches.open(CACHE)
    .then(c => Promise.all(FILES.map(f => c.add(f).catch(() => { /* one file missing must not stop the rest */ }))))
    .then(() => self.skipWaiting()));
});

self.addEventListener("activate", ev => {
  ev.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
    .then(() => self.clients.claim()));
});

self.addEventListener("fetch", ev => {
  const url = new URL(ev.request.url);
  if (ev.request.method !== "GET" || url.origin !== self.location.origin) return;
  const name = url.pathname.split("/").pop();
  const fromNet = () => fetch(ev.request).then(resp => {
    if (resp.ok) { const copy = resp.clone(); caches.open(CACHE).then(c => c.put(ev.request, copy)); }
    return resp;
  });
  if (FRESH_FIRST.has(name)) {
    ev.respondWith(fromNet().catch(() => caches.match(ev.request)));
    return;
  }
  ev.respondWith(caches.match(ev.request, { ignoreSearch: true }).then(hit => {
    const net = fromNet();
    if (hit) { ev.waitUntil(net.catch(() => {})); return hit; }
    return net.catch(() => caches.match("index.html"));
  }));
});
