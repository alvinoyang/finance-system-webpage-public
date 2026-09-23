"use strict";
const CACHE = "finance-system-webpage-caf0a5a4608e";      // deploy replaces "v8" with a stamp of the page's files
const FILES = ["./", "index.html", "app.js", "style.css", "config.json", "manifest.webmanifest", "icon.svg"];
const FRESH_FIRST = new Set(["config.json"]);

self.addEventListener("install", ev => {
  ev.waitUntil(caches.keys().then(keys => {
    const mode = keys.some(k => k !== CACHE && k.startsWith("finance-system-webpage-")) ? "reload" : "default";
    return caches.open(CACHE).then(c => Promise.all(FILES.map(f =>
      c.add(new Request(f, { cache: mode })).catch(() => { /* one file missing must not stop the rest */ }))));
  }).then(() => self.skipWaiting()));
});

self.addEventListener("activate", ev => {
  ev.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
    .then(() => self.clients.claim()));
});

self.addEventListener("fetch", ev => {
  const url = new URL(ev.request.url);
  if (ev.request.method !== "GET" || url.origin !== self.location.origin) return;
  const name = url.pathname.split("/").pop();
  const fromNet = () => fetch(ev.request.url, { cache: "no-cache", credentials: "same-origin" }).then(resp => {
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
