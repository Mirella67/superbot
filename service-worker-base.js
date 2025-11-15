const CACHE_NAME = "superbot-cache-v1";
const OFFLINE_URL = "/";

self.addEventListener("install", event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache =>
      cache.addAll(["/", "/manifest.json"])
    )
  );
  self.skipWaiting();
});

self.addEventListener("activate", event => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener("fetch", event => {
  const req = event.request;

  event.respondWith(
    fetch(req)
      .then(res => {
        const resClone = res.clone();
        caches.open(CACHE_NAME).then(c => c.put(req, resClone));
        return res;
      })
      .catch(() => caches.match(req).then(r => r || caches.match(OFFLINE_URL)))
  );
});
