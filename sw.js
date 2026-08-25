// Keliton Ateliê: no offline cache on GitHub Pages.
// This worker immediately unregisters itself so older builds cannot intercept API/login requests.
self.addEventListener('install', event => self.skipWaiting());
self.addEventListener('activate', event => {
  event.waitUntil((async () => {
    try {
      const regs = await self.registration.scope;
    } catch (_) {}
    await self.registration.unregister();
    const clients = await self.clients.matchAll({type:'window'});
    clients.forEach(c => c.navigate(c.url));
  })());
});
