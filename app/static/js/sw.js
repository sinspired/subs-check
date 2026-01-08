// 这是一个最小化的 Service Worker，仅为了满足 PWA 安装标准
self.addEventListener('install', (e) => {
  self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  e.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', (e) => {
  // 可以在这里添加缓存逻辑，目前保持透传即可
  e.respondWith(fetch(e.request));
});