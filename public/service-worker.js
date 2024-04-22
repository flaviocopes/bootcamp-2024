const CACHE_NAME = 'pwa-cache-v1'
const ASSETS_TO_CACHE = [
  'offline.html',
  'favicon.svg',
  'manifest.json'
]

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(ASSETS_TO_CACHE)
    })
  )
})

self.addEventListener('fetch', (event) => {
  event.respondWith(
    fetch(event.request).catch(() => {
      if (event.request.mode === 'navigate') {
        return caches.match('/offline.html')
      }
    })
  )
})
