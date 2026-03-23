const CACHE_NAME = 'ncokit-v1';
const STATIC_ASSETS = [
  '/',
  '/manifest.json',
  '/icons/icon-192.png',
  '/icons/icon-512.png',
  'https://fonts.googleapis.com/css2?family=Oswald:wght@400;500;600;700&family=Source+Code+Pro:wght@400;500&family=Libre+Franklin:wght@300;400;500;600&display=swap'
];

// Install — cache static assets
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      return cache.addAll(STATIC_ASSETS).catch(err => {
        console.log('Cache install error:', err);
      });
    })
  );
  self.skipWaiting();
});

// Activate — clean up old caches
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys => {
      return Promise.all(
        keys.filter(key => key !== CACHE_NAME).map(key => caches.delete(key))
      );
    })
  );
  self.clients.claim();
});

// Fetch — network first, fall back to cache
self.addEventListener('fetch', event => {
  const { request } = event;
  const url = new URL(request.url);

  // Always fetch API calls fresh — never cache
  if (url.pathname.startsWith('/api/') || url.hostname === 'api.anthropic.com') {
    event.respondWith(
      fetch(request).catch(() => {
        return new Response(
          JSON.stringify({ error: 'You are offline. AI features require an internet connection.' }),
          { headers: { 'Content-Type': 'application/json' } }
        );
      })
    );
    return;
  }

  // For navigation requests — network first, fall back to cached homepage
  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request)
        .then(response => {
          // Cache the fresh response
          const clone = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(request, clone));
          return response;
        })
        .catch(() => {
          return caches.match('/').then(cached => {
            if (cached) return cached;
            return new Response(
              `<!DOCTYPE html>
              <html><head><title>NCO Kit — Offline</title>
              <meta name="viewport" content="width=device-width, initial-scale=1">
              <style>
                body { background:#0d0f0d; color:#C8B48A; font-family:Arial,sans-serif; display:flex; align-items:center; justify-content:center; height:100vh; margin:0; text-align:center; }
                .logo { font-size:48px; font-weight:bold; letter-spacing:8px; margin-bottom:16px; }
                .msg { color:#a08e65; font-size:14px; line-height:1.6; }
              </style></head>
              <body>
                <div>
                  <div class="logo">NCO KIT</div>
                  <p class="msg">You're currently offline.<br>Connect to the internet to use NCO Kit's AI features.</p>
                </div>
              </body></html>`,
              { headers: { 'Content-Type': 'text/html' } }
            );
          });
        })
    );
    return;
  }

  // For static assets — cache first, fall back to network
  event.respondWith(
    caches.match(request).then(cached => {
      if (cached) return cached;
      return fetch(request).then(response => {
        if (response.ok) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(request, clone));
        }
        return response;
      }).catch(() => cached || new Response('Offline', { status: 503 }));
    })
  );
});
