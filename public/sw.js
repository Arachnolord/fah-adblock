// ============================================================================
// Erdacht und programmiert von Fabian Hammer.
// (c) 2026 Fabian Hammer - Alle Rechte vorbehalten. Geistiges Eigentum.
// Unbefugte Vervielfaeltigung, Weitergabe oder Verwertung dieses Quellcodes ohne
// schriftliche Genehmigung des Urhebers ist untersagt.
// ============================================================================
// Service-Worker nur für Benachrichtigungen (Kinderschutz-Meldungen per Web-Push) – kein Zwischenspeicher, die Oberfläche
// kommt immer frisch vom Server. Jede Push-Nachricht zeigt eine Benachrichtigung (iOS verlangt das).
'use strict';
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
self.addEventListener('push', (e) => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch (x) { d = { text: e.data ? e.data.text() : '' }; }
  const titel = String(d.titel || 'FAH-Adblock').slice(0, 200);
  e.waitUntil(self.registration.showNotification(titel, {
    body: String(d.text || '').slice(0, 1000), icon: 'icon-192.png', badge: 'icon-192.png', lang: 'de',
    tag: d.tag ? String(d.tag).slice(0, 64) : undefined, renotify: !!d.tag, requireInteraction: !!d.ernst,
    data: { url: typeof d.url === 'string' && d.url.startsWith('./') ? d.url : './#kinderschutz' },
  }));
});
self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  const ziel = new URL(e.notification.data?.url || './', self.registration.scope).href;
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((liste) => {
    for (const c of liste) if (c.url.startsWith(self.registration.scope) && 'focus' in c) { if ('navigate' in c) c.navigate(ziel).catch(() => {}); return c.focus(); }
    return self.clients.openWindow(ziel);
  }));
});
