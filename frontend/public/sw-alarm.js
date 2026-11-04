// The Watch SOC — Emergency Intrusion Alarm & Tab Auto-Focus Service Worker
// Automatically focuses or opens The Watch SOC screen/tab when an alarm fires.

self.addEventListener('install', () => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

async function focusOrOpenWatchTab(alertData) {
  const clientList = await self.clients.matchAll({
    type: 'window',
    includeUncontrolled: true,
  });

  for (const client of clientList) {
    try {
      client.postMessage({
        type: 'NAVIGATE_TO_WATCH_SOC',
        alert: alertData || null,
      });
      if ('focus' in client) {
        await client.focus();
        return client;
      }
    } catch (e) {
      // continue to next client or openWindow fallback
    }
  }

  if (self.clients.openWindow) {
    try {
      const opened = await self.clients.openWindow('/?soc_alarm=1');
      if (opened && 'focus' in opened) {
        await opened.focus();
      }
      return opened;
    } catch (e) {
      // ignore if browser blocks openWindow outside notificationclick
    }
  }
  return null;
}

self.addEventListener('message', (event) => {
  const data = event.data || {};
  if (data.type === 'TRIGGER_EMERGENCY_ALARM') {
    const alert = data.alert || {};
    const title = `🚨 INTRUSION ALERT [${alert.systemId || 'THE-WATCH'}]: ${alert.threatClassification || 'Active Threat'}`;
    const body = `Attacker IP: ${alert.offendingIp || 'Unknown'} (${alert.geoCity || 'Unknown'}, ${alert.geoCountry || 'Unknown'}) — Click or check The Watch SOC immediately.`;

    event.waitUntil(
      (async () => {
        await focusOrOpenWatchTab(alert);
        if (self.registration && self.registration.showNotification) {
          try {
            await self.registration.showNotification(title, {
              body,
              icon: '/logo.jpg',
              badge: '/favicon.jpg',
              tag: 'the-watch-emergency-alarm',
              renotify: true,
              requireInteraction: true,
              vibrate: [600, 200, 600, 200, 1000],
              data: alert,
              actions: [
                {
                  action: 'open-watch-soc',
                  title: '🚨 Go to The Watch SOC Now',
                },
              ],
            });
          } catch (e) {
            // fallback if actions not supported on platform
            try {
              await self.registration.showNotification(title, {
                body,
                icon: '/logo.jpg',
                tag: 'the-watch-emergency-alarm',
                requireInteraction: true,
                data: alert,
              });
            } catch {}
          }
        }
      })()
    );
  }
});

self.addEventListener('notificationclick', (event) => {
  const alertData = event.notification ? event.notification.data : null;
  if (event.notification) {
    event.notification.close();
  }
  event.waitUntil(focusOrOpenWatchTab(alertData));
});
