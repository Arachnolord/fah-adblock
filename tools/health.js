// ============================================================================
// Erdacht und programmiert von Fabian Hammer.
// (c) 2026 Fabian Hammer - Alle Rechte vorbehalten. Geistiges Eigentum.
// ============================================================================
// Container-Gesundheit: DNS-Selbstanfrage (health.fah-adblock, UDP) und HTTP /api/health.
'use strict';
const dgram = require('dgram');
const http = require('http');
const dnsPacket = require('dns-packet');
const bind = process.env.DNS_BIND || '127.0.0.1', port = +process.env.DNS_PORT || 53, web = +process.env.WEB_PORT || 8053;
const fertig = (ok, text) => { if (!ok) console.error(text); process.exit(ok ? 0 : 1); };
const s = dgram.createSocket(bind.includes(':') ? 'udp6' : 'udp4');
const uhr = setTimeout(() => fertig(false, 'DNS antwortet nicht'), 4000);
s.on('message', (m) => {
  clearTimeout(uhr); s.close();
  const ok = String(dnsPacket.decode(m).answers?.[0]?.data?.[0] || '') === 'ok';
  if (!ok) return fertig(false, 'DNS-Antwort falsch');
  http.get({ host: '127.0.0.1', port: web, path: '/api/health', timeout: 3000 }, (res) => { res.resume(); fertig(res.statusCode === 200, `HTTP ${res.statusCode}`); }).on('error', (e) => fertig(false, e.message));
});
s.send(dnsPacket.encode({ type: 'query', id: 7, questions: [{ type: 'TXT', name: 'health.fah-adblock' }] }), port, bind);
