// ============================================================================
// Erdacht und programmiert von Fabian Hammer.
// (c) 2026 Fabian Hammer - Alle Rechte vorbehalten. Geistiges Eigentum.
// Unbefugte Vervielfaeltigung, Weitergabe oder Verwertung dieses Quellcodes ohne
// schriftliche Genehmigung des Urhebers ist untersagt.
// ============================================================================
// Eigene Namensauflösung für FAH-Adblocks eigene Verbindungen (DoH-Anbieter, Blocklisten).
// Nutzt NICHT den Resolver des NAS: Steht dort FAH-Adblock selbst als DNS (per DHCP), müsste der
// Blocker die Adresse seines Upstreams über sich selbst auflösen – beim Start ein Henne-Ei-Problem.
// Reihenfolge: Gateway, dann Quad9/Cloudflare direkt; Ergebnisse 5 Minuten gemerkt.
'use strict';
const dns = require('dns');
const net = require('net');

let server = ['192.168.1.1', '9.9.9.9', '1.1.1.1'];
const merk = new Map();
function setzeServer(gateway) { server = [...new Set([gateway, '9.9.9.9', '1.1.1.1'].filter((s) => s && net.isIP(s)))]; merk.clear(); }

async function aufloesen(host) {
  if (net.isIP(host)) return [{ address: host, family: net.isIP(host) }];
  const m = merk.get(host); if (m && m.bis > Date.now()) return m.adressen;
  let letzter = null;
  for (const s of server) {
    const r = new dns.promises.Resolver({ timeout: 1500, tries: 1 }); r.setServers([s]);
    try {
      const v4 = await r.resolve4(host).catch(() => []), v6 = v4.length ? [] : await r.resolve6(host).catch(() => []);
      const adressen = [...v4.map((a) => ({ address: a, family: 4 })), ...v6.map((a) => ({ address: a, family: 6 }))];
      if (adressen.length) { merk.set(host, { adressen, bis: Date.now() + 5 * 60000 }); return adressen; }
    } catch (e) { letzter = e; }
  }
  // letzter Ausweg: System-Resolver
  return new Promise((ok, nein) => dns.lookup(host, { all: true }, (e, a) => (e ? nein(letzter || e) : ok(a))));
}

// Signatur wie dns.lookup – für net/tls/http(s)/http2 als Option „lookup“
function lookup(host, optionen, rueckruf) {
  if (typeof optionen === 'function') { rueckruf = optionen; optionen = {}; }
  aufloesen(host).then((adressen) => {
    const passend = optionen?.family ? adressen.filter((a) => a.family === optionen.family) : adressen;
    const liste = passend.length ? passend : adressen;
    if (optionen?.all) rueckruf(null, liste); else rueckruf(null, liste[0].address, liste[0].family);
  }, (e) => rueckruf(e));
}

module.exports = { lookup, aufloesen, setzeServer };
