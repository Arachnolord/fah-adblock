// ============================================================================
// Erdacht und programmiert von Fabian Hammer.
// (c) 2026 Fabian Hammer - Alle Rechte vorbehalten. Geistiges Eigentum.
// Unbefugte Vervielfaeltigung, Weitergabe oder Verwertung dieses Quellcodes ohne
// schriftliche Genehmigung des Urhebers ist untersagt.
// ============================================================================
// Lokale Records (Split-Horizon-DNS): einzelne Namen direkt mit einer internen IP beantworten,
// statt sie ins Internet oder ans Gateway weiterzureichen. So zeigt z. B. nextcloud.example.org
// im Heimnetz UND im VPN auf den Proxy (192.168.1.29) – von außen liefert der öffentliche DNS weiter die
// WAN-IP. Zusammen mit der Proxy-Schutzstufe „Nur Heimnetz + VPN" sind solche Domains damit von außen
// gesperrt, aber für Heim- und VPN-Geräte direkt (ohne Umweg über die WAN-IP) erreichbar.
// Ein Eintrag mit „*."-Vorsilbe (z. B. *.example.org) gilt für ALLE Subdomains; exakte Einträge
// haben Vorrang vor dem Wildcard, und ein längeres Wildcard-Suffix vor einem kürzeren.
'use strict';
const net = require('net');

const TTL = 60;

function normHost(h) {
  return String(h || '').trim().toLowerCase().replace(/^\.+|\.+$/g, '');
}

class Records {
  constructor({ eintraege = [], ttl = TTL } = {}) { this.ttl = ttl; this.konfigurieren({ eintraege }); }
  konfigurieren({ eintraege } = {}) {
    this.exakt = new Map();
    this.wild = [];   // [{ suffix, a, aaaa }], längstes Suffix zuerst
    for (const e of Array.isArray(eintraege) ? eintraege : []) {
      const host = normHost(e && e.host);
      if (!host) continue;
      const ip = String((e && e.ip) || '').trim();
      const v = net.isIP(ip);
      if (!v) continue;
      if (host.startsWith('*.')) {
        const suffix = host.slice(2);
        if (!suffix || !/^[a-z0-9.-]+$/.test(suffix)) continue;
        let w = this.wild.find((x) => x.suffix === suffix);
        if (!w) { w = { suffix }; this.wild.push(w); }
        if (v === 4) w.a = ip; else w.aaaa = ip;
      } else {
        if (!/^[a-z0-9.-]+$/.test(host)) continue;
        const r = this.exakt.get(host) || {};
        if (v === 4) r.a = ip; else r.aaaa = ip;
        this.exakt.set(host, r);
      }
    }
    this.wild.sort((a, b) => b.suffix.length - a.suffix.length);   // spezifischstes Suffix gewinnt
  }
  get leer() { return this.exakt.size === 0 && this.wild.length === 0; }
  // Exakter Name zuerst; sonst das erste passende Wildcard (*.suffix matcht nur Subdomains, nicht den Apex selbst).
  treffer(name) {
    const n = normHost(name);
    const ex = this.exakt.get(n);
    if (ex) return ex;
    for (const w of this.wild) if (n.endsWith(`.${w.suffix}`)) return w;
    return null;
  }
}

module.exports = { Records, normHost };
