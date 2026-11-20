// ============================================================================
// Erdacht und programmiert von Fabian Hammer.
// (c) 2026 Fabian Hammer - Alle Rechte vorbehalten. Geistiges Eigentum.
// Unbefugte Vervielfaeltigung, Weitergabe oder Verwertung dieses Quellcodes ohne
// schriftliche Genehmigung des Urhebers ist untersagt.
// ============================================================================
// Katalog kostenloser, öffentlicher DNS-Anbieter mit verschlüsseltem DNS (DNS-over-HTTPS).
// Auswahl per Haken in den Einstellungen; die Reihenfolge in der Liste ist die Rangfolge
// (der erste Anbieter wird gefragt, erst bei Ausfall der nächste).
'use strict';

const GRUPPEN = [
  { id: 'schutz', name: 'Mit Schadsoftware-Schutz' },
  { id: 'werbung', name: 'Mit Werbe- und Trackersperre' },
  { id: 'familie', name: 'Mit Jugendschutz' },
  { id: 'neutral', name: 'Ungefiltert' },
];

const ANBIETER = [
  // Mit Schadsoftware-Schutz
  { id: 'quad9', name: 'Quad9', url: 'https://dns.quad9.net/dns-query', gruppe: 'schutz', land: 'Schweiz', beschreibung: 'Sperrt bekannte Schadsoftware- und Phishing-Domains, keine Protokollierung personenbezogener Daten' },
  { id: 'cloudflare-security', name: 'Cloudflare Security', url: 'https://security.cloudflare-dns.com/dns-query', gruppe: 'schutz', land: 'USA', beschreibung: 'Wie Cloudflare, zusätzlich mit Schadsoftware-Sperre (1.1.1.2)' },
  { id: 'opendns', name: 'OpenDNS', url: 'https://doh.opendns.com/dns-query', gruppe: 'schutz', land: 'USA', beschreibung: 'Cisco OpenDNS mit Schutz vor Phishing-Seiten' },
  { id: 'controld-malware', name: 'Control D – Malware', url: 'https://freedns.controld.com/p2', gruppe: 'schutz', land: 'Kanada', beschreibung: 'Sperrt Schadsoftware, Werbung und Tracker' },

  // Mit Werbe- und Trackersperre
  { id: 'adguard', name: 'AdGuard DNS', url: 'https://dns.adguard-dns.com/dns-query', gruppe: 'werbung', land: 'Zypern', beschreibung: 'Sperrt Werbung und Tracker bereits beim Anbieter (zusätzlich zu FAH-Adblock)' },
  { id: 'mullvad-adblock', name: 'Mullvad AdBlock', url: 'https://adblock.dns.mullvad.net/dns-query', gruppe: 'werbung', land: 'Schweden', beschreibung: 'Ohne Protokollierung, sperrt Werbung und Tracker' },
  { id: 'controld-ads', name: 'Control D – Werbung', url: 'https://freedns.controld.com/p1', gruppe: 'werbung', land: 'Kanada', beschreibung: 'Sperrt Werbung und Tracker' },
  { id: 'dnsforge', name: 'DNSforge', url: 'https://dnsforge.de/dns-query', gruppe: 'werbung', land: 'Deutschland', beschreibung: 'Deutscher Anbieter, sperrt Werbung, Tracker und Schadsoftware nach eigenen Listen – darunter auch Adressen, die Microsoft Teams für Anrufe braucht' },

  // Mit Jugendschutz
  { id: 'cloudflare-family', name: 'Cloudflare for Families', url: 'https://family.cloudflare-dns.com/dns-query', gruppe: 'familie', land: 'USA', beschreibung: 'Sperrt Schadsoftware und Erwachseneninhalte (1.1.1.3)' },
  { id: 'adguard-family', name: 'AdGuard Family', url: 'https://family.adguard-dns.com/dns-query', gruppe: 'familie', land: 'Zypern', beschreibung: 'Werbung, Tracker, Erwachseneninhalte gesperrt, sichere Suche erzwungen' },
  { id: 'opendns-family', name: 'OpenDNS FamilyShield', url: 'https://doh.familyshield.opendns.com/dns-query', gruppe: 'familie', land: 'USA', beschreibung: 'Sperrt Erwachseneninhalte' },
  { id: 'controld-family', name: 'Control D – Familie', url: 'https://freedns.controld.com/family', gruppe: 'familie', land: 'Kanada', beschreibung: 'Sperrt Erwachseneninhalte, Werbung und Schadsoftware' },

  // Ungefiltert
  { id: 'cloudflare', name: 'Cloudflare', url: 'https://cloudflare-dns.com/dns-query', gruppe: 'neutral', land: 'USA', beschreibung: 'Sehr schnell, keine Filterung, Protokolle werden nach 24 h gelöscht (1.1.1.1)' },
  { id: 'google', name: 'Google Public DNS', url: 'https://dns.google/dns-query', gruppe: 'neutral', land: 'USA', beschreibung: 'Sehr zuverlässig, keine Filterung (8.8.8.8)' },
  { id: 'quad9-unfiltered', name: 'Quad9 ungefiltert', url: 'https://dns10.quad9.net/dns-query', gruppe: 'neutral', land: 'Schweiz', beschreibung: 'Quad9 ohne Schadsoftware-Sperre' },
  { id: 'mullvad', name: 'Mullvad DNS', url: 'https://dns.mullvad.net/dns-query', gruppe: 'neutral', land: 'Schweden', beschreibung: 'Ohne Protokollierung, keine Filterung' },
  { id: 'adguard-unfiltered', name: 'AdGuard ungefiltert', url: 'https://unfiltered.adguard-dns.com/dns-query', gruppe: 'neutral', land: 'Zypern', beschreibung: 'AdGuard ohne jede Sperre' },
  { id: 'applied-privacy', name: 'Applied Privacy', url: 'https://doh.applied-privacy.net/query', gruppe: 'neutral', land: 'Österreich', beschreibung: 'Gemeinnütziger Betreiber, ohne Protokollierung' },
  { id: 'uncensoreddns', name: 'UncensoredDNS', url: 'https://anycast.uncensoreddns.org/dns-query', gruppe: 'neutral', land: 'Dänemark', beschreibung: 'Unzensiert, ohne Protokollierung' },
  { id: 'libredns', name: 'LibreDNS', url: 'https://doh.libredns.gr/dns-query', gruppe: 'neutral', land: 'Griechenland', beschreibung: 'Gemeinnützig, ohne Protokollierung' },
  { id: 'dnssb', name: 'DNS.SB', url: 'https://doh.sb/dns-query', gruppe: 'neutral', land: 'Deutschland', beschreibung: 'Schnell, ohne Protokollierung' },
];

const vonUrl = (url) => ANBIETER.find((a) => a.url === String(url || '').trim());

module.exports = { ANBIETER, GRUPPEN, vonUrl };
