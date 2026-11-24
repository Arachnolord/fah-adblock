// ============================================================================
// Erdacht und programmiert von Fabian Hammer.
// (c) 2026 Fabian Hammer - Alle Rechte vorbehalten. Geistiges Eigentum.
// Unbefugte Vervielfaeltigung, Weitergabe oder Verwertung dieses Quellcodes ohne
// schriftliche Genehmigung des Urhebers ist untersagt.
// ============================================================================
// Einstellungen (data/einstellungen.json, atomar geschrieben) mit Vorgaben und
// Verschlüsselung geheimer Werte (AES-256-GCM, Schlüssel aus SESSION_SECRET).
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const net = require('net');
const { netz } = require('./netz');
const dienstKatalog = require('./dienste');

const KATEGORIEN = [
  { id: 'werbung', name: 'Werbung & Tracker', symbol: '📢', beschreibung: 'Werbebanner, Werbenetzwerke, Tracking und Telemetrie' },
  { id: 'schadsoftware', name: 'Schadsoftware & Phishing', symbol: '🦠', beschreibung: 'Betrugsseiten, Phishing, Malware und Kryptomining' },
  { id: 'social', name: 'Social Media', symbol: '💬', beschreibung: 'Facebook, Instagram, TikTok, Snapchat, X und ähnliche Netzwerke' },
  { id: 'jugendschutz', name: 'Jugendschutz', symbol: '🔞', beschreibung: 'Seiten mit Erwachseneninhalten' },
  { id: 'gluecksspiel', name: 'Glücksspiel', symbol: '🎰', beschreibung: 'Online-Casinos, Sportwetten, Lotterien' },
  // Kinderschutz (23.11.2026)
  { id: 'anonym', name: 'Anonyme Chats & Fragen-Apps', symbol: '🕵️', beschreibung: 'NGL, Tellonym, Zufalls-Videochats & Co. – dort läuft das meiste Cybermobbing, dort sprechen Fremde Kinder an' },
  { id: 'drogen', name: 'Drogen & Vaping', symbol: '💊', beschreibung: 'Drogen-Shops und -Foren, E-Zigaretten-Werbung' },
  { id: 'umgehung', name: 'Umgehung (VPN, Proxy, fremdes DNS)', symbol: '🚪', beschreibung: 'VPN-Apps, Web-Proxys, fremde DNS-Server und iCloud Privat-Relay – damit ließe sich der ganze Filter umgehen' },
  { id: 'piraterie', name: 'Piraterie', symbol: '🏴‍☠️', beschreibung: 'Illegale Film-, Serien- und Spieleseiten (oft voller Schadsoftware und Abo-Fallen)' },
  { id: 'freigabe', name: 'Freigabeliste', symbol: '✅', art: 'erlauben', beschreibung: 'Geprüfte Ausnahmen: heben Fehlalarme der Werbelisten auf' },
];

const LISTEN = [
  { id: 'hagezi-pro', name: 'HaGeZi Pro', url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt', kategorie: 'werbung', an: true, beschreibung: 'Werbung, Tracker, Telemetrie – umfassend bei wenigen Fehlalarmen, mehrmals täglich gepflegt' },
  { id: 'stevenblack', name: 'StevenBlack Unified', url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', kategorie: 'werbung', an: true, beschreibung: 'Bewährte Sammel-Hosts-Liste aus mehreren Quellen (MIT)' },
  { id: 'hagezi-tif', name: 'HaGeZi Threat Intelligence (mini)', url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt', kategorie: 'schadsoftware', an: true, beschreibung: 'Aktuelle Phishing-, Malware- und Betrugsdomains' },
  { id: 'hagezi-social', name: 'HaGeZi Social', url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/social-onlydomains.txt', kategorie: 'social', an: true, beschreibung: 'Soziale Netzwerke – greift nur in Profilen mit Kategorie Social Media' },
  { id: 'hagezi-nsfw', name: 'HaGeZi NSFW', url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/nsfw-onlydomains.txt', kategorie: 'jugendschutz', an: true, beschreibung: 'Erwachseneninhalte – greift nur in Profilen mit Jugendschutz' },
  { id: 'hagezi-gambling', name: 'HaGeZi Gambling', url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/gambling-onlydomains.txt', kategorie: 'gluecksspiel', an: true, beschreibung: 'Glücksspielseiten – greift nur in Profilen mit Glücksspiel' },
  // Kinderschutz (23.11.2026 geprüft: erreichbar, gepflegt; Blocklist Project = Unlicense, HaGeZi = GPL-3.0, beide nur zur Laufzeit geladen)
  { id: 'fah-anonym', name: 'FAH Anonyme Chats', url: 'eingebaut:anonym', kategorie: 'anonym', an: true, beschreibung: 'Eigene Liste: anonyme Frage-Apps (NGL, Tellonym, sendit …) und Zufalls-Videochats – kommt mit jedem Update' },
  { id: 'blp-drogen', name: 'Blocklist Project Drogen', url: 'https://blocklistproject.github.io/Lists/alt-version/drugs-nl.txt', kategorie: 'drogen', an: true, beschreibung: 'Drogen-Shops, -Foren und -Werbung (Unlicense)' },
  { id: 'blp-vaping', name: 'Blocklist Project Vaping', url: 'https://blocklistproject.github.io/Lists/alt-version/vaping-nl.txt', kategorie: 'drogen', an: true, beschreibung: 'E-Zigaretten-Shops und -Werbung (Unlicense)' },
  { id: 'hagezi-umgehung', name: 'HaGeZi DoH/VPN/TOR/Proxy-Umgehung', url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/doh-vpn-proxy-bypass-onlydomains.txt', kategorie: 'umgehung', an: true, beschreibung: 'Fremde verschlüsselte DNS-Server, VPN- und Proxy-Dienste, iCloud Privat-Relay – greift nur in Profilen mit Kategorie Umgehung' },
  { id: 'blp-piraterie', name: 'Blocklist Project Piraterie', url: 'https://blocklistproject.github.io/Lists/alt-version/piracy-nl.txt', kategorie: 'piraterie', an: true, beschreibung: 'Illegale Streaming- und Download-Seiten (Unlicense)' },
  { id: 'blp-betrug', name: 'Blocklist Project Betrug', url: 'https://blocklistproject.github.io/Lists/alt-version/scam-nl.txt', kategorie: 'schadsoftware', an: false, beschreibung: 'Betrugs- und Fake-Shop-Seiten – gilt für ALLE Profile mit Schadsoftware-Schutz, darum ab Werk aus (vereinzelte Fehlalarme möglich)' },
  // Freigabelisten (15.09.2026 geprüft: erreichbar, gepflegt, verbreitet)
  { id: 'frei-adguard', name: 'AdGuard DNS-Filter – Ausnahmen', url: 'https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exceptions.txt', kategorie: 'freigabe', an: true, beschreibung: 'Vom AdGuard-Team gepflegte Ausnahmen seines DNS-Filters – Domains, deren Sperre Seiten nachweislich kaputt macht' },
  { id: 'frei-anudeep', name: 'anudeepND Whitelist', url: 'https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt', kategorie: 'freigabe', an: true, beschreibung: 'Häufig fälschlich gesperrte Dienste (Microsoft, Apple, Google, Spotify, Updates …), MIT' },
  { id: 'frei-hagezi-kurzlinks', name: 'HaGeZi URL-Shortener', url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-urlshortener.txt', kategorie: 'freigabe', an: true, beschreibung: 'Kurzlink-Dienste (z. B. in Mails, Chats, QR-Codes) funktionieren' },
  { id: 'frei-hagezi-referral', name: 'HaGeZi Referral', url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/whitelist-referral-onlydomains.txt', kategorie: 'freigabe', an: false, beschreibung: 'Affiliate- und Tracking-Links aus Mails, Suchergebnissen und Preisvergleichen öffnen sich – schwächt den Tracking-Schutz, nur bei Bedarf' },
  { id: 'frei-anudeep-referral', name: 'anudeepND Referral-Seiten', url: 'https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/referral-sites.txt', kategorie: 'freigabe', an: false, beschreibung: 'Weiterleitungen von Werbe- und Partnerlinks (u. a. ad.doubleclick.net) – nur bei Bedarf' },
  { id: 'frei-anudeep-optional', name: 'anudeepND Optional', url: 'https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/optional-list.txt', kategorie: 'freigabe', an: false, beschreibung: 'Zusätzliche Freigaben für einzelne Dienste (z. B. Nachrichten-Videos) – nur bei Bedarf' },
];

// Kinderschutz-Ergänzung für das Profil „Kinder“ – neue Installationen ab Werk, bestehende einmalig beim ersten Start (Migration)
const KINDER_NEU = {
  kategorien: { anonym: { an: true, zeitplan: [] }, drogen: { an: true, zeitplan: [] }, umgehung: { an: true, zeitplan: [] } },
  ruhezeiten: { messenger: [{ tage: [1, 2, 3, 4, 5, 6, 7], von: '21:00', bis: '06:30' }] },
  sicher: { suche: true, youtube: 'aus' },
};
const MIGRATIONEN = ['kinderschutz-2026-11', 'meldungen-lokal-2026-11'];

const PROFILE = [
  { id: 'standard', name: 'Standard', farbe: '#40e0a0', beschreibung: 'Werbung, Tracker und Schadsoftware', kategorien: { werbung: { an: true, zeitplan: [] }, schadsoftware: { an: true, zeitplan: [] } } },
  { id: 'kinder', name: 'Kinder', farbe: '#ffb020', beschreibung: 'Zusätzlich Jugendschutz, Glücksspiel, anonyme Chats, Drogen und Umgehung, Social Media abends', kategorien: {
    werbung: { an: true, zeitplan: [] }, schadsoftware: { an: true, zeitplan: [] }, jugendschutz: { an: true, zeitplan: [] }, gluecksspiel: { an: true, zeitplan: [] },
    social: { an: true, zeitplan: [{ tage: [1, 2, 3, 4, 5, 6, 7], von: '20:00', bis: '07:00' }] }, ...KINDER_NEU.kategorien },
    ruhezeiten: KINDER_NEU.ruhezeiten, sicher: KINDER_NEU.sicher },
  { id: 'frei', name: 'Unbeschränkt', farbe: '#8b93a7', beschreibung: 'Nur Schadsoftware wird geblockt', kategorien: { schadsoftware: { an: true, zeitplan: [] } } },
];

function vorgaben(env = process.env) {
  return {
    version: 1,
    dns: {
      erlaubteNetze: (env.ERLAUBTE_NETZE || '192.168.1.0/24,192.168.5.0/24,127.0.0.1/32').split(',').map((s) => s.trim()).filter(Boolean),
      gateway: env.GATEWAY || '192.168.1.1',
      lokaleZonen: (env.LOKALE_ZONEN || 'example.org,localdomain,lan,local,10.in-addr.arpa,168.192.in-addr.arpa').split(',').map((s) => s.trim()).filter(Boolean),
      lokaleRecords: [],   // Split-Horizon: [{host, ip}] – Name zeigt im Heim-/VPN-Netz direkt auf eine interne IP
      bremse: { rate: 100, schub: 300 },
    },
    upstream: [
      { name: 'Quad9', url: 'https://dns.quad9.net/dns-query' },
      { name: 'Cloudflare', url: 'https://cloudflare-dns.com/dns-query' },
      { name: 'DNS.SB', url: 'https://doh.sb/dns-query' },
    ],   // bewusst nur Anbieter OHNE eigene Werbe-/Trackersperre: FAH-Adblock filtert selbst, ein zweiter Filter sperrt unbemerkt (Teams, 21.09.2026)
    kategorien: KATEGORIEN, listen: LISTEN, profile: PROFILE, vorgabenListen: LISTEN.map((l) => l.id),
    geraete: {}, regeln: [], dienste: {}, pausen: { global: 0, geraete: {} },
    protokoll: { tage: 7 },
    sperrseite: { an: false },
    // Kinderschutz-Meldungen – nur in FAH-Adblock (Ansicht Kinderschutz und Kachel), kein Fremddienst
    meldungen: { an: true, profile: ['kinder'], kategorien: ['anonym', 'jugendschutz', 'drogen', 'umgehung'], dienste: false, zeitlimit: true, stille: true, stilleMin: 30, ruheMin: 60 },
    // Schutz unterwegs (DNS-over-TLS/-HTTPS je Gerät): Basisdomain, deren Unternamen auf den Proxy zeigen; Geräte mit eigener Kennung
    unterwegs: { an: false, basis: '', email: '', geraete: {} },
    migrationen: [...MIGRATIONEN],
    unifi: { url: env.UNIFI_URL || '', schluessel: null },
    // Weboberfläche hinter einem Reverse-Proxy (NPM): Adressen/Netze, deren X-Forwarded-For für die Anmeldebremse zählt
    web: { vertrauteProxies: (env.VERTRAUTE_PROXIES || '').split(',').map((s) => s.trim()).filter(Boolean) },
  };
}

// Kaputte Einträge (z. B. aus einer fehlerhaften Sicherung oder von Hand bearbeitet) überspringen,
// damit der Start nie an den Einstellungen scheitert – das Heimnetz bliebe sonst ohne DNS.
function bereinigen(w, v, melden = (t) => console.warn(`[einstellungen] ${t}`)) {
  const objekt = (x) => x && typeof x === 'object' && !Array.isArray(x);
  const liste = (name, pruefung) => {
    const alt = Array.isArray(w[name]) ? w[name] : [];
    const gut = alt.filter((e) => objekt(e) && pruefung(e));
    if (gut.length !== alt.length || !Array.isArray(w[name])) melden(`${name}: ${alt.length - gut.length + (Array.isArray(w[name]) ? 0 : 1)} ungültige Einträge übersprungen`);
    w[name] = gut;
  };
  liste('kategorien', (k) => typeof k.id === 'string' && k.id);
  liste('listen', (l) => typeof l.id === 'string' && l.id);   // eine unbrauchbare Adresse meldet die Liste selbst als Fehler
  liste('profile', (p) => typeof p.id === 'string' && p.id && (p.kategorien === undefined || objekt(p.kategorien)));
  liste('regeln', (r) => typeof r.id === 'string' && ['erlauben', 'sperren'].includes(r.typ) && typeof r.muster === 'string');
  liste('upstream', (u) => { try { return new URL(String(u.url)).protocol === 'https:'; } catch (e) { return false; } });
  if (!w.upstream.length) { melden('kein gültiger DoH-Anbieter – Vorgaben (Quad9, Cloudflare, DNS.SB) verwendet'); w.upstream = JSON.parse(JSON.stringify(v.upstream)); }
  if (!w.profile.some((p) => p.id === 'standard')) { melden('Profil „Standard“ fehlte – ergänzt'); w.profile.unshift(JSON.parse(JSON.stringify(v.profile[0]))); }
  for (const p of w.profile) { if (!objekt(p.kategorien)) p.kategorien = {}; if (p.dienste !== undefined && !objekt(p.dienste)) delete p.dienste; }
  for (const name of ['geraete', 'dienste']) {
    if (!objekt(w[name])) { melden(`${name}: kein Objekt – geleert`); w[name] = {}; }
    for (const [k, e] of Object.entries(w[name])) if (!objekt(e)) { melden(`${name}: Eintrag ${k} ungültig – entfernt`); delete w[name][k]; }
  }
  // Zustände für Dienste, die es im Katalog nicht mehr gibt (z. B. „skype“, aufgegangen in „teams“): entfernen – sie wirken nicht mehr, würden aber mitgeschleppt, in der Profilkarte mitgezählt und von der API (PUT Profil) abgewiesen
  const bekannt = new Set(dienstKatalog.DIENSTE.map((d) => d.id));
  for (const [ort, karte] of [['dienste', w.dienste], ...w.profile.map((p) => [`Profil „${p.id}“`, p.dienste])]) {
    for (const id of Object.keys(karte || {})) if (!bekannt.has(id)) { melden(`${ort}: Dienst „${id}“ gibt es nicht mehr – Zustand entfernt`); delete karte[id]; }
  }
  if (!objekt(w.pausen)) w.pausen = { global: 0, geraete: {} };
  if (!objekt(w.pausen.geraete)) w.pausen.geraete = {};
  w.pausen.global = Number(w.pausen.global) || 0;
  for (const [g, t] of Object.entries(w.pausen.geraete)) if (!Number.isFinite(t)) delete w.pausen.geraete[g];
  if (!objekt(w.dns)) w.dns = { ...v.dns };
  const netze = (Array.isArray(w.dns.erlaubteNetze) ? w.dns.erlaubteNetze : []).filter((n) => { try { netz(n); return true; } catch (e) { melden(`erlaubtes Netz „${n}“ ungültig – übersprungen`); return false; } });
  w.dns.erlaubteNetze = netze.length ? netze : (melden('keine gültigen erlaubten Netze – Vorgaben verwendet'), [...v.dns.erlaubteNetze]);
  w.dns.lokaleZonen = (Array.isArray(w.dns.lokaleZonen) ? w.dns.lokaleZonen : v.dns.lokaleZonen).filter((z) => typeof z === 'string' && /^[a-z0-9.-]+$/i.test(z));
  w.dns.lokaleRecords = (Array.isArray(w.dns.lokaleRecords) ? w.dns.lokaleRecords : []).filter((r) => r && typeof r === 'object' && typeof r.host === 'string' && /^(\*\.)?[a-z0-9.-]+$/i.test(r.host) && net.isIP(String(r.ip))).map((r) => ({ host: String(r.host).toLowerCase(), ip: String(r.ip) }));
  if (w.dns.gateway && !net.isIP(String(w.dns.gateway))) { melden(`Gateway „${w.dns.gateway}“ ist keine IP – Vorgabe verwendet`); w.dns.gateway = v.dns.gateway; }
  if (!objekt(w.dns.bremse) || !(w.dns.bremse.rate > 0) || !(w.dns.bremse.schub > 0)) w.dns.bremse = { ...v.dns.bremse };
  if (!objekt(w.protokoll)) w.protokoll = { ...v.protokoll };
  w.protokoll.tage = Math.max(1, Math.min(90, Math.round(Number(w.protokoll.tage)) || v.protokoll.tage));
  if (!objekt(w.unifi)) w.unifi = { ...v.unifi };
  if (!objekt(w.web)) w.web = { ...v.web };
  // Kinderschutz: Profile (Ruhezeiten je Rubrik, sichere Suche, Zeitlimits), Meldungen, unterwegs
  const RUBRIKEN = new Set(dienstKatalog.GRUPPEN.filter((g) => !g.fest).map((g) => g.id));
  const fensterOk = (f) => objekt(f) && /^\d{1,2}:\d{2}$/.test(String(f.von)) && /^\d{1,2}:\d{2}$/.test(String(f.bis)) && Array.isArray(f.tage);
  for (const p of w.profile) {
    if (!objekt(p.ruhezeiten)) delete p.ruhezeiten;
    else for (const [r, z] of Object.entries(p.ruhezeiten)) { if (!RUBRIKEN.has(r) || !Array.isArray(z)) delete p.ruhezeiten[r]; else p.ruhezeiten[r] = z.filter(fensterOk); }
    if (!objekt(p.sicher)) delete p.sicher; else p.sicher = { suche: !!p.sicher.suche, youtube: ['moderat', 'streng'].includes(p.sicher.youtube) ? p.sicher.youtube : 'aus' };
    if (!objekt(p.limits)) delete p.limits;
    else for (const [ziel, m] of Object.entries(p.limits)) { if (!limitZielOk(ziel) || !(Number(m) >= 5 && Number(m) <= 1440)) delete p.limits[ziel]; else p.limits[ziel] = Math.round(Number(m)); }
  }
  if (!objekt(w.meldungen)) w.meldungen = JSON.parse(JSON.stringify(v.meldungen));
  const m = w.meldungen, mv = v.meldungen;
  w.meldungen = {
    an: !!m.an, profile: Array.isArray(m.profile) ? m.profile.filter((x) => typeof x === 'string').slice(0, 20) : [...mv.profile],
    kategorien: Array.isArray(m.kategorien) ? m.kategorien.filter((x) => typeof x === 'string').slice(0, 20) : [...mv.kategorien], dienste: !!m.dienste, zeitlimit: m.zeitlimit !== false, stille: m.stille !== false,
    stilleMin: Math.max(10, Math.min(720, Math.round(Number(m.stilleMin)) || mv.stilleMin)), ruheMin: Math.max(5, Math.min(1440, Math.round(Number(m.ruheMin)) || mv.ruheMin)),
  };
  if (!objekt(w.unterwegs)) w.unterwegs = JSON.parse(JSON.stringify(v.unterwegs));
  const u = w.unterwegs;
  w.unterwegs = { kurznamen: u.kurznamen ? 1 : 0, an: !!u.an, basis: /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(String(u.basis || '')) ? String(u.basis) : '', email: /^[^\s@<>]+@[a-z0-9.-]+\.[a-z]{2,}$/i.test(String(u.email || '')) ? String(u.email) : '', geraete: {} };
  for (const [gid, g] of Object.entries(objekt(u.geraete) ? u.geraete : {})) if (objekt(g) && /^dns-[a-z0-9](?:[a-z0-9-]{0,22}[a-z0-9])?$/.test(String(g.kennung)) && /^[A-Za-z0-9_-]{20,64}$/.test(String(g.geheim))) w.unterwegs.geraete[gid] = { kennung: g.kennung, geheim: g.geheim, an: g.an !== false };
  w.web.vertrauteProxies = (Array.isArray(w.web.vertrauteProxies) ? w.web.vertrauteProxies : []).filter((n) => { try { netz(n); return true; } catch (e) { melden(`vertrauter Proxy „${n}“ ungültig – übersprungen`); return false; } });
  return w;
}

// Ziel eines Zeitlimits: „dienst:<id>“ oder „rubrik:<id>“ (Hilfe nie)
function limitZielOk(ziel) {
  const [art, id] = String(ziel).split(':');
  if (art === 'dienst') { const d = dienstKatalog.DIENSTE.find((x) => x.id === id); return !!d && !d.fest; }
  if (art === 'rubrik') return dienstKatalog.GRUPPEN.some((g) => g.id === id && !g.fest);
  return false;
}

function schluesselAus(geheimnis) { return crypto.createHash('sha256').update(`fah-adblock|${geheimnis}`).digest(); }
function verschluesseln(text, geheimnis) {
  if (!text) return null;
  const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', schluesselAus(geheimnis), iv);
  const daten = Buffer.concat([c.update(String(text), 'utf8'), c.final()]);
  return `v1:${iv.toString('base64')}:${c.getAuthTag().toString('base64')}:${daten.toString('base64')}`;
}
function entschluesseln(wert, geheimnis) {
  if (!wert) return '';
  try {
    const [v, iv, tag, daten] = String(wert).split(':');
    if (v !== 'v1') return '';
    const d = crypto.createDecipheriv('aes-256-gcm', schluesselAus(geheimnis), Buffer.from(iv, 'base64'));
    d.setAuthTag(Buffer.from(tag, 'base64'));
    return Buffer.concat([d.update(Buffer.from(daten, 'base64')), d.final()]).toString('utf8');
  } catch (e) { return ''; }
}

class Einstellungen {
  constructor({ verzeichnis, geheimnis, env = process.env }) {
    Object.assign(this, { verzeichnis, geheimnis, env });
    this.datei = path.join(verzeichnis, 'einstellungen.json');
    this.werte = null; this.beobachter = [];
  }
  laden() {
    const v = vorgaben(this.env);
    let gelesen = null;
    try { gelesen = JSON.parse(fs.readFileSync(this.datei, 'utf8')); } catch (e) {}
    if (!gelesen) { this.werte = v; this.speichern(); return this; }
    // Neue Vorgaben ergänzen (neue Listen/Kategorien/Profile), vorhandene Werte bleiben
    if (typeof gelesen !== 'object' || Array.isArray(gelesen)) gelesen = {};
    const w = { ...v, ...gelesen, dns: { ...v.dns, ...(gelesen.dns || {}) }, unifi: { ...v.unifi, ...(gelesen.unifi || {}) }, protokoll: { ...v.protokoll, ...(gelesen.protokoll || {}) }, pausen: { global: 0, geraete: {}, ...(gelesen.pausen || {}) }, web: { ...v.web, ...(gelesen.web || {}) },
      meldungen: { ...v.meldungen, ...(gelesen.meldungen || {}) }, unterwegs: { ...v.unterwegs, ...(gelesen.unterwegs || {}) } };
    bereinigen(w, v);
    // Migrationen (je einmal): Kinderschutz 23.11.2026 – das Profil „Kinder“ bekommt anonyme Chats, Drogen, Umgehung,
    // Messenger-Nachtruhe und sichere Suche; was dort schon eingestellt ist, bleibt
    const erledigt = new Set(Array.isArray(gelesen.migrationen) ? gelesen.migrationen.filter((x) => typeof x === 'string') : []);
    let migriert = false;
    if (!erledigt.has('kinderschutz-2026-11')) {
      const k = w.profile.find((p) => p.id === 'kinder');
      if (k) {
        for (const [kid, kw] of Object.entries(KINDER_NEU.kategorien)) if (!k.kategorien[kid]) k.kategorien[kid] = JSON.parse(JSON.stringify(kw));
        if (!k.ruhezeiten) k.ruhezeiten = JSON.parse(JSON.stringify(KINDER_NEU.ruhezeiten));
        if (!k.sicher) k.sicher = { ...KINDER_NEU.sicher };
      }
      erledigt.add('kinderschutz-2026-11'); migriert = true;
    }
    // ntfy entfernt (Betreiber 23.11.2026): Meldungen laufen jetzt in FAH-Adblock selbst – einmalig einschalten
    if (!erledigt.has('meldungen-lokal-2026-11')) { w.meldungen.an = true; erledigt.add('meldungen-lokal-2026-11'); migriert = true; }
    w.migrationen = [...erledigt];
    // Kategorien: neue ergänzen, Beschreibung/Art der Vorgaben nachziehen
    for (const k of v.kategorien) { const x = w.kategorien.find((y) => y.id === k.id); if (!x) w.kategorien.push(k); else Object.assign(x, { beschreibung: x.beschreibung || k.beschreibung, ...(k.art ? { art: k.art } : {}) }); }
    // Vorgabelisten: neue einmalig ergänzen (bereits angebotene nicht erneut), Beschreibungen nachziehen
    const angeboten = new Set(Array.isArray(gelesen.vorgabenListen) ? gelesen.vorgabenListen.filter((x) => typeof x === 'string') : w.listen.map((l) => l.id));
    let geaendert = false;
    for (const l of v.listen) {
      const x = w.listen.find((y) => y.id === l.id);
      if (x) { if (!x.beschreibung && l.beschreibung) { x.beschreibung = l.beschreibung; geaendert = true; } }
      else if (!angeboten.has(l.id) && w.listen.length < 30) { w.listen.push(l); geaendert = true; }
      angeboten.add(l.id);
    }
    w.vorgabenListen = [...angeboten];
    this.werte = w;
    if (geaendert || migriert || !gelesen.vorgabenListen) this.speichern();
    return this;
  }
  speichern() {
    fs.mkdirSync(this.verzeichnis, { recursive: true });
    fs.writeFileSync(this.datei + '.tmp', JSON.stringify(this.werte, null, 1));
    fs.renameSync(this.datei + '.tmp', this.datei);
  }
  aendern(fn) {
    const kopie = JSON.parse(JSON.stringify(this.werte));
    const ergebnis = fn(kopie);
    this.werte = kopie; this.speichern();
    for (const b of this.beobachter) try { b(this.werte); } catch (e) { console.error('[einstellungen]', e.message); }
    return ergebnis;
  }
  beobachten(fn) { this.beobachter.push(fn); }
  unifiZugang() { return { url: this.werte.unifi.url || this.env.UNIFI_URL || '', schluessel: entschluesseln(this.werte.unifi.schluessel, this.geheimnis) || this.env.UNIFI_API_KEY || '' }; }
  setzeUnifi(url, schluessel) {
    this.aendern((w) => { w.unifi.url = url; if (schluessel !== undefined && schluessel !== null && schluessel !== '') w.unifi.schluessel = verschluesseln(schluessel, this.geheimnis); });
  }
  // Für Sicherung/Anzeige ohne Geheimnisse
  oeffentlich() {
    const w = JSON.parse(JSON.stringify(this.werte));
    w.unifi = { url: w.unifi.url, schluesselGesetzt: !!this.unifiZugang().schluessel };
    return w;
  }
}

module.exports = { Einstellungen, vorgaben, bereinigen, verschluesseln, entschluesseln, limitZielOk, KATEGORIEN, LISTEN, PROFILE, KINDER_NEU };
