// ============================================================================
// Erdacht und programmiert von Fabian Hammer.
// (c) 2026 Fabian Hammer - Alle Rechte vorbehalten. Geistiges Eigentum.
// Unbefugte Vervielfaeltigung, Weitergabe oder Verwertung dieses Quellcodes ohne
// schriftliche Genehmigung des Urhebers ist untersagt.
// ============================================================================
// Client-IP → Gerät. Quellen (in dieser Reihenfolge): eigener Name aus den Einstellungen,
// UniFi-Clientliste (nur lesend, alle 5 min), Rückwärtsauflösung am Gateway, IP.
// Geräte-ID: MAC-Adresse, wenn bekannt – so bleiben Profil und Name bei neuer IP erhalten.
// Eine IP ohne bekannte MAC (neu im WLAN, Blocker gerade neu gestartet) würde sonst bis zur nächsten
// UniFi-Abfrage mit Profil „Standard“ gefiltert und als zweites Gerät gezählt. Deshalb:
//   · beim Start die letzte bekannte IP→MAC-Zuordnung aus dem Protokoll übernehmen (vorbelegen)
//   · bei unbekannter IP UniFi sofort fragen (höchstens alle 15 s, je IP alle 5 min)
//   · danach die kurz unter „ip:…“ gelaufenen Anfragen dem Gerät zuordnen (onZuordnung)
'use strict';
const https = require('https');
const http = require('http');
const tls = require('tls');
const net = require('net');
const dnsPacket = require('dns-packet');
const dgram = require('dgram');

function unifiHole({ url, schluessel }, pfad) {
  return new Promise((ok, nein) => {
    const req = https.get(new URL(url.replace(/\/$/, '') + pfad), { rejectUnauthorized: false, timeout: 15000, headers: { 'X-API-KEY': schluessel, Accept: 'application/json' } }, (res) => {
      let t = ''; res.on('data', (d) => { t += d; });
      res.on('end', () => { if (res.statusCode >= 400) return nein(new Error(`UniFi: HTTP ${res.statusCode}`)); try { ok(JSON.parse(t)); } catch (e) { nein(new Error('UniFi: keine JSON-Antwort')); } });
    });
    req.on('timeout', () => req.destroy(new Error('UniFi: Zeitüberschreitung')));
    req.on('error', nein);
  });
}

// UniFi-Anfrage für die Portfreigabe des Schutzes unterwegs (Schlüssel mit Schreibrecht): erst TLS aufbauen und den Abdruck prüfen
// (beim ersten Mal gemerkt: z.merken), dann auf genau dieser Verbindung senden.
function unifiAnfrage(z, methode, pfad, daten) {
  return new Promise((ok, nein) => {
    const u = new URL(z.url.replace(/\/$/, '') + pfad), host = u.hostname, text = daten === undefined ? undefined : JSON.stringify(daten);
    const s = tls.connect({ host, port: Number(u.port || 443), servername: net.isIP(host) ? undefined : host, rejectUnauthorized: false });
    const uhr = setTimeout(() => { s.destroy(); nein(new Error('UniFi: Zeitüberschreitung')); }, 15000);
    s.once('error', (e) => { clearTimeout(uhr); nein(new Error(`UniFi: ${e.message}`)); });
    s.once('secureConnect', () => {
      const fp = s.getPeerCertificate().fingerprint256 || '';
      if (z.abdruck && fp !== z.abdruck) { clearTimeout(uhr); s.destroy(); return nein(new Error('UniFi: Zertifikat der Konsole hat sich geändert – nichts gesendet')); }
      // Erstes Merken scheitert (volle Platte …) → nichts senden: ohne gespeicherten Abdruck wäre die Verbindung nicht festgenagelt
      if (!fp) { clearTimeout(uhr); s.destroy(); return nein(new Error('UniFi: Konsole zeigt kein Zertifikat – nichts gesendet')); }
      // Erster Kontakt: Abdruck merken und SOFORT im Zugang festhalten – Folgeanfragen mit demselben Zugang (Portfreigabe: GET, dann POST/PUT)
      // gelten nur noch mit genau diesem Zertifikat. Scheitert das Merken (volle Platte …), wird nichts gesendet.
      if (!z.abdruck && z.merken) { try { z.merken(fp); z.abdruck = fp; } catch (e) { clearTimeout(uhr); s.destroy(); return nein(new Error(`UniFi: Zertifikat nicht speicherbar (${e.message}) – nichts gesendet`)); } }
      const req = http.request({ method: methode, path: u.pathname + u.search, createConnection: () => s, headers: { Host: u.host, 'X-API-KEY': z.schluessel, Accept: 'application/json', ...(text !== undefined ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(text) } : {}) } }, (res) => {
        let t = ''; res.on('data', (d) => { if (t.length < 2e6) t += d; });
        res.on('end', () => { clearTimeout(uhr); let j = null; try { j = JSON.parse(t); } catch (e) {} if (res.statusCode >= 400) return nein(new Error(`UniFi: HTTP ${res.statusCode}${j?.meta?.msg ? ` (${j.meta.msg})` : ''}`)); ok(j || {}); });
      });
      req.on('error', (e) => { clearTimeout(uhr); nein(new Error(`UniFi: ${e.message}`)); });
      req.end(text);
    });
  });
}

// Name eines UniFi-Clients; ohne Namen der Hersteller (OUI) bzw. Hinweis auf eine zufällige/virtuelle MAC
function clientName(c) {
  const name = String(c.name || c.hostname || '').trim();
  if (name) return name;
  if (c.oui) return `Gerät von ${String(c.oui).trim()}`;
  return /^.[26ae]/i.test(String(c.mac || '')) ? 'Gerät mit privater MAC' : '';
}

// UniFi-Gerätesymbol (Fingerprint): vom Nutzer gewähltes Symbol vor dem erkannten
function symbolId(c) { const id = c.dev_id_override || c.dev_id; return Number.isInteger(id) && id > 0 ? id : null; }

function ptrName(ip) {
  const t = ip.split('.');
  return t.length === 4 ? `${t.reverse().join('.')}.in-addr.arpa` : null;
}

class Geraete {
  constructor({ zugang = () => ({}), gateway = () => '192.168.1.1', eigene = () => ({}), vpnNetz = /^192\.168\.5\./, jetzt = () => Date.now(), holer = unifiHole, protokoll = (t) => console.log(`[geraete] ${t}`), onZuordnung = () => {} }) {
    Object.assign(this, { zugang, gateway, eigene, vpnNetz, jetzt, holer, protokoll, onZuordnung });
    this.ohneMac = new Map();     // ip → seit wann sie ohne MAC gefragt hat (Kandidaten zum Zusammenführen)
    this.nachgefragt = new Map(); // ip → letzte sofortige UniFi-Abfrage wegen dieser IP
    this.letzterVersuch = 0; this.laeuft = null;
    this.jeIp = new Map();        // ip → {mac, name, netz, quelle, ts}
    this.jeMac = new Map();       // mac → {name, netz, ip}
    this.ptr = new Map();         // ip → {name, ts}
    this.stand = 0; this.fehler = null;
  }
  starten() {
    setTimeout(() => this.unifiLesen(), 3000).unref();
    setInterval(() => this.unifiLesen(), 5 * 60000).unref();
    return this;
  }
  // Letzte bekannte Zuordnungen aus dem Protokoll: [{mac, name, ip, zuletzt}] für MAC-Geräte, [{ipId: true, ip, zuletzt}] für „ip:…“
  vorbelegen(liste = []) {
    for (const r of liste) {
      if (!r.ip) continue;
      if (r.ipId) { if (!this.vpnNetz.test(r.ip) && !this.ohneMac.has(r.ip)) this.ohneMac.set(r.ip, r.zuletzt || this.jetzt()); continue; }
      if (!this.jeIp.has(r.ip)) this.jeIp.set(r.ip, { mac: r.mac, name: r.name || '', netz: '', ip: r.ip, quelle: 'protokoll', ts: r.zuletzt || 0 });
    }
  }
  unifiLesen() {
    if (!this.laeuft) this.laeuft = this.unifiLesenJetzt().finally(() => { this.laeuft = null; });
    return this.laeuft;
  }
  async unifiLesenJetzt() {
    const z = this.zugang() || {};
    this.letzterVersuch = this.jetzt();
    if (!z.url || !z.schluessel) { this.fehler = 'kein UniFi-Zugang (Einstellungen)'; return false; }
    try {
      const j = await this.holer(z, '/proxy/network/api/s/default/stat/sta');
      const netzNamen = {};
      try { const n = await this.holer(z, '/proxy/network/api/s/default/rest/networkconf'); for (const x of n.data || []) netzNamen[x._id] = x.name; } catch (e) {}
      let n = 0;
      const gemeldet = new Set();
      for (const c of j.data || []) {
        if (!c.mac) continue;
        const eintrag = { mac: c.mac.toLowerCase(), name: clientName(c), netz: c.network || netzNamen[c.network_id] || (c.is_wired === false ? 'WLAN' : ''), ip: c.ip || c.last_ip || '', verbunden: (c.assoc_time || c.latest_assoc_time || 0) * 1000, icon: symbolId(c), gesehen: this.jetzt() };
        this.jeMac.set(eintrag.mac, eintrag);
        if (eintrag.ip) { this.jeIp.set(eintrag.ip, { ...eintrag, quelle: 'unifi', ts: this.jetzt() }); gemeldet.add(eintrag.ip); }
        n++;
      }
      // Veraltete Zuordnungen weg: IPs, die UniFi jetzt nicht (mehr) meldet oder deren MAC eine andere IP bekam
      // (DHCP-Wechsel) – sonst bekäme ein neues Gerät unter der alten IP das Profil des Vorgängers.
      // Nur bei einer brauchbaren Antwort (mindestens ein Client), eine leere Liste wäre eher eine Störung.
      if (n) for (const ip of [...this.jeIp.keys()]) if (!gemeldet.has(ip)) this.jeIp.delete(ip);
      // Alle bekannten Clients (auch offline) – nur für Namen, z. B. Kindergeräte mit Profil, die heute noch nicht online waren
      try {
        const bekannt = await this.holer(z, '/proxy/network/api/s/default/rest/user');
        for (const c of bekannt.data || []) {
          const mac = String(c.mac || '').toLowerCase(), name = clientName(c);
          if (!mac || (!name && !symbolId(c))) continue;
          const da = this.jeMac.get(mac);
          if (!da) this.jeMac.set(mac, { mac, name, netz: '', ip: '', offline: true, icon: symbolId(c) });
          else { if (!da.name) da.name = name; if (!da.icon) da.icon = symbolId(c); }
        }
      } catch (e) {}
      // VPN-Zugänge des WireGuard-Servers der Konsole: Name je fester Tunnel-IP (25.11.2026, Betreiber: „VPN-Geräte besser erkenntlich machen“) –
      // aus „VPN 192.168.5.4“ wird z. B. „Reiserouter · VPN“. Ältere Konsolen ohne diesen Endpunkt: bleibt wie bisher.
      try {
        const wg = await this.holer(z, '/proxy/network/v2/api/site/default/wireguard/users');
        const neu = new Map();
        for (const x of (Array.isArray(wg) ? wg : wg?.data) || []) {
          const ip = String(x?.interface_ip || '').split('/')[0], name = String(x?.name || '').trim().slice(0, 60);
          if (net.isIPv4(ip) && name) neu.set(ip, name);
        }
        this.vpnNamen = neu;
      } catch (e) {}
      this.stand = this.jetzt(); this.fehler = null; this.online = n;
      this.zuordnen();
      return n;
    } catch (e) { this.fehler = e.message; return false; }
  }
  // IPs, die ohne MAC gefragt haben und die UniFi jetzt kennt → Anfragen seit dem Verbinden (höchstens 24 h) dem Gerät zuordnen
  zuordnen() {
    for (const ip of [...this.ohneMac.keys()]) {
      const u = this.jeIp.get(ip);
      if (!u?.mac || u.quelle !== 'unifi') continue;
      this.ohneMac.delete(ip);
      const seit = Math.max(u.verbunden || 0, this.jetzt() - 24 * 3600000);
      try { this.onZuordnung({ von: `ip:${ip}`, nach: u.mac, name: u.name, ip, seit }); } catch (e) { this.protokoll(`Zuordnung ${ip}: ${e.message}`); }
    }
  }
  // Unbekannte IP: UniFi gleich fragen statt bis zu 5 min zu warten
  bald(ip) {
    const jetzt = this.jetzt();
    if (jetzt - (this.nachgefragt.get(ip) || 0) < 5 * 60000 || jetzt - this.letzterVersuch < 15000) return;
    this.nachgefragt.set(ip, jetzt);
    if (this.nachgefragt.size > 500) this.nachgefragt.clear();
    this.unifiLesen().catch(() => {});
  }
  // Rückwärtsname am Gateway (einmal je IP, 1 h gemerkt) – für Geräte, die UniFi (noch) nicht kennt
  ptrAnfragen(ip) {
    const alt = this.ptr.get(ip), name = ptrName(ip), gw = this.gateway();
    if (!name || !gw || (alt && this.jetzt() - alt.ts < 3600000)) return;
    this.ptr.set(ip, { name: alt?.name || '', ts: this.jetzt() });
    const s = dgram.createSocket('udp4'), uhr = setTimeout(() => { try { s.close(); } catch (e) {} }, 1500);
    s.on('message', (m) => {
      clearTimeout(uhr);
      try { const a = dnsPacket.decode(m).answers?.find((r) => r.type === 'PTR'); if (a) this.ptr.set(ip, { name: String(a.data).replace(/\.$/, '').replace(/\.(localdomain|lan|local)$/i, ''), ts: this.jetzt() }); } catch (e) {}
      try { s.close(); } catch (e) {}
    });
    s.on('error', () => { try { s.close(); } catch (e) {} });
    s.send(dnsPacket.encode({ type: 'query', id: Math.floor(Math.random() * 65535), flags: dnsPacket.RECURSION_DESIRED, questions: [{ type: 'PTR', name }] }), 53, gw);
  }
  von(ip) {
    let u = this.jeIp.get(ip);
    if (u && this.jetzt() - (u.ts || 0) > 24 * 3600000) { this.jeIp.delete(ip); u = undefined; }   // älter als 24 h (DHCP-Lease) = unbekannt, UniFi neu fragen
    const id = u?.mac || `ip:${ip}`;
    const eigen = this.eigene()[id]?.name;
    if (!u && !this.vpnNetz.test(ip)) { if (!this.ohneMac.has(ip) && this.ohneMac.size < 1000) this.ohneMac.set(ip, this.jetzt()); this.bald(ip); }
    const vpnName = this.vpnNetz.test(ip) ? this.vpnNamen?.get(ip) : null;
    if (!u && !eigen && !vpnName) this.ptrAnfragen(ip);
    const name = eigen || u?.name || (vpnName ? `${vpnName} · VPN` : null) || this.ptr.get(ip)?.name || (this.vpnNetz.test(ip) ? `VPN ${ip}` : ip);
    return { id, name, mac: u?.mac || '', netz: u?.netz || (this.vpnNetz.test(ip) ? 'VPN' : ''), ip };
  }
  /** Alle Clients, die UniFi kennt – auch gerade offline (rest/user) – für „Gerät hinzufügen“ (25.11.2026: Reiserouter unterwegs) */
  bekannteUnifi() { return [...this.jeMac.values()].filter((e) => e.mac).map((e) => ({ id: e.mac, name: e.name || clientName({ mac: e.mac }), offline: !!e.offline || !e.ip })); }
  iconVon(id) { return this.jeMac.get(String(id || '').toLowerCase())?.icon || null; }
  nameVon(id) { const mac = String(id || '').toLowerCase(); return this.jeMac.get(mac)?.name || (/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/.test(mac) ? clientName({ mac }) : ''); }
  status() { return { unifi: { stand: this.stand, fehler: this.fehler, geraete: this.online ?? this.jeMac.size, bekannt: this.jeMac.size } }; }
}

module.exports = { Geraete, unifiHole, unifiAnfrage, clientName, symbolId };
