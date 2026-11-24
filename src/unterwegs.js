// ============================================================================
// Erdacht und programmiert von Fabian Hammer.
// (c) 2026 Fabian Hammer - Alle Rechte vorbehalten. Geistiges Eigentum.
// Unbefugte Vervielfaeltigung, Weitergabe oder Verwertung dieses Quellcodes ohne
// schriftliche Genehmigung des Urhebers ist untersagt.
// ============================================================================
// Schutz unterwegs (23.11.2026): ein Handy filtert auch im Mobilfunk über FAH-Adblock – mit dem eigenen Profil des Geräts.
// Jedes Gerät bekommt einen Namen unter der Basisdomain (dns-<kennung>.<basis>), der öffentlich auf den Proxy zeigt:
//   · Android „Privates DNS“ = DNS-over-TLS (Port 853): das Gerät wird am Namen (SNI) erkannt, Zertifikat je Name per ACME
//   · iPhone/iPad = DNS-over-HTTPS über ein Konfigurationsprofil: https://<name>/dns-query/<geheim> (FAH-Proxy → hier)
// Unter einem Gerätenamen antwortet die Weboberfläche NUR auf /dns-query/<geheim>, die ACME-Prüfung und das Profil –
// Anmeldung, API und Oberfläche sind von draußen nicht erreichbar. DoT läuft nur auf Haupt/allein (nie am Ersatz).
// Zertifikate: data/unterwegs/<name>.key|.crt (0600), Erneuerung 30 Tage vor Ablauf, nach Fehlschlag frühestens nach 6 h.
'use strict';
const fs = require('fs');
const path = require('path');
const tls = require('tls');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const { normIp } = require('./netz');
const { lookup } = require('./aufloeser');
const { unifiAnfrage, unifiHole } = require('./geraete');

const PORT_NAME = 'FAH-Adblock DoT (unterwegs)';
const UEBERNAHME_MS = 6 * 60000;   // Ersatz übernimmt, wenn der Haupt so lange nicht erreichbar ist
// Übergabe Haupt → Ersatz (Zertifikate, FAH-Proxy-Zugang): je Abgleich ein Schlüssel aus X25519 (Ersatz und Haupt erzeugen je
// ein Einmal-Schlüsselpaar), abgeleitet per HKDF mit dem Kopplungscode, AES-256-GCM mit beiden öffentlichen Schlüsseln als AAD.
// Wer die (unverschlüsselte) Verbindung im LAN nur mitliest, kann das Paket damit nicht öffnen.
const pubAus = (b64) => crypto.createPublicKey({ key: Buffer.from(String(b64), 'base64'), format: 'der', type: 'spki' });
const pubText = (k) => k.export({ format: 'der', type: 'spki' }).toString('base64');
function paketSchluessel(privat, oeffentlich, code) { return Buffer.from(crypto.hkdfSync('sha256', crypto.diffieHellman({ privateKey: privat, publicKey: oeffentlich }), crypto.createHash('sha256').update(String(code)).digest(), 'fah-adblock-unterwegs-v2', 32)); }
function einmalSchluessel() { return crypto.generateKeyPairSync('x25519'); }
function paketVerschluesseln(obj, code, ersatzPub) {
  const { privateKey, publicKey } = einmalSchluessel(), hauptPub = pubText(publicKey), iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', paketSchluessel(privateKey, pubAus(ersatzPub), code), iv, { authTagLength: 16 });
  c.setAAD(Buffer.from(`${ersatzPub}|${hauptPub}`));
  const d = Buffer.concat([c.update(JSON.stringify(obj), 'utf8'), c.final()]);
  return { pub: hauptPub, daten: `${iv.toString('base64')}.${c.getAuthTag().toString('base64')}.${d.toString('base64')}` };
}
function paketEntschluesseln({ pub, daten }, code, ersatz) {
  const [iv, tag, d] = String(daten).split('.'), ersatzPub = pubText(ersatz.publicKey);
  const x = crypto.createDecipheriv('aes-256-gcm', paketSchluessel(ersatz.privateKey, pubAus(pub), code), Buffer.from(iv, 'base64'), { authTagLength: 16 });
  x.setAAD(Buffer.from(`${ersatzPub}|${pub}`)); x.setAuthTag(Buffer.from(tag, 'base64'));
  return JSON.parse(Buffer.concat([x.update(Buffer.from(d, 'base64')), x.final()]).toString('utf8'));
}
// Strenger Gerätename als Dateiname (kein „..“, kein „/“)
const HOSTNAME = /^dns-[a-z0-9](?:[a-z0-9-]{0,22}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
const privatV4 = (ip) => /^(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})$/.test(String(ip));

const TAG = 86400000;
const gleich = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const xml = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' }[c]));
const uuidAus = (text) => { const h = crypto.createHash('sha256').update(text).digest('hex'); return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-a${h.slice(17, 20)}-${h.slice(20, 32)}`.toUpperCase(); };

// 16 Zeichen aus 32 (a–z, 2–7) = 80 bit – nicht zu erraten. Achtung: Namen mit Zertifikat stehen in öffentlichen CT-Logs.
const B32 = 'abcdefghijklmnopqrstuvwxyz234567';
function neueKennung() { return `dns-${[...crypto.randomBytes(16)].map((b) => B32[b & 31]).join('')}`; }
// Kurzer, lesbarer Name aus dem Gerätenamen („The Fairphone Gen 6“ → dns-fairphone-gen-6) – Android will ihn eingetippt haben.
// Ob lesbar oder zufällig, macht für die Sicherheit kaum Unterschied: Namen mit Zertifikat stehen ohnehin in öffentlichen CT-Logs.
const KENNUNG = /^dns-[a-z0-9](?:[a-z0-9-]{0,22}[a-z0-9])?$/;
function kennungAus(name) {
  const s = String(name || '').toLowerCase().replace(/ä/g, 'ae').replace(/ö/g, 'oe').replace(/ü/g, 'ue').replace(/ß/g, 'ss')
    .replace(/^(the|das|der|die)[\s-]+/, '').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 20).replace(/-+$/, '');
  return s ? `dns-${s}` : '';
}
/** Host-Kopf normieren: Kleinschreibung, Port (auch nach [IPv6]) ab, Punkte am Ende weg */
function hostNorm(roh) { let h = String(roh || '').trim().toLowerCase(); if (h.startsWith('[')) return h.slice(0, h.indexOf(']') + 1); h = h.replace(/:\d*$/, ''); return h.replace(/\.+$/, ''); }
/** Ein Gerätename (erstes Label „dns-…“) – unter solchen Namen gibt es NIE Oberfläche oder API, unabhängig von der Basisdomain */
const istGeraeteName = (roh) => /^dns-[a-z0-9-]*(\.|$)/.test(hostNorm(roh));
function neuesGeheimnis() { return crypto.randomBytes(24).toString('base64url'); }

/** Vorprüfung vor ACME: kommt http://<name>/.well-known/acme-challenge/<probe> über den Proxy bei uns an? (folgt einer Umleitung auf https) */
function vorpruefen(host, probe, erwartet, zeitlimit = 10000) {
  const hole = (url, rest) => new Promise((ok) => {
    const mod = url.startsWith('https:') ? https : http;
    const req = mod.get(url, { lookup, timeout: zeitlimit, rejectUnauthorized: false, headers: { 'User-Agent': 'FAH-Adblock-Vorpruefung' } }, (res) => {
      if ([301, 302, 307, 308].includes(res.statusCode) && res.headers.location && rest > 0) { res.resume(); return ok(hole(new URL(res.headers.location, url).href, rest - 1)); }
      let t = ''; res.on('data', (d) => { if (t.length < 2000) t += d; }); res.on('end', () => ok(res.statusCode === 200 && t.trim() === erwartet ? null : `Kommt über FAH-Proxy noch nicht hier an (Antwort ${res.statusCode}).`));
    });
    req.on('timeout', () => req.destroy(new Error('Zeitüberschreitung')));
    req.on('error', () => ok('Kommt über FAH-Proxy noch nicht hier an – der Eintrag in FAH-Proxy fehlt oder hat noch kein Zertifikat.'));
  });
  return hole(`http://${host}/.well-known/acme-challenge/${probe}`, 3);
}

class Unterwegs {
  constructor({ einst, dns, verzeichnis, acme = null, jetzt = () => Date.now(), istErsatz = () => false, hauptZuletzt = () => 0, bind = '0.0.0.0', port = 853, nameVon = (id) => id, pruefer = vorpruefen, zielUrl = () => '', proxy = null, unifi = null, zusatz = null, protokoll = (t) => console.log(`[unterwegs] ${t}`) }) {
    Object.assign(this, { einst, dns, acme, jetzt, istErsatz, hauptZuletzt, bind, port, nameVon, pruefer, zielUrl, proxy, unifi, zusatz, protokoll });   // zusatz: {geben, nehmen} – weitere Geheimnisse fürs Paket (Benachrichtigungen)
    this.freigabe = { proxy: null, port: null, zeit: null };
    this.paketHash = null;
    this.ordner = path.join(verzeichnis, 'unterwegs');
    this.zert = new Map();      // name → {kontext, bis}
    this.zustand = new Map();   // name → {fehler, versucht}
    this.zuletzt = new Map();   // gid → {ts, art}
    this.server = null; this.verbindungen = new Set(); this.laeuftAcme = null; this.timer = null;
    this.zaehler = { dot: 0, doh: 0, abgewiesen: 0 };
    this.ladeZertifikate();
  }
  get u() { return this.einst.werte.unterwegs || { an: false, basis: '', geraete: {} }; }
  hostVon(gid) { const g = this.u.geraete[gid]; return g && this.u.basis ? `${g.kennung}.${this.u.basis}` : null; }
  /** Gerät zu einem Namen (nur eingeschaltete Geräte bei eingeschaltetem Schutz) */
  geraetVonHost(host) {
    const h = hostNorm(host), basis = this.u.basis;
    if (!this.u.an || !basis || !h.endsWith(`.${basis}`)) return null;
    const kennung = h.slice(0, -basis.length - 1);
    for (const [gid, g] of Object.entries(this.u.geraete)) if (g.an !== false && g.kennung === kennung) return gid;
    return null;
  }
  /** Gerätename (auch ausgeschaltet, alte Basisdomain, Punkt am Ende, tiefere Namen)? Dann gilt die eingeschränkte Weboberfläche. */
  istHost(host) { return istGeraeteName(host); }
  geraetVonGeheimnis(geheim) {
    if (!this.u.an || !/^[A-Za-z0-9_-]{20,64}$/.test(String(geheim || ''))) return null;
    for (const [gid, g] of Object.entries(this.u.geraete)) if (g.an !== false && gleich(g.geheim, geheim)) return gid;
    return null;
  }
  // ── Zertifikate ──
  dateien(host) { if (!HOSTNAME.test(String(host)) || path.basename(host) !== host) throw new Error(`Ungültiger Gerätename: ${host}`); return { key: path.join(this.ordner, `${host}.key`), crt: path.join(this.ordner, `${host}.crt`) }; }
  ladeZertifikate() {
    let liste = [];
    try { liste = fs.readdirSync(this.ordner).filter((f) => f.endsWith('.crt')); } catch (e) {}
    for (const f of liste) {
      const host = f.slice(0, -4);
      try {
        const d = this.dateien(host);
        const kette = fs.readFileSync(d.crt, 'utf8'), schluessel = fs.readFileSync(d.key, 'utf8');
        const bis = Date.parse(new crypto.X509Certificate(kette).validTo);
        this.zert.set(host, { kontext: tls.createSecureContext({ key: schluessel, cert: kette }), bis });
      } catch (e) { this.protokoll(`Zertifikat ${host} unlesbar: ${e.message}`); }
    }
  }
  speichereZertifikat(host, { schluessel, kette, bis }) {
    fs.mkdirSync(this.ordner, { recursive: true, mode: 0o700 });
    const d = this.dateien(host);
    fs.writeFileSync(d.key + '.tmp', schluessel, { mode: 0o600 }); fs.renameSync(d.key + '.tmp', d.key);
    fs.writeFileSync(d.crt + '.tmp', kette, { mode: 0o600 }); fs.renameSync(d.crt + '.tmp', d.crt);
    this.zert.set(host, { kontext: tls.createSecureContext({ key: schluessel, cert: kette }), bis });
  }
  /** Fehlende oder bald ablaufende Zertifikate holen (nacheinander; nach Fehlschlag 6 h Pause je Name, außer `sofort`) */
  zertifikatePflegen({ sofort = false } = {}) {
    if (this.laeuftAcme) return this.laeuftAcme;
    this.laeuftAcme = (async () => {
      if (!this.istErsatz()) await this.freigabenPflegen().catch(() => {});   // auch beim Ausschalten: Einträge und Portfreigabe wieder weg
      if (!this.u.an || !this.u.basis || this.istErsatz()) return;
      // Gekoppelt: dasselbe Zertifikat wie FAH-Proxy/Caddy übernehmen (je Name nur EIN Zertifikat – selfhost.eu & Co. teilen sich bei
      // Let's Encrypt 50 Zertifikate pro Woche; Caddy weicht bei Bedarf auf ZeroSSL aus und erneuert selbst)
      if (this.proxy?.gekoppelt()) { await this.zertifikateVomProxy(); this.dotPruefen(); return; }
      if (!this.acme) return;
      for (const gid of Object.keys(this.u.geraete)) {
        const host = this.hostVon(gid), g = this.u.geraete[gid];
        if (!host || g.an === false) continue;
        const z = this.zert.get(host), st = this.zustand.get(host) || {};
        if (z && z.bis - this.jetzt() > 30 * TAG) continue;
        if (!sofort && st.versucht && this.jetzt() - st.versucht < 6 * 3600000) continue;
        this.zustand.set(host, { ...st, versucht: this.jetzt(), laeuft: true });
        try {
          const probe = `fah-pruefung-${crypto.randomBytes(8).toString('hex')}`, wert = crypto.randomBytes(12).toString('hex');
          this.acme.herausforderungen.set(probe, wert);
          let fehler;
          try { fehler = await this.pruefer(host, probe, wert); } finally { this.acme.herausforderungen.delete(probe); }
          if (fehler) { this.zustand.set(host, { versucht: this.jetzt() - 6 * 3600000 + 2 * 60000, fehler, art: 'proxy' }); this.protokoll(`${host}: ${fehler}`); continue; }   // in 2 min wieder versuchen (FAH-Proxy braucht kurz für sein Zertifikat)
          this.speichereZertifikat(host, await this.acme.zertifikat(host));
          this.zustand.set(host, { versucht: this.jetzt(), fehler: null });
          this.protokoll(`Zertifikat für ${host} geholt`);
        } catch (e) {
          this.zustand.set(host, { versucht: this.jetzt(), fehler: `Zertifikat: ${e.message}`, art: 'acme' });
          this.protokoll(`${host}: ${e.message}`);
        }
      }
      this.dotPruefen();
    })().finally(() => { this.laeuftAcme = null; });
    return this.laeuftAcme;
  }
  /** Einmalig (23.11.2026): Zufallsnamen aus älteren Versionen (dns-<16 Zeichen>) auf kurze Namen aus dem Gerätenamen umstellen */
  kurznamenUmstellen() {
    if (this.u.kurznamen) return 0;
    let n = 0;
    this.einst.aendern((x) => {
      const belegt = new Set(Object.values(x.unterwegs.geraete).map((g) => g.kennung));
      for (const [gid, g] of Object.entries(x.unterwegs.geraete)) {
        if (!/^dns-[a-z2-7]{16}$/.test(g.kennung)) continue;
        let k = kennungAus(x.geraete[gid]?.name || this.nameVon(gid));
        if (!k || k === g.kennung) continue;
        for (let i = 2; belegt.has(k) && i < 50; i++) k = `${kennungAus(x.geraete[gid]?.name || this.nameVon(gid)).slice(0, 21)}-${i}`;
        if (belegt.has(k) || !KENNUNG.test(k)) continue;
        belegt.delete(g.kennung); belegt.add(k); this.protokoll(`Name ${g.kennung} → ${k}`); g.kennung = k; n++;
      }
      x.unterwegs.kurznamen = 1;
    });
    return n;
  }
  async zertifikateVomProxy() {
    const hosts = new Set(Object.keys(this.u.geraete).filter((gid) => this.u.geraete[gid].an !== false).map((gid) => this.hostVon(gid)).filter(Boolean));
    let liste;
    try { liste = await this.proxy.zertifikate(); } catch (e) { for (const h of hosts) if (!this.zert.has(h)) this.zustand.set(h, { versucht: this.jetzt(), fehler: e.message, art: 'acme' }); return; }
    for (const z of liste.zertifikate || []) {
      if (!hosts.has(z.domain) || !HOSTNAME.test(z.domain) || !/BEGIN CERTIFICATE/.test(String(z.kette))) continue;
      let bis; try { bis = Date.parse(new crypto.X509Certificate(z.kette).validTo); tls.createSecureContext({ key: z.schluessel, cert: z.kette }); } catch (e) { continue; }
      const alt = this.zert.get(z.domain);
      if (!alt || alt.bis < bis) { this.speichereZertifikat(z.domain, { schluessel: z.schluessel, kette: z.kette, bis }); this.protokoll(`Zertifikat für ${z.domain} von FAH-Proxy übernommen (bis ${new Date(bis).toLocaleDateString('de-DE')})`); }
      this.zustand.set(z.domain, { versucht: this.jetzt(), fehler: null });
    }
    for (const h of hosts) if (!this.zert.has(h)) this.zustand.set(h, { versucht: this.jetzt(), fehler: 'FAH-Proxy holt das Zertifikat noch', art: 'proxy' });
    // Wartet noch ein Gerät? Dann in einer Minute wieder nachsehen (statt im 10-Minuten-Takt)
    if ([...hosts].some((h) => !this.zert.has(h)) && !this.baldTimer) { this.baldTimer = setTimeout(() => { this.baldTimer = null; this.zertifikatePflegen().catch(() => {}); }, 60000); this.baldTimer.unref?.(); }
  }
  // ── Freigaben selbst pflegen: FAH-Proxy-Einträge (DoH, ACME) und UCG-Portfreigabe TCP 853 (DoT) ──
  // Soll: alle eingeschalteten Geräte bei eingeschaltetem Schutz. Ziel ist immer DIESE Instanz – beim Failover stellt der Ersatz damit alles auf sich um,
  // der zurückgekehrte Haupt holt es mit seiner nächsten Pflege zurück. Gelöschte Geräte verschwinden aus FAH-Proxy.
  async freigabenPflegen() {
    if (!this.zustaendig()) return this.freigabe;
    if (this.laeuftFreigabe) return this.laeuftFreigabe;
    this.laeuftFreigabe = (async () => {
      if (!this.istErsatz()) this.kurznamenUmstellen();
      const aktiv = this.u.an && !!this.u.basis;
      const soll = aktiv ? Object.keys(this.u.geraete).filter((gid) => this.u.geraete[gid].an !== false).map((gid) => ({ domain: this.hostVon(gid), name: this.nameVon(gid) })) : [];
      const ziel = this.zielUrl();
      if (this.proxy?.gekoppelt()) {
        try {
          if (!ziel) throw new Error('Eigene Adresse unbekannt (DNS_BIND/WEB_PORT)');
          const r = await this.proxy.abgleichen(soll, ziel, this.u.basis);
          this.freigabe.proxy = { ok: !r.fehler, fehler: r.fehler || null, instanz: r.instanz, zeit: this.jetzt() };
          if (r.angelegt.length || r.geaendert.length) for (const h of [...r.angelegt, ...r.geaendert]) { const st = this.zustand.get(h); if (st) this.zustand.set(h, { ...st, versucht: this.jetzt() - 6 * 3600000 + 60000 }); }
          if (r.angelegt.length && !this.baldTimer) { this.baldTimer = setTimeout(() => { this.baldTimer = null; this.zertifikatePflegen().catch(() => {}); }, 45000); this.baldTimer.unref?.(); }
        } catch (e) { this.freigabe.proxy = { ok: false, fehler: e.message, zeit: this.jetzt() }; }
      } else this.freigabe.proxy = { ok: false, fehler: 'FAH-Proxy ist nicht gekoppelt', zeit: this.jetzt() };
      // UCG: genau eine Portfreigabe „FAH-Adblock DoT (unterwegs)“ → diese Instanz:853 (UniFi kennt nur EIN Ziel je Freigabe)
      const z = this.unifi?.();
      if (z?.url && z?.schluessel) {
        try {
          if (!privatV4(this.bind)) throw new Error(`Eigene Adresse ${this.bind} ist keine private IPv4 – Portfreigabe nicht angelegt`);
          const uz = { ...z, abdruck: this.unifiAbdruck(), merken: (fp) => this.unifiAbdruck(fp) };
          const liste = (await unifiAnfrage(uz, 'GET', '/proxy/network/api/s/default/rest/portforward')).data || [];
          const da = liste.find((p) => p.name === PORT_NAME);
          const brauchtPort = aktiv && soll.length > 0;
          if (brauchtPort) {
            const vorlage = liste.find((p) => p.pfwd_interface) || {};
            const satz = { name: PORT_NAME, enabled: true, log: false, dst_port: '853', fwd: this.bind, fwd_port: String(this.port), proto: 'tcp', pfwd_interface: vorlage.pfwd_interface || 'wan', src_limiting_enabled: false, ...(vorlage.destination_ip !== undefined ? { destination_ip: vorlage.destination_ip } : {}), ...(Array.isArray(vorlage.destination_ips) ? { destination_ips: vorlage.destination_ips } : {}) };
            if (!da) { await unifiAnfrage(uz, 'POST', '/proxy/network/api/s/default/rest/portforward', satz); this.protokoll(`UCG-Portfreigabe 853 → ${this.bind} angelegt`); }
            else if (da.fwd !== this.bind || String(da.fwd_port) !== String(this.port) || !da.enabled || da.proto !== 'tcp') { await unifiAnfrage(uz, 'PUT', `/proxy/network/api/s/default/rest/portforward/${da._id}`, { ...satz, _id: da._id }); this.protokoll(`UCG-Portfreigabe 853 → ${this.bind} umgestellt`); }
            this.freigabe.port = { ok: true, ziel: `${this.bind}:${this.port}`, zeit: this.jetzt() };
          } else if (da && !this.istErsatz()) {
            await unifiAnfrage(uz, 'DELETE', `/proxy/network/api/s/default/rest/portforward/${da._id}`); this.protokoll('UCG-Portfreigabe 853 entfernt (kein Gerät unterwegs)');
            this.freigabe.port = { ok: true, ziel: null, zeit: this.jetzt() };
          } else this.freigabe.port = { ok: true, ziel: null, zeit: this.jetzt() };
        } catch (e) { this.freigabe.port = { ok: false, fehler: e.message, zeit: this.jetzt() }; }
      } else this.freigabe.port = { ok: false, fehler: 'Kein UniFi-Zugang (Einstellungen → UniFi)', zeit: this.jetzt() };
      this.freigabe.zeit = this.jetzt();
      return this.freigabe;
    })().finally(() => { this.laeuftFreigabe = null; });
    return this.laeuftFreigabe;
  }
  /** Zertifikats-Abdruck der UCG (beim ersten schreibenden Kontakt gemerkt, danach Pflicht) */
  unifiAbdruck(neu) {
    const datei = path.join(this.ordner, 'unifi-abdruck.txt');
    if (neu) { fs.mkdirSync(this.ordner, { recursive: true, mode: 0o700 }); fs.writeFileSync(datei, neu, { mode: 0o600 }); return neu; }
    try { return fs.readFileSync(datei, 'utf8').trim(); } catch (e) { return ''; }
  }
  // ── Übergabe an den Ersatz (beim Abgleich, X25519 + Kopplungscode) ──
  /** Ersatz: Einmal-Schlüssel für diesen Abgleich (öffentlicher Teil geht mit) */
  ersatzSchluessel() { this.einmal = einmalSchluessel(); return pubText(this.einmal.publicKey); }
  paketFuerErsatz(code, bekannt, ersatzPub) {
    const zert = [...this.zert.keys()].map((host) => { const d = this.dateien(host); try { return { host, schluessel: fs.readFileSync(d.key, 'utf8'), kette: fs.readFileSync(d.crt, 'utf8') }; } catch (e) { return null; } }).filter(Boolean);
    const k = this.proxy?.lesen(), proxyZugang = k ? { urls: k.urls, name: k.name, passwort: this.proxy.passwort(), abdruecke: k.abdruecke || {} } : null;
    const inhalt = { zert, proxy: proxyZugang };
    if (this.zusatz) { try { inhalt.zusatz = this.zusatz.geben() || null; } catch (e) { inhalt.zusatz = null; } }
    const h = crypto.createHash('sha256').update(JSON.stringify(inhalt)).digest('hex').slice(0, 32);
    if (h === bekannt || !ersatzPub) return { hash: h };
    return { hash: h, ...paketVerschluesseln(inhalt, code, ersatzPub) };
  }
  paketUebernehmen(paket, code) {
    if (!paket || !paket.hash || !paket.daten || !paket.pub || !this.einmal || paket.hash === this.paketHash) return false;
    const inhalt = paketEntschluesseln(paket, code, this.einmal);
    const erlaubt = new Set(Object.keys(this.u.geraete).map((gid) => this.hostVon(gid)).filter(Boolean));   // nur Namen eigener Geräte
    for (const z of inhalt.zert || []) if (erlaubt.has(z.host) && HOSTNAME.test(z.host) && /BEGIN CERTIFICATE/.test(z.kette)) { const bis = Date.parse(new crypto.X509Certificate(z.kette).validTo); this.speichereZertifikat(z.host, { schluessel: z.schluessel, kette: z.kette, bis }); }
    if (inhalt.proxy && this.proxy) this.proxy.uebernehmen(inhalt.proxy);
    if (inhalt.proxy === null && this.proxy?.lesen()?.vomHaupt) this.proxy.loesen();   // am Haupt entkoppelt → hier auch
    if (inhalt.zusatz && this.zusatz) { try { this.zusatz.nehmen(inhalt.zusatz); } catch (e) { this.protokoll(`Übergabe Benachrichtigungen: ${e.message}`); } }
    this.paketHash = paket.hash;
    this.dotPruefen();
    return true;
  }

  // ── DNS-over-TLS ──
  /** Diese Instanz bedient unterwegs: Haupt/allein – oder der Ersatz, wenn der Haupt seit 6 min nicht erreichbar ist */
  uebernommen() { return this.istErsatz() && this.jetzt() - (this.hauptZuletzt() || 0) > UEBERNAHME_MS; }
  zustaendig() { return !this.istErsatz() || this.uebernommen(); }
  dotSoll() { return this.u.an && this.zustaendig() && [...this.zert.keys()].some((h) => this.geraetVonHost(h)); }
  dotPruefen() {
    if (this.dotSoll() && !this.server) this.dotStarten();
    else if (!this.dotSoll() && this.server) this.dotStoppen();
  }
  dotStarten() {
    const srv = tls.createServer({
      minVersion: 'TLSv1.2', handshakeTimeout: 10000,
      SNICallback: (name, fertig) => { const z = this.geraetVonHost(name) ? this.zert.get(String(name).toLowerCase()) : null; if (!z) { this.zaehler.abgewiesen++; return fertig(new Error('unbekannter Name')); } fertig(null, z.kontext); },
    }, (sock) => this.dotVerbindung(sock));
    // je Quell-IP höchstens 10 Verbindungen (auch während des Handshakes) – sonst legen 400 halboffene Verbindungen DoT lahm
    this.jeIp = new Map();
    srv.on('connection', (roh) => {
      const ip = normIp(roh.remoteAddress), n = (this.jeIp.get(ip) || 0) + 1;
      if (n > 10) { this.zaehler.abgewiesen++; return roh.destroy(); }
      this.jeIp.set(ip, n);
      roh.once('close', () => { const m = (this.jeIp.get(ip) || 1) - 1; if (m > 0) this.jeIp.set(ip, m); else this.jeIp.delete(ip); });
    });
    srv.on('tlsClientError', () => {});
    srv.on('error', (e) => { this.protokoll(`DoT auf Port ${this.port}: ${e.message}`); this.fehler = e.message; try { srv.close(); } catch (x) {} if (this.server === srv) this.server = null; });
    srv.maxConnections = 400;
    srv.listen(this.port, this.bind, () => { this.fehler = null; this.protokoll(`DNS-over-TLS auf ${this.bind}:${this.port}`); });
    this.server = srv;
  }
  dotStoppen() { try { this.server?.close(); } catch (e) {} for (const s of this.verbindungen) s.destroy(); this.verbindungen.clear(); this.server = null; }
  dotVerbindung(sock) {
    const gid = this.geraetVonHost(sock.servername);
    if (!gid) return sock.destroy();
    this.verbindungen.add(sock); sock.on('close', () => this.verbindungen.delete(sock));
    sock.setTimeout(60000, () => sock.destroy());
    sock.on('error', () => {});
    const ip = normIp(sock.remoteAddress);
    let puffer = Buffer.alloc(0), offen = 0;
    sock.on('data', (d) => {
      puffer = Buffer.concat([puffer, d]);
      if (puffer.length > 70000) return sock.destroy();
      while (puffer.length >= 2) {
        const n = puffer.readUInt16BE(0);
        if (puffer.length < 2 + n) break;
        const nachricht = puffer.subarray(2, 2 + n); puffer = puffer.subarray(2 + n);
        // Rückstau: wer nicht liest oder zu viele Anfragen gleichzeitig offen hat, fliegt raus
        if (offen >= 64 || sock.writableLength > 1e6) return sock.destroy();
        offen++; this.zaehler.dot++; this.vermerke(gid, 'DoT', ip);
        this.dns.bearbeite(nachricht, ip, false, this.kontext(gid, ip)).then((antwort) => {
          offen--;
          if (!antwort || sock.destroyed) return;
          const kopf = Buffer.alloc(2); kopf.writeUInt16BE(antwort.length); sock.write(Buffer.concat([kopf, antwort]));
        }).catch(() => { offen--; });
      }
    });
  }
  // DoT: direkte Verbindung, die Quell-IP ist echt – aus dem Heimnetz gelten die Heimnetz-Namen. DoH kommt immer über den Proxy: stets extern.
  kontext(gid, ip, immerExtern = false) { return { extern: immerExtern || !this.dns.erlaubt.enthaelt(ip), geraet: { id: gid, name: this.nameVon(gid), mac: '', netz: 'unterwegs' } }; }
  vermerke(gid, art, ip, immerExtern = false) { const extern = immerExtern || !this.dns.erlaubt.enthaelt(ip); this.zuletzt.set(gid, { ts: this.jetzt(), art, extern }); }
  // ── DNS-over-HTTPS (RFC 8484) über FAH-Proxy ──
  async doh(req, res, gid, ip) {
    let nachricht = null;
    if (req.method === 'GET') {
      const q = new URL(req.url, 'http://x').searchParams.get('dns');
      if (q && q.length < 2000) nachricht = Buffer.from(q, 'base64url');
    } else if (req.method === 'POST' && String(req.headers['content-type'] || '').startsWith('application/dns-message')) {
      nachricht = await new Promise((ok) => { const t = []; let n = 0; req.on('data', (d) => { n += d.length; if (n > 65535) req.destroy(); else t.push(d); }); req.on('end', () => ok(Buffer.concat(t))); req.on('error', () => ok(null)); });
    }
    if (!nachricht || nachricht.length < 12) { res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('Keine DNS-Anfrage'); }
    this.zaehler.doh++; this.vermerke(gid, 'DoH', ip, true);
    const antwort = await this.dns.bearbeite(nachricht, ip, false, this.kontext(gid, ip, true)).catch(() => null);
    if (!antwort) { res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('Ungültige DNS-Anfrage'); }
    res.writeHead(200, { 'Content-Type': 'application/dns-message', 'Content-Length': antwort.length, 'Cache-Control': 'no-store' });
    res.end(antwort);
  }
  /** iOS/iPadOS/macOS-Profil: DNS-over-HTTPS über den Gerätenamen, immer an (auch im WLAN) */
  profil(gid) {
    const g = this.u.geraete[gid], host = this.hostVon(gid);
    if (!g || !host) return null;
    const name = this.nameVon(gid) || gid;
    return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>DNSSettings</key>
      <dict>
        <key>DNSProtocol</key><string>HTTPS</string>
        <key>ServerURL</key><string>https://${xml(host)}/dns-query/${xml(g.geheim)}</string>
      </dict>
      <key>OnDemandRules</key>
      <array><dict><key>Action</key><string>Connect</string></dict></array>
      <key>PayloadDisplayName</key><string>FAH-Adblock DNS</string>
      <key>PayloadIdentifier</key><string>de.fah.adblock.dns.${xml(g.kennung)}</string>
      <key>PayloadType</key><string>com.apple.dnsSettings.managed</string>
      <key>PayloadUUID</key><string>${uuidAus(`dns|${g.geheim}`)}</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>ProhibitDisablement</key><true/>
    </dict>
  </array>
  <key>PayloadDescription</key><string>Filtert Werbung und schützt ${xml(name)} auch unterwegs im Mobilfunk – mit dem Profil dieses Geräts in FAH-Adblock.</string>
  <key>PayloadDisplayName</key><string>FAH-Adblock – ${xml(name)}</string>
  <key>PayloadIdentifier</key><string>de.fah.adblock.${xml(g.kennung)}</string>
  <key>PayloadRemovalDisallowed</key><false/>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadUUID</key><string>${uuidAus(`profil|${g.geheim}`)}</string>
  <key>PayloadVersion</key><integer>1</integer>
</dict>
</plist>
`;
  }
  starten() {
    this.dotPruefen();
    this.timer = setInterval(() => { this.dotPruefen(); this.zertifikatePflegen().catch(() => {}); if (this.istErsatz() && this.uebernommen()) this.freigabenPflegen().catch(() => {}); }, 10 * 60000);
    // Ersatz: öfter nachsehen, ob übernommen werden muss (oder der Haupt zurück ist)
    this.wache = setInterval(() => { if (!this.istErsatz()) return; const jetzt = this.uebernommen(); if (jetzt !== this.warUebernommen) { this.warUebernommen = jetzt; this.protokoll(jetzt ? 'Haupt nicht erreichbar – Ersatz übernimmt den Schutz unterwegs' : 'Haupt wieder da – er übernimmt den Schutz unterwegs'); if (jetzt) this.freigabenPflegen().catch(() => {}); } this.dotPruefen(); }, 60000);
    this.wache.unref?.();
    this.timer.unref?.();
    setTimeout(() => this.zertifikatePflegen().catch(() => {}), 15000).unref?.();
    return this;
  }
  stoppen() { clearInterval(this.timer); clearInterval(this.wache); this.dotStoppen(); }
  status() {
    return {
      an: !!this.u.an, basis: this.u.basis, email: this.u.email || '', ersatz: this.istErsatz(), uebernommen: this.uebernommen(), proxyZiel: this.zielUrl() || '',
      freigabe: this.freigabe, proxy: this.proxy ? this.proxy.status() : null, dot: { laeuft: !!this.server?.listening, port: this.port, bind: this.bind, fehler: this.fehler || null },
      zaehler: this.zaehler,
      geraete: Object.entries(this.u.geraete).map(([gid, g]) => {
        const host = this.hostVon(gid), z = host ? this.zert.get(host) : null, st = host ? this.zustand.get(host) || {} : {};
        return { id: gid, name: this.nameVon(gid), an: g.an !== false, kennung: g.kennung, host, geheim: g.geheim, zertifikatBis: z?.bis || null, fehler: st.fehler || null, wartetAufProxy: st.art === 'proxy', versucht: st.versucht || null, zuletzt: this.zuletzt.get(gid) || null };
      }),
    };
  }
}

module.exports = { Unterwegs, neueKennung, kennungAus, KENNUNG, neuesGeheimnis, vorpruefen, hostNorm, istGeraeteName };
